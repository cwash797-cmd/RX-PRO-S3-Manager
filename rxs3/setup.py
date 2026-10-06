"""Interactive setup with a durable inbound intent and isolated fresh bootstrap."""
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import subprocess
import sys
import time

from .errors import ManagerError, RemoteError
from .http import Panel, validate_panel_url
from .runtime import run
from .s3 import S3, validate_bucket
from .secure import Store, atomic_json, load_private, private_dir

STATE = Path('/var/lib/rxs3')
HOME = Path('/opt/rxs3')
PANEL_BINARY = '/usr/local/x-ui/x-ui'
PANEL_UNIT = '''# RX-PRO-S3-Manager fresh ordinary 3x-ui installation
[Unit]
Description=3x-ui 3.9.0
After=network.target
Wants=network.target
[Service]
Type=simple
WorkingDirectory=/usr/local/x-ui
ExecStart=/usr/local/x-ui/x-ui
Environment=XUI_DB_FOLDER=/etc/x-ui
Environment=XUI_LOG_FOLDER=/var/log/x-ui
Environment=XUI_BIN_FOLDER=/usr/local/x-ui/bin
Environment=XUI_NODE_TOKEN_KEY_FILE=/etc/x-ui/nodekey.json
Restart=on-failure
RestartSec=5
UMask=0077
[Install]
WantedBy=multi-user.target
'''


def secret(prompt):
    if not sys.stdin.isatty(): raise ManagerError('Для ввода секретов нужен интерактивный терминал')
    value = getpass.getpass(prompt).strip()
    if not value or any(c in value for c in '\r\n'): raise ManagerError('Пустой или некорректный секрет')
    return value


def free_port(port):
    try:
        with socket.socket() as sock: sock.bind(('127.0.0.1', port))
    except OSError: raise ManagerError('Локальный порт занят; выберите другой') from None


def choose_port(prompt, default):
    port = int(input(prompt + f' [{default}]: ').strip() or str(default))
    if not 1024 <= port <= 65535: raise ManagerError('Нужен порт от 1024 до 65535')
    free_port(port)
    return port


def local_token(name):
    output = run([PANEL_BINARY, 'setting', '-getApiToken', '-tokenName', name, '-tokenScope', 'admin']).stdout.decode()
    match = re.search(r'apiToken:\s*(\S+)', output)
    if not match: raise ManagerError('3x-ui не вернула API token')
    return match.group(1)


def bootstrap():
    # Called only by `unshare --net`; initial default subscriptions stay private.
    if os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        raise ManagerError('Bootstrap требует отдельного network namespace')
    run(['ip', 'link', 'set', 'lo', 'up'])
    config = load_private(STATE / 'setup.json')
    run([PANEL_BINARY, 'setting', '-port', str(config['web_port']), '-listenIP', '127.0.0.1',
         '-webBasePath', config['web_path']])
    # Unique installation token only, never invalidate an operator token.
    config['panel_token'] = local_token('rxs3-' + config['installation'])
    atomic_json(STATE / 'setup.json', config)
    panel = Panel(config['panel_url'], config['panel_token'])
    proc = subprocess.Popen([PANEL_BINARY], cwd='/usr/local/x-ui',
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    try:
        for _ in range(200):
            try:
                settings = panel.call('setting/all', {})
                break
            except ManagerError: time.sleep(.1)
        else: raise ManagerError('Панель не запустилась в bootstrap')
        payload = {'oldUsername': 'admin', 'oldPassword': 'admin',
                   'newUsername': config['web_user'], 'newPassword': config['web_password']}
        try: panel.call('setting/updateUser', payload)
        except RemoteError:
            # Password change can succeed despite a lost response. No DB edits.
            payload.update(oldUsername=config['web_user'], oldPassword=config['web_password'])
            panel.call('setting/updateUser', payload)
        settings.update(webListen='127.0.0.1', subListen='127.0.0.1', subEnable=False)
        panel.call('setting/update', settings)
        saved = panel.call('setting/all', {})
        if saved.get('subEnable') is not False or saved.get('webListen') != '127.0.0.1':
            raise ManagerError('Безопасные настройки панели не подтверждены')
        config['bootstrap_complete'] = True
        atomic_json(STATE / 'setup.json', config)
    finally:
        os.killpg(proc.pid, signal.SIGTERM)
        try: proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()


def setup():
    private_dir(STATE)
    store = Store(STATE)
    try:
        with store.locked():
            if (STATE / 'config.json').exists():
                load_private(STATE / 'config.json')
                run(['systemctl', 'enable', '--now', 'rxs3-sync.timer'])
                (HOME / 'fresh-panel-pending').unlink(missing_ok=True)
                print('Менеджер уже настроен; таймер синхронизации включён. Панель/бакет не изменены.')
                return
            pending = STATE / 'setup.json'
            if pending.exists():
                config = load_private(pending)
                print('Продолжаю сохранённую операцию настройки; новые ключи не генерируются без необходимости.')
            else:
                version = run([PANEL_BINARY, '-v']).stdout.strip()
                if version != b'3.9.0': raise ManagerError('Нужна обычная локальная 3x-ui ровно версии 3.9.0')
                fresh = (HOME / 'fresh-panel-pending').is_file()
                install_id = secrets.token_hex(12)
                config = {'installation': install_id, 'fresh': fresh, 'format': 1}
                if fresh:
                    config.update(web_port=choose_port('Локальный порт панели', 2053),
                                  web_path='/rxs3-' + secrets.token_hex(12) + '/',
                                  web_user='rxs3-admin', web_password=secrets.token_urlsafe(30))
                    config['panel_url'] = f"http://127.0.0.1:{config['web_port']}{config['web_path']}"
                else:
                    print('Существующие inbound, WS, пароль, подписки и настройки панели не меняются.')
                    config['panel_url'] = validate_panel_url(input('URL панели с её base path: ').strip())
                    config['panel_token'] = secret('Admin API token 3x-ui (ввод скрыт): ')
                    Panel(config['panel_url'], config['panel_token']).inbounds()
                config['panel_port'] = choose_port('Loopback порт нового S3 inbound', 10001)
                if config['panel_port'] == config.get('web_port'): raise ManagerError('Порты должны различаться')
                print('Нужны ключи ОТДЕЛЬНОЙ учётной записи Object Storage VK Москва.')
                config['endpoint'] = 'https://hb.ru-msk.vkcloud-storage.ru'
                config['accessKey'] = secret('VK Access Key ID (скрыто): ')
                config['secretKey'] = secret('VK Secret Key (скрыто): ')
                config['bucket'] = validate_bucket(input('Имя отдельного приватного бакета [rxs3-' + install_id + ']: ').strip() or 'rxs3-' + install_id)
                config['create_bucket'] = input('Создать этот бакет, если он отсутствует? [да/нет]: ').strip().lower() == 'да'
                keys = run(['/usr/local/x-ui/bin/xray-linux-amd64', 'vlessenc']).stdout.decode()
                dec = re.search(r'"decryption": "([^"]+)"', keys)
                enc = re.search(r'"encryption": "([^"]+)"', keys)
                if not dec or not enc: raise ManagerError('Не удалось создать VLESS Encryption')
                config['decryption'] = dec.group(1)
                config['encryption'] = enc.group(1).replace('.0rtt.', '.1rtt.')
                config['decryption_sha256'] = hashlib.sha256(config['decryption'].encode()).hexdigest()
                atomic_json(pending, config)  # Before cloud/panel resource mutation.
            if config['fresh']:
                if not config.get('bootstrap_complete'):
                    private_dir('/etc/x-ui')
                    private_dir('/var/log/x-ui')
                    run(['unshare', '--net', '--', '/usr/local/bin/rxs3', '_bootstrap'], timeout=120)
                    config = load_private(pending)
                path = Path('/etc/systemd/system/x-ui.service')
                if path.exists() and 'RX-PRO-S3-Manager' not in path.read_text():
                    raise ManagerError('Нельзя заменить чужую x-ui.service')
                if path.is_symlink(): raise ManagerError('Нельзя заменить symlink службы панели')
                path.write_text(PANEL_UNIT)
                path.chmod(0o644)
                run(['systemctl', 'daemon-reload'])
                run(['systemctl', 'enable', '--now', 'x-ui.service'])
            panel = Panel(config['panel_url'], config['panel_token'])
            for _ in range(100):
                try:
                    inbounds = panel.inbounds()
                    break
                except RemoteError: time.sleep(.1)
            else: raise ManagerError('Панель недоступна')
            cloud = S3(config['endpoint'], config['bucket'], config['accessKey'], config['secretKey'])
            try: cloud.call('HEAD')
            except RemoteError as error:
                if error.status != 404 or not config['create_bucket']: raise
                cloud.create_bucket()
            cloud.check_bucket()
            cloud.list_keys()  # Validate real PAK contract before issuing users.
            remark = 'RXS3 ' + config['installation']
            matches = [row for row in inbounds if row.get('remark') == remark]
            if len(matches) > 1: raise ManagerError('Найдены дубликаты управляемого inbound')
            if matches:
                config['inbound_id'] = matches[0]['id']
            else:
                free_port(config['panel_port'])
                if any(r.get('port') == config['panel_port'] for r in inbounds):
                    raise ManagerError('Порт уже назначен другому inbound; настройка остановлена')
                inbound = panel.call('inbounds/add', {'remark': remark, 'enable': True,
                    'listen': '127.0.0.1', 'port': config['panel_port'], 'protocol': 'vless',
                    'settings': {'clients': [], 'decryption': config['decryption']},
                    'streamSettings': {'network': 'tcp', 'security': 'none'},
                    'sniffing': {'enabled': False}})
                config['inbound_id'] = inbound['id']
            atomic_json(pending, config)
            from .engine import Engine
            Engine(store, config, panel, cloud, None).check_inbound()
            atomic_json(STATE / 'config.json', config)
            run(['systemctl', 'enable', '--now', 'rxs3-sync.timer'])
            (HOME / 'fresh-panel-pending').unlink(missing_ok=True)
            pending.unlink()
            print('Настройка завершена. Секреты: /var/lib/rxs3/config.json (root, 0600).')
            if config['fresh']:
                print('Панель доступна только через SSH-туннель. Адрес и пароль: sudo rxs3 panel-info')
            print('Далее: sudo rxs3. Первый пользователь проверит реальные PAK PUT/GET/LIST/DELETE.')
    finally:
        store.db.close()
