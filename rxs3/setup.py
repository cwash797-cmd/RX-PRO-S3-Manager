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

from .errors import ManagerError, RemoteError, CloudError
from .http import Panel, validate_panel_url
from .runtime import run
from .s3 import S3, validate_bucket
from .secure import Store, atomic_json, load_private, private_dir, identifier

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


def setup_status():
    """Read-only, redacted status; absence is distinct from invalid/private files."""
    for name, state in [('config.json', 'ready'), ('setup.json', 'pending')]:
        path = STATE / name
        if path.exists() or path.is_symlink():
            config = load_private(path)
            if not isinstance(config, dict): raise ManagerError('Файл настройки повреждён; не удаляйте реестр')
            identifier(config.get('installation'))
            return {'state': state, 'stage': config.get('setup_stage', 'legacy' if state == 'pending' else 'ready'),
                    'cloud_keys_saved': bool(config.get('accessKey') and config.get('secretKey')),
                    'panel_port': config.get('panel_port'), 'web_port': config.get('web_port'),
                    'last_vk_error': config.get('last_vk_error'), 'next_command': 'sudo rxs3' if state == 'ready' else 'sudo rxs3 setup'}
    return {'state': 'pending' if (HOME / 'fresh-panel-pending').is_file() else 'not_configured',
            'stage': 'questions', 'cloud_keys_saved': False, 'next_command': 'sudo rxs3 setup'}


def print_ports(config):
    print('Порты и совместимость:')
    if config.get('fresh') and config.get('web_port'):
        print(f"  Панель: 127.0.0.1:{config['web_port']}/TCP — только локально, доступ через SSH-туннель.")
    else:
        print('  Адрес и порт существующей панели не изменяются.')
    if config.get('panel_port'):
        print(f"  Вход S3 в панели: 127.0.0.1:{config['panel_port']}/TCP — только локально.")
    print('  Облако: исходящие HTTPS-соединения на 443/TCP; новый публичный VPN-порт не нужен.')
    print('  Другие конфигурации можно добавлять на незанятых портах; управляемый вход S3 не изменяйте.')


def yes_no(prompt, default=False):
    while True:
        value = input(prompt).strip().lower()
        if not value: return default
        if value in ('да', 'д', 'yes', 'y'): return True
        if value in ('нет', 'н', 'no', 'n'): return False
        print('Введите да или нет. Enter означает нет.')


def collect_settings(config, pending):
    def save(**values):
        config.update(values)
        config['setup_stage'] = 'questions'
        atomic_json(pending, config)
    if config['fresh']:
        if 'web_port' not in config: save(web_port=choose_port('Локальный порт панели', 2053))
        if 'web_password' not in config:
            save(web_path='/rxs3-' + secrets.token_hex(12) + '/', web_user='rxs3-admin',
                 web_password=secrets.token_urlsafe(30))
        if 'panel_url' not in config:
            save(panel_url=f"http://127.0.0.1:{config['web_port']}{config['web_path']}")
    else:
        print('Существующие конфигурации, пароль и настройки панели не меняются.')
        if 'panel_url' not in config: save(panel_url=validate_panel_url(input('URL панели с её base path: ').strip()))
        if 'panel_token' not in config: save(panel_token=secret('Admin API token 3x-ui (ввод скрыт): '))
        Panel(config['panel_url'], config['panel_token']).inbounds()
    if 'panel_port' not in config:
        while True:
            port = choose_port('Локальный порт S3-входа (TCP)', 10001)
            if port != config.get('web_port'):
                save(panel_port=port)
                break
            print('Порт S3-входа должен отличаться от порта панели.')
    print_ports(config)
    print('VK Cloud: Object Storage → Аккаунты → ключ доступа АККАУНТА, не ключ из вкладки бакета.')
    print('Нужен отдельный ПРИВАТНЫЙ бакет в Москве: без версионирования, блокировки и публичных политик.')
    print('Папки, файлы и пользовательские ключи вручную создавать не нужно — этим занимается менеджер.')
    if 'endpoint' not in config: save(endpoint='https://hb.ru-msk.vkcloud-storage.ru')
    if 'accessKey' not in config: save(accessKey=secret('Access Key ID аккаунта (ввод скрыт): '))
    if 'secretKey' not in config: save(secretKey=secret('Secret Key той же пары (ввод скрыт): '))
    if 'bucket' not in config:
        while True:
            value = input('Точное имя вашего приватного бакета (если создаст менеджер — новое уникальное имя): ').strip()
            try:
                save(bucket=validate_bucket(value))
                break
            except ManagerError as error: print(error)
    if 'create_bucket' not in config:
        save(create_bucket=yes_no('Если бакета нет, разрешить менеджеру создать его? [да/нет; Enter = нет]: '))
    if 'decryption' not in config:
        keys = run(['/usr/local/x-ui/bin/xray-linux-amd64', 'vlessenc']).stdout.decode()
        dec = re.search(r'"decryption": "([^"]+)"', keys)
        enc = re.search(r'"encryption": "([^"]+)"', keys)
        if not dec or not enc: raise ManagerError('Не удалось создать VLESS Encryption')
        save(decryption=dec.group(1), encryption=enc.group(1).replace('.0rtt.', '.1rtt.'),
             decryption_sha256=hashlib.sha256(dec.group(1).encode()).hexdigest())
    config['setup_stage'] = 'panel'
    atomic_json(pending, config)


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


def setup(edit_vk=False):
    private_dir(STATE)
    store = Store(STATE)
    try:
        with store.locked():
            if (STATE / 'config.json').exists():
                ready = load_private(STATE / 'config.json')
                if edit_vk:
                    raise ManagerError('Настройка уже завершена. Смена аккаунта/бакета активной установки этим параметром запрещена.')
                run(['systemctl', 'enable', '--now', 'rxs3-sync.timer'])
                (HOME / 'fresh-panel-pending').unlink(missing_ok=True)
                print('Менеджер уже настроен; таймер синхронизации включён. Панель/бакет не изменены.')
                print_ports(ready)
                return
            if store.users():
                raise ManagerError('Есть реестр пользователей, но нет завершённой настройки. Не удаляйте файлы; требуется восстановление из копии.')
            pending = STATE / 'setup.json'
            if pending.exists() or pending.is_symlink():
                config = load_private(pending)
                identifier(config.get('installation'))
                print('Найдена незавершённая настройка. Сохранённые значения и уже созданные ресурсы сохраняются.')
                if (not edit_vk and sys.stdin.isatty() and config.get('accessKey') and config.get('secretKey')
                        and (config.get('last_vk_error') or 'setup_stage' not in config)):
                    print('1 — повторить проверку; 2 — исправить ключи/бакет VK; 0 — выйти без изменений.')
                    choice = input('Действие [1]: ').strip() or '1'
                    if choice == '0': return
                    if choice not in ('1', '2'): raise ManagerError('Нужно выбрать 1, 2 или 0')
                    edit_vk = choice == '2'
            else:
                if run([PANEL_BINARY, '-v']).stdout.strip() != b'3.9.0':
                    raise ManagerError('Нужна обычная локальная 3x-ui ровно версии 3.9.0')
                config = {'installation': secrets.token_hex(12),
                          'fresh': (HOME / 'fresh-panel-pending').is_file(), 'format': 1,
                          'setup_stage': 'questions'}
                atomic_json(pending, config)  # Before the first question, not after all secrets.
            if edit_vk:
                for field in ('accessKey', 'secretKey', 'bucket', 'create_bucket', 'last_vk_error'):
                    config.pop(field, None)
                config['setup_stage'] = 'questions'
                atomic_json(pending, config)
                print('Введите параметры VK заново. Панель, её порты и уже созданные бакеты не удаляются.')
            collect_settings(config, pending)
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
            config['setup_stage'] = 'cloud'
            atomic_json(pending, config)
            cloud = S3(config['endpoint'], config['bucket'], config['accessKey'], config['secretKey'])
            print('Проверка VK: доступ к бакету, приватность и управление пользовательскими ключами...')
            try:
                cloud.check_account()
                try: cloud.call('HEAD')
                except RemoteError as error:
                    # 403 is NOT evidence that a bucket is absent. Never PUT on 403.
                    if error.status != 404 or not config['create_bucket']: raise
                    cloud.create_bucket()
                cloud.check_bucket()
                cloud.list_keys()
            except CloudError as error:
                config['last_vk_error'] = {'operation': error.operation, 'status': error.status, 'code': error.code}
                atomic_json(pending, config)
                raise ManagerError(str(error) + '\n' + error.hint() +
                    '\nНастройки сохранены. Повторить: sudo rxs3 setup. Исправить параметры VK: sudo rxs3 setup --edit-vk') from None
            config.pop('last_vk_error', None)
            config['setup_stage'] = 'inbound'
            atomic_json(pending, config)
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
                    'settings': {'clients': [], 'decryption': config['decryption'],
                                 'encryption': config['encryption']},
                    'streamSettings': {'network': 'tcp', 'security': 'none'},
                    'sniffing': {'enabled': False}})
                config['inbound_id'] = inbound['id']
            atomic_json(pending, config)
            from .engine import Engine
            Engine(store, config, panel, cloud, None).check_inbound()
            config['setup_stage'] = 'ready'
            atomic_json(STATE / 'config.json', config)
            run(['systemctl', 'enable', '--now', 'rxs3-sync.timer'])
            (HOME / 'fresh-panel-pending').unlink(missing_ok=True)
            pending.unlink()
            print('Настройка завершена. Секреты: /var/lib/rxs3/config.json (root, 0600).')
            if config['fresh']:
                print('Панель доступна только через SSH-туннель. Адрес и пароль: sudo rxs3 panel-info')
            print_ports(config)
            print('Далее: sudo rxs3. Пользовательские префиксы и ключи создаются автоматически при добавлении пользователя.')
    finally:
        store.db.close()
