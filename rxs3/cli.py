"""Russian terminal interface. Secrets are interactive input, never argv/env."""
import argparse
import datetime
import getpass
import json
import os
from pathlib import Path
import sys
import time

from . import __version__
from .backup import backup, quarantine
from .engine import Engine
from .errors import ManagerError
from .http import Panel
from .profiles import safe_name
from .runtime import Runtime, run
from .s3 import S3
from .secure import Store, exclusive_bytes, load_private
from .setup import STATE, setup, bootstrap

STATES = {'active': 'активен', 'disabled': 'отключён', 'deleted': 'удалён',
          'creating': 'выдача не завершена', 'revocation_pending': 'ОТЗЫВ НЕ ЗАВЕРШЁН',
          'quarantined': 'карантин'}


def password(confirm=False):
    if not sys.stdin.isatty(): raise ManagerError('Пароль вводится только с терминала')
    value = getpass.getpass('Пароль резервной копии (минимум 12 символов): ')
    if confirm and value != getpass.getpass('Повторите пароль: '):
        raise ManagerError('Пароли не совпадают')
    return value


def listing(engine):
    rows = engine.store.users()
    if not rows: print('Пользователей пока нет.')
    for row in rows:
        print(row['id'], '|', safe_name(row['name']), '|', STATES.get(row['state'], 'неизвестно'),
              '| поколение', row['generation'])
    return rows


def choose(engine):
    rows = listing(engine)
    if not rows: raise ManagerError('Нет пользователей')
    uid = input('ID пользователя (24 символа): ').strip()
    engine.store.get(uid)
    return uid


def show(engine, uid, output=None, qr=False):
    link = engine.show(uid)
    if output:
        exclusive_bytes(output, (link + '\n').encode())
        print('Ссылка записана в новый приватный файл 0600.')
    else:
        if not sys.stdout.isatty():
            raise ManagerError('Для экспорта используйте --output, не перенаправление stdout')
        print('СЕКРЕТ: ссылка/QR содержит ключ доступа. Не публикуйте и не отправляйте в поддержку.')
        print(link)
    if qr:
        if not sys.stdout.isatty(): raise ManagerError('QR выводится только в терминал')
        import qrcode
        code = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_L, border=2)
        code.add_data(link)
        code.make(fit=True)
        if code.modules_count + 4 > os.get_terminal_size().columns:
            print('QR слишком большой для текущего терминала; расширьте окно или импортируйте ссылку.')
        else:
            code.print_ascii(invert=True)


def diagnosis(engine):
    checks = {}
    for name, action in [('panel_api', engine.panel.clients), ('managed_inbound', engine.check_inbound),
                         ('private_bucket', engine.cloud.check_bucket), ('pak_api', engine.cloud.list_keys)]:
        try:
            action()
            checks[name] = 'ok'
        except Exception: checks[name] = 'failed'
    try:
        checks['sync_timer'] = 'ok' if run(['systemctl', 'is-active', '--quiet', 'rxs3-sync.timer'], check=False).returncode == 0 else 'failed'
    except ManagerError: checks['sync_timer'] = 'failed'
    rows = engine.store.users()
    counts = {state: sum(row['state'] == state for row in rows) for state in STATES}
    bridges = 0
    for row in rows:
        if row['state'] == 'active':
            try:
                if not engine.runtime.active(row['id']): bridges += 1
            except ManagerError: bridges += 1
    report = {'manager_version': __version__, 'time_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'checks': checks, 'counts': counts, 'inactive_bridges': bridges,
              'note': 'Проверка не измеряет S3 billing и не доказывает доступность Android/БС'}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return all(value == 'ok' for value in checks.values()) and not bridges


def menu(engine):
    while True:
        print('\nRX-PRO S3 Manager ' + __version__)
        print('1. Добавить пользователя\n2. Список пользователей\n3. Ссылка и QR\n'
              '4. Отключить\n5. Включить с новой ссылкой\n6. Перевыпустить доступ\n'
              '7. Удалить доступ\n8. Синхронизация / восстановление\n9. Диагностика\n'
              '10. Зашифрованная резервная копия\n11. Очистить объекты отключённого пользователя\n'
              '12. Обновление менеджера\n0. Выход')
        choice = input('Выберите пункт: ').strip()
        try:
            if choice == '0': return
            if choice == '1':
                name = input('Имя: ')
                gib = int(input('Квота GiB (0 = без лимита VPN-трафика): ') or '0')
                days = int(input('Срок в днях (0 = без срока): ') or '0')
                if days < 0 or gib < 0: raise ManagerError('Отрицательные значения запрещены')
                expiry = int((time.time() + days * 86400) * 1000) if days else 0
                uid = engine.add(name, gib * 1024**3, expiry)
                print('Создан ID:', uid)
                show(engine, uid, qr=True)
            elif choice == '2': listing(engine)
            elif choice == '3': show(engine, choose(engine), qr=True)
            elif choice == '4': engine.disable(choose(engine))
            elif choice in ('5', '6'):
                uid = choose(engine)
                engine.enable(uid, rotate=choice == '6')
                print('Старая ссылка больше не подходит. Передайте новую:')
                show(engine, uid, qr=True)
            elif choice == '7':
                uid = choose(engine)
                if input('Удалить без возможности восстановления старой ссылки? Введите УДАЛИТЬ: ') == 'УДАЛИТЬ':
                    engine.disable(uid, delete=True)
            elif choice == '8':
                engine.sync()
                print('Синхронизация завершена.')
            elif choice == '9': diagnosis(engine)
            elif choice == '10':
                target = input('Новый абсолютный путь *.rxs3-backup: ').strip()
                if not Path(target).is_absolute(): raise ManagerError('Нужен абсолютный путь')
                backup(engine.store, engine.config, target, password(confirm=True))
                print('Зашифрованная копия менеджера создана; копию базы панели делайте отдельно.')
            elif choice == '11':
                uid = choose(engine)
                if input('Удалить объекты только этого отключённого пользователя? Введите ОЧИСТИТЬ: ') == 'ОЧИСТИТЬ':
                    print('Удалено объектов:', engine.purge(uid))
            elif choice == '12': update_help()
            else: print('Неизвестный пункт.')
        except ManagerError as error: print('Ошибка:', error)
        except (ValueError, OSError): print('Некорректный ввод или ошибка локального ввода/вывода.')


def update_help():
    print('Обновление только из нового проверенного release-архива этого приватного репозитория.')
    print('1. Сделайте зашифрованную резервную копию.\n2. Скачайте релиз через авторизованный браузер и скопируйте на VPS.\n'
          '3. Проверьте SHA256, распакуйте и выполните sudo python3 install.py БЕЗ --fresh-panel.\n'
          '4. Выполните sudo rxs3 sync и sudo rxs3 diagnose. Версии 3x-ui и RX-PRO автоматически не обновляются.')


def main():
    parser = argparse.ArgumentParser(description='RX-PRO S3 Manager — приватный терминальный менеджер')
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='command')
    for name in ('setup', 'list', 'sync', 'diagnose', 'panel-info', 'update', '_bootstrap'):
        sub.add_parser(name)
    add = sub.add_parser('add')
    add.add_argument('name')
    add.add_argument('--quota-gib', type=int, default=0)
    add.add_argument('--days', type=int, default=0)
    for name in ('show', 'disable', 'enable', 'rotate', 'delete', 'purge'):
        command = sub.add_parser(name)
        command.add_argument('id')
        if name == 'show':
            command.add_argument('--output')
            command.add_argument('--qr', action='store_true')
        if name in ('delete', 'purge'): command.add_argument('--yes', action='store_true', required=True)
    b = sub.add_parser('backup'); b.add_argument('path')
    restore = sub.add_parser('restore-quarantine')
    restore.add_argument('source'); restore.add_argument('new_directory')
    args = parser.parse_args()
    if os.geteuid() != 0: raise ManagerError('Запустите через sudo')
    os.umask(0o077)
    if args.command == 'setup': return setup()
    if args.command == '_bootstrap': return bootstrap()
    if args.command == 'update': return update_help()
    if args.command == 'restore-quarantine':
        count = quarantine(args.source, args.new_directory, password())
        print('Записей восстановлено в ОФЛАЙН-КАРАНТИН:', count)
        print('Ничего не включено. Не копируйте каталог поверх живого реестра: старой копии неизвестны новые ключи.')
        return
    config = load_private(STATE / 'config.json')
    if args.command == 'panel-info':
        if not sys.stdout.isatty(): raise ManagerError('Реквизиты показываются только в терминале')
        if not config.get('fresh'): raise ManagerError('Пароль существующей панели менеджер не хранит')
        print('СЕКРЕТ. URL:', config['panel_url'], '\nЛогин:', config['web_user'], '\nПароль:', config['web_password'])
        return
    store = Store(STATE)
    try:
        engine = Engine(store, config, Panel(config['panel_url'], config['panel_token']),
                        S3(config['endpoint'], config['bucket'], config['accessKey'], config['secretKey']), Runtime())
        cmd = args.command
        if cmd is None: menu(engine)
        elif cmd == 'list': listing(engine)
        elif cmd == 'add':
            if args.days < 0: raise ManagerError('Срок не может быть отрицательным')
            expiry = int((time.time() + args.days * 86400) * 1000) if args.days else 0
            print('Создан ID:', engine.add(args.name, args.quota_gib * 1024**3, expiry))
        elif cmd == 'show': show(engine, args.id, args.output, args.qr)
        elif cmd == 'disable': engine.disable(args.id)
        elif cmd == 'delete': engine.disable(args.id, delete=True)
        elif cmd == 'enable': engine.enable(args.id)
        elif cmd == 'rotate': engine.enable(args.id, rotate=True)
        elif cmd == 'purge': print('Удалено объектов:', engine.purge(args.id))
        elif cmd == 'sync': engine.sync()
        elif cmd == 'diagnose':
            if not diagnosis(engine): raise ManagerError('Диагностика обнаружила ошибки')
        elif cmd == 'backup': backup(store, config, args.path, password(confirm=True))
    finally: store.db.close()


def entry():
    try:
        main()
        return 0
    except ManagerError as error:
        print('Ошибка:', error, file=sys.stderr)
    except (KeyboardInterrupt, EOFError):
        print('\nОперация прервана. Перед новой выдачей выполните rxs3 sync.', file=sys.stderr)
    except Exception:
        print('Локальная ошибка. Секреты и traceback скрыты; выполните rxs3 diagnose и rxs3 sync.', file=sys.stderr)
    return 1
