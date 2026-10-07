#!/usr/bin/env python3
"""Explicit local installer. Run a verified release directory, never curl | bash."""
import argparse
import hashlib
import importlib
import os
from pathlib import Path, PurePosixPath
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile

from rxs3.errors import ManagerError
from rxs3.pins import PANEL_SHA, PANEL_URL, CORE_SHA, CORE_URL
from rxs3.runtime import BRIDGE_UNIT, SYNC_UNIT, SYNC_TIMER, run
from rxs3.secure import private_dir

SOURCE = Path(__file__).resolve().parent
HOME = Path('/opt/rxs3')
STATE = Path('/var/lib/rxs3')


def check_host():
    if os.geteuid() != 0: raise ManagerError('Запустите установщик через sudo')
    if platform.machine() != 'x86_64': raise ManagerError('Первая версия поддерживает только x86_64')
    info = dict(line.strip().split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    distro, version = info.get('ID', '').strip('"'), info.get('VERSION_ID', '').strip('"')
    if (distro, version) not in {('ubuntu', '22.04'), ('ubuntu', '24.04'), ('debian', '12')}:
        raise ManagerError('Поддерживаются Ubuntu 22.04/24.04 и Debian 12')
    if not Path('/run/systemd/system').is_dir(): raise ManagerError('Нужна обычная VPS с systemd, не Docker')
    for command in ('curl', 'systemctl', 'unshare', 'ip'):
        if not shutil.which(command): raise ManagerError('Не найдена зависимость: ' + command)
    for module in ('cryptography', 'qrcode'):
        try: importlib.import_module(module)
        except ImportError: raise ManagerError('Установите python3-cryptography и python3-qrcode') from None


def manifest():
    path = SOURCE / 'SHA256SUMS'
    if not path.is_file(): raise ManagerError('Используйте release-архив с SHA256SUMS, не checkout ветки')
    files = []
    for line in path.read_text().splitlines():
        digest, name = line.split('  ', 1)
        relative = PurePosixPath(name)
        if relative.is_absolute() or '..' in relative.parts or not relative.parts:
            raise ManagerError('Небезопасный путь в manifest')
        source = SOURCE / name
        if source.is_symlink() or not source.is_file(): raise ManagerError('Некорректный файл релиза')
        if hashlib.sha256(source.read_bytes()).hexdigest() != digest:
            raise ManagerError('SHA256 файла релиза не совпадает')
        files.append(name)
    if not {'install.py', 'rxs3_cli.py', 'rxs3/cli.py'}.issubset(files):
        raise ManagerError('Неполный release-архив')
    return files, hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def download(url, digest, path):
    run(['curl', '--fail', '--silent', '--show-error', '--location', '--proto', '=https',
         '--proto-redir', '=https', '--max-time', '300', '--max-filesize', '250000000',
         '--output', str(path), url], timeout=330)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise ManagerError('SHA256 загруженного upstream-архива не совпадает; установка остановлена')


def unpack(archive, destination):
    """Pinned archives still get traversal, link and size checks."""
    with tarfile.open(archive, 'r:gz') as tar:
        entries = tar.getmembers()
        if sum(m.size for m in entries) > 800 * 1024 * 1024:
            raise ManagerError('Слишком большой upstream-архив')
        for member in entries:
            name = PurePosixPath(member.name)
            if name.is_absolute() or '..' in name.parts or not (member.isfile() or member.isdir()):
                raise ManagerError('Небезопасная запись upstream-архива')
            target = destination.joinpath(*name.parts)
            if member.isdir(): target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, open(target, 'xb') as out:
                    shutil.copyfileobj(src, out)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def managed_text(path, text):
    path = Path(path)
    if path.is_symlink(): raise ManagerError('Отказ замены symlink')
    if path.exists() and 'RX-PRO-S3-Manager' not in path.read_text():
        raise ManagerError('Отказ замены чужого файла службы/команды')
    temporary = path.with_name(path.name + '.rxs3-new')
    if temporary.exists() or temporary.is_symlink(): raise ManagerError('Остался временный файл установки')
    with open(temporary, 'x') as out:
        out.write(text)
        out.flush()
        os.fsync(out.fileno())
    temporary.chmod(0o644)
    os.replace(temporary, path)


def install_source(files, release):
    target = HOME / 'releases' / release
    if target.is_symlink(): raise ManagerError('Каталог версии не может быть symlink')
    if target.exists():
        for name in [*files, 'SHA256SUMS']:
            installed = target / name
            if installed.is_symlink() or not installed.is_file() or installed.read_bytes() != (SOURCE / name).read_bytes():
                raise ManagerError('Существующая версия повреждена; переключение остановлено')
        return target
    # Never make an incomplete source tree the current release after a crash.
    with tempfile.TemporaryDirectory(prefix='.source-', dir=HOME / 'releases') as tmp:
        stage = Path(tmp)
        stage.chmod(0o755)
        for name in [*files, 'SHA256SUMS']:
            dest = stage / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(SOURCE / name, dest)
            dest.chmod(0o644)
        for directory in stage.rglob('*'):
            if directory.is_dir(): directory.chmod(0o755)
        os.replace(stage, target)
    return target


def main():
    parser = argparse.ArgumentParser(description='Установка проверенного RX-PRO S3 Manager')
    parser.add_argument('--fresh-panel', action='store_true', help='Установить 3x-ui 3.9.0 на чистую VPS')
    parser.add_argument('--check', action='store_true', help='Только проверить платформу и release manifest')
    args = parser.parse_args()
    check_host()
    files, release = manifest()
    if args.check:
        print('Платформа, зависимости и manifest: OK. Система не изменена.')
        return
    if HOME.is_symlink(): raise ManagerError('/opt/rxs3 не может быть symlink')
    if HOME.exists() and not (HOME / '.rxs3-managed').is_file():
        raise ManagerError('/opt/rxs3 занят другим приложением')
    panel_root = Path('/usr/local/x-ui')
    if args.fresh_panel and any(p.exists() for p in (panel_root, Path('/etc/x-ui'), Path('/etc/systemd/system/x-ui.service'))):
        if (HOME / '.rxs3-managed').is_file() and (panel_root / 'x-ui').is_file():
            print('Панель уже установлена. Обновляем только менеджер, сохраняя панель и незавершённую настройку.')
            args.fresh_panel = False
        else:
            raise ManagerError('Найдена сторонняя панель. Для подключения запустите install.py без --fresh-panel; панель не изменена.')
    if args.fresh_panel:
        run(['unshare', '--net', '--', 'true'])  # Fail BEFORE writing/installing panel.
    private_dir(STATE)
    HOME.mkdir(mode=0o755, exist_ok=True)
    (HOME / '.rxs3-managed').touch(mode=0o600)
    (HOME / 'releases').mkdir(exist_ok=True)
    (HOME / 'bin').mkdir(exist_ok=True)
    (HOME / 'licenses').mkdir(exist_ok=True)
    # DynamicUser must be able to traverse code/binary paths even with umask 077.
    # Secrets live separately under root-only STATE and LoadCredential.
    for directory in (HOME, HOME / 'releases', HOME / 'bin', HOME / 'licenses'):
        if directory.is_symlink() or directory.stat().st_uid != os.geteuid():
            raise ManagerError('Небезопасный каталог установки')
        directory.chmod(0o755)
    with tempfile.TemporaryDirectory(dir=HOME, prefix='install-') as tmp:
        work = Path(tmp)
        download(CORE_URL, CORE_SHA, work / 'core.tgz')
        (work / 'core').mkdir()
        unpack(work / 'core.tgz', work / 'core')
        core = work / 'core/xray-s3'
        if not core.is_file(): raise ManagerError('В архиве нет S3 core')
        shutil.copy2(core, HOME / 'bin/xray-s3.new')
        (HOME / 'bin/xray-s3.new').chmod(0o755)
        os.replace(HOME / 'bin/xray-s3.new', HOME / 'bin/xray-s3')
        for name in ('CLIENT-LICENSE', 'XRAY-LICENSE', 'AWS-LICENSE'):
            shutil.copy2(work / 'core' / name, HOME / 'licenses' / name)
        if args.fresh_panel:
            download(PANEL_URL, PANEL_SHA, work / 'panel.tgz')
            (work / 'panel').mkdir()
            unpack(work / 'panel.tgz', work / 'panel')
            shutil.copytree(work / 'panel/x-ui', panel_root)
            (HOME / 'fresh-panel-pending').touch(mode=0o600)
    target = install_source(files, release)
    current = HOME / 'current.new'
    current.unlink(missing_ok=True)
    current.symlink_to(target)
    os.replace(current, HOME / 'current')
    managed_text('/usr/local/bin/rxs3', '#!/bin/sh\n# RX-PRO-S3-Manager\nunset PYTHONPATH PYTHONHOME\nexec /usr/bin/python3 -I /opt/rxs3/current/rxs3_cli.py "$@"\n')
    Path('/usr/local/bin/rxs3').chmod(0o755)
    for name, value in [('rxs3-bridge@.service', BRIDGE_UNIT), ('rxs3-sync.service', SYNC_UNIT), ('rxs3-sync.timer', SYNC_TIMER)]:
        managed_text('/etc/systemd/system/' + name, value)
    run(['systemctl', 'daemon-reload'])
    if (STATE / 'config.json').is_file():
        print('Файлы обновлены. Примените миграцию: sudo rxs3 apply-upgrade --yes')
        print('Возможны краткие переподключения; ссылки, ключи и лимиты сохраняются.')
    else:
        print('Файлы установлены. Панель и облако ещё не настраивались. Далее: sudo rxs3 setup')


if __name__ == '__main__':
    try: main()
    except ManagerError as error:
        print('Ошибка:', error, file=sys.stderr)
        sys.exit(1)
    except Exception:
        print('Установка прервана локальной ошибкой. Секреты не выведены.', file=sys.stderr)
        sys.exit(1)
