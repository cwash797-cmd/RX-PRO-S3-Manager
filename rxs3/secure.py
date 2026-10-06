import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time

from .errors import ManagerError

ID = re.compile(r"^[a-f0-9]{24}$")


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ManagerError("Некорректный идентификатор записи")
    return value


def private_dir(path):
    path = Path(path)
    if path.is_symlink():
        raise ManagerError("Каталог состояния не может быть symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.geteuid():
        raise ManagerError("Неверный владелец каталога состояния")
    path.chmod(0o700)
    return path


def atomic_json(path, value, mode=0o600):
    path = Path(path)
    fd, temp = tempfile.mkstemp(prefix=".rxs3-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as out:
            json.dump(value, out, ensure_ascii=False, indent=2)
            out.write("\n"); out.flush(); os.fsync(out.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try: os.fsync(directory)
        finally: os.close(directory)
    finally:
        if os.path.exists(temp): os.unlink(temp)


def read_private(path, limit=16 * 1024 * 1024):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_nlink != 1):
                raise ManagerError("Небезопасные права приватного файла: нужны текущий владелец и 0600")
            data = source.read(limit + 1)
            if len(data) > limit: raise ManagerError("Превышен лимит приватного файла")
            return data
    except OSError:
        raise ManagerError("Приватный файл недоступен или является symlink") from None


def load_private(path):
    try: return json.loads(read_private(path))
    except (ValueError, UnicodeError):
        raise ManagerError("Некорректный JSON приватного файла") from None


def exclusive_bytes(path, value):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(value)
        out.flush()
        os.fsync(out.fileno())


class Store:
    def __init__(self, root):
        self.root = private_dir(root)
        self.dbpath = self.root / "state.sqlite"
        if self.dbpath.is_symlink(): raise ManagerError("SQLite symlink запрещён")
        if self.dbpath.exists():
            info = self.dbpath.stat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise ManagerError("Небезопасный файл SQLite")
        old = os.umask(0o077)
        try:
            self.db = sqlite3.connect(self.dbpath, timeout=5)
            self.db.execute("PRAGMA journal_mode=DELETE")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.executescript("""
                CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, data TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS events (at INTEGER, user_id TEXT, action TEXT);
            """)
            self.db.commit()
        finally: os.umask(old)
        self.dbpath.chmod(0o600)

    @contextlib.contextmanager
    def locked(self):
        fd = os.open(self.root / "manager.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise ManagerError("Другая операция менеджера уже выполняется")
            yield
        finally:
            os.close(fd)

    def put(self, user, event):
        identifier(user['id'])
        if not re.fullmatch(r'[a-z_]{1,48}', event):
            raise ManagerError("Некорректное событие журнала")
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO users VALUES (?,?)", (user['id'], json.dumps(user)))
            self.db.execute("INSERT INTO events VALUES (?,?,?)", (int(time.time()), user['id'], event))

    def get(self, uid):
        row = self.db.execute("SELECT data FROM users WHERE id=?", (identifier(uid),)).fetchone()
        if not row: raise ManagerError("Пользователь не найден")
        return json.loads(row[0])

    def users(self):
        return [json.loads(row[0]) for row in self.db.execute("SELECT data FROM users ORDER BY rowid")]
