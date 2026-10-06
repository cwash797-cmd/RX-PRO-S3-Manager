"""Versioned authenticated manager backups; restore is offline quarantine only."""
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import ManagerError
from .secure import atomic_json, exclusive_bytes, identifier, private_dir, read_private, Store

MAGIC = b'RXS3BACKUP\x01'
LIMIT = 16 * 1024 * 1024


def derive(password, salt):
    if not isinstance(password, str) or len(password) < 12:
        raise ManagerError('Пароль резервной копии: минимум 12 символов')
    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(password.encode())


def encrypt(payload, password):
    raw = json.dumps(payload, ensure_ascii=False).encode()
    if len(raw) > LIMIT: raise ManagerError('Резервная копия превышает лимит 16 MiB')
    salt, nonce = os.urandom(16), os.urandom(12)
    header = MAGIC + salt + nonce
    return header + AESGCM(derive(password, salt)).encrypt(nonce, raw, header)


def decrypt(data, password):
    hsize = len(MAGIC) + 28
    if not data.startswith(MAGIC) or not hsize + 16 <= len(data) <= LIMIT + hsize + 16:
        raise ManagerError('Неизвестный или повреждённый формат резервной копии')
    salt, nonce = data[len(MAGIC):len(MAGIC)+16], data[len(MAGIC)+16:hsize]
    try:
        raw = AESGCM(derive(password, salt)).decrypt(nonce, data[hsize:], data[:hsize])
        payload = json.loads(raw)
        if payload['format'] != 1 or not isinstance(payload['users'], list):
            raise ValueError()
        identifier(payload['config']['installation'])
        return payload
    except (InvalidTag, ValueError, KeyError, TypeError):
        raise ManagerError('Неверный пароль или повреждённая резервная копия') from None


def backup(store, config, target, password):
    with store.locked():
        data = encrypt({'format': 1, 'config': config, 'users': store.users()}, password)
        # Existing files are never overwritten. No plaintext temporary archive.
        exclusive_bytes(target, data)


def quarantine(source, target, password):
    """Create a NEW offline directory, never overwrite or activate live state.

    An old backup cannot know keys issued since its creation. For that reason it
    is not automatically installed into /var/lib/rxs3, nor a migration mechanism.
    """
    payload = decrypt(read_private(source, LIMIT + 1024), password)
    target = Path(target)
    if target.exists() or target.is_symlink():
        raise ManagerError('Для карантина нужен новый, ещё не существующий каталог')
    ids = set()
    installation = payload['config']['installation']
    try:
        for user in payload['users']:
            uid = identifier(user['id'])
            if uid in ids: raise ValueError()
            ids.add(uid)
            if user['email'] != f'rxs3-{installation}-{uid}': raise ValueError()
            for gen in user['generations']:
                if type(gen['number']) is not int or gen['number'] < 1: raise ValueError()
                prefix = f"rxs3/{installation}/{uid}/g{gen['number']}/"
                if gen['prefix'] != prefix or gen['names'] != {
                        role: prefix + role for role in ('client', 'bridge')}:
                    raise ValueError()
            user['state'] = 'quarantined'
            if user['desired'] != 'deleted': user['desired'] = 'disabled'
    except (KeyError, TypeError, ValueError):
        raise ManagerError('Структура реестра в копии не прошла проверку') from None
    private_dir(target)
    atomic_json(target / 'config.json', payload['config'])
    store = Store(target)
    try:
        with store.locked():
            for user in payload['users']: store.put(user, 'restore_quarantine')
    finally:
        store.db.close()
    return len(payload['users'])
