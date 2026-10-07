"""Durable, fail-closed resource lifecycle. All public mutations hold one flock.

Creating generations are NEVER resumed: after an ambiguous remote outcome their
exact recorded PAK names are revoked. Recovery cannot accidentally issue access.
Administrative credentials stay in the S3 adapter, never in bridge profiles.
"""
import hashlib
import json
import secrets
import time
import urllib.parse
import uuid

from .errors import ManagerError, RemoteError
from .profiles import profile, safe_name
from .http import managed_comment
from .secure import identifier
from .pins import CORE_RUNTIME_REVISION


class Engine:
    def __init__(self, store, config, panel, cloud, runtime):
        self.store, self.config = store, config
        self.panel, self.cloud, self.runtime = panel, cloud, runtime
        identifier(config['installation'])

    def save(self, user, event):
        self.store.put(user, event)

    def check_inbound(self):
        rows = [r for r in self.panel.inbounds() if r.get('id') == self.config['inbound_id']]
        if len(rows) != 1: raise ManagerError('Управляемый inbound отсутствует')
        row = rows[0]
        try:
            settings = row['settings']
            stream = row['streamSettings']
            if isinstance(settings, str): settings = json.loads(settings)
            if isinstance(stream, str): stream = json.loads(stream)
            digest = hashlib.sha256(settings['decryption'].encode()).hexdigest()
            valid = (row['enable'] is True and row['listen'] == '127.0.0.1'
                     and row['port'] == self.config['panel_port'] and row['protocol'] == 'vless'
                     and row['remark'] == 'RXS3 ' + self.config['installation']
                     and stream.get('network') in ('tcp', 'raw')
                     and stream.get('security', 'none') == 'none'
                     and digest == self.config['decryption_sha256'])
        except (ValueError, KeyError, TypeError, AttributeError):
            valid = False
        if not valid: raise ManagerError('Настройки управляемого inbound изменились; доступ запрещён')
        return row

    def owned(self, record, user):
        if record is None: return
        source = record['client']
        identities = [user['uuid']]
        if user['state'] != 'active' and user.get('previous_uuid'):
            identities.append(user['previous_uuid'])
        if (source.get('email') != user['email'] or source.get('uuid') not in identities
                or record['inboundIds'] != [self.config['inbound_id']]
                or source.get('comment') not in ('RXS3 managed', managed_comment(user))):
            raise ManagerError('Конфликт идентичности в панели; чужая запись не изменена')

    def repair_panel(self):
        """Fill display metadata only. Never rotate identities or regenerate keys."""
        with self.store.locked():
            return self._repair_panel()

    def _repair_panel(self):
        inbound = self.check_inbound()
        settings = inbound['settings']
        if isinstance(settings, str): settings = json.loads(settings)
        shown = settings.get('encryption')
        if shown not in (None, '', 'none', self.config['encryption']):
            raise ManagerError('Публичный ключ в панели отличается; автоматическая замена запрещена')
        changed = 0
        if shown != self.config['encryption']:
            self.panel.set_inbound_encryption(inbound, self.config['encryption'])
            current = self.check_inbound()['settings']
            if isinstance(current, str): current = json.loads(current)
            if current.get('encryption') != self.config['encryption']:
                raise ManagerError('Панель не подтвердила публичный ключ')
            changed += 1
        for user in self.store.users():
            if user['state'] == 'deleted': continue
            record = self.panel.client(user['email'])
            if record is None: continue
            self.owned(record, user)
            if record['client']['comment'] != managed_comment(user):
                self.panel.update_client(record, comment=managed_comment(user))
                updated = self.panel.client(user['email'])
                self.owned(updated, user)
                if updated is None or updated['client']['comment'] != managed_comment(user):
                    raise ManagerError('Панель не подтвердила имя пользователя')
                changed += 1
        return changed

    def upgrade_runtime(self):
        """Operator-triggered, idempotent upgrade; active streams may reconnect."""
        if CORE_RUNTIME_REVISION < 3:
            raise ManagerError('Сервер с watchdog ещё не включён в закреплённый выпуск; миграция runtime запрещена')
        with self.store.locked():
            changed = self._repair_panel()
            for user in self.store.users():
                if user['state'] != 'active' or user['desired'] != 'active': continue
                record = self.panel.client(user['email'])
                self.owned(record, user)
                if not self.allowed(record): continue
                if user.get('runtime_revision') == 3: continue
                self.check_inbound()
                _, bridge = self._profile(user, user['generations'][-1])
                self.runtime.start(user['id'], bridge)
                user['runtime_revision'] = 3
                self.save(user, 'runtime_upgraded')
                changed += 1
            return changed

    @staticmethod
    def allowed(record):
        if record is None: return False
        client = record['client']
        expiry, quota = client.get('expiryTime', 0), client.get('totalGB', 0)
        if type(expiry) is not int or type(quota) is not int:
            raise ManagerError('Неизвестный формат лимитов панели')
        return (client.get('enable') is True
                and (expiry <= 0 or expiry > int(time.time() * 1000))
                and (quota <= 0 or record['usedTraffic'] < quota))

    def add(self, name, quota=0, expires=0):
        if type(quota) is not int or quota < 0 or type(expires) is not int or expires < 0:
            raise ManagerError('Квота и срок должны быть неотрицательными целыми числами')
        if expires and expires <= int(time.time() * 1000):
            raise ManagerError('Срок должен быть в будущем')
        with self.store.locked():
            self.check_inbound()
            uid = secrets.token_hex(12)
            user = {'id': uid, 'name': safe_name(name), 'uuid': str(uuid.uuid4()),
                    'email': 'rxs3-' + self.config['installation'] + '-' + uid,
                    'sub_id': secrets.token_hex(12), 'quota': quota, 'expires': expires,
                    'generation': 0, 'generations': [], 'state': 'disabled', 'desired': 'disabled'}
            self.save(user, 'allocate')
            self._issue(user)
            return uid

    def _issue(self, user):
        if user['state'] != 'disabled' or user['desired'] == 'deleted':
            raise ManagerError('Сначала завершите отзыв старого доступа')
        self.check_inbound()
        existing = self.panel.client(user['email'])
        self.owned(existing, user)
        if existing is not None:
            # Preserve current panel quota/expiry, never silently reset usage.
            user['quota'] = existing['client'].get('totalGB', 0)
            user['expires'] = existing['client'].get('expiryTime', 0)
            user['previous_uuid'] = existing['client']['uuid']
            user['uuid'] = str(uuid.uuid4())
        user['generation'] += 1
        gen = {'number': user['generation'],
               'prefix': f"rxs3/{self.config['installation']}/{user['id']}/g{user['generation']}/",
               'keys': {}, 'revoked': False}
        # Names and scopes are durable BEFORE CreatePrefixKey, including lost replies.
        gen['names'] = {role: gen['prefix'] + role for role in ('client', 'bridge')}
        user['generations'].append(gen)
        user.update(state='creating', desired='active')
        self.save(user, 'generation_intent')
        try:
            for role, name in gen['names'].items():
                gen['keys'][role] = self.cloud.create_key(name, gen['prefix'])
                self.save(user, 'key_received')
                self.cloud.scoped(gen['keys'][role]).probe(gen['prefix'])
            if existing is None:
                self.panel.create_client(user, self.config['inbound_id'])
            else:
                # The old record is explicitly supplied; UUID change is journalled.
                self.panel.update_client(existing, id=user['uuid'], enable=True)
            record = self.panel.client(user['email'])
            self.owned(record, user)
            if not self.allowed(record): raise ManagerError('Панель не подтвердила активный доступ')
            self.check_inbound()
            link, bridge = self._profile(user, gen)
            self.runtime.start(user['id'], bridge)
            if record['client']['uuid'] != user['uuid']:
                raise ManagerError('Панель не подтвердила новый UUID')
            user.pop('previous_uuid', None)
            user.update(state='active', desired='active', runtime_revision=CORE_RUNTIME_REVISION)
            self.save(user, 'activated')
        except Exception:
            # Catch local IO failures too; never print credential-bearing exceptions.
            user['desired'] = 'disabled'
            self.save(user, 'issue_failed')
            self._revoke(user)
            raise ManagerError('Выдача не завершена; доступ отозван. Создайте новое поколение') from None

    def _profile(self, user, gen):
        common = {'endpoint': self.cloud.endpoint, 'bucket': self.cloud.bucket,
                  'region': 'ru-msk', 'prefix': gen['prefix']}
        client = dict(common, **gen['keys']['client'])
        bridge = dict(common, **gen['keys']['bridge'])
        query = urllib.parse.urlencode({'type': 'tcp', 'encryption': self.config['encryption']})
        base = f"vless://{user['uuid']}@127.0.0.1:{self.config['panel_port']}?{query}#" + urllib.parse.quote(user['name'])
        link, config, _ = profile(base, client, bridge, self.config['panel_port'])
        return link, config

    def show(self, uid):
        with self.store.locked():
            user = self.store.get(uid)
            if user['state'] != 'active': raise ManagerError('Активной ссылки нет; нужен новый доступ')
            self.check_inbound()
            record = self.panel.client(user['email'])
            self.owned(record, user)
            if not self.allowed(record): raise ManagerError('Доступ в панели уже ограничен; выполните синхронизацию')
            return self._profile(user, user['generations'][-1])[0]

    def _revoke(self, user):
        user['state'] = 'revocation_pending'
        self.save(user, 'revoke_intent')
        errors = []
        # Three independent revocation barriers. Continue if any remote is down.
        try: self.runtime.stop(user['id'])
        except Exception: errors.append('bridge')
        try:
            record = self.panel.client(user['email'])
            self.owned(record, user)
            if record is not None:
                if user['desired'] == 'deleted':
                    self.panel.delete_client(user['email'])
                    if self.panel.client(user['email']) is not None:
                        raise ManagerError('Удаление в панели не подтверждено')
                else:
                    self.panel.update_client(record, enable=False)
                    record = self.panel.client(user['email'])
                    self.owned(record, user)
                    if record is not None and record['client']['enable'] is not False:
                        raise ManagerError('Отключение в панели не подтверждено')
        except Exception: errors.append('panel')
        for gen in user['generations']:
            if gen['revoked']: continue
            good = True
            for role, name in gen['names'].items():
                try:
                    self.cloud.revoke_key(name, gen['prefix'])
                    if role in gen['keys']:
                        self.cloud.confirm_revoked(gen['keys'][role], gen['prefix'])
                except Exception:
                    good = False
                    errors.append('cloud')
            if good:
                gen.update(revoked=True, keys={})
                self.save(user, 'keys_revoked')
        user['pending'] = sorted(set(errors))
        if errors:
            self.save(user, 'revoke_pending')
            raise ManagerError('Отзыв НЕ завершён; выполните восстановление/синхронизацию')
        # Reconcile an interrupted UUID update before dropping its journal.
        if record is not None: user['uuid'] = record['client']['uuid']
        user.pop('previous_uuid', None)
        user['state'] = 'deleted' if user['desired'] == 'deleted' else 'disabled'
        self.save(user, 'revoked')

    def disable(self, uid, delete=False):
        with self.store.locked():
            user = self.store.get(uid)
            if user['state'] == 'deleted': return
            user['desired'] = 'deleted' if delete else 'disabled'
            self.save(user, 'disable_intent')
            self._revoke(user)

    def enable(self, uid, rotate=False):
        with self.store.locked():
            user = self.store.get(uid)
            if user['state'] == 'deleted' or user['desired'] == 'deleted':
                raise ManagerError('Удалённые записи не восстанавливаются')
            if rotate:
                user['desired'] = 'disabled'
                self.save(user, 'rotate_intent')
                self._revoke(user)
            self._issue(user)

    def sync(self):
        failures = 0
        with self.store.locked():
            for user in self.store.users():
                try:
                    if (user['state'] in ('creating', 'revocation_pending', 'quarantined')
                            or (user['state'] == 'active' and user['desired'] != 'active')):
                        if user['desired'] != 'deleted': user['desired'] = 'disabled'
                        self._revoke(user)
                    elif user['state'] == 'active':
                        # An API error is not absence; record remains active, and
                        # sync exits nonzero. Confirmed changes revoke the bridge.
                        record = self.panel.client(user['email'])
                        try:
                            self.owned(record, user)
                            self.check_inbound()
                            allowed = self.allowed(record)
                        except RemoteError:
                            raise  # An unavailable API is not a confirmed configuration change.
                        except ManagerError:
                            allowed = False
                        if not allowed:
                            user['desired'] = 'deleted' if record is None else 'disabled'
                            self._revoke(user)
                    elif user['state'] in ('disabled', 'deleted'):
                        # Manual panel enable must never resurrect a revoked link.
                        self.runtime.stop(user['id'])
                except Exception:
                    failures += 1
            if failures: raise ManagerError(f'Не завершены операции: {failures}; повторите синхронизацию')

    def purge(self, uid):
        with self.store.locked():
            user = self.store.get(uid)
            if user['state'] not in ('disabled', 'deleted'):
                raise ManagerError('Очистка разрешена только после полного отзыва доступа')
            removed = 0
            for gen in user['generations']:
                if not gen['revoked']: raise ManagerError('Остались неотозванные ключи')
                removed += self.cloud.purge(gen['prefix'])
            self.save(user, 'purged')
            return removed
