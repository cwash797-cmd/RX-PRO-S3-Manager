import copy
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from rxs3.engine import Engine
from rxs3.errors import ManagerError
from rxs3.secure import Store

ROOT = Path(__file__).resolve().parents[1]


class Crash(BaseException):
    pass


class PanelFake:
    def __init__(self, config):
        self.config, self.rows, self.fail, self.crash = config, {}, False, False
        self.encryption = None

    def inbounds(self):
        if self.fail: raise ManagerError('panel offline')
        return [{'id': 1, 'enable': True, 'listen': '127.0.0.1', 'port': 10001,
                 'remark': 'RXS3 ' + self.config['installation'], 'protocol': 'vless',
                 'settings': {'decryption': 'fixture-key', 'encryption': self.encryption},
                 'streamSettings': {'network': 'tcp', 'security': 'none'}}]

    def set_inbound_encryption(self, record, encryption):
        self.encryption = encryption

    def client(self, email):
        if self.fail: raise ManagerError('panel offline')
        return copy.deepcopy(self.rows.get(email))

    def create_client(self, user, inbound):
        self.rows[user['email']] = {'client': {'uuid': user['uuid'], 'email': user['email'],
            'enable': True, 'totalGB': user['quota'], 'expiryTime': user['expires'],
            'comment': 'RXS3 managed'}, 'inboundIds': [inbound], 'usedTraffic': 0}
        if self.crash: raise Crash()

    def update_client(self, record, **changes):
        if self.fail: raise ManagerError('panel offline')
        if 'id' in changes: changes['uuid'] = changes.pop('id')
        self.rows[record['client']['email']]['client'].update(changes)

    def delete_client(self, email):
        self.rows.pop(email, None)


class CloudFake:
    endpoint, bucket = 'https://hb.ru-msk.vkcloud-storage.ru', 'fixture-bucket'

    def __init__(self):
        self.keys, self.counter, self.stale_auth = {}, 0, False
        self.fail_revoke, self.lost_create, self.crash_create, self.fail_create = False, False, False, False

    def create_key(self, name, prefix):
        if self.fail_create: raise ManagerError('cloud offline')
        if name in self.keys: raise ManagerError('duplicate cloud identity')
        self.counter += 1
        key = {'accessKey': 'access-' + str(self.counter), 'secretKey': 'secret-' + str(self.counter)}
        self.keys[name] = (prefix, key)
        if self.crash_create: raise Crash()
        if self.lost_create: raise ManagerError('reply lost')
        return key

    def revoke_key(self, name, prefix):
        if self.fail_revoke: raise ManagerError('cloud offline')
        if name in self.keys:
            if self.keys[name][0] != prefix: raise ManagerError('scope conflict')
            del self.keys[name]

    def scoped(self, key):
        if key not in [row[1] for row in self.keys.values()]: raise ManagerError('invalid key')
        return self

    def probe(self, prefix):
        pass

    def confirm_revoked(self, key, prefix):
        if self.stale_auth or any(row[1] == key for row in self.keys.values()):
            raise ManagerError('authorization still cached')

    def purge(self, prefix):
        if any(row[0] == prefix for row in self.keys.values()): raise ManagerError('still active')
        return 1


class RuntimeFake:
    def __init__(self):
        self.running, self.fail_stop, self.crash_start = {}, False, False
        self.starts = []

    def start(self, uid, config):
        self.starts.append(uid)
        self.running[uid] = config
        if self.crash_start: raise Crash()

    def stop(self, uid):
        if self.fail_stop: raise ManagerError('systemd failure')
        self.running.pop(uid, None)


class LifecycleTest(unittest.TestCase):
    def setUp(self):
        revision = patch('rxs3.engine.CORE_RUNTIME_REVISION', 3)
        revision.start(); self.addCleanup(revision.stop)
        (ROOT / '.lab').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.lab')
        self.store = Store(self.tmp.name)
        self.config = {'installation': 'a' * 24, 'inbound_id': 1, 'panel_port': 10001,
                       'decryption_sha256': hashlib.sha256(b'fixture-key').hexdigest(),
                       'encryption': 'mlkem768x25519plus.native.1rtt.fixture'}
        self.panel, self.cloud, self.runtime = PanelFake(self.config), CloudFake(), RuntimeFake()
        self.engine = Engine(self.store, self.config, self.panel, self.cloud, self.runtime)

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def user(self, uid):
        return self.store.get(uid)

    def legacy(self, uid):
        user = self.user(uid)
        user.pop('runtime_revision', None)
        self.store.put(user, 'legacy_fixture')
        return user

    def test_upgrade_rejects_unreleased_native_pin(self):
        uid = self.engine.add('Тест'); self.legacy(uid)
        with patch('rxs3.engine.CORE_RUNTIME_REVISION', 2):
            with self.assertRaises(ManagerError): self.engine.upgrade_runtime()
        self.assertNotIn('runtime_revision', self.user(uid))
        self.assertIsNone(self.panel.encryption)

    def test_upgrade_preserves_access_and_is_idempotent(self):
        uid = self.engine.add('testvasya', 1024**3, 4102444800000)
        user = self.legacy(uid)
        link, keys = self.engine.show(uid), copy.deepcopy(self.cloud.keys)
        before = copy.deepcopy(self.panel.rows)
        self.assertEqual(self.engine.upgrade_runtime(), 3)
        self.assertEqual(self.engine.upgrade_runtime(), 0)
        self.assertEqual(self.engine.show(uid), link)
        self.assertEqual(self.cloud.keys, keys)
        self.assertEqual(self.user(uid)['generations'], user['generations'])
        changed = copy.deepcopy(self.panel.rows)
        changed[user['email']]['client']['comment'] = 'RXS3 managed'
        self.assertEqual(changed, before)
        self.assertEqual(self.runtime.starts.count(uid), 2)
        self.assertEqual(self.panel.encryption, self.config['encryption'])
        self.assertEqual(self.panel.rows[user['email']]['client']['comment'], 'RXS3 managed | testvasya')
        settings = self.runtime.running[uid]['inbounds'][0]['streamSettings']['xdriveSettings']
        self.assertEqual(settings['sessionTtlSeconds'], 180)

    def test_upgrade_never_restarts_ineligible_users(self):
        for kind in ('disabled', 'deleted', 'panel_disabled', 'expired', 'quota', 'pending'):
            uid = self.engine.add(kind)
            user = self.legacy(uid)
            if kind in ('disabled', 'deleted'):
                self.engine.disable(uid, delete=kind == 'deleted')
            elif kind == 'pending':
                user['desired'] = 'disabled'; self.store.put(user, 'disable_intent')
            else:
                row = self.panel.rows[user['email']]
                if kind == 'panel_disabled': row['client']['enable'] = False
                if kind == 'expired': row['client']['expiryTime'] = 1
                if kind == 'quota': row['client']['totalGB'] = 1; row['usedTraffic'] = 1
        self.runtime.starts.clear()
        self.engine.upgrade_runtime()
        self.assertEqual(self.runtime.starts, [])

    def test_upgrade_rejects_conflicting_public_key_or_identity(self):
        uid = self.engine.add('Тест'); user = self.legacy(uid)
        self.panel.encryption = 'another-key'
        with self.assertRaises(ManagerError): self.engine.upgrade_runtime()
        self.assertEqual(self.panel.encryption, 'another-key')
        self.panel.encryption = None
        self.panel.rows[user['email']]['client']['comment'] = 'unrelated owner'
        with self.assertRaises(ManagerError): self.engine.upgrade_runtime()
        self.assertEqual(self.runtime.starts.count(uid), 1)
        self.assertNotIn('runtime_revision', self.user(uid))

    def test_upgrade_interrupted_restart_is_retried(self):
        uid = self.engine.add('Тест'); self.legacy(uid)
        self.runtime.crash_start = True
        with self.assertRaises(Crash): self.engine.upgrade_runtime()
        self.assertNotIn('runtime_revision', self.user(uid))
        self.runtime.crash_start = False
        self.assertEqual(self.engine.upgrade_runtime(), 1)
        self.assertEqual(self.engine.upgrade_runtime(), 0)

    def test_two_users_isolated_and_independently_revoked(self):
        first, second = self.engine.add('Первый'), self.engine.add('Второй')
        self.assertEqual(len(self.cloud.keys), 4)
        first_user = self.user(first)
        gen = first_user['generations'][0]
        self.assertNotEqual(gen['keys']['client'], gen['keys']['bridge'])
        bridge_text = str(self.runtime.running[first])
        self.assertNotIn(gen['keys']['client']['secretKey'], bridge_text)
        self.assertIn(gen['keys']['bridge']['secretKey'], bridge_text)
        link = self.engine.show(first)
        self.assertTrue(link.startswith('vless://'))
        self.engine.disable(first)
        self.assertEqual(self.user(first)['state'], 'disabled')
        self.assertNotIn(first, self.runtime.running)
        self.assertIn(second, self.runtime.running)
        self.assertEqual(len(self.cloud.keys), 2)
        self.assertTrue(self.panel.client(self.user(second)['email'])['client']['enable'])

    def test_reenable_rotates_uuid_prefix_and_keys(self):
        uid = self.engine.add('Тест')
        old = self.user(uid)
        self.engine.disable(uid)
        self.engine.enable(uid)
        new = self.user(uid)
        self.assertNotEqual(old['uuid'], new['uuid'])
        self.assertEqual(new['generation'], 2)
        self.assertNotEqual(old['generations'][0]['prefix'], new['generations'][1]['prefix'])
        self.assertTrue(new['generations'][0]['revoked'])
        self.assertEqual(new['generations'][0]['keys'], {})

    def test_lost_create_reply_revokes_recorded_name(self):
        self.cloud.lost_create = True
        with self.assertRaises(ManagerError): self.engine.add('Тест')
        self.assertEqual(self.cloud.keys, {})
        self.assertEqual(self.store.users()[0]['state'], 'disabled')

    def test_crash_after_create_recovery_does_not_issue_more_keys(self):
        self.cloud.crash_create = True
        with self.assertRaises(Crash): self.engine.add('Тест')
        self.assertEqual(len(self.cloud.keys), 1)
        self.engine.sync()
        self.assertEqual(self.cloud.keys, {})
        self.assertEqual(self.cloud.counter, 1)
        self.assertEqual(self.store.users()[0]['state'], 'disabled')

    def test_crash_after_panel_create_is_recoverable(self):
        self.panel.crash = True
        with self.assertRaises(Crash): self.engine.add('Тест')
        self.engine.sync()
        row = self.store.users()[0]
        self.assertFalse(self.panel.client(row['email'])['client']['enable'])
        self.assertEqual(row['state'], 'disabled')

    def test_crash_after_bridge_start_is_recoverable(self):
        self.runtime.crash_start = True
        with self.assertRaises(Crash): self.engine.add('Тест')
        self.assertTrue(self.runtime.running)
        self.engine.sync()
        self.assertEqual(self.runtime.running, {})
        self.assertEqual(self.cloud.keys, {})

    def test_cloud_outage_keeps_revocation_pending(self):
        uid = self.engine.add('Тест')
        self.cloud.fail_revoke = True
        with self.assertRaises(ManagerError): self.engine.disable(uid)
        self.assertEqual(self.user(uid)['state'], 'revocation_pending')
        self.assertNotIn(uid, self.runtime.running)
        self.assertFalse(self.panel.client(self.user(uid)['email'])['client']['enable'])
        self.cloud.fail_revoke = False
        self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'disabled')

    def test_stale_cloud_authorization_keeps_revocation_pending(self):
        uid = self.engine.add('Тест')
        self.cloud.stale_auth = True
        with self.assertRaises(ManagerError): self.engine.disable(uid)
        self.assertEqual(self.cloud.keys, {})
        self.assertEqual(self.user(uid)['state'], 'revocation_pending')
        self.assertTrue(self.user(uid)['generations'][0]['keys'])
        self.cloud.stale_auth = False
        self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'disabled')

    def test_panel_outage_is_not_missing_user(self):
        uid = self.engine.add('Тест')
        self.panel.fail = True
        with self.assertRaises(ManagerError): self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'active')
        self.assertEqual(len(self.cloud.keys), 2)
        with self.assertRaises(ManagerError): self.engine.disable(uid)
        self.assertEqual(self.cloud.keys, {})
        self.assertNotIn(uid, self.runtime.running)
        self.assertEqual(self.user(uid)['state'], 'revocation_pending')
        self.panel.fail = False
        self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'disabled')

    def test_runtime_failure_does_not_skip_cloud_revoke(self):
        uid = self.engine.add('Тест')
        self.runtime.fail_stop = True
        with self.assertRaises(ManagerError): self.engine.disable(uid)
        self.assertEqual(self.cloud.keys, {})
        self.assertEqual(self.user(uid)['pending'], ['bridge'])
        self.runtime.fail_stop = False
        self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'disabled')

    def test_panel_quota_and_delete_propagate(self):
        uid = self.engine.add('Тест', quota=100)
        self.panel.rows[self.user(uid)['email']]['usedTraffic'] = 101
        self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'disabled')
        other = self.engine.add('Второй')
        self.panel.delete_client(self.user(other)['email'])
        self.engine.sync()
        self.assertEqual(self.user(other)['state'], 'deleted')
        with self.assertRaises(ManagerError): self.engine.enable(other)

    def test_identity_conflict_stops_bridge_without_mutating_stranger(self):
        uid = self.engine.add('Тест')
        self.panel.rows[self.user(uid)['email']]['client']['uuid'] = 'stranger'
        with self.assertRaises(ManagerError): self.engine.sync()
        self.assertEqual(self.cloud.keys, {})
        self.assertNotIn(uid, self.runtime.running)
        self.assertTrue(self.panel.rows[self.user(uid)['email']]['client']['enable'])
        self.assertEqual(self.user(uid)['state'], 'revocation_pending')

    def test_purge_rejects_live_access(self):
        uid = self.engine.add('Тест')
        with self.assertRaises(ManagerError): self.engine.purge(uid)
        self.engine.disable(uid, delete=True)
        self.assertEqual(self.engine.purge(uid), 1)
        with self.assertRaises(ManagerError): self.engine.enable(uid, rotate=True)

    def test_crash_after_disable_intent_still_revokes(self):
        uid = self.engine.add('Тест')
        row = self.user(uid)
        row['desired'] = 'disabled'
        self.store.put(row, 'disable_intent')
        self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'disabled')
        self.assertEqual(self.cloud.keys, {})

    def test_failed_reenable_before_uuid_update_remains_recoverable(self):
        uid = self.engine.add('Тест')
        self.engine.disable(uid)
        self.cloud.fail_create = True
        with self.assertRaises(ManagerError): self.engine.enable(uid)
        self.engine.sync()
        self.assertEqual(self.user(uid)['state'], 'disabled')


if __name__ == '__main__':
    unittest.main()
