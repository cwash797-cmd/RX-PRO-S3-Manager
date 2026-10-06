import datetime
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from rxs3.backup import decrypt, encrypt, quarantine
from rxs3.errors import ManagerError, RemoteError
from rxs3.http import Panel, validate_panel_url, request, NoRedirect
from rxs3.s3 import S3, parse_xml, sigv4
from rxs3.secure import Store, atomic_json, exclusive_bytes, load_private
from install import unpack, install_source

ROOT = Path(__file__).resolve().parents[1]


class SecurityTest(unittest.TestCase):
    def setUp(self):
        (ROOT / '.lab').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.lab')
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_source_install_is_atomic_and_retryable(self):
        home, source = self.root / 'home', self.root / 'source'
        (home / 'releases').mkdir(parents=True)
        source.mkdir()
        (source / 'code.py').write_text('print(1)\n')
        (source / 'SHA256SUMS').write_text('fixture-manifest\n')
        with patch('install.HOME', home), patch('install.SOURCE', source):
            with patch('install.shutil.copyfile', side_effect=OSError('simulated full disk')):
                with self.assertRaises(OSError): install_source(['code.py'], 'fixture')
            self.assertFalse((home / 'releases/fixture').exists())
            target = install_source(['code.py'], 'fixture')
            self.assertEqual((target / 'code.py').read_text(), 'print(1)\n')
            self.assertEqual(install_source(['code.py'], 'fixture'), target)
            (target / 'code.py').write_text('corruption')
            with self.assertRaises(ManagerError): install_source(['code.py'], 'fixture')

    def test_source_code_paths_are_traversable_with_private_umask(self):
        home, source = self.root / 'home', self.root / 'source'
        (home / 'releases').mkdir(parents=True)
        (source / 'rxs3').mkdir(parents=True)
        (source / 'rxs3/code.py').write_text('print(1)\n')
        (source / 'SHA256SUMS').write_text('fixture-manifest\n')
        previous = os.umask(0o077)
        try:
            with patch('install.HOME', home), patch('install.SOURCE', source):
                target = install_source(['rxs3/code.py'], 'fixture')
                self.assertEqual(target.stat().st_mode & 0o777, 0o755)
                self.assertEqual((target / 'rxs3').stat().st_mode & 0o777, 0o755)
                self.assertEqual((target / 'rxs3/code.py').stat().st_mode & 0o777, 0o644)
        finally: os.umask(previous)

    def test_private_files_reject_symlink_permissions_and_malformed_json(self):
        target = self.root / 'config'
        atomic_json(target, {'secret': 'not-logged'})
        self.assertEqual(load_private(target)['secret'], 'not-logged')
        link = self.root / 'symlink'; link.symlink_to(target)
        with self.assertRaises(ManagerError): load_private(link)
        target.chmod(0o644)
        with self.assertRaises(ManagerError): load_private(target)
        target.chmod(0o600)
        target.write_text('{not-logged')
        with self.assertRaises(ManagerError) as ctx: load_private(target)
        self.assertNotIn('not-logged', str(ctx.exception))

    def test_store_rejects_unsafe_existing_db(self):
        path = self.root / 'state.sqlite'
        path.write_bytes(b'not-a-database')
        path.chmod(0o644)
        with self.assertRaises(ManagerError): Store(self.root)

    def test_flock_blocks_parallel_mutation(self):
        store = Store(self.root)
        other = Store(self.root)
        try:
            with store.locked():
                with self.assertRaises(ManagerError):
                    with other.locked(): pass
            with other.locked(): pass
        finally:
            store.db.close(); other.db.close()

    def test_backups_are_randomized_authenticated_and_password_protected(self):
        payload = {'format': 1, 'config': {'installation': 'a' * 24}, 'users': [], 'secret': 'do-not-expose'}
        one = encrypt(payload, 'correct-long-password')
        two = encrypt(payload, 'correct-long-password')
        self.assertNotEqual(one, two)
        self.assertNotIn(b'do-not-expose', one)
        self.assertEqual(decrypt(one, 'correct-long-password'), payload)
        for damaged, password in [(one[:-1] + bytes([one[-1] ^ 1]), 'correct-long-password'),
                                  (one, 'wrong-long-password'), (one[:20], 'correct-long-password')]:
            with self.assertRaises(ManagerError): decrypt(damaged, password)

    def test_restore_is_new_offline_quarantine_never_active(self):
        uid, install = 'b' * 24, 'a' * 24
        prefix = f'rxs3/{install}/{uid}/g1/'
        user = {'id': uid, 'email': f'rxs3-{install}-{uid}', 'state': 'active', 'desired': 'active',
                'generations': [{'number': 1, 'prefix': prefix,
                                 'names': {r: prefix + r for r in ('client', 'bridge')}}]}
        archive = self.root / 'test.rxs3-backup'
        exclusive_bytes(archive, encrypt({'format': 1, 'config': {'installation': install}, 'users': [user]}, 'correct-long-password'))
        dest = self.root / 'quarantine'
        self.assertEqual(quarantine(archive, dest, 'correct-long-password'), 1)
        store = Store(dest)
        try:
            self.assertEqual(store.users()[0]['state'], 'quarantined')
            self.assertEqual(store.users()[0]['desired'], 'disabled')
        finally: store.db.close()
        with self.assertRaises(ManagerError): quarantine(archive, dest, 'correct-long-password')
        self.assertFalse((dest / 'runtime').exists())

    def test_private_export_does_not_overwrite(self):
        out = self.root / 'link'
        exclusive_bytes(out, b'private')
        with self.assertRaises(FileExistsError): exclusive_bytes(out, b'changed')
        self.assertEqual(out.read_bytes(), b'private')
        self.assertEqual(out.stat().st_mode & 0o777, 0o600)

    def test_panel_transport_validation(self):
        for url in ('http://example.com', 'ftp://localhost', 'https://user:password@host',
                    'https://host/?token=secret', 'https://host/#secret'):
            with self.assertRaises(ManagerError): validate_panel_url(url)
        self.assertEqual(validate_panel_url('http://127.0.0.1:2053/base/'), 'http://127.0.0.1:2053/base')
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, None, None, 'https://evil.test'))

    def test_panel_failure_never_becomes_absent_client(self):
        panel = Panel('http://127.0.0.1', 'fixture-token')
        for response in [(500, b'secret'), (200, b'{"success":false,"msg":"secret"}'),
                         (200, b'{"success":true,"obj":[{}]}'), (200, b'{"success":true,"obj":null}')]:
            with patch('rxs3.http.request', return_value=response):
                with self.assertRaises(ManagerError) as ctx: panel.client('someone')
                self.assertNotIn('secret', str(ctx.exception))

    def test_panel_list_flat_normalization(self):
        row = {'email': 'managed', 'uuid': 'fixture-uuid', 'enable': True, 'inboundIds': [1],
               'traffic': {'up': 11, 'down': 13}}
        with patch('rxs3.http.request', return_value=(200, json.dumps({'success': True, 'obj': [row]}).encode())):
            result = Panel('http://localhost', 'token').client('managed')
            self.assertEqual(result['usedTraffic'], 24)
            self.assertEqual(result['client']['uuid'], 'fixture-uuid')

    def test_sigv4_independent_botocore_1_40_70_vector(self):
        now = datetime.datetime(2026, 10, 6, 12, 0, 0, tzinfo=datetime.timezone.utc)
        url, headers = sigv4('PUT', 'https://hb.ru-msk.vkcloud-storage.ru/example-bucket',
            {'pak': '', 'prefix': 'a b/ж/', 'username': 'user/a+b'}, b'', 'TESTACCESS', 'TESTSECRET', now)
        self.assertTrue(headers['Authorization'].endswith('Signature=a0b7c78d53bf80a97308694aede2983467d3b9547d6664fd805487273f9f2b37'))
        self.assertIn('prefix=a%20b%2F%D0%B6%2F&username=user%2Fa%2Bb', url)
        self.assertNotIn('TESTSECRET', str(headers))

    def test_xml_entities_rejected(self):
        with self.assertRaises(RemoteError): parse_xml(b'<!DOCTYPE a [<!ENTITY x "abc">]><a>&x;</a>')

    def test_pak_response_scope_and_pagination_are_strict(self):
        cloud = S3('https://hb.ru-msk.vkcloud-storage.ru', 'test-bucket', 'access', 'secret')
        with patch.object(cloud, 'call', return_value=b'<r><BucketName>test-bucket</BucketName><IsTruncated>true</IsTruncated></r>'):
            with self.assertRaises(ManagerError): cloud.list_keys()
        with patch.object(cloud, 'call', return_value=b'<r><BucketName>other-bucket</BucketName><IsTruncated>false</IsTruncated></r>'):
            with self.assertRaises(ManagerError): cloud.list_keys()
        with patch.object(cloud, 'call', return_value=b'<r><AccessKey>secret</AccessKey><SecretKey>secret</SecretKey></r>'):
            with self.assertRaises(ManagerError): cloud.create_key('name', 'prefix/')
        with patch.object(cloud, 'list_keys', return_value=[{'UserName': 'managed', 'Prefix': 'other/'}]):
            with self.assertRaises(ManagerError): cloud.revoke_key('managed', 'expected/')

    def test_bucket_checks_reject_public_acl_policy_and_versioning(self):
        cloud = S3('https://hb.ru-msk.vkcloud-storage.ru', 'test-bucket', 'access', 'secret')
        private = b'<AccessControlPolicy><Owner><ID>owner</ID></Owner><AccessControlList><Grant><Grantee><ID>owner</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>'
        public = private.replace(b'<ID>owner</ID></Grantee>', b'<URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee>')
        for responses in [(b'', b'<v><Status>Enabled</Status></v>'),
                          (b'', b'<v/>', b'', public),
                          (b'', b'<v/>', b'', private, b'{"Statement":[]}')]:
            with patch.object(cloud, 'call', side_effect=responses):
                with self.assertRaises(ManagerError): cloud.check_bucket()
        with patch.object(cloud, 'call', side_effect=(b'', b'<v/>', b'', private, b'', b'')):
            cloud.check_bucket()

    def test_purge_never_deletes_returned_foreign_object(self):
        cloud = S3('https://hb.ru-msk.vkcloud-storage.ru', 'test-bucket', 'access', 'secret')
        with patch.object(cloud, 'call', return_value=b'<r><Contents><Key>foreign/key</Key></Contents></r>') as call:
            with self.assertRaises(ManagerError): cloud.purge('rxs3/' + 'a' * 24 + '/' + 'b' * 24 + '/g1/')
            self.assertEqual(call.call_count, 1)
        with self.assertRaises(ManagerError): cloud.purge('rxs3/')

    def test_archive_extraction_rejects_traversal_and_links(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('symlink', tarfile.SYMTYPE)]:
            path = self.root / 'bad.tar.gz'
            with tarfile.open(path, 'w:gz') as archive:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.linkname = '/etc/passwd' if kind == tarfile.SYMTYPE else ''
                archive.addfile(info, io.BytesIO())
            with self.assertRaises(ManagerError): unpack(path, self.root / 'out')


if __name__ == '__main__':
    unittest.main()
