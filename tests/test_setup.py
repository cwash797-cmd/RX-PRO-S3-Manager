import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from rxs3 import setup as wizard
from rxs3 import cli
from rxs3.errors import CloudError, ManagerError
from rxs3.http import safe_s3_error
from rxs3.s3 import S3
from rxs3.secure import atomic_json, load_private

ROOT = Path(__file__).resolve().parents[1]


class SetupTest(unittest.TestCase):
    def setUp(self):
        self.umask = os.umask(0o077)
        (ROOT / '.lab').mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT / '.lab')
        self.root = Path(self.tmp.name)
        self.home = self.root / 'home'; self.home.mkdir()
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.pending = self.state / 'setup.json'
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(wizard, 'STATE', self.state))
        self.stack.enter_context(patch.object(wizard, 'HOME', self.home))
        self.stack.enter_context(patch.object(cli, 'STATE', self.state))
        self.output = io.StringIO()
        self.stack.enter_context(contextlib.redirect_stdout(self.output))

    def tearDown(self):
        self.stack.close(); self.tmp.cleanup(); os.umask(self.umask)

    def seed(self, fresh=True):
        config = {'installation': 'a' * 24, 'fresh': fresh, 'format': 1, 'setup_stage': 'questions'}
        atomic_json(self.pending, config)
        return config

    def native(self, args, **kwargs):
        if args[-1] == '-v': return subprocess.CompletedProcess(args, 0, b'3.9.0\n')
        if args[-1] == 'vlessenc':
            return subprocess.CompletedProcess(args, 0,
                b'"decryption": "fixture-key"\n"encryption": "mlkem768x25519plus.native.0rtt.fixture"\n')
        return subprocess.CompletedProcess(args, 0, b'')

    def complete(self):
        config = self.seed(False)
        config.update(panel_url='http://127.0.0.1:2053/private-base', panel_token='fixture-panel-token',
                      panel_port=10001, endpoint='https://hb.ru-msk.vkcloud-storage.ru',
                      accessKey='old-access', secretKey='old-secret', bucket='old-bucket', create_bucket=False,
                      decryption='fixture-key', encryption='mlkem768x25519plus.native.1rtt.fixture',
                      decryption_sha256='fixture-digest')
        atomic_json(self.pending, config)
        return config

    def panel(self):
        panel = Mock()
        panel.inbounds.return_value = [{'id': 17, 'remark': 'RXS3 ' + 'a' * 24, 'port': 10001}]
        return panel

    def test_interrupt_at_access_key_keeps_identity_ports_and_password(self):
        config = self.seed()
        with patch.object(wizard, 'choose_port', side_effect=[2053, 10001]), \
                patch.object(wizard, 'secret', side_effect=EOFError):
            with self.assertRaises(EOFError): wizard.collect_settings(config, self.pending)
        saved = load_private(self.pending)
        self.assertEqual(saved['panel_port'], 10001)
        self.assertEqual(saved['web_port'], 2053)
        self.assertNotIn('accessKey', saved)
        password, installation = saved['web_password'], saved['installation']
        with patch.object(wizard, 'choose_port', side_effect=AssertionError('ports asked again')), \
                patch.object(wizard, 'secret', side_effect=['new-access', 'new-secret']), \
                patch('builtins.input', side_effect=['test-bucket', 'нет']), patch.object(wizard, 'run', side_effect=self.native):
            wizard.collect_settings(saved, self.pending)
        resumed = load_private(self.pending)
        self.assertEqual(resumed['web_password'], password)
        self.assertEqual(resumed['installation'], installation)
        self.assertEqual(resumed['secretKey'], 'new-secret')
        self.assertNotIn('new-secret', self.output.getvalue())

    def test_secret_pair_checkpoint_never_reuses_old_secret(self):
        config = self.seed()
        with patch.object(wizard, 'choose_port', side_effect=[2053, 10001]), \
                patch.object(wizard, 'secret', side_effect=['new-access', KeyboardInterrupt]):
            with self.assertRaises(KeyboardInterrupt): wizard.collect_settings(config, self.pending)
        saved = load_private(self.pending)
        self.assertEqual(saved['accessKey'], 'new-access')
        self.assertNotIn('secretKey', saved)

    def test_journal_exists_before_first_question(self):
        (self.home / 'fresh-panel-pending').touch()
        with patch.object(wizard, 'run', side_effect=self.native), \
                patch.object(wizard, 'choose_port', side_effect=EOFError):
            with self.assertRaises(EOFError): wizard.setup()
        self.assertEqual(load_private(self.pending)['setup_stage'], 'questions')

    def test_yes_no_reprompts_typos_and_defaults_to_no(self):
        with patch('builtins.input', side_effect=['??', 'да']): self.assertTrue(wizard.yes_no('test'))
        with patch('builtins.input', return_value=''): self.assertFalse(wizard.yes_no('test'))

    def test_cloud_403_reports_exact_stage_and_can_edit_then_resume(self):
        original = self.complete()
        panel, cloud = self.panel(), Mock()
        cloud.call.side_effect = CloudError('HeadBucket', 403, 'AccessDenied')
        with patch.object(wizard, 'Panel', return_value=panel), patch.object(wizard, 'S3', return_value=cloud), \
                patch.object(wizard, 'run', side_effect=self.native), patch('rxs3.engine.Engine.check_inbound'):
            with self.assertRaises(ManagerError) as ctx: wizard.setup()
        self.assertIn('HeadBucket', str(ctx.exception))
        self.assertIn('setup --edit-vk', str(ctx.exception))
        cloud.create_bucket.assert_not_called()
        self.assertEqual(load_private(self.pending)['last_vk_error']['status'], 403)
        cloud.call.side_effect = None
        with patch.object(wizard, 'Panel', return_value=panel), patch.object(wizard, 'S3', return_value=cloud), \
                patch.object(wizard, 'run', side_effect=self.native), patch('rxs3.engine.Engine.check_inbound'), \
                patch.object(wizard, 'secret', side_effect=['fixed-access', 'fixed-secret']), \
                patch('builtins.input', side_effect=['fixed-bucket', 'нет']):
            wizard.setup(edit_vk=True)
        ready = load_private(self.state / 'config.json')
        self.assertEqual(ready['installation'], original['installation'])
        self.assertEqual(ready['panel_port'], original['panel_port'])
        self.assertEqual(ready['bucket'], 'fixed-bucket')
        self.assertEqual(ready['secretKey'], 'fixed-secret')
        self.assertNotIn('last_vk_error', ready)
        panel.call.assert_not_called()  # Existing managed inbound reused, not duplicated.
        self.assertFalse(self.pending.exists())

    def test_edit_refused_after_completed_setup(self):
        config = self.complete()
        atomic_json(self.state / 'config.json', config)
        before = (self.state / 'config.json').read_bytes()
        with self.assertRaises(ManagerError): wizard.setup(edit_vk=True)
        self.assertEqual((self.state / 'config.json').read_bytes(), before)

    def test_status_and_missing_config_diagnostics_are_secret_free(self):
        self.complete()
        status = wizard.setup_status()
        self.assertEqual(status['state'], 'pending')
        self.assertNotIn('old-secret', json.dumps(status))
        self.assertNotIn('fixture-panel-token', json.dumps(status))
        with patch('sys.argv', ['rxs3', 'diagnose']), patch.object(cli, 'os', wraps=os) as process_os:
            process_os.geteuid.return_value = 0
            with self.assertRaises(ManagerError) as ctx: cli.main()
        self.assertIn('setup', str(ctx.exception))
        self.assertNotIn('symlink', self.output.getvalue())

    def test_bare_cli_resumes_interactively(self):
        self.seed()
        with patch('sys.argv', ['rxs3']), patch.object(cli, 'os', wraps=os) as process_os, \
                patch('sys.stdin.isatty', return_value=True), patch.object(cli, 'setup') as setup:
            process_os.geteuid.return_value = 0
            cli.main()  # Mocked setup leaves pending; must not try to load config.json.
            setup.assert_called_once()

    def test_corrupted_journal_not_replaced(self):
        self.pending.write_text('{broken')
        self.pending.chmod(0o600)
        with self.assertRaises(ManagerError): wizard.setup_status()
        self.assertEqual(self.pending.read_text(), '{broken')

    def test_safe_cloud_code_does_not_echo_response_secrets(self):
        data = b'<Error><Code>SignatureDoesNotMatch</Code><Message>secret-key-value</Message><StringToSign>credential</StringToSign></Error>'
        safe = safe_s3_error(data)
        self.assertEqual(safe, b'<Error><Code>SignatureDoesNotMatch</Code></Error>')
        self.assertEqual(safe_s3_error(b'<Error><Code>secret-key-value</Code></Error>'), b'')
        self.assertEqual(safe_s3_error(b'<!DOCTYPE x><Error><Code>AccessDenied</Code></Error>'), b'')
        self.assertEqual(safe_s3_error(b'x' * 17000), b'')

    def test_account_preflight_uses_signed_root_and_does_not_log_bucket_names(self):
        cloud = S3('https://hb.ru-msk.vkcloud-storage.ru', 'test-bucket', 'fixture-access', 'fixture-secret')
        with patch('rxs3.s3.request', return_value=(200, b'<ListAllMyBucketsResult><Buckets/></ListAllMyBucketsResult>')) as request:
            cloud.check_account()
            self.assertEqual(request.call_args.args[0], 'https://hb.ru-msk.vkcloud-storage.ru/')
        with patch('rxs3.s3.request', return_value=(403, b'<Error><Code>InvalidAccessKeyId</Code></Error>')):
            with self.assertRaises(CloudError) as ctx: cloud.check_account()
            self.assertEqual(ctx.exception.operation, 'ListBuckets')
            self.assertIn('Object Storage', ctx.exception.hint())

    def test_cloud_operation_and_optional_404(self):
        cloud = S3('https://hb.ru-msk.vkcloud-storage.ru', 'test-bucket', 'fixture-access', 'fixture-secret')
        with patch('rxs3.s3.request', return_value=(403, b'<Error><Code>AccessDenied</Code></Error>')):
            with self.assertRaises(CloudError) as ctx: cloud.call('GET', query={'pak': ''})
            self.assertEqual(ctx.exception.operation, 'ListPrefixKeys')
            self.assertNotIn('fixture-secret', str(ctx.exception))
        with patch('rxs3.s3.request', return_value=(404, b'<Error><Code>NoSuchBucketPolicy</Code></Error>')):
            self.assertEqual(cloud.call('GET', query={'policy': ''}, expected=(200, 404)), b'')


if __name__ == '__main__':
    unittest.main()
