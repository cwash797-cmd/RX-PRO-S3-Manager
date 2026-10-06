"""DESTRUCTIVE ONLY ON DISPOSABLE GITHUB RUNNER. No live cloud credentials.

Tests actual installation, bootstrap, systemd credentials and attach-existing.
VK is explicitly a mock here; this is NOT a real VK end-to-end test.
"""
import os
from pathlib import Path
import sys
from unittest.mock import patch

if os.environ.get('RXS3_ALLOW_INSTALL_TEST') != 'github-disposable-runner' or os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('Refusing installation smoke test outside explicitly authorized disposable CI')
if os.geteuid() != 0: raise SystemExit('Root required on disposable runner')

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rxs3 import setup as wizard
from rxs3.http import Panel
from rxs3.runtime import Runtime, run
from rxs3.secure import load_private, atomic_json
from rxs3.errors import CloudError, ManagerError


class MockCloud:
    """Setup contract only. No network calls and no authorization claim."""
    def __init__(self, *args): pass
    def call(self, *args, **kwargs): return b''
    def check_bucket(self): pass
    def check_account(self): pass
    def list_keys(self): return []


def require(condition, message):
    if not condition: raise RuntimeError(message)


def main():
    # Reproduce the user's terminal loss at the very first cloud credential.
    with patch.object(wizard, 'secret', side_effect=EOFError), patch('builtins.input', side_effect=['', '']):
        try: wizard.setup()
        except EOFError: pass
        else: raise RuntimeError('Expected interrupted credential prompt')
    pending = Path('/var/lib/rxs3/setup.json')
    before_prompt = load_private(pending)
    require(before_prompt['panel_port'] == 10001, 'Ports lost before cloud prompt')
    require(not Path('/var/lib/rxs3/config.json').exists(), 'Incomplete setup marked ready')
    require('не завершена' in run(['/usr/local/bin/rxs3', 'status']).stdout.decode(), 'Missing pre-setup status')

    class DeniedCloud(MockCloud):
        def check_account(self): raise CloudError('ListBuckets', 403, 'InvalidAccessKeyId')

    with patch.object(wizard, 'S3', DeniedCloud), patch.object(wizard, 'secret', return_value='fixture-not-real'), \
            patch('builtins.input', side_effect=['fixture-bucket', 'нет']):
        try: wizard.setup()
        except ManagerError as error:
            require('ListBuckets' in str(error) and '--edit-vk' in str(error), 'Cloud error not actionable')
        else: raise RuntimeError('Expected cloud authorization failure')
    failed = load_private(pending)
    require(failed['installation'] == before_prompt['installation'], 'Installation identity changed')
    require(failed['web_password'] == before_prompt['web_password'], 'Panel password changed on resume')
    require(failed['bootstrap_complete'], 'Secure panel bootstrap not completed')
    # The original rc1 journal had no stage/error fields. It must also be editable.
    failed.pop('setup_stage', None); failed.pop('last_vk_error', None)
    atomic_json(pending, failed)
    with patch.object(wizard, 'S3', MockCloud), patch.object(wizard, 'secret', return_value='fixed-fixture-key'), \
            patch('builtins.input', side_effect=['fixture-bucket', 'нет']):
        wizard.setup(edit_vk=True)
    config = load_private('/var/lib/rxs3/config.json')
    require(config['installation'] == failed['installation'], 'Legacy resume changed identity')
    require(config['panel_token'] == failed['panel_token'], 'Legacy resume regenerated panel token')
    print('PASS: interrupted credential entry, explicit cloud 403 and rc1 journal correction/resume')
    panel = Panel(config['panel_url'], config['panel_token'])
    settings = panel.call('setting/all', {})
    require(settings['subEnable'] is False, 'Subscription still enabled')
    require(settings['webListen'] == '127.0.0.1', 'Panel not loopback')
    sockets = run(['ss', '-H', '-ltn']).stdout.decode()
    require(':2096 ' not in sockets, 'Default subscription socket exposed')
    require(run(['systemctl', 'is-active', '--quiet', 'x-ui']).returncode == 0, 'Panel inactive')
    require(run(['systemctl', 'is-active', '--quiet', 'rxs3-sync.timer']).returncode == 0, 'Timer inactive')
    old_id = config['inbound_id']
    wizard.setup()
    require(load_private('/var/lib/rxs3/config.json')['inbound_id'] == old_id, 'Setup duplicated inbound')
    print('PASS: actual fresh bootstrap, private panel, disabled subscriptions, idempotent setup')

    # Exercise the exact hardened bridge unit with the pinned binary and local
    # SOCKS input, not S3 traffic. This isolates systemd/credential compatibility.
    runtime = Runtime()
    uid = 'f' * 24
    native = {'log': {'loglevel': 'warning'}, 'inbounds': [{'listen': '127.0.0.1', 'port': 17160,
               'protocol': 'socks', 'settings': {'auth': 'noauth'}}],
              'outbounds': [{'protocol': 'freedom'}]}
    try:
        runtime.start(uid, native)
        require(runtime.active(uid), 'Hardened native service did not start')
        dynamic = run(['systemctl', 'show', '-p', 'DynamicUser', '--value', runtime.unit(uid)]).stdout.strip()
        require(dynamic == b'yes', 'Bridge not using dynamic unprivileged user')
        run(['systemctl', 'restart', runtime.unit(uid)])
        require(runtime.active(uid), 'Bridge did not survive service restart')
    finally:
        runtime.stop(uid)
    require(not runtime.active(uid), 'Bridge still active after stop')
    require(not Path('/var/lib/rxs3/runtime/' + uid + '.json').exists(), 'Runtime credentials not removed')
    runtime.stop(uid)
    print('PASS: actual systemd LoadCredential, DynamicUser, native startup, restart, idempotent stop')

    unrelated = panel.call('inbounds/add', {'remark': 'existing-config-do-not-touch', 'enable': True,
        'listen': '127.0.0.1', 'port': 17180, 'protocol': 'vless',
        'settings': {'clients': [], 'decryption': 'none'},
        'streamSettings': {'network': 'ws', 'security': 'none', 'wsSettings': {'path': '/existing'}},
        'sniffing': {'enabled': False}})
    before = panel.inbounds()
    # No user was ever issued. Only this test's own manager setup is removed.
    Path('/var/lib/rxs3/config.json').unlink()
    with patch.object(wizard, 'S3', MockCloud), patch.object(wizard, 'secret', side_effect=[config['panel_token'], 'fixture-access', 'fixture-secret']), \
            patch('builtins.input', side_effect=[config['panel_url'], '17181', 'other-fixture-bucket', 'нет']):
        wizard.setup()
    after = panel.inbounds()
    for inbound in before:
        match = next(row for row in after if row['id'] == inbound['id'])
        for field in ('remark', 'enable', 'listen', 'port', 'protocol', 'settings', 'streamSettings'):
            require(match[field] == inbound[field], 'Existing inbound changed')
    require(any(row['id'] == unrelated['id'] for row in after), 'Existing configuration disappeared')
    require(panel.call('setting/all', {}) == settings, 'Attach-existing changed panel settings')
    print('PASS: attach-existing preserves previous inbounds and panel settings')


if __name__ == '__main__':
    main()
