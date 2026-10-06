"""Opt-in real-binary contract test. MUST run in a private network namespace.

From the repository, after verifying/extracting the pinned panel archive:
  sudo unshare --net -- bash -c 'ip link set lo up; python3 tests/integration_panel.py'
No production paths, cloud credentials, firewall or system services are used.
"""
import json
import hashlib
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from rxs3.http import Panel
from rxs3.errors import ManagerError
from rxs3.engine import Engine
from rxs3.secure import Store
from test_lifecycle import CloudFake, RuntimeFake


def check(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    check(os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'),
          'Refusing to start a default-credential panel outside a network namespace')
    binary = ROOT / '.lab/x-ui/x-ui'
    xray = ROOT / '.lab/x-ui/bin/xray-linux-amd64'
    check(subprocess.check_output([str(binary), '-v']).strip() == b'3.9.0', 'Wrong panel version')
    with tempfile.TemporaryDirectory(prefix='panel-contract-', dir=ROOT / '.lab') as tmp:
        work = Path(tmp)
        (work / 'db').mkdir(mode=0o700)
        (work / 'logs').mkdir(mode=0o700)
        # Xray writes generated config in BIN_FOLDER: never use a production directory.
        (work / 'bin').mkdir()
        (work / 'bin/xray-linux-amd64').symlink_to(xray)
        env = dict(os.environ, XUI_DB_FOLDER=str(work / 'db'),
                   XUI_LOG_FOLDER=str(work / 'logs'), XUI_BIN_FOLDER=str(work / 'bin'),
                   XUI_NODE_TOKEN_KEY_FILE=str(work / 'db/nodekey.json'),
                   HOME=str(work), TMPDIR=str(work))
        def cli(*args):
            return subprocess.check_output([str(binary), *args], env=env, cwd=work,
                                           stderr=subprocess.DEVNULL, timeout=30).decode()
        cli('setting', '-port', '17153', '-listenIP', '127.0.0.1', '-webBasePath', '/rxs3-test/')
        token_output = cli('setting', '-getApiToken', '-tokenName', 'rxs3-test', '-tokenScope', 'admin')
        match = re.search(r'apiToken:\s*(\S+)', token_output)
        check(match is not None, 'CLI did not return a token')
        panel = Panel('http://127.0.0.1:17153/rxs3-test', match.group(1))
        proc = subprocess.Popen([str(binary)], env=env, cwd=work,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        try:
            for _ in range(100):
                try:
                    panel.inbounds()
                    break
                except ManagerError:
                    time.sleep(.1)
            else:
                raise RuntimeError('Panel readiness timeout')
            # /setting/all is POST, not GET. Test credential update separately.
            settings = panel.call('setting/all', {})
            check(isinstance(settings, dict), 'Invalid settings envelope')
            password = secrets.token_urlsafe(32)
            panel.call('setting/updateUser', {'oldUsername': 'admin', 'oldPassword': 'admin',
                       'newUsername': 'rxs3-test', 'newPassword': password})
            settings.update(webListen='127.0.0.1', subEnable=False, subListen='127.0.0.1')
            panel.call('setting/update', settings)
            saved = panel.call('setting/all', {})
            check(saved.get('subEnable') is False, 'Subscription was not disabled')
            check(saved.get('webListen') == '127.0.0.1', 'Panel not loopback')
            print('PASS: settings POST, password change and subscription disable')

            keys = subprocess.check_output([str(xray), 'vlessenc'], stderr=subprocess.DEVNULL).decode()
            decryption = re.search(r'"decryption": "([^"]+)"', keys).group(1)
            installation = secrets.token_hex(12)
            inbound = panel.call('inbounds/add', {
                'remark': 'RXS3 ' + installation, 'enable': True, 'listen': '127.0.0.1',
                'port': 17154, 'protocol': 'vless',
                'settings': {'clients': [], 'decryption': decryption},
                'streamSettings': {'network': 'tcp', 'security': 'none'},
                'sniffing': {'enabled': False}})
            check(isinstance(inbound, dict) and isinstance(inbound.get('id'), int), 'Invalid inbound result')
            users = []
            for index in range(2):
                user = {'email': f'rxs3-fixture-{index}', 'uuid': str(uuid.uuid4()),
                        'sub_id': secrets.token_hex(8), 'quota': 1073741824, 'expires': 0}
                panel.create_client(user, inbound['id'])
                users.append(user)
            first = panel.client(users[0]['email'])
            check(first is not None, 'Client lookup lost created identity')
            check(first['client']['uuid'] == users[0]['uuid'], 'UUID contract mismatch')
            check(first['inboundIds'] == [inbound['id']], 'Inbound attachment mismatch')
            panel.update_client(first, enable=False)
            check(panel.client(users[0]['email'])['client']['enable'] is False, 'Disable failed')
            check(panel.client(users[1]['email'])['client']['enable'] is True, 'Unrelated client changed')
            changed = panel.client(users[0]['email'])
            check(changed['client']['totalGB'] == users[0]['quota'], 'Quota lost during update')
            replacement = str(uuid.uuid4())
            panel.update_client(changed, enable=True, id=replacement)
            check(panel.client(users[0]['email'])['client']['uuid'] == replacement, 'UUID rotation failed')
            panel.delete_client(users[0]['email'])
            check(panel.client(users[0]['email']) is None, 'Delete not reflected')
            check(panel.client(users[1]['email'])['client']['enable'] is True, 'Sibling lost')
            print('PASS: real client create, lookup, disable, UUID rotation, delete and sibling preservation')
            store = Store(work / 'manager')
            try:
                config = {'installation': installation, 'inbound_id': inbound['id'], 'panel_port': 17154,
                          'encryption': re.search(r'"encryption": "([^"]+)"', keys).group(1).replace('.0rtt.', '.1rtt.'),
                          'decryption_sha256': hashlib.sha256(decryption.encode()).hexdigest()}
                cloud, runtime = CloudFake(), RuntimeFake()
                engine = Engine(store, config, panel, cloud, runtime)
                a, b = engine.add('Первый', 1024**3), engine.add('Второй')
                check(len(cloud.keys) == 4, 'Manager did not create isolated credentials')
                original = engine.show(a)
                engine.disable(a)
                check(a not in runtime.running and b in runtime.running, 'Revocation affected sibling')
                engine.enable(a)
                check(original != engine.show(a), 'Re-enable reused link')
                engine.enable(a, rotate=True)
                check(store.get(a)['generation'] == 3, 'Rotation lost generation')
                panel.update_client(panel.client(store.get(b)['email']), enable=False)
                engine.sync()
                check(store.get(b)['state'] == 'disabled', 'Panel disable was not synchronized')
                panel.delete_client(store.get(a)['email'])
                engine.sync()
                check(store.get(a)['state'] == 'deleted', 'Panel delete was not synchronized')
                check(not cloud.keys and not runtime.running, 'Managed resources left enabled')
                check(panel.client(users[1]['email'])['client']['enable'], 'Unmanaged client changed')
                print('PASS: manager lifecycle against real 3x-ui (VK/runtime models), two users and panel sync')
            finally:
                store.db.close()
        finally:
            os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()


if __name__ == '__main__':
    main()
