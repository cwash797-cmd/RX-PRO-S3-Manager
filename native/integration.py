#!/usr/bin/env python3
"""Actual legacy client binary -> new guarded server -> encrypted VLESS -> TCP.
Uses local object storage, not live VK. No public listeners or real credentials.
"""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]


def read_exact(sock, size):
    result = b''
    while len(result) < size:
        data = sock.recv(size - len(result))
        if not data: raise RuntimeError('Unexpected SOCKS EOF')
        result += data
    return result


class Target(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.opened.set()
        try:
            # A real download lasting longer than the server's two-second TTL.
            for _ in range(150):
                self.request.sendall(b'x' * 32768)
                time.sleep(.025)
            self.server.sent.set()
            while self.request.recv(4096): pass
        except OSError:
            pass
        finally:
            self.server.closed.set()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', required=True)
    parser.add_argument('--server', required=True)
    args = parser.parse_args()
    binaries = {'client': str(Path(args.client).resolve()), 'bridge': str(Path(args.server).resolve()),
                'panel': str(Path(args.server).resolve())}
    workroot = ROOT / '.lab'; workroot.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(dir=workroot, prefix='native-compat-') as tmp:
        work = Path(tmp)
        storage = work / 'objects'; storage.mkdir()
        with Server(('127.0.0.1', 0), Target) as target:
            target.opened, target.sent, target.closed = threading.Event(), threading.Event(), threading.Event()
            threading.Thread(target=target.serve_forever, daemon=True).start()
            panelport, socksport = port(), port()
            keys = subprocess.check_output([binaries['panel'], 'vlessenc'], stderr=subprocess.DEVNULL).decode()
            dec = re.search(r'"decryption": "([^"]+)"', keys).group(1)
            enc = re.search(r'"encryption": "([^"]+)"', keys).group(1).replace('.0rtt.', '.1rtt.')
            identity = str(uuid.uuid4())
            def stream(ttl):
                return {'network': 'xdrive', 'security': 'none', 'xdriveSettings': {'service': 'local',
                    'remoteFolder': str(storage), 'segmentBytes': 262144, 'flushIntervalMs': 30,
                    'pollIntervalMs': 20, 'maxPollIntervalMs': 100, 'concurrency': 4, 'sessionTtlSeconds': ttl}}
            configs = {
                'panel': {'inbounds': [{'listen': '127.0.0.1', 'port': panelport, 'protocol': 'vless',
                    'settings': {'clients': [{'id': identity}], 'decryption': dec}}], 'outbounds': [{'protocol': 'freedom'}]},
                'bridge': {'inbounds': [{'listen': '127.0.0.1', 'port': 11600, 'protocol': 'dokodemo-door',
                    'settings': {'address': '127.0.0.1', 'port': panelport, 'network': 'tcp'},
                    'streamSettings': stream(2)}], 'outbounds': [{'protocol': 'freedom'}]},
                'client': {'inbounds': [{'listen': '127.0.0.1', 'port': socksport, 'protocol': 'socks',
                    'settings': {'auth': 'noauth'}}], 'outbounds': [{'protocol': 'vless',
                    'settings': {'vnext': [{'address': '127.0.0.1', 'port': panelport,
                                          'users': [{'id': identity, 'encryption': enc}]}]},
                    'streamSettings': stream(300), 'mux': {'enabled': True, 'concurrency': 8}}]},
            }
            # Current Xray blocks private targets by default. Fixture-only
            # permissions allow precisely the local panel and local TCP target.
            for name, allowed in [('panel', target.server_address[1]), ('bridge', panelport)]:
                configs[name]['outbounds'][0]['settings'] = {'finalRules': [
                    {'action': 'allow', 'network': 'tcp', 'ip': ['127.0.0.1'], 'port': str(allowed)},
                    {'action': 'block'}]}
            processes = {}
            try:
                for name, config in configs.items():
                    config['log'] = {'loglevel': 'warning'}
                    path = work / (name + '.json'); path.write_text(json.dumps(config)); path.chmod(0o600)
                    processes[name] = subprocess.Popen([binaries[name], 'run', '-c', str(path)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        env=dict(os.environ, GOMEMLIMIT='128MiB'))
                for _ in range(100):
                    try:
                        sock = socket.create_connection(('127.0.0.1', socksport), timeout=1); break
                    except OSError: time.sleep(.05)
                else: raise RuntimeError('Legacy client did not start')
                with sock:
                    sock.settimeout(20)
                    sock.sendall(b'\x05\x01\x00')
                    assert read_exact(sock, 2) == b'\x05\x00'
                    sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('127.0.0.1') + target.server_address[1].to_bytes(2, 'big'))
                    response = read_exact(sock, 10)
                    assert response[1] == 0
                    received = 0
                    started = time.monotonic()
                    while received < 150 * 32768:
                        data = sock.recv(min(65536, 150*32768-received))
                        if not data: raise RuntimeError('Active download closed prematurely')
                        assert data == b'x' * len(data)
                        received += len(data)
                    elapsed = time.monotonic()-started
                    assert elapsed > 2, 'Fixture must outlive server TTL'
                    print('PASS: old 1.6.0 client, mux, VLESS encryption, one-way download beyond TTL;', received, 'bytes')
                    assert target.sent.wait(3)
                    processes['client'].kill(); processes['client'].wait(timeout=5)
                    assert target.closed.wait(8), 'Killed peer left real upstream TCP session open'
                    assert processes['bridge'].poll() is None, 'Watchdog killed the whole bridge'
                    print('PASS: abrupt legacy-client termination closes upstream session without stopping bridge')
            finally:
                for process in processes.values():
                    if process.poll() is None: process.terminate()
                for process in processes.values():
                    try: process.wait(timeout=5)
                    except subprocess.TimeoutExpired: process.kill(); process.wait()
                target.shutdown()


if __name__ == '__main__': main()
