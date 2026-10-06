"""Own systemd instances only. Never touch s3-rixxx@ or unrelated x-ui units."""
from pathlib import Path
import subprocess
import time

from .errors import ManagerError
from .secure import atomic_json, identifier, private_dir

BRIDGE_UNIT = '''# RX-PRO-S3-Manager
[Unit]
Description=RX-PRO S3 isolated bridge %i
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
DynamicUser=yes
LoadCredential=bridge.json:/var/lib/rxs3/runtime/%i.json
ExecStart=/opt/rxs3/bin/xray-s3 run -c ${CREDENTIALS_DIRECTORY}/bridge.json
Restart=on-failure
RestartSec=5
TimeoutStopSec=15
KillMode=control-group
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077
MemoryMax=256M
TasksMax=64
LimitNOFILE=2048
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
'''

SYNC_UNIT = '''# RX-PRO-S3-Manager
[Unit]
Description=Reconcile managed RX-PRO S3 access
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/rxs3 sync
UMask=0077
TimeoutStartSec=15min
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
'''

SYNC_TIMER = '''# RX-PRO-S3-Manager
[Unit]
Description=Synchronize RX-PRO S3 access every minute

[Timer]
OnBootSec=20s
OnUnitInactiveSec=60s
RandomizedDelaySec=5s
Unit=rxs3-sync.service

[Install]
WantedBy=timers.target
'''


def run(args, timeout=60, check=True):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise ManagerError('Локальная команда недоступна или превысила время ожидания') from None
    if check and result.returncode != 0:
        raise ManagerError('Локальная команда завершилась с ошибкой; проверьте диагностику')
    return result


class Runtime:
    def __init__(self, root='/var/lib/rxs3', binary='/opt/rxs3/bin/xray-s3'):
        self.directory = private_dir(Path(root) / 'runtime')
        self.binary = binary

    @staticmethod
    def unit(uid):
        return 'rxs3-bridge@' + identifier(uid) + '.service'

    def start(self, uid, config):
        unit = self.unit(uid)
        path = self.directory / (uid + '.json')
        atomic_json(path, config)
        # Discard captured config diagnostics: native error strings may be sensitive.
        result = run([self.binary, 'run', '-test', '-c', str(path)])
        if b'FATAL' in result.stdout: raise ManagerError('Native core отклонил конфигурацию')
        run(['systemctl', 'enable', unit])
        run(['systemctl', 'restart', unit])
        time.sleep(1)
        if not self.active(uid): raise ManagerError('Bridge завершился после запуска')

    def active(self, uid):
        return run(['systemctl', 'is-active', '--quiet', self.unit(uid)], check=False).returncode == 0

    def stop(self, uid):
        unit = self.unit(uid)
        # Template is always installed, so stopping an unused instance is idempotent.
        run(['systemctl', 'disable', unit])
        run(['systemctl', 'stop', unit])
        result = run(['systemctl', 'show', '-p', 'ActiveState', '--value', unit])
        if result.stdout.strip() not in (b'inactive', b'failed'):
            raise ManagerError('Bridge ещё не остановлен')
        (self.directory / (uid + '.json')).unlink(missing_ok=True)
