#!/usr/bin/env python3
"""Package the independently versioned server binary and its license notices."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / '.lab/native'


def main():
    go = os.environ.get('GO', 'go')
    env = dict(os.environ, GOPATH=str(WORK/'gopath'), GOTOOLCHAIN='local')
    cache = Path(subprocess.check_output([go, 'env', 'GOMODCACHE'], env=env).decode().strip())
    files = {'xray-s3': (WORK/'bin/xray-s3').read_bytes(),
             'CLIENT-LICENSE': (ROOT/'LICENSE').read_bytes(),
             'XRAY-LICENSE': (WORK/'xray/LICENSE').read_bytes(),
             'AWS-LICENSE': (cache/'github.com/aws/aws-sdk-go-v2@v1.36.3/LICENSE.txt').read_bytes()}
    source = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((ROOT/'native').iterdir()) if p.is_file()}
    files['SOURCE.json'] = json.dumps({'upstream': 'b26a91de4f3294e26a0ad0a970b81a386a41f789',
                                     'files': source, 'server_only': True}, sort_keys=True, indent=2).encode()
    dest = WORK/'dist'; dest.mkdir(exist_ok=True)
    archive = dest/'rxs3-bridge-linux-amd64-0.1.0.tar.gz'
    with archive.open('wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', filename='', mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode='w') as tar:
            for name, data in files.items():
                info = tarfile.TarInfo(name); info.size = len(data); info.mtime = 0
                info.mode = 0o755 if name == 'xray-s3' else 0o644
                tar.addfile(info, io.BytesIO(data))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (dest/'SHA256SUMS.bridge').write_text(checksum+'  '+archive.name+'\n')
    print(archive.name, checksum)


if __name__ == '__main__': main()
