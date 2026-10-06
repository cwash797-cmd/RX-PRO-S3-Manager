#!/usr/bin/env python3
"""Build a reproducible source-only release; never include .lab or local state."""
import gzip
import hashlib
import io
from pathlib import Path
import subprocess
import tarfile

from rxs3 import __version__

ROOT = Path(__file__).resolve().parent


def build():
    if subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT).strip():
        raise SystemExit('Commit tracked changes before packaging')
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    contents = {}
    for name in sorted(filter(None, files)):
        if name.startswith(('.lab/', '.git/')) or name.endswith(('.sqlite', '.db', '.rxs3-backup')):
            raise SystemExit('Forbidden state file in source tree')
        path = ROOT / name
        if path.is_symlink(): raise SystemExit('Symlinks forbidden in release source')
        contents[name] = path.read_bytes()
    sums = ''.join(hashlib.sha256(data).hexdigest() + '  ' + name + '\n' for name, data in contents.items())
    contents['SHA256SUMS'] = sums.encode()
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).strip()
    contents['SOURCE_COMMIT'] = commit + b'\n'
    folder = 'rx-pro-s3-manager-' + __version__
    out = ROOT / 'dist'
    out.mkdir(exist_ok=True)
    archive = out / (folder + '.tar.gz')
    with open(archive, 'wb') as raw, gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as tar:
            for name, data in contents.items():
                info = tarfile.TarInfo(folder + '/' + name)
                info.size, info.mode, info.mtime = len(data), 0o644, 0
                tar.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (out / 'SHA256SUMS.release').write_text(digest + '  ' + archive.name + '\n')
    print(archive.name, digest)
    return archive


if __name__ == '__main__':
    build()
