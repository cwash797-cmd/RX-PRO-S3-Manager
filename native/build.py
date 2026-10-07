#!/usr/bin/env python3
"""Pinned, manager-owned SERVER build. Does not build or modify the Android APK."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / '.lab/native'
SRC = WORK / 'xray'
PIN = 'b26a91de4f3294e26a0ad0a970b81a386a41f789'


def run(*args, cwd=SRC, env=None):
    subprocess.run(args, cwd=cwd, env=env, check=True)


def replace(path, old, new):
    data = path.read_text()
    if data.count(old) != 1: raise RuntimeError('Pinned source mismatch: ' + str(path.relative_to(SRC)))
    path.write_text(data.replace(old, new))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=['prepare', 'test', 'linux'])
    args = parser.parse_args()
    for directory in ('tmp', 'gopath', 'cache', 'bin'):
        (WORK / directory).mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, GOPATH=str(WORK/'gopath'), GOCACHE=os.environ.get('GOCACHE', str(WORK/'cache')),
               TMPDIR=str(WORK/'tmp'), GOMAXPROCS='2', GOFLAGS='-p=2', GOTOOLCHAIN='local')
    go = os.environ.get('GO', 'go')
    if not SRC.exists():
        SRC.mkdir()
        run('git', 'init')
        run('git', 'remote', 'add', 'origin', 'https://github.com/XTLS/Xray-core.git')
        run('git', 'fetch', '--depth=1', 'origin', PIN)
    run('git', 'reset', '--hard', PIN)
    for name in ('s3.go', 's3_test.go', 'peer_guard.go', 'peer_guard_test.go'):
        shutil.copyfile(ROOT/'native'/name, SRC/'transport/internet/xdrive'/('rx_'+name))
    replace(SRC/'transport/internet/xdrive/storage.go', 'case "local":',
            'case "S3":\n\t\treturn sharedStorage(streamSettings, config, func() (Storage, error) { return newS3Storage(streamSettings, config) })\n\tcase "local":')
    replace(SRC/'infra/conf/transport_method.go', 'switch c.Service {\n\tcase "local":',
            'switch c.Service {\n\tcase "S3":\n\t\tif len(c.Secrets) != 1 { return nil, errors.New("S3 requires one credentials JSON") }\n\tcase "local":')
    wal = SRC/'transport/internet/xdrive/wal.go'
    replace(wal, '\n\tn := len(w.buf)\n', '\n\tselect { case w.sem <- struct{}{}: case <-w.ctx.Done(): w.err = w.ctx.Err(); return w.err }\n\tn := len(w.buf)\n')
    replace(wal, '''	select {
	case w.sem <- struct{}{}:
	case <-w.ctx.Done():
		return
	}
	defer func() { <-w.sem }()

	if err := w.storage.Put(w.ctx, objectName(w.prefix, seq, segSuffix), chunk); err != nil {''', '''	err := w.storage.Put(w.ctx, objectName(w.prefix, seq, segSuffix), chunk)
	<-w.sem
	if err != nil {''')
    listener = SRC/'transport/internet/xdrive/xdrive.go'
    replace(listener, 'if l.active[session] || !l.handled[session].IsZero() {',
            'if len(l.active) >= 32 || l.active[session] || !l.handled[session].IsZero() {')
    replace(listener, '''	return newConn(l.ctx, l.storage,
		downlinkPrefix(session), uplinkPrefix(session), l.params, func() {
			l.mu.Lock()
			delete(l.active, session)
			l.mu.Unlock()
		})''', '''	ctx, cancel := context.WithCancel(l.ctx)
	guard := newPeerStorage(ctx, l.storage, uplinkPrefix(session), downlinkPrefix(session), l.sessionTTL)
	conn := newConn(ctx, guard,
		downlinkPrefix(session), uplinkPrefix(session), l.params, func() {
			cancel()
			l.mu.Lock()
			delete(l.active, session)
			l.mu.Unlock()
		})
	go guard.watch(func() { conn.expirePeer(l.storage, downlinkPrefix(session)) })
	return conn''')
    run(go, 'mod', 'edit', '-require=github.com/aws/aws-sdk-go-v2@v1.36.3', env=env)
    run(go, 'mod', 'tidy', env=env)
    run(go, 'mod', 'verify', env=env)
    if args.target == 'test':
        run(go, 'test', '-race', '-timeout=180s', './transport/internet/xdrive', env=env)
    elif args.target == 'linux':
        env.update(GOOS='linux', GOARCH='amd64', CGO_ENABLED='0')
        run(go, 'build', '-mod=readonly', '-trimpath', '-buildvcs=false', '-ldflags=-s -w',
            '-o', str(WORK/'bin/xray-s3'), './main', env=env)
        print('Built server:', WORK/'bin/xray-s3')


if __name__ == '__main__':
    main()
