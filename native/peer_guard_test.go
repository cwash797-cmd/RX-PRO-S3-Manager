// SPDX-License-Identifier: MPL-2.0
package xdrive

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"
)

func guardFixture(t *testing.T) (*peerStorage, Storage, context.CancelFunc) {
	t.Helper()
	storage, err := newLocalStorage(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return newPeerStorage(ctx, storage, "up", "down", time.Second), storage, cancel
}

func TestPeerGuardPollingIsNotLiveness(t *testing.T) {
	guard, _, cancel := guardFixture(t)
	defer cancel()
	for i := 0; i < 10; i++ {
		_, _ = guard.List(context.Background(), "up")
	}
	if guard.peerAlive(time.Now().Add(2 * time.Second)) {
		t.Fatal("empty polling kept absent peer alive")
	}
}

func TestPeerGuardDownloadConsumptionAndCumulativeAcknowledgement(t *testing.T) {
	guard, storage, cancel := guardFixture(t)
	defer cancel()
	for i := int64(0); i < 3; i++ {
		if err := guard.Put(context.Background(), objectName("down", i, segSuffix), []byte("data")); err != nil {
			t.Fatal(err)
		}
	}
	// Older DELETEs can be lost by old clients' best-effort cleanup. WAL delivery
	// is ordered, so consuming #2 still proves consumption through #0 and #1.
	if err := storage.Delete(context.Background(), objectName("down", 2, segSuffix)); err != nil {
		t.Fatal(err)
	}
	if !guard.peerAlive(time.Now().Add(2 * time.Second)) {
		t.Fatal("active one-way download expired")
	}
	guard.mu.Lock()
	pending, ack := len(guard.pending), guard.acknowledged
	guard.mu.Unlock()
	if pending != 0 || ack != 2 {
		t.Fatalf("unretired cumulative acknowledgement: %d / %d", pending, ack)
	}
}

func TestPeerGuardUnconsumedDownlinkDoesNotKeepPeerAlive(t *testing.T) {
	guard, _, cancel := guardFixture(t)
	defer cancel()
	if err := guard.Put(context.Background(), objectName("down", 0, segSuffix), []byte("remote keepalive")); err != nil {
		t.Fatal(err)
	}
	if guard.peerAlive(time.Now().Add(2 * time.Second)) {
		t.Fatal("server-originated data kept dead peer alive")
	}
}

func TestPeerGuardBoundedPendingWindowCancellation(t *testing.T) {
	guard, _, cancel := guardFixture(t)
	defer cancel()
	for i := int64(0); i < peerPendingLimit; i++ {
		if err := guard.Put(context.Background(), objectName("down", i, segSuffix), []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- guard.Put(context.Background(), objectName("down", peerPendingLimit, segSuffix), []byte("x"))
	}()
	select {
	case <-done:
		t.Fatal("unbounded upload window")
	case <-time.After(30 * time.Millisecond):
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("canceled PUT succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked PUT leaked")
	}
}

func TestPeerGuardActiveDownloadSurvivesAndAbsentPeerExpires(t *testing.T) {
	settings := settings(t.TempDir())
	settings.ProtocolSettings.(*Config).SessionTtlSeconds = 1
	client, server, cleanup := pairWith(t, settings)
	defer cleanup()
	// Only server->client traffic for longer than TTL; old wire client still
	// acknowledges by removing consumed .seg files.
	until := time.Now().Add(2200 * time.Millisecond)
	for time.Now().Before(until) {
		if _, err := server.Write([]byte("download")); err != nil {
			t.Fatal(err)
		}
		expectRead(t, client, "download")
		time.Sleep(40 * time.Millisecond)
	}
	raw := client.(*Conn)
	raw.cancel() // Simulate Android process death: no graceful .end marker.
	done := make(chan error, 1)
	go func() { var b [1]byte; _, err := server.Read(b[:]); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expired stream returned no error")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("abandoned server session remained open")
	}
}

func TestPeerGuardConcurrentGracefulCloseDoesNotDeadlock(t *testing.T) {
	guard, storage, cancel := guardFixture(t)
	defer cancel()
	p := paramsFromConfig(&Config{SegmentBytes: 1, PollIntervalMs: 5, MaxPollIntervalMs: 10})
	conn := newConn(guard.ctx, guard, "down", "up", p, nil)
	writer := make(chan struct{})
	go func() { _, _ = conn.Write(make([]byte, peerPendingLimit+8)); close(writer) }()
	time.Sleep(50 * time.Millisecond)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _ = conn.Close() }()
	go func() { defer wg.Done(); conn.expirePeer(storage, "down") }()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close and expiry deadlocked")
	}
	select {
	case <-writer:
	case <-time.After(time.Second):
		t.Fatal("writer leaked")
	}
}

func TestPeerGuardGracefulCloseStillSignalsEOF(t *testing.T) {
	client, server, cleanup := pair(t)
	defer cleanup()
	if _, err := client.Write([]byte("bye")); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	data, err := io.ReadAll(server)
	if err != nil || string(data) != "bye" {
		t.Fatalf("graceful EOF failed: %q %v", data, err)
	}
}

// Simulate LIST failures and an upload that completes during the listing.
type guardListStorage struct {
	Storage
	list func(context.Context, string) ([]Entry, error)
}

func (s guardListStorage) List(ctx context.Context, prefix string) ([]Entry, error) {
	return s.list(ctx, prefix)
}

func TestPeerGuardListErrorIsNotAcknowledgement(t *testing.T) {
	guard, storage, cancel := guardFixture(t)
	defer cancel()
	if err := guard.Put(context.Background(), objectName("down", 0, segSuffix), []byte("x")); err != nil {
		t.Fatal(err)
	}
	guard.Storage = guardListStorage{storage, func(context.Context, string) ([]Entry, error) {
		return nil, context.DeadlineExceeded
	}}
	if guard.peerAlive(time.Now().Add(2 * time.Second)) {
		t.Fatal("failed LIST kept peer alive")
	}
	if len(guard.pending) != 1 {
		t.Fatal("failed LIST retired pending upload")
	}
}

func TestPeerGuardListSnapshotExcludesConcurrentUpload(t *testing.T) {
	guard, storage, cancel := guardFixture(t)
	defer cancel()
	if err := guard.Put(context.Background(), objectName("down", 0, segSuffix), []byte("x")); err != nil {
		t.Fatal(err)
	}
	guard.Storage = guardListStorage{storage, func(ctx context.Context, prefix string) ([]Entry, error) {
		entries, err := storage.List(ctx, prefix)
		if err != nil {
			return nil, err
		}
		if err := guard.Put(ctx, objectName("down", 1, segSuffix), []byte("y")); err != nil {
			t.Fatal(err)
		}
		return entries, nil
	}}
	if guard.peerAlive(time.Now().Add(2 * time.Second)) {
		t.Fatal("concurrent upload became false acknowledgement")
	}
	if len(guard.pending) != 2 || guard.acknowledged != -1 {
		t.Fatal("upload retired without consumption")
	}
}

func TestPeerGuardCanceledListCannotRenewActivity(t *testing.T) {
	guard, storage, cancel := guardFixture(t)
	defer cancel()
	if err := guard.Put(context.Background(), objectName("down", 0, segSuffix), []byte("x")); err != nil {
		t.Fatal(err)
	}
	guard.Storage = guardListStorage{storage, func(context.Context, string) ([]Entry, error) {
		cancel()
		return nil, nil
	}}
	if guard.peerAlive(time.Now().Add(2 * time.Second)) {
		t.Fatal("canceled LIST counted as progress")
	}
	if len(guard.pending) != 1 {
		t.Fatal("canceled LIST retired upload")
	}
}
