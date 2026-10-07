// SPDX-License-Identifier: MPL-2.0
package xdrive

// Server-only watchdog. The existing XDRIVE wire format is unchanged: deleting
// downloaded .seg objects is the acknowledgement already used by old clients.
// Empty LISTs are not user activity. Downlink-only traffic stays alive when the
// peer consumes segments; an absent peer cannot keep a session alive by causing
// a remote service to send data forever.
import (
	"context"
	"io"
	"strings"
	"sync"
	"time"
)

const peerPendingLimit = 16

type peerSegment struct{ uploaded bool }

type peerStorage struct {
	Storage
	ctx                     context.Context
	readPrefix, writePrefix string
	ttl                     time.Duration
	mu                      sync.Mutex
	lastPeer                time.Time
	pending                 map[string]peerSegment
	wake                    chan struct{}
	acknowledged            int64
}

func newPeerStorage(ctx context.Context, storage Storage, readPrefix, writePrefix string, ttl time.Duration) *peerStorage {
	return &peerStorage{Storage: storage, ctx: ctx, readPrefix: readPrefix + "/", writePrefix: writePrefix + "/",
		ttl: ttl, lastPeer: time.Now(), pending: make(map[string]peerSegment), wake: make(chan struct{}, 1), acknowledged: -1}
}

func (p *peerStorage) Get(ctx context.Context, name string) ([]byte, error) {
	data, err := p.Storage.Get(ctx, name)
	if err == nil && ctx.Err() == nil && p.ctx.Err() == nil && len(data) > 0 && strings.HasPrefix(name, p.readPrefix) && strings.HasSuffix(name, segSuffix) {
		p.mu.Lock()
		p.lastPeer = time.Now()
		p.mu.Unlock()
	}
	return data, err
}

func (p *peerStorage) Put(ctx context.Context, name string, data []byte) error {
	track := strings.HasPrefix(name, p.writePrefix) && strings.HasSuffix(name, segSuffix)
	if !track {
		return p.Storage.Put(ctx, name, data)
	}
	for {
		p.mu.Lock()
		if len(p.pending) < peerPendingLimit {
			p.pending[name] = peerSegment{}
			p.mu.Unlock()
			break
		}
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.ctx.Done():
			return p.ctx.Err()
		case <-p.wake:
		case <-time.After(100 * time.Millisecond):
		}
	}
	err := p.Storage.Put(ctx, name, data)
	p.mu.Lock()
	seq, valid := parseEntry(strings.TrimPrefix(name, p.writePrefix))
	if err == nil && valid && seq > p.acknowledged {
		p.pending[name] = peerSegment{uploaded: true}
	} else {
		delete(p.pending, name)
	}
	p.mu.Unlock()
	return err
}

func (p *peerStorage) peerAlive(now time.Time) bool {
	// Snapshot only completed uploads BEFORE LIST. An upload completing during
	// LIST must not be mistaken for an acknowledged segment.
	p.mu.Lock()
	snapshot := make([]string, 0, len(p.pending))
	for name, segment := range p.pending {
		if segment.uploaded {
			snapshot = append(snapshot, name)
		}
	}
	p.mu.Unlock()
	if len(snapshot) > 0 {
		ctx, cancel := context.WithTimeout(p.ctx, 10*time.Second)
		entries, err := p.Storage.List(ctx, strings.TrimSuffix(p.writePrefix, "/"))
		cancel()
		if err == nil && p.ctx.Err() == nil {
			present := make(map[string]bool, len(entries))
			for _, entry := range entries {
				present[p.writePrefix+entry.Name] = true
			}
			p.mu.Lock()
			for _, name := range snapshot {
				seq, valid := parseEntry(strings.TrimPrefix(name, p.writePrefix))
				if !present[name] && valid && seq > p.acknowledged {
					p.acknowledged = seq
					if now.After(p.lastPeer) {
						p.lastPeer = now
					}
				}
			}
			// WAL delivery is sequential. A later consumed segment proves all
			// earlier ones were consumed too, even if best-effort DELETE failed.
			for name := range p.pending {
				seq, valid := parseEntry(strings.TrimPrefix(name, p.writePrefix))
				if valid && seq <= p.acknowledged {
					delete(p.pending, name)
				}
			}
			p.mu.Unlock()
			select {
			case p.wake <- struct{}{}:
			default:
			}
		}
		// Errors never count as progress. A long outage closes the stream,
		// rather than producing billable responses for a disconnected peer.
	}
	p.mu.Lock()
	alive := now.Sub(p.lastPeer) < p.ttl
	p.mu.Unlock()
	return alive
}

func (p *peerStorage) watch(expire func()) {
	interval := p.ttl / 6
	if interval > 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}
	if interval < 20*time.Millisecond {
		interval = 20 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-ticker.C:
			if !p.peerAlive(now) {
				expire()
				return
			}
		}
	}
}

// Unblock both WAL sides before waiting for writer completion. Attempt a bounded
// error marker for a still-connected idle client so it opens a new session.
func (c *Conn) expirePeer(storage Storage, writePrefix string) {
	// A concurrent graceful Close can be holding Once while waiting for the
	// upload window. Cancel before entering Once to release those blocked PUTs.
	c.reader.setErr(io.EOF)
	c.cancel()
	c.closeOnce.Do(func() {
		c.closeErr = c.writer.Close()
		c.writer.mu.Lock()
		seq := c.writer.seq
		c.writer.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = storage.Put(ctx, objectName(writePrefix, seq, errSuffix), nil)
		cancel()
		if c.onClose != nil {
			c.onClose()
		}
	})
}
