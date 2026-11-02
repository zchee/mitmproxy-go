// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package packettransport

import (
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/proxy/layer"
)

// pressureSocket holds an actual socket write outside the listener mutex, so
// pending jobs cannot leave the queue while its accounting is inspected.
type pressureSocket struct {
	*net.UDPConn
	reading chan struct{}
	writing chan struct{}
	release chan struct{}
	once    sync.Once
	writes  atomic.Int64
}

func (s *pressureSocket) ReadFrom(p []byte) (int, net.Addr, error) {
	s.reading <- struct{}{}
	return s.UDPConn.ReadFrom(p)
}

func (s *pressureSocket) WriteTo(p []byte, addr net.Addr) (int, error) {
	s.once.Do(func() {
		close(s.writing)
		<-s.release
	})
	s.writes.Add(1)
	return s.UDPConn.WriteTo(p, addr)
}

type pressureFixture struct {
	listener *Listener
	socket   *pressureSocket
	victim   *TupleConn
	neighbor *TupleConn
	peer     *net.UDPConn
	blocker  *TupleConn
	blocked  <-chan writeResult
	release  func()
}

func newPressureFixture(t *testing.T) *pressureFixture {
	t.Helper()
	socket, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfigureSocketBuffers(socket); err != nil {
		_ = socket.Close()
		t.Fatal(err)
	}
	observed := &pressureSocket{UDPConn: socket, reading: make(chan struct{}, 1), writing: make(chan struct{}), release: make(chan struct{})}
	listener := NewListener(t.Context(), observed)
	release := sync.OnceFunc(func() { close(observed.release) })
	t.Cleanup(func() { release(); _ = listener.Close() })
	awaitPacketSignal(t, observed.reading, "initial socket read")
	fixture := &pressureFixture{listener: listener, socket: observed, release: release}
	fixture.victim, fixture.peer = fixture.admit(t)
	fixture.neighbor, _ = fixture.admit(t)
	fixture.blocker, _ = fixture.admit(t)
	blocked := make(chan writeResult, 1)
	fixture.blocked = blocked
	go func() {
		n, err := fixture.blocker.WriteTo([]byte("active"), nil)
		blocked <- writeResult{n, err}
	}()
	awaitPacketSignal(t, observed.writing, "active socket write barrier")
	return fixture
}

func (f *pressureFixture) admit(t *testing.T) (*TupleConn, *net.UDPConn) {
	t.Helper()
	peer, err := net.DialUDP("udp", nil, f.listener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = peer.Close() })
	f.send(t, peer, nil)
	conn, err := f.listener.Accept(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadFrom(nil); err != nil {
		t.Fatal(err)
	}
	return conn, peer
}

func (f *pressureFixture) send(t *testing.T, peer *net.UDPConn, payload []byte) {
	t.Helper()
	if _, err := peer.Write(payload); err != nil {
		t.Fatal(err)
	}
	// The next socket read starts only after the previous datagram's admission
	// and enqueue have completed, unlike acknowledgement of kernel delivery.
	awaitPacketSignal(t, f.socket.reading, "completed datagram dispatch")
}

func queuePressureWrite(l *Listener, conn *TupleConn, payload []byte) *packetWrite {
	job := &packetWrite{conn: conn, payload: slices.Clone(payload), result: make(chan writeResult, 1)}
	if conn.pending == nil {
		conn.pending = make(map[*packetWrite]struct{})
	}
	conn.pending[job] = struct{}{}
	conn.writePackets++
	conn.writeBytes += len(payload)
	l.writePackets++
	l.writeBytes += len(payload)
	l.writes <- job
	return job
}

func pressureAccounting(t *testing.T, l *Listener) [4]int {
	t.Helper()
	l.mu.Lock()
	defer l.mu.Unlock()
	var actual [4]int
	for key, conn := range l.tuples {
		var queuedBytes, writeBytes int
		for _, payload := range conn.packets {
			queuedBytes += len(payload)
		}
		for job := range conn.pending {
			writeBytes += len(job.payload)
			if job.conn != conn || job.err != nil {
				t.Errorf("invalid pending write for %q: owner=%p want=%p err=%v", key, job.conn, conn, job.err)
			}
		}
		if conn.bytes != queuedBytes || conn.writeBytes != writeBytes || conn.writePackets != len(conn.pending) {
			t.Errorf("tuple %q accounting: read=%d/%d write=%d/%d packets=%d/%d", key, conn.bytes, queuedBytes, conn.writeBytes, writeBytes, conn.writePackets, len(conn.pending))
		}
		if len(conn.packets)+len(conn.pending) > layer.PacketQueueCapacity || queuedBytes+writeBytes > layer.PacketQueueBytes {
			t.Errorf("tuple %q exceeds queue bounds", key)
		}
		actual[0] += len(conn.packets)
		actual[1] += queuedBytes
		actual[2] += len(conn.pending)
		actual[3] += writeBytes
	}
	got := [4]int{l.queuedPackets, l.queuedBytes, l.writePackets, l.writeBytes}
	if diff := cmp.Diff(actual, got); diff != "" {
		t.Fatalf("listener accounting (-payloads +counters):\n%s", diff)
	}
	if got[0]+got[2] > layer.ListenerPacketQueueCapacity || got[1]+got[3] > layer.ListenerPacketQueueBytes {
		t.Fatalf("listener exceeds queue bounds: %v", got)
	}
	return got
}

func assertPressureLive(t *testing.T, f *pressureFixture) {
	t.Helper()
	l := f.listener
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, conn := range []*TupleConn{f.victim, f.neighbor} {
		if l.tuples[conn.key] != conn || conn.err != nil || conn.Context().Err() != nil {
			t.Fatalf("pressure retired live tuple: key=%q retained=%t err=%v cause=%v", conn.key, l.tuples[conn.key] == conn, conn.err, context.Cause(conn.Context()))
		}
	}
	if len(l.accept) != 0 {
		t.Fatalf("pressure caused a second Accept: %d queued", len(l.accept))
	}
}

func TestListenerPressureIsolation(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct {
			bytes     bool
			write     bool
			mixed     bool
			unknown   bool
			shutdown  bool
			tombstone bool
		}{
			"read_packet_budget_live":          {},
			"read_byte_budget_live":            {bytes: true},
			"write_packet_budget_live":         {write: true},
			"write_byte_budget_live":           {bytes: true, write: true},
			"mixed_read_write_budget":          {mixed: true},
			"new_peer_rejected_without_churn":  {unknown: true},
			"drain_restores_progress":          {},
			"shutdown_releases_accounting":     {mixed: true, shutdown: true},
			"write_channel_rollback_tombstone": {tombstone: true},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				f := newPressureFixture(t)
				l := f.listener
				var fillers []*TupleConn
				var jobs []*packetWrite
				if tt.tombstone {
					// Closing each real owner releases its pending payloads while
					// the held writer leaves canceled jobs in the bounded channel.
					for range layer.ListenerPacketQueueCapacity / layer.PacketQueueCapacity {
						conn, _ := f.admit(t)
						l.mu.Lock()
						for range layer.PacketQueueCapacity {
							jobs = append(jobs, queuePressureWrite(l, conn, []byte("canceled")))
						}
						l.mu.Unlock()
						if err := conn.Close(); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					// Admit all peers over owned sockets before filling individually
					// legal queues; bulk UDP delivery is not the capacity assertion.
					for range layer.ListenerPacketQueueCapacity / layer.PacketQueueCapacity {
						conn, _ := f.admit(t)
						fillers = append(fillers, conn)
					}
					for i, conn := range fillers {
						remaining := layer.PacketQueueBytes
						count := layer.PacketQueueCapacity
						if tt.bytes {
							count = (remaining + layer.MaxUDPPacketBytes - 1) / layer.MaxUDPPacketBytes
						}
						l.mu.Lock()
						for range count {
							size := 1
							if tt.bytes {
								size = min(remaining, layer.MaxUDPPacketBytes)
								remaining -= size
							}
							payload := make([]byte, size)
							if tt.write || (tt.mixed && i%2 == 0) {
								jobs = append(jobs, queuePressureWrite(l, conn, payload))
							} else if !l.enqueueLocked(conn, payload) {
								l.mu.Unlock()
								t.Fatal("queue rejected real payload before aggregate pressure")
							}
						}
						l.mu.Unlock()
					}
				}
				before := pressureAccounting(t, l)
				if tt.tombstone {
					if before != [4]int{} || len(l.writes) != cap(l.writes) {
						t.Fatalf("tombstone setup counters=%v channel=%d/%d", before, len(l.writes), cap(l.writes))
					}
				} else if tt.bytes {
					if before[1]+before[3] != layer.ListenerPacketQueueBytes {
						t.Fatalf("byte setup did not reach bound: %v", before)
					}
				} else if before[0]+before[2] != layer.ListenerPacketQueueCapacity {
					t.Fatalf("packet setup did not reach bound: %v", before)
				}

				if !tt.tombstone {
					l.mu.Lock()
					accepted := l.enqueueLocked(f.victim, []byte("newest"))
					l.mu.Unlock()
					assertPressureLive(t, f)
					if accepted {
						t.Fatal("aggregate pressure admitted newest read")
					}
				}
				for _, conn := range []*TupleConn{f.victim, f.neighbor} {
					n, err := conn.WriteTo([]byte("newest"), nil)
					assertPressureLive(t, f)
					if n != len("newest") || err != nil {
						t.Fatalf("dropped newest write=(%d, %v), want (%d, nil)", n, err, len("newest"))
					}
				}
				if !tt.tombstone {
					f.send(t, f.peer, []byte("same peer"))
					assertPressureLive(t, f)
				}
				if tt.unknown {
					other, err := net.DialUDP("udp", nil, l.LocalAddr().(*net.UDPAddr))
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = other.Close() })
					f.send(t, other, []byte("not admitted"))
					assertPressureLive(t, f)
					l.mu.Lock()
					retained := l.tuples[other.LocalAddr().Network()+"\x00"+other.LocalAddr().String()] != nil
					l.mu.Unlock()
					if retained {
						t.Fatal("unknown peer admitted without aggregate capacity")
					}
				}
				if diff := cmp.Diff(before, pressureAccounting(t, l)); diff != "" {
					t.Fatalf("newest drops changed accounting (-before +after):\n%s", diff)
				}
				if tt.shutdown {
					f.release()
					if err := l.Close(); err != nil {
						t.Fatal(err)
					}
					awaitPacketSignal(t, f.blocked, "active write shutdown")
				} else {
					// Reads consume retained payloads; canceled pending writes become
					// harmless channel tombstones, not double-released accounting.
					for _, conn := range fillers {
						l.mu.Lock()
						count := len(conn.packets)
						l.mu.Unlock()
						for range count {
							if _, _, err := conn.ReadFrom(nil); err != nil {
								t.Fatal(err)
							}
						}
						if err := conn.Close(); err != nil {
							t.Fatal(err)
						}
					}
					if got := pressureAccounting(t, l); got != [4]int{} {
						t.Fatalf("drain retained accounting: %v", got)
					}
					f.release()
					if result := awaitPacketSignal(t, f.blocked, "active socket write release"); result.err != nil || result.n != len("active") {
						t.Fatalf("active write=%+v", result)
					}
					for _, job := range jobs {
						result := awaitPacketSignal(t, job.result, "canceled queued write completion")
						if !errors.Is(result.err, net.ErrClosed) || result.n != 0 || job.payload != nil {
							t.Fatalf("tombstone result=%+v payload=%d", result, len(job.payload))
						}
					}
					if n, err := f.victim.WriteTo([]byte("reply"), nil); n != len("reply") || err != nil {
						t.Fatalf("write after drain=(%d, %v)", n, err)
					}
					buf := make([]byte, 32)
					if n, _, err := readTestPacket(t, f.peer, buf); err != nil || string(buf[:n]) != "reply" {
						t.Fatalf("real reply after drain=(%q, %v)", buf[:n], err)
					}
					for _, conn := range []*TupleConn{f.victim, f.neighbor} {
						l.mu.Lock()
						accepted := l.enqueueLocked(conn, []byte("resumed"))
						l.mu.Unlock()
						if !accepted {
							t.Fatal("read failed to resume after drain")
						}
						if n, _, err := conn.ReadFrom(buf); err != nil || string(buf[:n]) != "resumed" {
							t.Fatalf("read after drain=(%q, %v)", buf[:n], err)
						}
					}
					assertPressureLive(t, f)
					if got := f.socket.writes.Load(); got != 2 {
						t.Fatalf("canceled channel jobs reached socket: writes=%d, want 2", got)
					}
					if err := l.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if got := pressureAccounting(t, l); got != [4]int{} {
					t.Fatalf("shutdown retained accounting: %v", got)
				}
				awaitPacketSignal(t, l.readDone, "reader joined")
				awaitPacketSignal(t, l.writeDone, "writer joined")
				l.mu.Lock()
				retainedTuples, retainedJobs, active := len(l.tuples), len(l.writes), l.active
				l.mu.Unlock()
				if retainedTuples != 0 || retainedJobs != 0 || active != nil {
					t.Fatalf("shutdown retained tuples=%d jobs=%d active=%p", retainedTuples, retainedJobs, active)
				}
			})
		}
	})
}
