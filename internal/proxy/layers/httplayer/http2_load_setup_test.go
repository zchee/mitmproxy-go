// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build h2load

package httplayer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestLoadHTTP2SetupPrefaceOrder(t *testing.T) {
	tests := map[string]struct{ client bool }{
		"success: client preface precedes reader acknowledgments": {client: true},
		"success: origin preface precedes reader acknowledgments": {client: false},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			conn, remote := net.Pipe()
			defer func() { _ = remote.Close() }()
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := remote.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			peer := makeLoadHTTP2Peer(ctx, conn, nil, nil, false)
			var workers sync.WaitGroup
			defer func() {
				cancel()
				_ = conn.Close()
				_ = remote.Close()
				workers.Wait()
				peer.close()
			}()
			prefaceDone := make(chan error, 1)
			remoteDone := make(chan error, 1)
			workers.Go(func() {
				remoteDone <- func() error {
					var err error
					if tt.client {
						prefix := make([]byte, len(http2.ClientPreface))
						_, err = io.ReadFull(remote, prefix)
						if err == nil && string(prefix) != http2.ClientPreface {
							err = errors.New("wrong client preface")
						}
					} else {
						_, err = io.WriteString(remote, http2.ClientPreface)
					}
					prefaceDone <- err
					if err != nil {
						return err
					}
					framer := http2.NewFramer(remote, remote)
					if err := framer.WriteSettings(); err != nil {
						return err
					}
					for i, want := range []http2.FrameType{http2.FrameSettings, http2.FrameWindowUpdate, http2.FrameSettings} {
						frame, err := framer.ReadFrame()
						if err != nil {
							return err
						}
						if frame.Header().Type != want {
							return fmt.Errorf("frame %d = %s, want %s", i, frame.Header().Type, want)
						}
						if settings, ok := frame.(*http2.SettingsFrame); ok && settings.IsAck() != (i == 2) {
							return fmt.Errorf("frame %d SETTINGS ACK = %t", i, settings.IsAck())
						}
					}
					return framer.WriteSettingsAck()
				}()
			})
			// Stop setup at its write lock while the remote offers SETTINGS. Wait
			// for that exact blocked state, not a scheduler delay or a sleep.
			peer.writeMu.Lock()
			unlock := sync.OnceFunc(peer.writeMu.Unlock)
			defer unlock()
			setupDone := make(chan error, 1)
			workers.Go(func() { setupDone <- peer.setup(tt.client) })
			if err := <-prefaceDone; err != nil {
				t.Fatal(err)
			}
			stacks := make([]byte, 1<<20)
			for {
				n := runtime.Stack(stacks, true)
				blocked := false
				for stack := range strings.SplitSeq(string(stacks[:n]), "\n\n") {
					if strings.Contains(stack, "[sync.Mutex.Lock") && strings.Contains(stack, "(*loadHTTP2Peer).setup(") {
						blocked = true
						break
					}
				}
				if blocked {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatalf("setup never waited for initial frame write ownership:\n%s", stacks[:n])
				default:
					runtime.Gosched()
				}
			}
			peer.mu.Lock()
			started := peer.readerStarted
			peer.mu.Unlock()
			if started {
				t.Error("reader started before setup acquired initial frame write ownership")
			}
			unlock()
			if err := <-setupDone; err != nil {
				t.Error(err)
			}
			if err := <-remoteDone; err != nil {
				t.Error(err)
			}
		})
	}
}
