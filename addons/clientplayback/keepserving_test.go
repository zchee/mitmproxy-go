// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package clientplayback

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/zchee/mitmproxy-go/addon"
	"github.com/zchee/mitmproxy-go/addons/keepserving"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/internal/proxy/proxytest"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
)

type shutdownObserver struct{ stopped chan struct{} }

func (o *shutdownObserver) Done(context.Context) error {
	select {
	case o.stopped <- struct{}{}:
	default:
	}
	return nil
}

func TestKeepServingClientReplayFile(t *testing.T) {
	tests := map[string]struct{ concurrency int }{"success: sequential file replay": {1}, "success: concurrent file replay": {-1}}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			leakCheck(t)
			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			origin := proxytest.StartOrigin(t, func(conn net.Conn) {
				reader := bufio.NewReader(conn)
				req, err := http.ReadRequest(reader)
				if err != nil {
					t.Error(err)
					return
				}
				if _, err := io.Copy(io.Discard, req.Body); err != nil {
					t.Error(err)
					return
				}
				if err := req.Body.Close(); err != nil {
					t.Error(err)
					return
				}
				entered <- struct{}{}
				select {
				case <-release:
				case <-t.Context().Done():
					return
				}
				if _, err := io.WriteString(conn, "HTTP/1.1 204 No Content\r\n\r\n"); err != nil {
					t.Error(err)
					return
				}
				_, _ = io.Copy(io.Discard, reader)
			})
			p := proxytest.Start(t, proxytest.WithOptions(map[string]any{"server": false}))
			c := New(p.Master)
			k := keepserving.New(p.Master, keepserving.Config{})
			observer := &shutdownObserver{stopped: make(chan struct{}, 1)}
			if err := p.Master.Addons.Add(t.Context(), c, k, observer); err != nil {
				t.Fatal(err)
			}
			f := testflow.TFlow()
			f.Live = false
			host, port, err := net.SplitHostPort(origin.Addr)
			if err != nil {
				t.Fatal(err)
			}
			f.Request.Host = host
			f.Request.Port, err = strconv.Atoi(port)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "requests.mitm")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := flowio.NewWriter(file).Add(f); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				return p.Master.Options.Update(ctx, map[string]any{"client_replay": []string{path}, "client_replay_concurrency": tt.concurrency})
			}); err != nil {
				t.Fatal(err)
			}
			if err := p.Master.Addons.Hook(t.Context(), addon.RunningHook{}); err != nil {
				t.Fatal(err)
			}
			await(t, entered)
			if !k.Keepgoing(t.Context()) {
				t.Fatal("keepserving considered the blocked replay idle")
			}
			close(release)
			await(t, observer.stopped)
			if err := p.Master.Do(t.Context(), func(ctx context.Context) error {
				if c.count(ctx) != 0 {
					t.Fatal("master shutdown retained replay work")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
