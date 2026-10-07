// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
)

func syntheticLinuxLauncher(t *testing.T, messages chan<- *FromProxy, shutdown chan<- struct{}) func(context.Context, string, string) (*exec.Cmd, io.ReadCloser, error) {
	t.Helper()
	return func(ctx context.Context, _, dir string) (*exec.Cmd, io.ReadCloser, error) {
		peer, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: filepath.Join(dir, "redirector"), Net: "unixgram"})
		if err != nil {
			return nil, nil, err
		}
		if err := errors.Join(peer.SetReadBuffer(2*maxNativeIPCMessageSize), peer.SetWriteBuffer(2*maxNativeIPCMessageSize)); err != nil {
			_ = peer.Close()
			return nil, nil, err
		}
		if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			_ = peer.Close()
			return nil, nil, err
		}
		// The fixture shell prints only a socket path and waits for stdin EOF.
		// It never loads a native redirector, TUN, eBPF, sudo, or acquired artifact.
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", `printf '%s/redirector\n' "$1"; read line`, "synthetic-redirector", dir)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			_ = peer.Close()
			return nil, nil, err
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			_ = peer.Close()
			return nil, nil, err
		}
		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			_ = peer.Close()
			return nil, nil, err
		}
		var workers sync.WaitGroup
		workers.Go(func() {
			defer func() { _ = peer.Close(); _, _ = io.WriteString(stdin, "done\n"); _ = stdin.Close() }()
			buf := make([]byte, maxNativeIPCMessageSize+1)
			for {
				n, addr, err := peer.ReadFromUnix(buf)
				if err != nil {
					return
				}
				if n == 0 {
					shutdown <- struct{}{}
					return
				}
				var msg FromProxy
				if err := proto.Unmarshal(buf[:n], &msg); err != nil {
					t.Error(err)
					return
				}
				select {
				case messages <- &msg:
				case <-ctx.Done():
					return
				}
				if msg.GetPacket() != nil {
					pid, name := uint32(123), "synthetic-redirector"
					packet := &PacketWithMeta{Data: msg.GetPacket().Data, TunnelInfo: &TunnelInfo{Pid: &pid, ProcessName: &name}}
					wire, err := proto.Marshal(packet)
					if err != nil {
						t.Error(err)
						return
					}
					if _, err := peer.WriteToUnix(wire, addr); err != nil {
						t.Error(err)
						return
					}
				}
			}
		})
		t.Cleanup(func() { _ = peer.Close(); workers.Wait() })
		return cmd, stdout, nil
	}
}

func TestLinuxNative(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("synthetic peer uses Unix datagrams and a Unix shell")
	}
	root := t.TempDir()
	tests := map[string]struct {
		run func(*testing.T, *linuxRedirector, <-chan *FromProxy)
	}{
		"success: raw packet and intercept envelopes": {run: func(t *testing.T, r *linuxRedirector, messages <-chan *FromProxy) {
			for _, spec := range []string{"curl", ""} {
				if err := r.SetIntercept(t.Context(), spec); err != nil {
					t.Fatal(err)
				}
				msg := <-messages
				want, err := EncodeInterceptSpec(spec, uint32(os.Getpid()))
				if err != nil || !proto.Equal(msg.GetInterceptConf(), want) {
					t.Fatalf("intercept envelope = %v, want %v (%v)", msg, want, err)
				}
			}
			packet := &Packet{Data: []byte("synthetic packet payload")}
			if err := r.WritePacket(t.Context(), packet); err != nil {
				t.Fatal(err)
			}
			if msg := <-messages; !proto.Equal(msg.GetPacket(), packet) {
				t.Fatalf("packet envelope = %v", msg)
			}
			got, err := r.ReadPacket(t.Context())
			if err != nil || !proto.Equal(got.GetTunnelInfo(), &TunnelInfo{Pid: proto.Uint32(123), ProcessName: new("synthetic-redirector")}) || !proto.Equal(&Packet{Data: got.GetData()}, packet) {
				t.Fatalf("owned packet = %v, %v", got, err)
			}
		}},
		"success: maximum packet boundary": {run: func(t *testing.T, r *linuxRedirector, messages <-chan *FromProxy) {
			packet := &Packet{Data: make([]byte, maxNativePacketSize)}
			if err := r.WritePacket(t.Context(), packet); err != nil {
				t.Fatal(err)
			}
			if msg := <-messages; !proto.Equal(msg.GetPacket(), packet) {
				t.Fatal("maximum packet envelope changed")
			}
			got, err := r.ReadPacket(t.Context())
			if err != nil || len(got.GetData()) != maxNativePacketSize {
				t.Fatalf("maximum received packet = %d, %v", len(got.GetData()), err)
			}
			if err := r.WritePacket(t.Context(), &Packet{Data: make([]byte, maxNativePacketSize+1)}); !errors.Is(err, errNativeMessageTooLarge) {
				t.Fatalf("packet overflow = %v", err)
			}
		}},
		"error: Linux rule table preserves own PID": {run: func(t *testing.T, r *linuxRedirector, messages <-chan *FromProxy) {
			if err := r.SetIntercept(t.Context(), strings.Repeat("curl,", 19)+"curl"); err == nil {
				t.Fatal("twenty caller rules would truncate self-exclusion")
			}
			if err := r.SetIntercept(t.Context(), strings.Repeat("curl,", 18)+"curl"); err != nil {
				t.Fatal(err)
			}
			msg := <-messages
			if got := msg.GetInterceptConf().GetActions(); len(got) != 20 || got[19] != fmt.Sprintf("!%d", os.Getpid()) {
				t.Fatalf("native rules = %v", got)
			}
		}},
		"error: canceled packet read does not stop daemon": {run: func(t *testing.T, r *linuxRedirector, _ <-chan *FromProxy) {
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			if _, err := r.ReadPacket(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("canceled packet read = %v", err)
			}
			if err := r.Launch(t.Context()); err != nil {
				t.Fatalf("packet-call cancellation stopped daemon: %v", err)
			}
		}},
		"success: final close wakes packet readers": {run: func(t *testing.T, r *linuxRedirector, _ <-chan *FromProxy) {
			result := make(chan error, 1)
			go func() {
				_, err := r.ReadPacket(t.Context())
				result <- err
			}()
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			if err := <-result; !errors.Is(err, net.ErrClosed) {
				t.Fatalf("pending reader after final shutdown = %v", err)
			}
		}},
		"success: concurrent final shutdown": {run: func(t *testing.T, r *linuxRedirector, _ <-chan *FromProxy) {
			var group sync.WaitGroup
			for range 8 {
				group.Go(func() {
					if err := r.Close(); err != nil {
						t.Error(err)
					}
				})
			}
			group.Wait()
			if err := r.WritePacket(t.Context(), &Packet{Data: []byte("late")}); !errors.Is(err, net.ErrClosed) {
				t.Fatalf("write after final Close = %v", err)
			}
		}},
	}
	index := 0
	for name, test := range tests {
		index++
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(root, fmt.Sprint(index))
			path := syntheticMacOSStarter(t, dir, false)
			r := NewLinuxRedirector(dir, path).(*linuxRedirector)
			r.hostOS = "linux"
			r.runtimeParent = dir
			messages := make(chan *FromProxy, 16)
			shutdown := make(chan struct{}, 1)
			r.start = syntheticLinuxLauncher(t, messages, shutdown)
			t.Cleanup(func() { _ = r.Close() })
			if err := r.Launch(t.Context()); err != nil {
				t.Fatal(err)
			}
			test.run(t, r, messages)
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-shutdown:
			default:
				t.Fatal("native peer did not receive its zero-datagram shutdown signal")
			}
		})
	}
}
