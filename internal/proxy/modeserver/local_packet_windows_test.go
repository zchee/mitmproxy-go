// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build windows

package modeserver

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/tcpip/header"

	"github.com/zchee/mitmproxy-go/addons/nextlayer"
	"github.com/zchee/mitmproxy-go/internal/local"
	"github.com/zchee/mitmproxy-go/options"
)

type localTestPipe struct {
	handle windows.Handle
	mu     sync.Mutex
	active sync.WaitGroup
	closed bool
}

func (p *localTestPipe) operation(ctx context.Context, start func(*windows.Overlapped, *uint32) error) (uint32, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	event, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = windows.CloseHandle(event) }()
	overlapped := &windows.Overlapped{HEvent: event}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, net.ErrClosed
	}
	p.active.Add(1)
	defer p.active.Done()
	var count uint32
	err = start(overlapped, &count)
	p.mu.Unlock()
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = windows.CancelIoEx(p.handle, overlapped); close(finished) })
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		err = windows.GetOverlappedResult(p.handle, overlapped, &count, true)
	}
	if !stop() {
		<-finished
	}
	runtime.KeepAlive(overlapped)
	if ctx.Err() != nil {
		return count, ctx.Err()
	}
	return count, err
}

func (p *localTestPipe) read(ctx context.Context, data []byte) (int, error) {
	n, err := p.operation(ctx, func(o *windows.Overlapped, n *uint32) error { return windows.ReadFile(p.handle, data, n, o) })
	runtime.KeepAlive(data)
	return int(n), err
}

func (p *localTestPipe) write(ctx context.Context, data []byte) error {
	_, err := p.operation(ctx, func(o *windows.Overlapped, n *uint32) error { return windows.WriteFile(p.handle, data, n, o) })
	runtime.KeepAlive(data)
	return err
}

func (p *localTestPipe) close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	_ = windows.CancelIoEx(p.handle, nil)
	p.mu.Unlock()
	p.active.Wait()
	return windows.CloseHandle(p.handle)
}

// Real message-mode named pipes exercise the shared packet pump without an
// elevation prompt. Native constructor/UAC ownership is tested by package local.
type localWindowsPipeRedirector struct {
	server, client *localTestPipe
	ctx            context.Context
	cancel         context.CancelFunc
	once           sync.Once
}

func (r *localWindowsPipeRedirector) Launch(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (r *localWindowsPipeRedirector) SetIntercept(ctx context.Context, spec string) error {
	conf, err := local.EncodeInterceptSpec(spec, uint32(os.Getpid()))
	if err != nil {
		return err
	}
	data, err := proto.Marshal(&local.FromProxy{Message: &local.FromProxy_InterceptConf{InterceptConf: conf}})
	if err != nil {
		return err
	}
	return r.server.write(ctx, data)
}

func (r *localWindowsPipeRedirector) ReadPacket(ctx context.Context) (*local.PacketWithMeta, error) {
	data := make([]byte, 131072)
	n, err := r.server.read(ctx, data)
	if err != nil {
		return nil, err
	}
	packet := new(local.PacketWithMeta)
	if err := proto.Unmarshal(data[:n], packet); err != nil {
		return nil, err
	}
	return packet, nil
}

func (r *localWindowsPipeRedirector) WritePacket(ctx context.Context, packet *local.Packet) error {
	data, err := proto.Marshal(&local.FromProxy{Message: &local.FromProxy_Packet{Packet: packet}})
	if err != nil {
		return err
	}
	return r.server.write(ctx, data)
}

func (r *localWindowsPipeRedirector) Close() error {
	var err error
	r.once.Do(func() { r.cancel(); err = errors.Join(r.server.close(), r.client.close()) })
	return err
}

func localWindowsPipeFixture(t *testing.T) *localWindowsPipeRedirector {
	t.Helper()
	name, err := windows.UTF16PtrFromString(`\\.\pipe\local-mode-test-` + strconv.Itoa(os.Getpid()) + "-" + strconv.FormatInt(time.Now().UnixNano(), 10))
	if err != nil {
		t.Fatal(err)
	}
	server, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE, windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 131072, 131072, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		_ = windows.CloseHandle(server)
		t.Fatal(err)
	}
	mode := uint32(windows.PIPE_READMODE_MESSAGE)
	if err := windows.SetNamedPipeHandleState(client, &mode, nil, nil); err != nil {
		_ = windows.CloseHandle(server)
		_ = windows.CloseHandle(client)
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	r := &localWindowsPipeRedirector{server: &localTestPipe{handle: server}, client: &localTestPipe{handle: client}, ctx: ctx, cancel: cancel}
	t.Cleanup(func() { _ = r.Close() })
	_, err = r.server.operation(ctx, func(o *windows.Overlapped, _ *uint32) error {
		err := windows.ConnectNamedPipe(server, o)
		if errors.Is(err, windows.ERROR_PIPE_CONNECTED) {
			return nil
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestLocalWindowsPacketIPCTCPNoElevation(t *testing.T) {
	tests := map[string]struct{ network, host, source string }{
		"IPv4 real named-pipe TCP without elevation": {"tcp4", "127.0.0.1", "10.0.0.1:4242"},
		"IPv6 real named-pipe TCP without elevation": {"tcp6", "::1", "[fd00::1]:4242"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := localWindowsPipeFixture(t)
			device := tuntest.NewChannelTUN()
			ctx, cancel := context.WithCancel(t.Context())
			var workers sync.WaitGroup
			t.Cleanup(func() { cancel(); _ = r.Close(); workers.Wait() })
			workers.Go(func() {
				data := make([]byte, 131072)
				for {
					n, err := r.client.read(ctx, data)
					if err != nil {
						if ctx.Err() == nil {
							t.Error(err)
						}
						return
					}
					var message local.FromProxy
					if err := proto.Unmarshal(data[:n], &message); err != nil {
						t.Error(err)
						return
					}
					if packet := message.GetPacket(); packet != nil {
						select {
						case device.Inbound <- packet.Data:
						case <-ctx.Done():
							return
						}
					}
				}
			})
			workers.Go(func() {
				for {
					select {
					case packet := <-device.Outbound:
						wire, err := proto.Marshal(&local.PacketWithMeta{Data: packet, TunnelInfo: &local.TunnelInfo{Pid: new(uint32(42)), ProcessName: new("curl")}})
						if err != nil {
							t.Error(err)
							return
						}
						if err := r.client.write(ctx, wire); err != nil {
							if ctx.Err() == nil {
								t.Error(err)
							}
							return
						}
					case <-ctx.Done():
						return
					}
				}
			})
			cfg, m, _ := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "When to establish origin connections."); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			instance := localIPCMode(t, cfg, r, "local")
			t.Cleanup(func() { _ = instance.Stop() })
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			origin, err := net.Listen(tt.network, net.JoinHostPort(tt.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = origin.Close() })
			if err := origin.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			peer := tunTCPPeer(t, instance, device, netip.MustParseAddrPort(tt.source), origin.Addr().(*net.TCPAddr).AddrPort())
			if _, err := io.WriteString(peer, "windows-pipe-tcp"); err != nil {
				t.Fatal(err)
			}
			conn, err := origin.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			data := make([]byte, len("windows-pipe-tcp"))
			if _, err := io.ReadFull(conn, data); err != nil || string(data) != "windows-pipe-tcp" {
				t.Fatalf("origin TCP = %q, %v", data, err)
			}
			if _, err := conn.Write(data); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(peer, data); err != nil || string(data) != "windows-pipe-tcp" {
				t.Fatalf("pipe TCP = %q, %v", data, err)
			}
		})
	}
}

func TestLocalWindowsPacketIPCNoElevation(t *testing.T) {
	tests := map[string]struct{ network, host, source string }{
		"IPv4 real named-pipe UDP without elevation": {"udp4", "127.0.0.1", "10.0.0.1:4242"},
		"IPv6 real named-pipe UDP without elevation": {"udp6", "::1", "[fd00::1]:4242"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r := localWindowsPipeFixture(t)
			origin, err := net.ListenPacket(tt.network, net.JoinHostPort(tt.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = origin.Close() }()
			if err := origin.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
				t.Fatal(err)
			}
			packet := tunUDPTestPacket(netip.MustParseAddrPort(tt.source), origin.LocalAddr().(*net.UDPAddr).AddrPort(), []byte("windows-pipe-ipc"))
			done := make(chan error, 1)
			go func() {
				data := make([]byte, 131072)
				n, err := r.client.read(r.ctx, data)
				if err != nil {
					done <- err
					return
				}
				var conf local.FromProxy
				if err = proto.Unmarshal(data[:n], &conf); err != nil || conf.GetInterceptConf() == nil {
					done <- errors.Join(err, errors.New("missing intercept configuration"))
					return
				}
				wire, err := proto.Marshal(&local.PacketWithMeta{Data: packet, TunnelInfo: &local.TunnelInfo{Pid: new(uint32(42)), ProcessName: new("curl")}})
				if err != nil {
					done <- err
					return
				}
				if err = r.client.write(r.ctx, wire); err != nil {
					done <- err
					return
				}
				n, err = r.client.read(r.ctx, data)
				if err != nil {
					done <- err
					return
				}
				var reply local.FromProxy
				if err = proto.Unmarshal(data[:n], &reply); err != nil || reply.GetPacket() == nil {
					done <- errors.Join(err, errors.New("missing packet reply"))
					return
				}
				raw := reply.GetPacket().Data
				var payload []byte
				if tt.network == "udp4" {
					payload = header.IPv4(raw).Payload()
				} else {
					payload = header.IPv6(raw).Payload()
				}
				if string(header.UDP(payload).Payload()) != "windows-pipe-ipc" {
					done <- errors.New("named-pipe reply payload mismatch")
					return
				}
				done <- nil
				// Keep the real pipe drained through the frontend's disable message.
				for {
					if _, err := r.client.read(r.ctx, data); err != nil {
						return
					}
				}
			}()
			cfg, m, _ := fixture(t)
			if err := m.Options.Add(t.Context(), "connection_strategy", options.TypeStr, "lazy", "When to establish origin connections."); err != nil {
				t.Fatal(err)
			}
			if err := m.Addons.Add(t.Context(), nextlayer.New(m.Options)); err != nil {
				t.Fatal(err)
			}
			instance := localIPCMode(t, cfg, r, "local")
			t.Cleanup(func() { _ = instance.Stop() })
			if err := instance.Start(t.Context()); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 64)
			n, client, err := origin.ReadFrom(buf)
			if err != nil || string(buf[:n]) != "windows-pipe-ipc" {
				t.Fatalf("origin=%q,%v", buf[:n], err)
			}
			if _, err := origin.WriteTo(buf[:n], client); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("Windows IPC reply hang detector")
			}
		})
	}
}
