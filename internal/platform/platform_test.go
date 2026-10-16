// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package platform

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/connection"
)

func address(host string, port int) connection.Address {
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	}
	return connection.Address{Host: host, Port: port}
}

func TestOriginalDestinationAddress(t *testing.T) {
	tests := map[string]struct {
		ipv4   bool
		host   string
		port   uint16
		family uint16
		length int
		bad    bool
	}{
		"success: IPv4 network order":        {true, "5.5.5.5", 443, 2, 16, false},
		"success: IPv6 network order":        {false, "2a03:2880:f21f:c5:face:b00c::167", 443, 10, 28, false},
		"success: mapped IPv4 normalization": {false, "::ffff:5.5.5.5", 80, 10, 28, false},
		"error: wrong family":                {true, "5.5.5.5", 80, 10, 16, true},
		"error: short IPv4":                  {true, "5.5.5.5", 80, 2, 8, true},
		"error: long IPv6":                   {false, "::1", 80, 10, 29, true},
		"error: zero port":                   {true, "5.5.5.5", 0, 2, 16, true},
		"error: unspecified":                 {true, "0.0.0.0", 80, 2, 16, true},
		"error: multicast":                   {false, "ff02::1", 80, 10, 28, true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			buf := make([]byte, 32)
			binary.NativeEndian.PutUint16(buf, tt.family)
			binary.BigEndian.PutUint16(buf[2:], tt.port)
			offset := 8
			if tt.ipv4 {
				offset = 4
			}
			copy(buf[offset:], netip.MustParseAddr(tt.host).AsSlice())
			got, err := decodeSockaddr(buf[:tt.length], tt.ipv4)
			if tt.bad {
				if !errors.Is(err, ErrInvalidAddress) {
					t.Fatalf("address=%v error=%v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := address(tt.host, int(tt.port))
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("destination (-want +got):\n%s", diff)
			}
		})
	}
	t.Run("success: native PF address and port layout", func(t *testing.T) {
		tests := map[string]struct {
			layout              pfLayout
			local, peer, result string
			family              byte
		}{
			"Darwin IPv4":   {darwinPFLayout, "127.0.0.1:8080", "192.168.1.111:40000", "5.5.5.5:80", 2},
			"Darwin mapped": {darwinPFLayout, "[::ffff:127.0.0.1]:8080", "[::ffff:192.168.1.111]:40000", "5.5.5.5:80", 2},
			"Darwin IPv6":   {darwinPFLayout, "[::1]:8080", "[2001:db8::1]:40002", "[2001:db8::2]:443", 30},
			"FreeBSD IPv4":  {freebsdPFLayout, "127.0.0.1:8080", "192.168.1.111:40000", "5.5.5.5:80", 2},
			"FreeBSD IPv6":  {freebsdPFLayout, "[::1]:8080", "[2001:db8::1]:40002", "[2001:db8::2]:443", 28},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				local, peer, result := netip.MustParseAddrPort(tt.local), netip.MustParseAddrPort(tt.peer), netip.MustParseAddrPort(tt.result)
				calls := pfCalls{
					family4: 2, family6: tt.family,
					open: func() (int, error) { return 7, nil }, close: func(int) error { return nil },
					ioctl: func(_ int, request uintptr, buf []byte) error {
						if request != tt.layout.ioctl || len(buf) != tt.layout.size || buf[tt.layout.family] != tt.family || buf[tt.layout.protocol] != 6 || buf[tt.layout.direction] != 2 {
							t.Fatalf("bad ioctl request=%x bytes=%x", request, buf)
						}
						if binary.BigEndian.Uint16(buf[tt.layout.sourcePort:]) != peer.Port() || binary.BigEndian.Uint16(buf[tt.layout.destinationPort:]) != local.Port() {
							t.Fatal("input port byte order")
						}
						n := len(peer.Addr().Unmap().AsSlice())
						if diff := cmp.Diff(peer.Addr().Unmap().AsSlice(), buf[tt.layout.source:tt.layout.source+n]); diff != "" {
							t.Fatal(diff)
						}
						if diff := cmp.Diff(local.Addr().Unmap().AsSlice(), buf[tt.layout.destination:tt.layout.destination+n]); diff != "" {
							t.Fatal(diff)
						}
						copy(buf[tt.layout.result:], result.Addr().AsSlice())
						binary.BigEndian.PutUint16(buf[tt.layout.resultPort:], result.Port())
						return nil
					},
				}
				got, err := pfNatLook(t.Context(), local, peer, tt.layout, calls)
				if err != nil {
					t.Fatal(err)
				}
				if diff := cmp.Diff(address(result.Addr().String(), int(result.Port())), got); diff != "" {
					t.Fatal(diff)
				}
			})
		}
	})
	t.Run("success: mapped local address selects IPv4", func(t *testing.T) {
		got, err := tcpAddress(&net.TCPAddr{IP: net.ParseIP("::ffff:127.0.0.1"), Port: 8080})
		if err != nil || !got.Addr().Is4() {
			t.Fatalf("local=%v error=%v", got, err)
		}
	})
	t.Run("success: IPv6 flow and scope", func(t *testing.T) {
		buf := make([]byte, 28)
		binary.NativeEndian.PutUint16(buf, 10)
		binary.BigEndian.PutUint16(buf[2:], 443)
		binary.BigEndian.PutUint32(buf[4:], 123)
		copy(buf[8:], netip.MustParseAddr("fe80::1").AsSlice())
		binary.NativeEndian.PutUint32(buf[24:], 7)
		got, err := decodeSockaddr(buf, false)
		if err != nil || got.Scope == nil || got.Scope.FlowInfo != 123 || got.Scope.ScopeID != 7 {
			t.Fatalf("scope=%+v err=%v", got.Scope, err)
		}
	})
}

func TestPFStateLookup(t *testing.T) {
	pf01, err := os.ReadFile("testdata/pf01")
	if err != nil {
		t.Fatal(err)
	}
	pf02, err := os.ReadFile("testdata/pf02")
	if err != nil {
		t.Fatal(err)
	}
	const peer = "192.168.1.111:40000"
	tests := map[string]struct {
		output []byte
		peer   string
		host   string
		port   int
		cause  error
	}{
		"success: Darwin IPv4":                  {pf01, peer, "5.5.5.5", 80, nil},
		"success: mapped IPv4":                  {pf01, "[::ffff:192.168.1.111]:40000", "5.5.5.5", 80, nil},
		"success: established IPv6":             {pf01, "[2a01:e35:8bae:50f0:396f:e6c7:f4f1:f3db]:40002", "2a03:2880:f21f:c5:face:b00c::167", 443, nil},
		"success: FreeBSD parentheses":          {pf02, peer, "5.5.5.5", 80, nil},
		"error: FIN_WAIT IPv4":                  {pf01, "192.168.1.111:40001", "", 0, ErrNotFound},
		"error: FIN_WAIT IPv6":                  {pf01, "[2a01:e35:8bae:50f0:396f:e6c7:f4f1:f3db]:40003", "", 0, ErrNotFound},
		"error: wrong client":                   {pf01, "192.168.1.11:40000", "", 0, ErrNotFound},
		"error: wrong port":                     {pf01, "192.168.1.111:4000", "", 0, ErrNotFound},
		"error: substring peer":                 {[]byte("ALL tcp 1192.168.1.111:40000 -> 5.5.5.5:80 ESTABLISHED:ESTABLISHED\n"), peer, "", 0, ErrPFOutput},
		"error: truncated":                      {pf01[:len(pf01)-1], peer, "", 0, ErrPFOutput},
		"error: oversized":                      {[]byte(strings.Repeat("\n", pfOutputLimit+1)), peer, "", 0, ErrPFOutput},
		"error: malformed matched destination":  {[]byte("ALL tcp 192.168.1.111:40000 -> bad:80 ESTABLISHED:ESTABLISHED\n"), peer, "", 0, ErrPFOutput},
		"error: malformed tail after valid row": {append(append([]byte(nil), pf01...), []byte("incomplete state\n")...), peer, "", 0, ErrPFOutput},
		"error: ambiguous":                      {[]byte("ALL tcp 192.168.1.111:40000 -> 5.5.5.5:80 ESTABLISHED:ESTABLISHED\nALL tcp 192.168.1.111:40000 -> 5.5.5.6:80 ESTABLISHED:ESTABLISHED\n"), peer, "", 0, ErrPFOutput},
		"error: zero destination port":          {[]byte("ALL tcp 192.168.1.111:40000 -> 5.5.5.5:0 ESTABLISHED:ESTABLISHED\n"), peer, "", 0, ErrPFOutput},
		"error: empty table":                    {nil, peer, "", 0, ErrNotFound},
		"error: invalid UTF8":                   {[]byte{255, '\n'}, peer, "", 0, ErrPFOutput},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := pfStateLookup(netip.MustParseAddrPort(tt.peer), tt.output)
			if tt.cause != nil {
				if !errors.Is(err, tt.cause) {
					t.Fatalf("destination=%v error=%v want=%v", got, err, tt.cause)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff(address(tt.host, tt.port), got); diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestOriginalDestinationFailures(t *testing.T) {
	tests := map[string]struct {
		os    string
		cause error
	}{
		"success: linux": {"linux", nil}, "success: darwin": {"darwin", nil}, "success: freebsd": {"freebsd", nil}, "success: openbsd": {"openbsd", nil},
		"error: windows": {"windows", ErrWindowsRefusal}, "error: unsupported": {"plan9", ErrUnsupported},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkOS(tt.os)
			if !errors.Is(err, tt.cause) {
				t.Fatalf("error=%v want=%v", err, tt.cause)
			}
			if tt.os == "windows" && (err.Error() != windowsRefusal || !errors.Is(err, ErrUnsupported)) {
				t.Fatalf("Windows refusal=%v", err)
			}
		})
	}
	t.Run("error: cancelled availability and lookup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if err := CheckTransparent(ctx); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if _, err := OriginalAddr(ctx, nil); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	})
	t.Run("error: bounded output cancels", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		out := boundedPFOutput{cancel: cancel}
		if _, err := out.Write(make([]byte, pfOutputLimit)); err != nil {
			t.Fatal(err)
		}
		if _, err := out.Write([]byte{1}); !errors.Is(err, ErrPFOutput) || !out.full || ctx.Err() == nil {
			t.Fatalf("error=%v full=%v context=%v", err, out.full, ctx.Err())
		}
	})
	t.Run("error: native resources closed once", func(t *testing.T) {
		tests := map[string]struct{ openErr, ioctlErr, closeErr error }{
			"open refusal": {ErrPrivileges, nil, nil}, "ioctl refusal": {nil, ErrNotFound, nil}, "close refusal": {nil, nil, net.ErrClosed}, "success": {},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				opened, closed := 0, 0
				calls := pfCalls{
					family4: 2, family6: 30,
					open: func() (int, error) { opened++; return 7, tt.openErr },
					close: func(fd int) error {
						if fd != 7 {
							t.Errorf("close fd=%d", fd)
						}
						closed++
						return tt.closeErr
					},
					ioctl: func(fd int, request uintptr, buf []byte) error {
						if fd != 7 || request != 0xc0544417 || len(buf) != 84 {
							t.Errorf("native request fd=%d request=%x size=%d", fd, request, len(buf))
						}
						copy(buf[48:], netip.MustParseAddr("5.5.5.5").AsSlice())
						binary.BigEndian.PutUint16(buf[76:], 80)
						return tt.ioctlErr
					},
				}
				got, err := pfNatLook(t.Context(), netip.MustParseAddrPort("127.0.0.1:8080"), netip.MustParseAddrPort("192.168.1.111:40000"), darwinPFLayout, calls)
				wantErr := errors.Join(tt.openErr, tt.ioctlErr, tt.closeErr)
				if wantErr == nil {
					if err != nil || got.Host != "5.5.5.5" {
						t.Fatalf("got=%v err=%v", got, err)
					}
				} else if err == nil {
					t.Fatal("expected native failure")
				}
				wantClosed := 1
				if tt.openErr != nil {
					wantClosed = 0
				}
				if opened != 1 || closed != wantClosed {
					t.Fatalf("opens=%d closes=%d want=%d", opened, closed, wantClosed)
				}
			})
		}
	})
}

func TestOriginalDestinationPFSelfCheck(t *testing.T) {
	t.Run("post-validation fallback binds accepted local", func(t *testing.T) {
		tests := map[string]struct {
			local, peer, output, host string
			port                      int
			cause                     error
		}{
			"success: Darwin matching redirect": {
				"127.0.0.1:8080", "192.168.1.111:40000", "ALL tcp 127.0.0.1:8080 <- 5.5.5.5:80 <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\n", "5.5.5.5", 80, nil,
			},
			"error: mismatching redirected port": {
				"127.0.0.1:8080", "192.168.1.111:40000", "ALL tcp 127.0.0.1:8081 <- 5.5.5.5:80 <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\n", "", 0, ErrNotFound,
			},
			"error: mismatching redirected address": {
				"127.0.0.1:8080", "192.168.1.111:40000", "ALL tcp 127.0.0.2:8080 <- 5.5.5.5:80 <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\n", "", 0, ErrNotFound,
			},
			"error: peer-only forward row": {
				"127.0.0.1:8080", "192.168.1.111:40000", "ALL tcp 192.168.1.111:40000 -> 5.5.5.5:80 ESTABLISHED:ESTABLISHED\n", "", 0, ErrNotFound,
			},
			"success: FreeBSD matching redirect": {
				"127.0.0.1:8080", "192.168.1.111:40000", "all tcp 127.0.0.1:8080 (5.5.5.5:80) <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\n", "5.5.5.5", 80, nil,
			},
			"error: FreeBSD mismatching redirect": {
				"127.0.0.1:8080", "192.168.1.111:40000", "all tcp 127.0.0.1:8081 (5.5.5.5:80) <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\n", "", 0, ErrNotFound,
			},
			"success: mapped accepted endpoints": {
				"[::ffff:127.0.0.1]:8080", "[::ffff:192.168.1.111]:40000", "ALL tcp 127.0.0.1:8080 <- 5.5.5.5:80 <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\n", "5.5.5.5", 80, nil,
			},
			"success: equivalent IPv6 notation": {
				"[0:0:0:0:0:0:0:1]:8080", "[2001:db8::1]:40002", "ALL tcp ::1[8080] <- 2001:db8::2[443] <- 2001:db8::1[40002] ESTABLISHED:ESTABLISHED\n", "2001:db8::2", 443, nil,
			},
			"success: ignore colliding other listener": {
				"127.0.0.1:8080", "192.168.1.111:40000", "ALL tcp 127.0.0.1:8081 <- 5.5.5.6:80 <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\nALL tcp 127.0.0.1:8080 <- 5.5.5.5:80 <- 192.168.1.111:40000 ESTABLISHED:ESTABLISHED\n", "5.5.5.5", 80, nil,
			},
			"error: matching listener with wrong peer": {
				"127.0.0.1:8080", "192.168.1.111:40000", "ALL tcp 127.0.0.1:8080 <- 5.5.5.5:80 <- 192.168.1.112:40000 ESTABLISHED:ESTABLISHED\n", "", 0, ErrNotFound,
			},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				nativeCalls, textCalls := 0, 0
				r := pfResolver{
					validated: true,
					native: func(context.Context, netip.AddrPort, netip.AddrPort) (connection.Address, error) {
						nativeCalls++
						return connection.Address{}, net.ErrClosed
					},
					text: func(context.Context) ([]byte, error) {
						textCalls++
						return []byte(tt.output), nil
					},
				}
				// Exercise both the transition from native lookup and the next text-only lookup.
				for range 2 {
					got, err := r.lookup(t.Context(), netip.MustParseAddrPort(tt.local), netip.MustParseAddrPort(tt.peer))
					if !errors.Is(err, tt.cause) {
						t.Fatalf("lookup=%v error=%v want=%v", got, err, tt.cause)
					}
					want := connection.Address{}
					if tt.cause == nil {
						want = address(tt.host, tt.port)
					}
					if diff := cmp.Diff(want, got); diff != "" {
						t.Fatalf("fallback destination (-want +got):\n%s", diff)
					}
				}
				if !r.disabled || r.validated || nativeCalls != 1 || textCalls != 2 {
					t.Fatalf("fallback state disabled=%v validated=%v native=%d text=%d", r.disabled, r.validated, nativeCalls, textCalls)
				}
			})
		}
	})
	t.Run("success: generated ABI sizes and offsets", func(t *testing.T) {
		tests := map[string]struct{ got, want pfLayout }{
			"Darwin":  {darwinPFLayout, pfLayout{size: 84, alignment: 4, ioctl: 0xc0544417, source: 0, destination: 16, result: 48, sourcePort: 64, destinationPort: 68, resultPort: 76, family: 80, protocol: 81, direction: 83}},
			"FreeBSD": {freebsdPFLayout, pfLayout{size: 76, alignment: 4, ioctl: 0xc04c4417, source: 0, destination: 16, result: 48, sourcePort: 64, destinationPort: 66, resultPort: 70, family: 72, protocol: 73, direction: 74}},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				if tt.got != tt.want {
					t.Fatalf("layout=%+v want=%+v", tt.got, tt.want)
				}
			})
		}
	})
	local, peer := netip.MustParseAddrPort("127.0.0.1:8080"), netip.MustParseAddrPort("192.168.1.111:40000")
	text := []byte("ALL tcp 192.168.1.111:40000 -> 5.5.5.5:80 ESTABLISHED:ESTABLISHED\n")
	tests := map[string]struct {
		nativeHost         string
		nativeErr, textErr error
		output             []byte
		validated          bool
		cause              error
	}{
		"success: exact match":                 {"5.5.5.5", nil, nil, text, true, nil},
		"success: mismatch disables native":    {"5.5.5.6", nil, nil, text, false, nil},
		"success: refusal uses text":           {"", ErrPrivileges, nil, text, false, nil},
		"error: absent text does not validate": {"5.5.5.5", nil, nil, nil, false, ErrNotFound},
		"error: text privileges":               {"5.5.5.5", nil, ErrPrivileges, nil, false, ErrPrivileges},
		"error: text malformed":                {"5.5.5.5", nil, nil, []byte("truncated"), false, ErrPFOutput},
		"error: native invalid uses text":      {"0.0.0.0", nil, nil, text, false, nil},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			nativeCalls, textCalls := 0, 0
			r := pfResolver{
				native: func(context.Context, netip.AddrPort, netip.AddrPort) (connection.Address, error) {
					nativeCalls++
					return address(tt.nativeHost, 80), tt.nativeErr
				},
				text: func(context.Context) ([]byte, error) { textCalls++; return tt.output, tt.textErr },
			}
			for range 2 {
				got, err := r.lookup(t.Context(), local, peer)
				if !errors.Is(err, tt.cause) {
					t.Fatalf("lookup=%v error=%v want=%v", got, err, tt.cause)
				}
				if err == nil && got.Host != "5.5.5.5" {
					t.Fatalf("got wrong destination %v", got)
				}
			}
			if r.validated != tt.validated || r.disabled == tt.validated {
				t.Fatalf("validated=%v disabled=%v", r.validated, r.disabled)
			}
			if tt.validated {
				if nativeCalls != 2 || textCalls != 1 {
					t.Fatalf("native=%d text=%d", nativeCalls, textCalls)
				}
			} else if nativeCalls != 1 || textCalls != 2 {
				t.Fatalf("disabled calls native=%d text=%d", nativeCalls, textCalls)
			}
		})
	}
	t.Run("success: concurrent first use and cancelled waiter", func(t *testing.T) {
		started, release := make(chan struct{}), make(chan struct{})
		var nativeCalls, textCalls atomic.Int32
		r := pfResolver{
			native: func(ctx context.Context, _, _ netip.AddrPort) (connection.Address, error) {
				if nativeCalls.Add(1) == 1 {
					close(started)
					select {
					case <-release:
					case <-ctx.Done():
						return connection.Address{}, ctx.Err()
					}
				}
				return address("5.5.5.5", 80), nil
			},
			text: func(context.Context) ([]byte, error) { textCalls.Add(1); return text, nil },
		}
		var wg sync.WaitGroup
		errs := make(chan error, 17)
		wg.Go(func() { _, err := r.lookup(t.Context(), local, peer); errs <- err })
		<-started
		ctx, cancel := context.WithCancel(t.Context())
		waiter := make(chan error, 1)
		wg.Go(func() { _, err := r.lookup(ctx, local, peer); waiter <- err })
		cancel()
		if err := <-waiter; !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		for range 16 {
			wg.Go(func() { _, err := r.lookup(t.Context(), local, peer); errs <- err })
		}
		close(release)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Error(err)
			}
		}
		if nativeCalls.Load() != 17 || textCalls.Load() != 1 {
			t.Fatalf("native=%d text=%d", nativeCalls.Load(), textCalls.Load())
		}
	})
	t.Run("success: cancelled checker joins and can retry", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		r := pfResolver{
			native: func(context.Context, netip.AddrPort, netip.AddrPort) (connection.Address, error) {
				cancel()
				return connection.Address{}, context.Canceled
			},
			text: func(ctx context.Context) ([]byte, error) { return nil, ctx.Err() },
		}
		if _, err := r.lookup(ctx, local, peer); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
		if r.checking != nil || r.validated || r.disabled {
			t.Fatal("cancelled checker left resolver held or certified")
		}
	})
}
