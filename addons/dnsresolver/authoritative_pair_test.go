// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dnsresolver

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"syscall"
	"testing"
	"time"
)

const authoritativeBindAttempts = 64

func listenAuthoritativePair(listenTCP func() (net.Listener, error), listenUDP func(*net.UDPAddr) (*net.UDPConn, error)) (net.Listener, *net.UDPConn, error) {
	var rejected []net.Listener
	defer func() {
		for _, listener := range rejected {
			_ = listener.Close()
		}
	}()
	var lastErr error
	for range authoritativeBindAttempts {
		tcp, err := listenTCP()
		if err != nil {
			return nil, nil, err
		}
		udp, err := listenUDP(net.UDPAddrFromAddrPort(tcp.Addr().(*net.TCPAddr).AddrPort()))
		if err == nil {
			return tcp, udp, nil
		}
		// Retain rejected TCP ports so the allocator cannot recycle a
		// candidate that the UDP bind already refused.
		rejected = append(rejected, tcp)
		if !retryAuthoritativeUDPBind(err) {
			return nil, nil, err
		}
		lastErr = err
	}
	return nil, nil, fmt.Errorf("DNS fixture shared bind exhausted %d candidates: %w", authoritativeBindAttempts, lastErr)
}

func retryAuthoritativeUDPBind(err error) bool {
	const (
		wsaAddrInUse = syscall.Errno(10048)
		wsaAccess    = syscall.Errno(10013)
	)
	return errors.Is(err, syscall.EADDRINUSE) || runtime.GOOS == "windows" && (errors.Is(err, wsaAddrInUse) || errors.Is(err, wsaAccess))
}

func TestAuthoritativePairRetry(t *testing.T) {
	fatal := errors.New("UDP acquisition failed")
	tests := map[string]struct {
		rejects  int
		forced   error
		wantErr  bool
		minCalls int
		maxCalls int
	}{
		"success: same port":                {minCalls: 1, maxCalls: authoritativeBindAttempts},
		"success: real UDP collision":       {rejects: 1, minCalls: 2, maxCalls: authoritativeBindAttempts},
		"error: collision budget exhausted": {rejects: authoritativeBindAttempts, wantErr: true, minCalls: authoritativeBindAttempts, maxCalls: authoritativeBindAttempts},
		"error: other UDP error fails fast": {rejects: 1, forced: fatal, wantErr: true, minCalls: 1, maxCalls: 1},
	}
	if runtime.GOOS == "windows" {
		excluded := tests["success: real UDP collision"]
		excluded.forced = syscall.Errno(10013)
		tests["success: Windows UDP exclusion"] = excluded
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var listeners []*net.TCPListener
			t.Cleanup(func() {
				for _, listener := range listeners {
					_ = listener.Close()
				}
			})
			calls := 0
			tcp, udp, err := listenAuthoritativePair(func() (net.Listener, error) {
				listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				if err == nil {
					listeners = append(listeners, listener)
				}
				return listener, err
			}, func(address *net.UDPAddr) (*net.UDPConn, error) {
				calls++
				if calls <= tt.rejects {
					if tt.forced != nil {
						return nil, &net.OpError{Op: "listen", Net: "udp4", Addr: address, Err: tt.forced}
					}
					blocker, err := net.ListenUDP("udp4", address)
					if err != nil {
						return nil, err
					}
					t.Cleanup(func() { _ = blocker.Close() })
				}
				return net.ListenUDP("udp4", address)
			})
			if tcp != nil {
				t.Cleanup(func() { _ = tcp.Close() })
			}
			if udp != nil {
				t.Cleanup(func() { _ = udp.Close() })
			}
			if calls < tt.minCalls || calls > tt.maxCalls {
				t.Errorf("UDP candidates = %d, want within [%d,%d]", calls, tt.minCalls, tt.maxCalls)
			}
			if tt.wantErr {
				if err == nil || tcp != nil || udp != nil {
					t.Errorf("failed acquisition = (%v, %v, %v)", tcp, udp, err)
				}
				if tt.forced != nil && !errors.Is(err, tt.forced) {
					t.Errorf("acquisition lost error: %v", err)
				} else if tt.forced == nil && !retryAuthoritativeUDPBind(err) {
					t.Errorf("exhaustion lost bind error: %v", err)
				}
			} else if err != nil || tcp == nil || udp == nil {
				t.Errorf("successful acquisition = (%v, %v, %v)", tcp, udp, err)
			} else if tcp.Addr().(*net.TCPAddr).Port != udp.LocalAddr().(*net.UDPAddr).Port {
				t.Error("TCP and UDP selected different ports")
			}
			for _, listener := range listeners {
				if listener == tcp {
					continue
				}
				if err := listener.SetDeadline(time.Time{}); !errors.Is(err, net.ErrClosed) {
					t.Errorf("rejected TCP candidate was not closed: %v", err)
				}
			}
		})
	}
}
