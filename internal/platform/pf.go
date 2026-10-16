// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/connection"
)

const (
	pfOutputLimit    = 4 << 20
	pfCommandTimeout = 5 * time.Second
)

func pfEndpoint(s string) (netip.AddrPort, error) {
	s = strings.Trim(s, "()")
	var host, port string
	if h, p, found := strings.CutLast(s, "["); found && strings.HasSuffix(p, "]") {
		host, port = h, strings.TrimSuffix(p, "]")
	} else {
		host, port, _ = strings.CutLast(s, ":")
		if strings.Contains(host, ":") {
			return netip.AddrPort{}, ErrPFOutput
		}
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return netip.AddrPort{}, ErrPFOutput
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || ip.IsUnspecified() || ip.IsMulticast() {
		return netip.AddrPort{}, ErrPFOutput
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)), nil
}

func pfStateLookup(peer netip.AddrPort, output []byte) (connection.Address, error) {
	if len(output) > pfOutputLimit || !utf8.Valid(output) {
		return connection.Address{}, ErrPFOutput
	}
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	var found netip.AddrPort
	for line := range strings.SplitSeq(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if line == "No ALTQ support in kernel" || line == "ALTQ related functions disabled" {
			continue
		}
		if len(fields) < 3 || (fields[0] != "ALL" && fields[0] != "all") {
			return connection.Address{}, ErrPFOutput
		}
		if fields[1] != "tcp" {
			continue
		}
		states := []string{"CLOSED", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "CLOSE_WAIT", "FIN_WAIT_1", "CLOSING", "LAST_ACK", "FIN_WAIT_2", "TIME_WAIT"}
		left, right, complete := strings.Cut(fields[len(fields)-1], ":")
		if !complete || !slices.Contains(states, left) || !slices.Contains(states, right) {
			return connection.Address{}, ErrPFOutput
		}
		var client, destination string
		switch {
		case len(fields) == 6 && fields[3] == "->":
			client, destination = fields[2], fields[4]
		case len(fields) == 8 && fields[3] == "<-" && fields[5] == "<-":
			client, destination = fields[6], fields[4]
		case len(fields) == 7 && strings.HasPrefix(fields[3], "(") && strings.HasSuffix(fields[3], ")") && fields[4] == "<-":
			client, destination = fields[5], fields[3]
		default:
			return connection.Address{}, ErrPFOutput
		}
		// Validate every endpoint, not just the candidate client, before accepting a row.
		if _, err := pfEndpoint(fields[2]); err != nil {
			return connection.Address{}, err
		}
		c, err := pfEndpoint(client)
		if err != nil {
			return connection.Address{}, err
		}
		d, err := pfEndpoint(destination)
		if err != nil {
			return connection.Address{}, err
		}
		if left != "ESTABLISHED" || right != "ESTABLISHED" || c != peer {
			continue
		}
		if found.IsValid() && found != d {
			return connection.Address{}, fmt.Errorf("ambiguous peer state: %w", ErrPFOutput)
		}
		found = d
	}
	if !found.IsValid() {
		return connection.Address{}, ErrNotFound
	}
	return connection.Address{Host: found.Addr().String(), Port: int(found.Port())}, nil
}

// boundedPFOutput is used for both stdout and stderr by exec, which serializes writes
// to a shared writer. An overrun kills the command through cancellation, then Wait joins it.
type boundedPFOutput struct {
	bytes.Buffer
	cancel context.CancelFunc
	full   bool
}

func (b *boundedPFOutput) Write(p []byte) (int, error) {
	if len(p) > pfOutputLimit-b.Len() {
		b.full = true
		b.cancel()
		return 0, ErrPFOutput
	}
	return b.Buffer.Write(p)
}

func readPFState(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, pfCommandTimeout)
	defer cancel()
	out := &boundedPFOutput{cancel: cancel}
	cmd := exec.CommandContext(ctx, "sudo", "-n", "/sbin/pfctl", "-s", "state")
	cmd.WaitDelay = time.Second
	cmd.Stdout, cmd.Stderr = out, out
	err := cmd.Run()
	if out.full {
		return nil, ErrPFOutput
	}
	if bytes.Contains(out.Bytes(), []byte("sudo: a password is required")) {
		return nil, ErrPrivileges
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("Error getting pfctl state: %w", err)
	}
	return out.Bytes(), nil
}

type pfResolver struct {
	mu        sync.Mutex
	checking  chan struct{}
	validated bool
	disabled  bool
	native    func(context.Context, netip.AddrPort, netip.AddrPort) (connection.Address, error)
	text      func(context.Context) ([]byte, error)
}

func (r *pfResolver) lookup(ctx context.Context, local, peer netip.AddrPort) (connection.Address, error) {
	for {
		if err := ctx.Err(); err != nil {
			return connection.Address{}, err
		}
		r.mu.Lock()
		if wait := r.checking; wait != nil {
			r.mu.Unlock()
			select {
			case <-ctx.Done():
				return connection.Address{}, ctx.Err()
			case <-wait:
			}
			continue
		}
		validated, disabled := r.validated, r.disabled
		if !validated && !disabled {
			r.checking = make(chan struct{})
		}
		r.mu.Unlock()
		if disabled {
			return r.textLookup(ctx, peer)
		}
		native, nativeErr := r.native(ctx, local, peer)
		if nativeErr == nil {
			native, nativeErr = validatedAddress(native)
		}
		if validated && nativeErr == nil {
			return native, nil
		}
		text, textErr := r.textLookup(ctx, peer)
		r.mu.Lock()
		if !validated {
			// A cancelled first caller may retry; all other failures disable the
			// unvalidated ABI path. No absent text tuple can certify native lookup.
			if ctx.Err() == nil {
				r.validated = nativeErr == nil && textErr == nil && native.Host == text.Host && native.Port == text.Port
				r.disabled = !r.validated
			}
			close(r.checking)
			r.checking = nil
		} else if nativeErr != nil && !errors.Is(nativeErr, context.Canceled) && !errors.Is(nativeErr, context.DeadlineExceeded) {
			r.disabled, r.validated = true, false
		}
		r.mu.Unlock()
		if textErr != nil {
			return connection.Address{}, errors.Join(textErr, nativeErr)
		}
		return text, nil
	}
}

func (r *pfResolver) textLookup(ctx context.Context, peer netip.AddrPort) (connection.Address, error) {
	out, err := r.text(ctx)
	if err != nil {
		return connection.Address{}, err
	}
	if err := ctx.Err(); err != nil {
		return connection.Address{}, err
	}
	return pfStateLookup(peer, out)
}
