// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build integration && darwin

package platform

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestOriginalDestinationPFIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("manual PF ioctl acceptance requires effective uid 0")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	pfctl := func(ctx context.Context, input string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, pfCommandTimeout)
		defer cancel()
		out := &boundedPFOutput{cancel: cancel}
		cmd := exec.CommandContext(ctx, "/sbin/pfctl", args...)
		cmd.Stdin = strings.NewReader(input)
		cmd.Stdout, cmd.Stderr = out, out
		cmd.WaitDelay = time.Second
		err := cmd.Run()
		if out.full {
			return "", ErrPFOutput
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		return out.String(), err
	}
	rules, err := pfctl(ctx, "", "-sn")
	if err != nil || !strings.Contains(rules, `rdr-anchor "com.apple/*"`) {
		t.Fatalf("prepared root rules must expose com.apple rdr anchor: error=%v output=%s", err, rules)
	}
	origin, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := origin.Close(); err != nil {
			t.Errorf("origin close: %v", err)
		}
	}()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Errorf("listener close: %v", err)
		}
	}()
	anchor := "com.apple/mitmproxy-go-" + strconv.Itoa(os.Getpid())
	old, err := pfctl(ctx, "", "-a", anchor, "-sn")
	if err != nil || strings.Contains(old, "rdr ") {
		t.Fatalf("owned anchor already occupied: error=%v output=%s", err, old)
	}
	enabled, err := pfctl(ctx, "", "-E")
	if err != nil {
		t.Fatalf("acquire PF enable reference: %v %s", err, enabled)
	}
	var token string
	for line := range strings.SplitSeq(enabled, "\n") {
		if _, value, ok := strings.Cut(line, "Token : "); ok {
			token = strings.TrimSpace(value)
		}
	}
	if token == "" {
		t.Fatalf("PF enable reference did not return token: %s", enabled)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*pfCommandTimeout)
		defer cancel()
		if out, err := pfctl(cleanup, "", "-a", anchor, "-F", "rules"); err != nil {
			t.Errorf("owned anchor teardown: %v %s", err, out)
		}
		if out, err := pfctl(cleanup, "", "-X", token); err != nil {
			t.Errorf("PF enable reference teardown: %v %s", err, out)
		}
	})
	originPort, proxyPort := origin.Addr().(*net.TCPAddr).Port, listener.Addr().(*net.TCPAddr).Port
	rule := fmt.Sprintf("rdr pass on lo0 inet proto tcp from 127.0.0.1 to 127.0.0.2 port %d -> 127.0.0.1 port %d\n", originPort, proxyPort)
	if out, err := pfctl(ctx, rule, "-a", anchor, "-f", "-"); err != nil {
		t.Fatalf("install owned redirect: %v %s", err, out)
	}
	client, err := (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}).DialContext(ctx, "tcp4", origin.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			t.Errorf("client close: %v", err)
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err := listener.SetDeadline(deadline); err != nil {
			t.Fatal(err)
		}
	}
	accepted, err := listener.AcceptTCP()
	if err != nil {
		t.Fatalf("redirected accept (not direct origin): %v; rule=%s", err, rule)
	}
	defer func() {
		if err := accepted.Close(); err != nil {
			t.Errorf("accepted close: %v", err)
		}
	}()
	if _, err := client.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := accepted.SetReadDeadline(time.Now().Add(pfCommandTimeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	if _, err := accepted.Read(buf); err != nil || !bytes.Equal(buf, []byte{1}) {
		t.Fatalf("establish state: bytes=%x error=%v", buf, err)
	}
	local, err := tcpAddress(accepted.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	peer, err := tcpAddress(accepted.RemoteAddr())
	if err != nil {
		t.Fatal(err)
	}
	native, err := nativePFAddr(ctx, local, peer)
	if err != nil {
		t.Fatalf("native ioctl must pass root acceptance: %v", err)
	}
	state, err := readPFState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	text, err := pfStateLookup(peer, state)
	if err != nil {
		t.Fatal(err)
	}
	want := address("127.0.0.2", originPort)
	if diff := cmp.Diff(want, native); diff != "" {
		t.Fatalf("native destination: %s", diff)
	}
	if diff := cmp.Diff(native, text); diff != "" {
		t.Fatalf("ioctl/text tuple mismatch: %s", diff)
	}
	resolver := pfResolver{native: nativePFAddr, text: readPFState}
	got, err := resolver.lookup(ctx, local, peer)
	if err != nil || !resolver.validated || resolver.disabled {
		t.Fatalf("self-check decision: tuple=%v error=%v validated=%v disabled=%v", got, err, resolver.validated, resolver.disabled)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatal(diff)
	}
	t.Logf("header=xnu-12377.1.9 layout_size=%d ioctl=%#x peer=%s accepted=%s original=%s text=%s validated=%v owned_anchor=%s", darwinPFLayout.size, darwinPFLayout.ioctl, peer, local, native, text, resolver.validated, anchor)
}
