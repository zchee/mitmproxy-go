// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestParseExcludedPorts(t *testing.T) {
	const header = "Protocol tcp Port Exclusion Ranges\r\n\r\nStart Port    End Port\r\n----------    --------\r\n"
	tests := map[string]struct {
		output string
		want   []portRange
		fail   bool
	}{
		"success: ordinary and administered": {
			output: header + " 50000   50099\r\n 51000   51001 *\r\n\r\n* - Administered port exclusions.\r\n",
			want:   []portRange{{50000, 50099}, {51000, 51001}},
		},
		"success: no exclusions": {output: header + "\r\n* - Administered port exclusions.\r\n"},
		"success: port bounds": {
			output: header + "0 65535\n",
			want:   []portRange{{0, 65535}},
		},
		"success: localized headings": {
			output: "Localized headings\n---------- --------\n12345 12346\n",
			want:   []portRange{{12345, 12346}},
		},
		"error: missing table":    {output: "netsh unavailable", fail: true},
		"error: reversed range":   {output: header + "50099 50000\n", fail: true},
		"error: negative port":    {output: header + "-1 10\n", fail: true},
		"error: excessive port":   {output: header + "1 65536\n", fail: true},
		"error: invalid endpoint": {output: header + "1 invalid\n", fail: true},
		"error: truncated row":    {output: header + "12345\n", fail: true},
		"error: extra fields":     {output: header + "1 2 3\n", fail: true},
		"error: unexpected text":  {output: header + "unexpected output\n", fail: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := parseExcludedPorts(tt.output)
			if (err != nil) != tt.fail {
				t.Fatalf("parse error = %v, want failure=%t", err, tt.fail)
			}
			if diff := gocmp.Diff(tt.want, got, gocmp.AllowUnexported(portRange{})); diff != "" {
				t.Fatalf("excluded ranges (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExcludedPortReservations(t *testing.T) {
	tests := map[string]struct {
		paired   bool
		excluded int
	}{
		"success: paired skips excluded candidates":    {paired: true, excluded: 2},
		"success: TCP-only skips excluded candidates":  {excluded: 2},
		"error: paired exhausts excluded candidates":   {paired: true, excluded: attempts},
		"error: TCP-only exhausts excluded candidates": {excluded: attempts},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			var candidates []net.Listener
			blocked := make(map[int]bool)
			lc := &net.ListenConfig{}
			input := listeners{
				listen: func(ctx context.Context, network, address string) (net.Listener, error) {
					for _, candidate := range candidates {
						probe, err := lc.Listen(ctx, network, candidate.Addr().String())
						if err == nil {
							_ = probe.Close()
							t.Fatalf("excluded candidate %v released before selection ended", candidate.Addr())
						}
					}
					candidate, err := lc.Listen(ctx, network, address)
					if err == nil {
						candidates = append(candidates, candidate)
						blocked[candidate.Addr().(*net.TCPAddr).Port] = len(candidates) <= tt.excluded
						t.Cleanup(func() { _ = candidate.Close() })
					}
					return candidate, err
				},
				listenPacket: lc.ListenPacket,
				excluded: func(port int, paired bool) bool {
					if paired != tt.paired {
						t.Fatalf("paired exclusion check=%t, want %t", paired, tt.paired)
					}
					return blocked[port]
				},
			}
			var port int
			if tt.paired {
				var err error
				port, err = getFreePort(t.Context(), input)
				if (err != nil) != (tt.excluded == attempts) {
					t.Fatalf("selection error=%v for %d excluded candidates", err, tt.excluded)
				}
			} else {
				port = getFreeTCPPort(t.Context(), input)
			}
			if (port == 0) != (tt.excluded == attempts) || blocked[port] {
				t.Fatalf("selected port=%d for %d excluded candidates", port, tt.excluded)
			}
			if len(candidates) != min(tt.excluded+1, attempts) {
				t.Fatalf("candidate count=%d, want %d", len(candidates), min(tt.excluded+1, attempts))
			}
			for _, candidate := range candidates {
				_ = candidate.(*net.TCPListener).SetDeadline(time.Now())
				if _, err := candidate.Accept(); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("candidate %v retained after selection: %v", candidate.Addr(), err)
				}
			}
		})
	}
}

func TestInPortRanges(t *testing.T) {
	tests := map[string]struct {
		port   int
		ranges []portRange
		want   bool
	}{
		"success: no ranges":     {port: 12345},
		"success: before range":  {port: 12344, ranges: []portRange{{12345, 12347}}},
		"success: first port":    {port: 12345, ranges: []portRange{{12345, 12347}}, want: true},
		"success: interior port": {port: 12346, ranges: []portRange{{12345, 12347}}, want: true},
		"success: last port":     {port: 12347, ranges: []portRange{{12345, 12347}}, want: true},
		"success: after range":   {port: 12348, ranges: []portRange{{12345, 12347}}},
		"success: later range":   {port: 23456, ranges: []portRange{{12345, 12347}, {23456, 23456}}, want: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := inPortRanges(tt.port, tt.ranges); got != tt.want {
				t.Fatalf("port %d excluded=%t, want %t", tt.port, got, tt.want)
			}
		})
	}
}
