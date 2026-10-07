// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build linux

package tun

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInterfaceSetupErrors(t *testing.T) {
	tests := map[string]struct {
		name    string
		attach  bool
		wantErr error
	}{
		"error: malformed attach name":        {name: strings.Repeat("x", unix.IFNAMSIZ), attach: true},
		"error: malformed configuration name": {name: strings.Repeat("x", unix.IFNAMSIZ)},
		"error: bad attach descriptor":        {name: "tun0", attach: true, wantErr: unix.EBADF},
		"error: unknown interface":            {wantErr: unix.EPERM},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			before := descriptorCount(t)
			var err error
			if tt.attach {
				_, err = attachInterface(-1, tt.name)
			} else {
				err = configureInterface(tt.name)
			}
			if err == nil {
				t.Fatal("expected interface setup failure")
			}
			// An unknown interface is ENODEV with CAP_NET_ADMIN and EPERM
			// without it. Both paths must release the ioctl socket.
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) && (tt.name != "" || !errors.Is(err, unix.ENODEV)) {
				t.Errorf("setup error = %v, want %v", err, tt.wantErr)
			}
			if after := descriptorCount(t); after != before {
				t.Errorf("descriptor count after setup failure = %d, want %d", after, before)
			}
		})
	}
}
