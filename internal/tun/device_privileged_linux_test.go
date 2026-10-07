// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build linux && packetmodes

package tun

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"golang.org/x/sys/unix"
)

func TestCreatedDevice(t *testing.T) {
	// rs:src/packet_sources/tun.rs:49-65,89-107 specifies the created end state.
	if os.Geteuid() != 0 {
		t.Fatal("created-device evidence requires root")
	}
	warmDescriptorPoller(t)
	before := descriptorCount(t)
	original := snapshotSysctls(t)
	t.Cleanup(func() {
		for path, value := range original {
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Errorf("restore %s: %v", path, err)
			}
		}
		if diff := cmp.Diff(original, snapshotSysctls(t)); diff != "" {
			t.Errorf("restored sysctls (-want +got):\n%s", diff)
		}
		if after := descriptorCount(t); after != before {
			t.Errorf("descriptor count after close = %d, want %d", after, before)
		}
	})
	dev, err := Open("", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := dev.Close(); err != nil {
			t.Errorf("close created device: %v", err)
		}
	})
	name, err := dev.Name()
	if err != nil || name == "" {
		t.Fatalf("device name = %q, %v", name, err)
	}
	mtu, err := dev.MTU()
	if err != nil || mtu != 65535 {
		t.Errorf("device MTU = %d, %v, want 65535", mtu, err)
	}
	raw, err := dev.File().SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	var flagErr error
	if err := raw.Control(func(fd uintptr) { flags, flagErr = unix.FcntlInt(fd, unix.F_GETFD, 0) }); err != nil {
		t.Fatal(err)
	}
	if flagErr != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("device descriptor flags = %d, %v, want CLOEXEC", flags, flagErr)
	}
	if after := descriptorCount(t); after != before+1 {
		t.Errorf("live device descriptor count = %d, want %d", after, before+1)
	}
	request, err := unix.NewIfreq(name)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, request); err != nil {
		t.Fatal(err)
	}
	if request.Uint16()&unix.IFF_UP == 0 {
		t.Error("created device is not up")
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFADDR, request); err != nil {
		t.Fatal(err)
	}
	address, err := request.Inet4Addr()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]byte{169, 254, 0, 1}, address); diff != "" {
		t.Errorf("created address (-want +got):\n%s", diff)
	}
	for path, want := range map[string]string{
		filepath.Join(name, "rp_filter"):      "0",
		filepath.Join("all", "rp_filter"):     "0",
		filepath.Join(name, "route_localnet"): "1",
		filepath.Join(name, "accept_local"):   "1",
	} {
		value, err := os.ReadFile(filepath.Join("/proc/sys/net/ipv4/conf", path))
		if err != nil || strings.TrimSpace(string(value)) != want {
			t.Errorf("%s = %q, %v, want %q", path, value, err, want)
		}
	}
}

func TestPersistentDevice(t *testing.T) {
	// rs:src/packet_sources/tun.rs:67-83 specifies an unconfigured persistent retry.
	if os.Geteuid() == 0 {
		t.Fatal("persistent-device evidence must run without root")
	}
	name := os.Getenv("MITMPROXY_TUN_PERSISTENT")
	if name == "" {
		t.Fatal("MITMPROXY_TUN_PERSISTENT must name a pre-created interface")
	}
	warmDescriptorPoller(t)
	before := descriptorCount(t)
	original := snapshotSysctls(t)
	for range 2 {
		dev, err := Open(name, nil)
		if err != nil {
			t.Fatal(err)
		}
		actual, nameErr := dev.Name()
		if actual != name || nameErr != nil {
			t.Errorf("persistent name = %q, %v, want %q", actual, nameErr, name)
		}
		if err := dev.Close(); err != nil {
			t.Fatal(err)
		}
		if after := descriptorCount(t); after != before {
			t.Errorf("persistent close leaves %d descriptors, want %d", after, before)
		}
		if diff := cmp.Diff(original, snapshotSysctls(t)); diff != "" {
			t.Errorf("persistent sysctl writes (-want +got):\n%s", diff)
		}
	}
}

func warmDescriptorPoller(t *testing.T) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
}

func snapshotSysctls(t *testing.T) map[string]string {
	t.Helper()
	root := "/proc/sys/net/ipv4/conf"
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, entry := range entries {
		for _, field := range []string{"rp_filter", "route_localnet", "accept_local"} {
			path := filepath.Join(root, entry.Name(), field)
			value, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			values[path] = string(value)
		}
	}
	return values
}
