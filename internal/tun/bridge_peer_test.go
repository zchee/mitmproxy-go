// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package tun

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// pipeDevice preserves packet boundaries over a real blocking net.Pipe. A peer
// that does not read gives deterministic device-write backpressure.
type pipeDevice struct {
	conn         net.Conn
	batch        int
	readBatch    int
	readErr      error
	readErrUsed  bool
	closes       atomic.Int32
	activeReads  atomic.Int32
	activeWrites atomic.Int32
	readStarted  chan struct{}
	writeStarted chan struct{}
	readOnce     sync.Once
	writeOnce    sync.Once
}

func newPipeDevice(t *testing.T, batch int) (*pipeDevice, net.Conn) {
	t.Helper()
	conn, peer := net.Pipe()
	t.Cleanup(func() { _ = conn.Close(); _ = peer.Close() })
	return &pipeDevice{conn: conn, batch: batch, readStarted: make(chan struct{}), writeStarted: make(chan struct{})}, peer
}

func (d *pipeDevice) File() *os.File        { return nil }
func (d *pipeDevice) MTU() (int, error)     { return 65535, nil }
func (d *pipeDevice) Name() (string, error) { return "pipe", nil }
func (d *pipeDevice) BatchSize() int        { return d.batch }
func (d *pipeDevice) Events() <-chan wgtun.Event {
	panic("packet bridge must not wait for device events")
}

func (d *pipeDevice) Close() error {
	d.closes.Add(1)
	return d.conn.Close()
}

func (d *pipeDevice) Read(buffers [][]byte, sizes []int, offset int) (int, error) {
	d.activeReads.Add(1)
	defer d.activeReads.Add(-1)
	d.readOnce.Do(func() { close(d.readStarted) })
	count := max(1, d.readBatch)
	for i := range count {
		var length [2]byte
		if _, err := io.ReadFull(d.conn, length[:]); err != nil {
			return i, err
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n > len(buffers[i][offset:]) {
			return i, io.ErrShortBuffer
		}
		if _, err := io.ReadFull(d.conn, buffers[i][offset:offset+n]); err != nil {
			return i, err
		}
		sizes[i] = n
	}
	if d.readErr != nil && !d.readErrUsed {
		d.readErrUsed = true
		return count, d.readErr
	}
	return count, nil
}

func (d *pipeDevice) Write(buffers [][]byte, offset int) (int, error) {
	d.activeWrites.Add(1)
	defer d.activeWrites.Add(-1)
	d.writeOnce.Do(func() { close(d.writeStarted) })
	if offset < 10 {
		return 0, errors.New("device write lacks virtio-header headroom")
	}
	for i, buffer := range buffers {
		// NativeTun is allowed to overwrite this headroom with offload metadata.
		for j := range offset {
			buffer[j] = 0xab
		}
		if err := writeFrame(d.conn, buffer[offset:]); err != nil {
			return i, err
		}
	}
	return len(buffers), nil
}

func writeFrame(conn net.Conn, packet []byte) error {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(packet)))
	if _, err := conn.Write(length[:]); err != nil {
		return err
	}
	if len(packet) == 0 {
		return nil
	}
	_, err := conn.Write(packet)
	return err
}

func sendFrame(t *testing.T, conn net.Conn, packet []byte) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := writeFrame(conn, packet); err != nil {
		bridgeHang(t, "sending packet", err)
	}
	if err := conn.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
}

func receiveFrame(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var length [2]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		bridgeHang(t, "receiving length", err)
	}
	packet := make([]byte, 65535)
	n := int(binary.BigEndian.Uint16(length[:]))
	if _, err := io.ReadFull(conn, packet[:n]); err != nil {
		bridgeHang(t, "receiving packet", err)
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	return packet[:n]
}

func waitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-signal:
	case <-timer.C:
		bridgeHang(t, "waiting for device I/O entry", nil)
	}
}

func waitBridge(t *testing.T, result <-chan error) error {
	t.Helper()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		bridgeHang(t, "waiting for bridge shutdown", nil)
		return nil
	}
}

func bridgeHang(t *testing.T, operation string, err error) {
	t.Helper()
	buffer := make([]byte, 1<<20)
	n := runtime.Stack(buffer, true)
	t.Fatalf("bridge hang detector while %s: %v\n%s", operation, err, buffer[:n])
}

func assertDeviceJoined(t *testing.T, dev *pipeDevice) {
	t.Helper()
	if got := dev.closes.Load(); got != 1 {
		t.Errorf("device Close calls = %d, want exactly one", got)
	}
	if got := dev.activeReads.Load(); got != 0 {
		t.Errorf("active device reads after Serve = %d", got)
	}
	if got := dev.activeWrites.Load(); got != 0 {
		t.Errorf("active device writes after Serve = %d", got)
	}
}
