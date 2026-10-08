// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build quicfixture

// Capture the first two real client datagrams, without accepting a handshake.
// Run once with Go 1.27 and quic-go v0.63.0:
// go run -tags quicfixture ./tlsparse/testdata/quic/generate.go <output-directory>
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	quic "github.com/quic-go/quic-go"
)

func main() {
	if err := capture(); err != nil {
		slog.Error("capture failed", "error", err)
		os.Exit(1)
	}
}

func capture() error {
	if len(os.Args) != 2 {
		return fmt.Errorf("usage: quicfixture output-directory")
	}
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer server.Close()
	client, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer client.Close()
	tr := quic.Transport{Conn: client}
	defer tr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		conn, err := tr.Dial(ctx, server.LocalAddr(), &tls.Config{
			ServerName:       "two-datagram.example",
			NextProtos:       []string{"h3"},
			MinVersion:       tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{tls.X25519MLKEM768},
		}, &quic.Config{Versions: []quic.Version{quic.Version1}, InitialPacketSize: 1200})
		if conn != nil {
			_ = conn.CloseWithError(0, "capture complete")
		}
		done <- err
	}()
	defer func() { cancel(); <-done }()
	if err := server.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	for i := range 2 {
		data := make([]byte, 65535)
		n, _, err := server.ReadFrom(data)
		if err != nil {
			return err
		}
		path := filepath.Join(os.Args[1], fmt.Sprintf("quic_go_initial_%d.hex", i+1))
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := fmt.Fprintln(file, hex.EncodeToString(data[:n]))
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return fmt.Errorf("capture write/close: %w", err)
		}
	}
	return nil
}
