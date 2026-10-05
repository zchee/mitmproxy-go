// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// The recorder reports the launched process through a real loopback connection.
package main

import (
	"encoding/json/v2"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
)

func main() {
	if err := run(); err != nil {
		slog.Error("record browser launch", "error", err)
		os.Exit(2)
	}
}

func run() error {
	conn, err := net.Dial("tcp", os.Getenv("BROWSER_RECORD_ADDR"))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	record := struct {
		Args  []string
		Prefs string
	}{Args: os.Args[1:]}
	for i, arg := range record.Args {
		if arg == "--profile" && i+1 < len(record.Args) {
			prefs, err := os.ReadFile(filepath.Join(record.Args[i+1], "prefs.js"))
			if err != nil {
				return err
			}
			record.Prefs = string(prefs)
		}
	}
	if err := json.MarshalWrite(conn, record); err != nil {
		return err
	}
	if _, err := conn.Write([]byte("\n")); err != nil {
		return err
	}
	var status [1]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		return err
	}
	if status[0] == '1' {
		os.Exit(1)
	}
	return nil
}
