// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package grideditor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/zchee/mitmproxy-go/internal/privfile"
	"github.com/zchee/mitmproxy-go/internal/strutil"
)

// ReadFile reads an operator-selected file, optionally decoding Python escapes.
func ReadFile(path string, escaped bool) ([]byte, error) {
	path, err := expandHome(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path) //nolint:gosec // The operator explicitly selects this grid input file.
	if err != nil {
		return nil, err
	}
	if escaped {
		return DecodeEscaped(string(data))
	}
	return data, nil
}

// DecodeEscaped decodes a grid value using the shared Python-style byte codec.
func DecodeEscaped(value string) ([]byte, error) { return strutil.EscapedStrToBytes(value) }

func expandHome(path string) (string, error) {
	if !strings.HasPrefix(path, "~") {
		return path, nil
	}
	account, rest, _ := strings.Cut(path[1:], string(filepath.Separator))
	home := ""
	if account == "" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", err
		}
	} else {
		u, err := user.Lookup(account)
		if err != nil {
			return "", err
		}
		home = u.HomeDir
	}
	return filepath.Join(home, rest), nil
}

// SaveFile writes CRLF-terminated CSV through the private output-file policy.
// Embedded CR and LF bytes remain unchanged, including quoted multiline cells.
func SaveFile(path string, rows [][]Cell) error {
	path, err := expandHome(path)
	if err != nil {
		return err
	}
	file, err := privfile.Create(path)
	if err != nil {
		return err
	}
	err = writeCSV(file, rows)
	return errors.Join(err, file.Close())
}

func writeCSV(dst io.Writer, rows [][]Cell) error {
	var buffer bytes.Buffer
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				buffer.WriteByte(',')
			}
			// Python's minimal dialect leaves leading whitespace unquoted and
			// quotes a sole empty field, unlike encoding/csv's writer.
			quoted := bytes.ContainsAny(cell.Data, ",\"\r\n") || len(row) == 1 && len(cell.Data) == 0
			if quoted {
				buffer.WriteByte('"')
			}
			for _, value := range cell.Data {
				buffer.WriteByte(value)
				if quoted && value == '"' {
					buffer.WriteByte('"')
				}
			}
			if quoted {
				buffer.WriteByte('"')
			}
		}
		buffer.WriteString("\r\n")
		if _, err := buffer.WriteTo(dst); err != nil {
			return err
		}
	}
	return nil
}
