// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package grideditor

import (
	"bytes"
	"encoding/csv"
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
	data, err := os.ReadFile(path)
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
	writer := csv.NewWriter(&buffer)
	for _, row := range rows {
		values := make([]string, len(row))
		for i, cell := range row {
			values[i] = string(cell.Data)
		}
		if err := writer.Write(values); err != nil {
			return err
		}
		writer.Flush()
		if err := writer.Error(); err != nil {
			return err
		}
		data := buffer.Bytes()
		if len(data) > 0 {
			if _, err := dst.Write(data[:len(data)-1]); err != nil {
				return err
			}
			if _, err := io.WriteString(dst, "\r\n"); err != nil {
				return err
			}
		}
		buffer.Reset()
	}
	return nil
}
