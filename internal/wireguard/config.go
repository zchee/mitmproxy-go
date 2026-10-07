// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package wireguard

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/zchee/mitmproxy-go/internal/privfile"
)

const maxConfigSize = 4096

var errInvalidKey = errors.New("Invalid key.") //nolint:staticcheck // Preserve upstream's key-validation diagnostic.

// Config contains the base64 X25519 private keys stored in wireguard.conf.
// Treat both fields as secrets; only ClientConfig deliberately renders the client key.
type Config struct {
	ServerKey string `json:"server_key"`
	ClientKey string `json:"client_key"`
}

// LoadConfig loads the operator-selected file or creates it with generated keys.
// The path must have trusted parent directories. Reads are limited to 4096 bytes.
// It returns a file diagnostic for invalid JSON or "Invalid key." for invalid keys.
func LoadConfig(path string) (Config, error) {
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() {
			return Config{}, fmt.Errorf("Invalid configuration file (%s): not a regular file", path) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
		}
		return readConfig(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("Invalid configuration file (%s): %w", path, err) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return Config{}, fmt.Errorf("create WireGuard configuration directory: %w", err)
	}
	serverKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Config{}, fmt.Errorf("generate WireGuard server key: %w", err)
	}
	clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return Config{}, fmt.Errorf("generate WireGuard client key: %w", err)
	}
	configuration := Config{
		ServerKey: base64.StdEncoding.EncodeToString(serverKey.Bytes()),
		ClientKey: base64.StdEncoding.EncodeToString(clientKey.Bytes()),
	}
	data, err := json.Marshal(&configuration, jsontext.WithIndent("    "))
	if err != nil {
		return Config{}, fmt.Errorf("encode WireGuard configuration: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".wireguard-*.conf")
	if err != nil {
		return Config{}, fmt.Errorf("create WireGuard configuration: %w", err)
	}
	temporaryPath := temporary.Name()
	defer func() {
		if err := os.Remove(temporaryPath); err != nil {
			slog.Warn("could not remove private WireGuard temporary file", "error", err)
		}
	}()
	if err := temporary.Close(); err != nil {
		return Config{}, fmt.Errorf("close WireGuard temporary file: %w", err)
	}
	file, err := privfile.Create(temporaryPath)
	if err != nil {
		return Config{}, fmt.Errorf("create private WireGuard configuration: %w", err)
	}
	_, writeErr := file.Write(data)
	if err := errors.Join(writeErr, file.Sync(), file.Close()); err != nil {
		return Config{}, fmt.Errorf("write WireGuard configuration: %w", err)
	}
	// Publish a complete file without replacing keys created by another startup.
	if err := os.Link(temporaryPath, path); errors.Is(err, os.ErrExist) {
		return readConfig(path)
	} else if err != nil {
		return Config{}, fmt.Errorf("publish WireGuard configuration: %w", err)
	}
	return configuration, nil
}

func readConfig(path string) (Config, error) {
	file, err := os.Open(path) //nolint:gosec // The operator explicitly selects this configuration file; reads are bounded.
	if err != nil {
		return Config{}, fmt.Errorf("Invalid configuration file (%s): %w", path, err) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	data, readErr := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	closeErr := file.Close()
	if err := errors.Join(readErr, closeErr); err != nil {
		return Config{}, fmt.Errorf("Invalid configuration file (%s): %w", path, err) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	if len(data) > maxConfigSize {
		return Config{}, fmt.Errorf("Invalid configuration file (%s): exceeds %d bytes", path, maxConfigSize) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	var fields struct {
		ServerKey *string `json:"server_key"`
		ClientKey *string `json:"client_key"`
	}
	// Python's json.loads accepts duplicate names and uses the last value.
	if err := json.Unmarshal(data, &fields, jsontext.AllowDuplicateNames(true)); err != nil {
		// Decoder diagnostics can quote private input; do not echo those values.
		return Config{}, fmt.Errorf("Invalid configuration file (%s): invalid JSON configuration", path) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	if fields.ServerKey == nil || fields.ClientKey == nil {
		return Config{}, fmt.Errorf("Invalid configuration file (%s): server_key and client_key are required", path) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	configuration := Config{ServerKey: *fields.ServerKey, ClientKey: *fields.ClientKey}
	if _, err := privateKey(configuration.ServerKey); err != nil {
		return Config{}, err
	}
	if _, err := privateKey(configuration.ClientKey); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

func privateKey(text string) (*ecdh.PrivateKey, error) {
	if len(text) != base64.StdEncoding.EncodedLen(32) {
		return nil, errInvalidKey
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(text)
	if err != nil || len(decoded) != 32 {
		return nil, errInvalidKey
	}
	key, err := ecdh.X25519().NewPrivateKey(decoded)
	if err != nil {
		return nil, errInvalidKey
	}
	return key, nil
}

// ClientConfig renders the upstream client configuration for host and port.
// It returns "Invalid key." for malformed keys and never logs their values.
func (c Config) ClientConfig(host string, port uint16) (string, error) {
	serverKey, err := privateKey(c.ServerKey)
	if err != nil {
		return "", err
	}
	if _, err := privateKey(c.ClientKey); err != nil {
		return "", err
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.0.0.1/32\nDNS = 10.0.0.53\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:%d", c.ClientKey, base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes()), host, port), nil
}
