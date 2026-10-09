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
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/zchee/mitmproxy-go/internal/privfile"
)

const maxConfigSize = 4096

var errInvalidKey = errors.New("Invalid key.") //nolint:staticcheck // Preserve upstream's key-validation diagnostic.

var (
	// ErrConflictingClientKeys rejects configurations containing both peer forms.
	ErrConflictingClientKeys = errors.New("client_key and client_keys are mutually exclusive")
	// ErrEmptyClientKeys rejects an empty ordered peer list.
	ErrEmptyClientKeys = errors.New("client_keys must contain at least one peer")
	// ErrDuplicateClientKeys rejects keys identifying the same X25519 peer.
	ErrDuplicateClientKeys = errors.New("client_keys contains duplicate peers")
)

// Config contains the base64 X25519 private keys stored in wireguard.conf.
// ClientKey is the legacy single-peer form; ClientKeys is the ordered multi-peer
// form, whose first entry is the fallback peer. They are mutually exclusive.
// Treat every key as a secret; only client configuration rendering exposes them.
type Config struct {
	ServerKey  string   `json:"server_key"`
	ClientKey  string   `json:"client_key,omitzero"`
	ClientKeys []string `json:"client_keys,omitzero"`
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
		ServerKey  *string        `json:"server_key"`
		ClientKey  jsontext.Value `json:"client_key"`
		ClientKeys jsontext.Value `json:"client_keys"`
	}
	// Python's json.loads accepts duplicate names and uses the last value.
	if err := json.Unmarshal(data, &fields, jsontext.AllowDuplicateNames(true)); err != nil {
		// Decoder diagnostics can quote private input; do not echo those values.
		return Config{}, fmt.Errorf("Invalid configuration file (%s): invalid JSON configuration", path) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	if fields.ClientKey != nil && fields.ClientKeys != nil {
		return Config{}, ErrConflictingClientKeys
	}
	if fields.ServerKey == nil || (fields.ClientKeys == nil && (fields.ClientKey == nil || string(fields.ClientKey) == "null")) {
		return Config{}, fmt.Errorf("Invalid configuration file (%s): server_key and client_key are required", path) //nolint:staticcheck // Preserve upstream's file diagnostic prefix.
	}
	configuration := Config{ServerKey: *fields.ServerKey}
	if fields.ClientKeys != nil {
		if err := json.Unmarshal(fields.ClientKeys, &configuration.ClientKeys); err != nil {
			return Config{}, fmt.Errorf("Invalid configuration file (%s): invalid JSON configuration", path) //nolint:staticcheck // Decoder errors must not expose private input.
		}
		if len(configuration.ClientKeys) == 0 {
			return Config{}, ErrEmptyClientKeys
		}
	} else if err := json.Unmarshal(fields.ClientKey, &configuration.ClientKey); err != nil {
		return Config{}, fmt.Errorf("Invalid configuration file (%s): invalid JSON configuration", path) //nolint:staticcheck // Decoder errors must not expose private input.
	}
	if _, err := privateKey(configuration.ServerKey); err != nil {
		return Config{}, err
	}
	if _, err := configuration.PeerKeys(); err != nil {
		return Config{}, err
	}
	return configuration, nil
}

// PeerKeys returns an independent ordered list of validated client private keys.
// The first peer is the fallback for destinations with no learned source.
// It returns ErrConflictingClientKeys, ErrEmptyClientKeys, ErrDuplicateClientKeys,
// or "Invalid key." without quoting private material.
func (c Config) PeerKeys() ([]string, error) {
	if c.ClientKey != "" && c.ClientKeys != nil {
		return nil, ErrConflictingClientKeys
	}
	keys := c.ClientKeys
	if keys == nil {
		keys = []string{c.ClientKey}
	}
	if len(keys) == 0 {
		return nil, ErrEmptyClientKeys
	}
	seen := make(map[[32]byte]struct{}, len(keys))
	for _, text := range keys {
		key, err := privateKey(text)
		if err != nil {
			return nil, err
		}
		identity := [32]byte(key.PublicKey().Bytes())
		if _, exists := seen[identity]; exists {
			return nil, ErrDuplicateClientKeys
		}
		seen[identity] = struct{}{}
	}
	return slices.Clone(keys), nil
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

// ClientConfig renders the first peer's upstream configuration for host and port.
// It returns the same validation errors as ClientConfigs, without logging keys.
func (c Config) ClientConfig(host string, port uint16) (string, error) {
	configurations, err := c.ClientConfigs(host, port)
	if err != nil {
		return "", err
	}
	return configurations[0], nil
}

// ClientConfigs renders one configuration per peer in configured order.
// Addresses start at 10.0.0.1/32; DNS and AllowedIPs keep upstream's values.
// It returns PeerKeys validation errors or "Invalid key." for a server key,
// without logging private material.
func (c Config) ClientConfigs(host string, port uint16) ([]string, error) {
	serverKey, err := privateKey(c.ServerKey)
	if err != nil {
		return nil, err
	}
	keys, err := c.PeerKeys()
	if err != nil {
		return nil, err
	}
	publicKey := base64.StdEncoding.EncodeToString(serverKey.PublicKey().Bytes())
	configurations := make([]string, len(keys))
	address := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	for i, key := range keys {
		configurations[i] = fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\nDNS = 10.0.0.53\n\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = %s:%d", key, address, publicKey, host, port)
		address = address.Next()
	}
	return configurations, nil
}
