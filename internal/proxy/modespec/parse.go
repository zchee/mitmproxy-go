// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package modespec

import (
	"errors"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"unicode"

	"github.com/zchee/mitmproxy-go/internal/netutil/serverspec"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

// ErrUnknownMode means that a specification names no registered proxy mode.
var ErrUnknownMode = errors.New("unknown mode")

// Parse parses all upstream proxy mode names and validates their configuration.
// Errors preserve upstream's text. A successful call returns a comparable mode
// value; repeated calls are independent and safe to run concurrently.
func Parse(spec string) (Mode, error) {
	return parse(spec, "")
}

// ParseAs parses a specification for a particular mode value type, such as
// ParseAs[Socks5Mode]("socks5@1080"). M must be a concrete mode value type or
// Mode itself, not a pointer. A different mode name is rejected before its
// configuration is validated, matching upstream's subclass parse methods.
func ParseAs[M Mode](spec string) (M, error) {
	var zero M
	typ := reflect.TypeFor[M]()
	expected := ""
	if typ != reflect.TypeFor[Mode]() {
		if typ.Kind() != reflect.Struct {
			return zero, errors.New("ParseAs requires a concrete mode value type or Mode")
		}
		expected = zero.Name()
	}
	mode, err := parse(spec, expected)
	if err != nil {
		return zero, err
	}
	result, ok := mode.(M)
	if !ok {
		return zero, fmt.Errorf("unsupported mode type: %s", typ)
	}
	return result, nil
}

func parse(fullSpec, expected string) (Mode, error) {
	head, listen, found := strings.CutLast(fullSpec, "@")
	if !found {
		head, listen = fullSpec, ""
	} else if head == "" {
		head, listen = listen, ""
	}
	name, data, _ := strings.Cut(head, ":")
	spec := Spec{FullSpec: fullSpec, Data: data}
	if listen != "" {
		host, portText, hasHost := strings.CutLast(listen, ":")
		if !hasHost {
			portText = listen
		}
		port, ok := parsePort(portText)
		if !ok {
			return nil, errors.New("invalid port: " + portText)
		}
		spec.CustomListenPort, spec.HasCustomListenPort = port, true
		if hasHost {
			spec.CustomListenHost, spec.HasCustomListenHost = host, true
		}
	}

	// Python lower expands dotted capital I to i plus a combining dot, so it
	// cannot occur in a registered name. Go's simple lowercase would accept it.
	if strings.ContainsRune(name, 'İ') {
		return nil, ErrUnknownMode
	}
	lower := strings.ToLower(name)
	switch lower {
	case "regular", "transparent", "upstream", "reverse", "socks5", "dns", "wireguard", "local", "tun", "osproxy":
	default:
		return nil, ErrUnknownMode
	}
	if expected != "" && lower != expected {
		return nil, fmt.Errorf("%s is not a spec for a %s mode", pyrepr.Str(name), expected)
	}
	if data != "" {
		switch lower {
		case "regular", "transparent", "socks5", "dns":
			return nil, errors.New("mode takes no arguments")
		}
	}

	switch lower {
	case "regular":
		return RegularMode{Spec: spec}, nil
	case "transparent":
		return TransparentMode{Spec: spec}, nil
	case "upstream":
		scheme, address, err := serverspec.Parse(data, "http")
		if err != nil {
			return nil, err
		}
		if scheme != "http" && scheme != "https" {
			return nil, errors.New("invalid upstream proxy scheme")
		}
		return UpstreamMode{Spec: spec, Scheme: scheme, Address: address}, nil
	case "reverse":
		scheme, address, err := serverspec.Parse(data, "https")
		if err != nil {
			return nil, err
		}
		return ReverseMode{Spec: spec, Scheme: scheme, Address: address}, nil
	case "socks5":
		return Socks5Mode{Spec: spec}, nil
	case "dns":
		return DNSMode{Spec: spec}, nil
	case "wireguard":
		return WireGuardMode{Spec: spec}, nil
	case "local":
		if !validInterceptSpec(data) {
			return nil, errors.New("invalid intercept spec: " + data)
		}
		return LocalMode{Spec: spec}, nil
	case "tun":
		if runtime.GOOS == "darwin" && data != "" && !validDarwinTunName(data) {
			return nil, errors.New("Invalid tun name: " + data + ". On macOS, the tun name must be the form utunx where x is a number, such as utun3.")
		}
		return TunMode{Spec: spec}, nil
	default: // osproxy is registered but always rejects construction.
		return nil, errors.New("osproxy mode has been renamed to local mode. Thanks for trying our experimental features!") //nolint:staticcheck // ST1005: preserve upstream's user-facing error text.
	}
}

// parsePort implements Python's decimal int syntax without allocating an
// arbitrary-precision integer: Unicode decimal digits, surrounding whitespace,
// one sign, and single underscores between digits. Accumulation stays bounded
// by the largest valid port. Python's default conversion limit is 4300 digits.
func parsePort(text string) (int, bool) {
	text = strings.TrimSpace(text)
	negative := false
	if text != "" && (text[0] == '+' || text[0] == '-') {
		negative = text[0] == '-'
		text = text[1:]
	}
	port, digits := 0, 0
	previousDigit := false
	for _, r := range text {
		if r == '_' && previousDigit {
			previousDigit = false
			continue
		}
		digit, ok := decimalDigit(r)
		if !ok {
			return 0, false
		}
		port = port*10 + digit
		digits++
		if port > 65535 || digits > 4300 {
			return 0, false
		}
		previousDigit = true
	}
	return port, previousDigit && (!negative || port == 0)
}

func decimalDigit(r rune) (int, bool) {
	if r >= '0' && r <= '9' {
		return int(r - '0'), true
	}
	if r < 128 {
		return 0, false
	}
	// Unicode decimal digit ranges contain one or more consecutive 0–9 sets.
	for _, span := range unicode.Digit.R16 {
		if uint32(r) >= uint32(span.Lo) && uint32(r) <= uint32(span.Hi) && (uint32(r)-uint32(span.Lo))%uint32(span.Stride) == 0 {
			return int((uint32(r)-uint32(span.Lo))/uint32(span.Stride)) % 10, true
		}
	}
	for _, span := range unicode.Digit.R32 {
		if uint32(r) >= span.Lo && uint32(r) <= span.Hi && (uint32(r)-span.Lo)%span.Stride == 0 {
			return int((uint32(r)-span.Lo)/span.Stride) % 10, true
		}
	}
	return 0, false
}

func validInterceptSpec(data string) bool {
	data = strings.TrimSpace(data)
	if data == "" {
		return true
	}
	for action := range strings.SplitSeq(data, ",") {
		pattern, _ := strings.CutPrefix(strings.TrimSpace(action), "!")
		if strings.TrimSpace(pattern) == "" {
			return false
		}
	}
	return true
}

func validDarwinTunName(name string) bool {
	digits, ok := strings.CutPrefix(name, "utun")
	if !ok {
		return false
	}
	// Python's regexp end anchor also matches immediately before a final LF.
	digits = strings.TrimSuffix(digits, "\n")
	if digits == "" {
		return false
	}
	for _, r := range digits {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}
