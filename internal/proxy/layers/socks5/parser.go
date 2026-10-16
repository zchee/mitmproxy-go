// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/connection"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
)

type stage uint8

const (
	greeting stage = iota
	methods
	credentials
	username
	password
	request
	address
	handover
)

func (s stage) String() string {
	switch s {
	case greeting, methods:
		return "greeting"
	case credentials, username, password:
		return "authentication"
	case request, address:
		return "CONNECT"
	case handover:
		return "handover"
	default:
		return "unknown"
	}
}

// A frame never exceeds two credential lengths and their three framing bytes.
// Reads stop at each field boundary, leaving application bytes on the transport.
type parser struct {
	stage stage
	frame [513]byte
	n     int
	need  int
	auth  bool
}

type protocolError struct {
	message string
	reply   byte
}

func (e *protocolError) Error() string { return e.message }

func (p *parser) reset(s stage, need int) {
	clear(p.frame[:])
	p.stage, p.n, p.need = s, 0, need
}

// next advances to a method choice, complete credentials, or destination.
func (p *parser) next(r io.Reader) error {
	for {
		n, err := io.ReadFull(r, p.frame[p.n:p.need])
		p.n += n
		if err != nil {
			return err
		}
		switch p.stage {
		case greeting:
			if p.frame[0] != 5 {
				guess := ""
				upper := false
				lower := false
				for _, b := range p.frame[:p.n] {
					upper = upper || b >= 'A' && b <= 'Z'
					lower = lower || b >= 'a' && b <= 'z'
				}
				if upper && !lower {
					guess = "Probably not a SOCKS request but a regular HTTP request. "
				}
				return &protocolError{message: fmt.Sprintf("%sInvalid SOCKS version. Expected 0x05, got 0x%x", guess, p.frame[0])}
			}
			p.stage, p.need = methods, 2+int(p.frame[1])
		case methods:
			method, name := byte(0), "no"
			if p.auth {
				method, name = 2, "user/password"
			}
			if !bytes.Contains(p.frame[2:p.n], []byte{method}) {
				return &protocolError{message: "Client does not support SOCKS5 with " + name + " authentication.", reply: 0xff}
			}
			return nil
		case credentials:
			// The pinned parser ignores the subnegotiation version and permits
			// zero-length credentials; validation belongs to the auth hook.
			p.stage, p.need = username, 3+int(p.frame[1])
		case username:
			p.stage, p.need = password, p.need+int(p.frame[p.need-1])
		case password:
			return nil
		case request:
			if !bytes.Equal(p.frame[:3], []byte{5, 1, 0}) {
				return &protocolError{message: "Unsupported SOCKS5 request: " + pyrepr.Bytes(p.frame[:p.n]), reply: 7}
			}
			switch p.frame[3] {
			case 1:
				p.need = 10
			case 3:
				p.need = 7 + int(p.frame[4])
			case 4:
				p.need = 22
			default:
				return &protocolError{message: fmt.Sprintf("Unknown address type: %d", p.frame[3]), reply: 8}
			}
			p.stage = address
		case address:
			p.stage = handover
			return nil
		case handover:
			return nil
		}
	}
}

func (p *parser) credentials() (string, string) {
	end := 2 + int(p.frame[1])
	return decodeCredentials(p.frame[2:end]), decodeCredentials(p.frame[end+1 : p.n])
}

func (p *parser) destination() connection.Address {
	var host string
	switch p.frame[3] {
	case 1:
		host = netip.AddrFrom4([4]byte(p.frame[4:8])).String()
	case 4:
		host = netip.AddrFrom16([16]byte(p.frame[4:20])).String()
	case 3:
		var name strings.Builder
		for _, b := range p.frame[5 : p.n-2] {
			if b > 127 {
				name.WriteRune(utf8.RuneError)
			} else {
				name.WriteByte(b)
			}
		}
		host = name.String()
	}
	return connection.Address{Host: host, Port: int(binary.BigEndian.Uint16(p.frame[p.n-2 : p.n]))}
}

func decodeCredentials(b []byte) string {
	var text strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&text, `\x%02x`, b[0])
		} else {
			text.Write(b[:size])
		}
		b = b[size:]
	}
	return text.String()
}
