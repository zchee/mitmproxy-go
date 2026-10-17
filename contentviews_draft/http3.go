// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"strings"
	"unicode/utf8"

	"github.com/quic-go/qpack"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
)

// HTTP3Frames displays HTTP/3 stream frames without changing endpoint state.
type HTTP3Frames struct{}

// Name returns the view's selection name.
func (HTTP3Frames) Name() string { return "HTTP/3 Frames" }

// SyntaxHighlight returns the renderer's syntax name.
func (HTTP3Frames) SyntaxHighlight() string { return "none" }

// RenderPriority selects TCP streams carrying an HTTP/3 ALPN.
func (HTTP3Frames) RenderPriority(_ []byte, metadata contentviews.Metadata) float64 {
	f, ok := metadata.Flow.(*flow.TCPFlow)
	if ok && f != nil && f.ClientConn != nil && (bytes.Equal(f.ClientConn.ALPN, []byte("h3")) || bytes.HasPrefix(f.ClientConn.ALPN, []byte("h3-"))) {
		return 2
	}
	return 0
}

// Prettify replays an immutable message prefix and attributes completed frames
// to the message that supplied the final bytes. Calls retain no flow pointers.
func (HTTP3Frames) Prettify(data []byte, metadata contentviews.Metadata) (string, error) {
	f, ok := metadata.Flow.(*flow.TCPFlow)
	if !ok || f == nil || metadata.TCPMessage == nil {
		return "", fmt.Errorf("HTTP/3 view requires a TCP flow and message")
	}
	if len(data) > maxViewBytes {
		return "", &LimitError{View: "HTTP/3", Stage: "input", Bound: "input bytes"}
	}
	selected := -1
	for i, message := range f.Messages {
		if message == metadata.TCPMessage {
			selected = i
			break
		}
	}
	if selected < 0 {
		return "", fmt.Errorf("HTTP/3 message is not in the flow")
	}
	budget := &viewBudget{view: "HTTP/3"}
	if err := budget.reserveNodes(selected+1, "replay messages"); err != nil {
		return "", err
	}
	unidirectional := false
	if f.Metadata != nil {
		value, _ := f.Metadata.Get("quic_is_unidirectional")
		unidirectional, _ = value.(bool)
	}
	var buffers [2][]byte
	initialDirection := f.Messages[0] != nil && f.Messages[0].FromClient
	streamSeen := !unidirectional
	inputBytes := 0
	var output strings.Builder
	appendText := func(text string) error {
		if output.Len() != 0 {
			if err := http3Write(&output, budget, "\n\n"); err != nil {
				return err
			}
		}
		output.WriteString(text)
		return nil
	}
	for i, message := range f.Messages[:selected+1] {
		if message == nil {
			return "", fmt.Errorf("nil HTTP/3 replay message")
		}
		if len(message.Content) > maxViewBytes-inputBytes {
			return "", &LimitError{View: "HTTP/3", Stage: "replay", Bound: "input bytes"}
		}
		inputBytes += len(message.Content)
		direction := 0
		if message.FromClient {
			direction = 1
		}
		buffer := append(buffers[direction], message.Content...)
		if !streamSeen && message.FromClient == initialDirection {
			stream, n, err := readHTTP3Varint(buffer)
			if err != nil {
				buffers[direction] = buffer
				continue
			}
			streamSeen = true
			buffer = buffer[n:]
			if i == selected {
				text := http3StreamName(stream)
				if err := budget.reserveBytes(len(text), "stream type"); err != nil {
					return "", err
				}
				if err := appendText(text); err != nil {
					return "", err
				}
			}
		}
		for len(buffer) != 0 {
			typ, n, err := readHTTP3Varint(buffer)
			if err != nil {
				break
			}
			size, m, err := readHTTP3Varint(buffer[n:])
			if err != nil {
				break
			}
			if size > maxViewBytes {
				return "", &LimitError{View: "HTTP/3", Stage: "frame", Bound: "payload bytes"}
			}
			if size > uint64(len(buffer)-n-m) {
				break
			}
			if err := budget.reserveNodes(1, "frame"); err != nil {
				return "", err
			}
			if i == selected {
				text, err := renderHTTP3Frame(typ, buffer[n+m:n+m+int(size)], budget)
				if err != nil {
					return "", err
				}
				if err := appendText(text); err != nil {
					return "", err
				}
			}
			buffer = buffer[n+m+int(size):]
		}
		buffers[direction] = buffer
	}
	return output.String(), nil
}

func readHTTP3Varint(data []byte) (uint64, int, error) {
	if len(data) == 0 || len(data) < 1<<(data[0]>>6) {
		return 0, 0, errors.New("Read out of bounds") //nolint:staticcheck // Preserve the pinned buffer-reader error text.
	}
	return quicvarint.Parse(data)
}

func http3StreamName(typ uint64) string {
	switch typ {
	case 0:
		return "Control Stream"
	case 1:
		return "Push Stream"
	case 2:
		return "QPACK Encoder Stream"
	case 3:
		return "QPACK Decoder Stream"
	default:
		return fmt.Sprintf("0x%x Stream", typ)
	}
}

func http3Write(out *strings.Builder, budget *viewBudget, text string) error {
	if err := budget.reserveBytes(len(text), "frame output"); err != nil {
		return err
	}
	out.WriteString(text)
	return nil
}

func renderHTTP3Frame(typ uint64, data []byte, budget *viewBudget) (string, error) {
	name := fmt.Sprintf("0x%x Frame", typ)
	switch typ {
	case 0:
		name = "DATA Frame"
	case 1:
		text, err := renderHTTP3Headers(data, budget)
		if err == nil {
			return text, nil
		}
		if _, limited := errors.AsType[*LimitError](err); limited {
			return "", err
		}
		name = "HEADERS Frame (error: invalid QPACK header block)"
	case 4:
		text, err := renderHTTP3Settings(data, budget)
		if err == nil {
			return text, nil
		}
		if _, limited := errors.AsType[*LimitError](err); limited {
			return "", err
		}
		name = "SETTINGS Frame (error: " + err.Error() + ")"
	}
	var out strings.Builder
	if err := http3Write(&out, budget, name+"\n"); err != nil {
		return "", err
	}
	rows := (len(data) + 15) / 16
	if err := budget.reserveNodes(rows, "hex rows"); err != nil {
		return "", err
	}
	size := 0
	for offset := 0; offset < len(data); offset += 16 {
		size += max(4, (bits.Len(uint(offset))+3)/4) + 4 + 50 + 3 + min(16, len(data)-offset)
		if offset != 0 {
			size++
		}
	}
	if err := budget.reserveBytes(size, "hex output"); err != nil {
		return "", err
	}
	text, err := (contentviews.HexDump{}).Prettify(data, contentviews.Metadata{})
	if err != nil {
		return "", err
	}
	out.WriteString(text)
	return out.String(), nil
}

func renderHTTP3Headers(data []byte, budget *viewBudget) (string, error) {
	var out strings.Builder
	if err := http3Write(&out, budget, "HEADERS Frame\n"); err != nil {
		return "", err
	}
	decode := qpack.NewDecoder().Decode(data)
	first := true
	for {
		field, err := decode()
		if errors.Is(err, io.EOF) {
			return out.String(), nil
		}
		if err != nil {
			return "", err
		}
		if err := budget.reserveNodes(1, "header"); err != nil {
			return "", err
		}
		if !first {
			if err := http3Write(&out, budget, "\n"); err != nil {
				return "", err
			}
		}
		first = false
		if err := http3UTF8(&out, budget, field.Name); err != nil {
			return "", err
		}
		if err := http3Write(&out, budget, ": "); err != nil {
			return "", err
		}
		if err := http3UTF8(&out, budget, field.Value); err != nil {
			return "", err
		}
	}
}

func http3UTF8(out *strings.Builder, budget *viewBudget, text string) error {
	for len(text) != 0 {
		r, n := utf8.DecodeRuneInString(text)
		part := text[:n]
		if r == utf8.RuneError && n == 1 {
			part = fmt.Sprintf("\\x%02x", text[0])
		}
		if err := http3Write(out, budget, part); err != nil {
			return err
		}
		text = text[n:]
	}
	return nil
}

func renderHTTP3Settings(data []byte, budget *viewBudget) (string, error) {
	var out strings.Builder
	if err := http3Write(&out, budget, "SETTINGS Frame\n"); err != nil {
		return "", err
	}
	seen := make(map[uint64]bool)
	for len(data) != 0 {
		key, n, err := readHTTP3Varint(data)
		if err != nil {
			return "", err
		}
		value, m, err := readHTTP3Varint(data[n:])
		if err != nil {
			return "", err
		}
		if key == 0 || key >= 2 && key <= 5 {
			return "", fmt.Errorf("Setting identifier 0x%x is reserved", key) //nolint:staticcheck // Preserve the upstream error text.
		}
		if seen[key] {
			return "", fmt.Errorf("Setting identifier 0x%x is included twice", key) //nolint:staticcheck // Preserve the upstream error text.
		}
		if err := budget.reserveNodes(1, "setting"); err != nil {
			return "", err
		}
		if len(seen) != 0 {
			if err := http3Write(&out, budget, "\n"); err != nil {
				return "", err
			}
		}
		seen[key] = true
		name := fmt.Sprintf("0x%x", key)
		switch key {
		case 1:
			name = "QPACK_MAX_TABLE_CAPACITY"
		case 6:
			name = "MAX_FIELD_SECTION_SIZE"
		case 7:
			name = "QPACK_BLOCKED_STREAMS"
		case 8:
			name = "ENABLE_CONNECT_PROTOCOL"
		case 0x33:
			name = "H3_DATAGRAM"
		case 0x2b603742:
			name = "ENABLE_WEBTRANSPORT"
		case 0x21:
			name = "DUMMY"
		}
		if err := http3Write(&out, budget, fmt.Sprintf("%s: 0x%x", name, value)); err != nil {
			return "", err
		}
		data = data[n+m:]
	}
	return out.String(), nil
}
