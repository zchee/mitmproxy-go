// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package h2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strconv"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func validateUpgrade(cfg *Config) error {
	u := cfg.Upgrade
	if u == nil {
		return nil
	}
	if cfg.Client {
		return errors.New("h2: Upgrade requires the server role")
	}
	if len(u.Body) > InitialStreamWindow {
		return fmt.Errorf("h2: upgrade body exceeds initial stream window limit of %d bytes", InitialStreamWindow)
	}
	o := &owner{e: &Endpoint{cfg: *cfg}, peerInitial: 65535, controls: []*writeFrame{{kind: writeInitial}}}
	if err := upgradeParameters(u.Settings, o.applySetting); err != nil {
		return err
	}
	var size uint64
	for _, field := range u.Headers {
		size += uint64(len(field.Name) + len(field.Value) + 32)
		if size > maxHeaderBytes {
			return protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 header list too large")
		}
	}
	if cfg.ValidateInboundHeaders {
		if err := validateFields(u.Headers); err != nil {
			return err
		}
	}
	if err := checkPseudo(u.Headers, false); err != nil {
		return err
	}
	s := &streamState{contentLength: -1, received: int64(len(u.Body))}
	if err := s.setContentLength(u.Headers); err != nil {
		return err
	}
	if err := s.checkLength(true); err != nil {
		return err
	}
	cfg.Upgrade = &UpgradeRequest{Settings: slices.Clone(u.Settings), Headers: slices.Clone(u.Headers), Body: slices.Clone(u.Body)}
	return nil
}

func upgradeParameters(payload []byte, apply func(http2.Setting) error) error {
	if len(payload)%6 != 0 {
		return http2.ConnectionError(http2.ErrCodeFrameSize)
	}
	if len(payload) > MaxFrameSize {
		return protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 upgrade SETTINGS payload too large")
	}
	for len(payload) > 0 {
		setting := http2.Setting{ID: http2.SettingID(binary.BigEndian.Uint16(payload)), Val: binary.BigEndian.Uint32(payload[2:])}
		if err := apply(setting); err != nil {
			return err
		}
		payload = payload[6:]
	}
	return nil
}

func (o *owner) seedUpgrade() {
	u := o.e.cfg.Upgrade
	// New already validated every parameter; no wire acknowledgement is needed
	// because the HTTP/1 switching response acknowledges HTTP2-Settings.
	if err := upgradeParameters(u.Settings, o.applySetting); err != nil {
		panic("h2: validated upgrade settings changed")
	}
	s := o.newStream(1)
	s.inHeaders, s.remoteEnd = true, true
	s.received = int64(len(u.Body))
	s.window.available -= len(u.Body)
	o.lastPeer = 1
	o.connectionEvents = append(o.connectionEvents, Event{Kind: Headers, Identity: s.id, Headers: u.Headers, EndStream: len(u.Body) == 0})
	body := u.Body
	for len(body) > 0 {
		n := min(len(body), ChunkSize)
		chunk := make([]byte, n, ChunkSize)
		copy(chunk, body[:n])
		body = body[n:]
		s.queue = append(s.queue, queuedEvent{event: Event{Kind: Data, Identity: s.id, Data: chunk, EndStream: len(body) == 0}, original: n})
	}
}

func (o *owner) applySetting(setting http2.Setting) error {
	if len(o.controls) >= MaxConcurrentStreams*2 {
		return protocolError(http2.ErrCodeEnhanceYourCalm, "HTTP/2 control queue limit exceeded")
	}
	if err := setting.Valid(); err != nil {
		return err
	}
	switch setting.ID {
	case http2.SettingMaxConcurrentStreams:
		o.peerConcurrent = min(setting.Val, MaxConcurrentStreams)
	case http2.SettingInitialWindowSize:
		delta := int64(setting.Val) - o.peerInitial
		for _, s := range o.streams {
			if s.outWindow+delta > 0x7fffffff {
				return protocolError(http2.ErrCodeFlowControl, "HTTP/2 stream window overflow after SETTINGS")
			}
			s.outWindow += delta
		}
		o.peerInitial = int64(setting.Val)
	case http2.SettingMaxFrameSize:
		o.peerFrame = setting.Val
	case http2.SettingHeaderTableSize:
		return o.queueControl(&writeFrame{kind: writeTableLimit, value: setting.Val})
	case http2.SettingMaxHeaderListSize:
		o.peerHeaders = setting.Val
	case http2.SettingEnablePush:
		if o.e.cfg.Client {
			return protocolError(http2.ErrCodeProtocol, "HTTP/2 server sent ENABLE_PUSH")
		}
	}
	return nil
}

func (s *streamState) setContentLength(fields []hpack.HeaderField) error {
	for _, field := range fields {
		if field.Name == "content-length" {
			length, err := strconv.ParseInt(field.Value, 10, 64)
			if err != nil || length < 0 || s.contentLength >= 0 && s.contentLength != length {
				return protocolError(http2.ErrCodeProtocol, "Invalid HTTP/2 content-length")
			}
			s.contentLength = length
		}
	}
	return nil
}
