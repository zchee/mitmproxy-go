// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dns

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/omap"
)

var svcParamNames = []string{"mandatory", "alpn", "no_default_alpn", "port", "ipv4hint", "ech", "ipv6hint"}

// ToJSON returns an owned, insertion-ordered mitmweb representation of m.
// Record data is decoded for display; malformed known types remain hexadecimal.
// Reserved bits are omitted, and a nil or zero timestamp is not emitted.
func (m *Message) ToJSON() *omap.Map[any] {
	value := omap.NewWithCapacity[any](15)
	value.Set("id", m.ID)
	value.Set("query", m.Query)
	value.Set("op_code", OpCodeToString(m.OpCode))
	value.Set("authoritative_answer", m.AuthoritativeAnswer)
	value.Set("truncation", m.Truncation)
	value.Set("recursion_desired", m.RecursionDesired)
	value.Set("recursion_available", m.RecursionAvailable)
	value.Set("response_code", ResponseCodeToString(m.ResponseCode))
	value.Set("status_code", HTTPEquivStatusCode(m.ResponseCode))
	questions := make([]any, len(m.Questions))
	for i, question := range m.Questions {
		q := omap.NewWithCapacity[any](3)
		q.Set("name", question.Name)
		q.Set("type", TypeToString(question.Type))
		q.Set("class", ClassToString(question.Class))
		questions[i] = q
	}
	value.Set("questions", questions)
	for i, records := range [][]ResourceRecord{m.Answers, m.Authorities, m.Additionals} {
		section := make([]any, len(records))
		for j := range records {
			r := &records[j]
			record := omap.NewWithCapacity[any](5)
			record.Set("name", r.Name)
			record.Set("type", TypeToString(r.Type))
			record.Set("class", ClassToString(r.Class))
			record.Set("ttl", r.TTL)
			record.Set("data", recordDataJSON(r))
			section[j] = record
		}
		value.Set([]string{"answers", "authorities", "additionals"}[i], section)
	}
	value.Set("size", m.Size())
	if m.Timestamp != nil && *m.Timestamp != 0 {
		value.Set("timestamp", *m.Timestamp)
	}
	return value
}

func recordDataJSON(r *ResourceRecord) any {
	var value any
	var err error
	switch r.Type {
	case TypeA:
		var address netip.Addr
		address, err = r.IPv4Address()
		value = address.String()
	case TypeAAAA:
		var address netip.Addr
		address, err = r.IPv6Address()
		value = address.String()
	case TypeNS, TypeCNAME, TypePTR:
		value, err = r.DomainName()
	case TypeTXT:
		value, err = r.Text()
	case TypeHTTPS:
		var record HTTPSRecord
		record, err = UnpackHTTPS(r.Data)
		if err == nil {
			object := omap.NewWithCapacity[any](len(record.Params) + 2)
			object.Set("target_name", record.TargetName)
			object.Set("priority", record.Priority)
			for _, param := range record.Params {
				key := strconv.Itoa(int(param.Key))
				if int(param.Key) < len(svcParamNames) {
					key = svcParamNames[param.Key]
				}
				object.Set(key, strutil.BytesToEscapedStr(param.Value, false, false))
			}
			value = object
		}
	default:
		return "0x" + hex.EncodeToString(r.Data)
	}
	if err != nil {
		return fmt.Sprintf("0x%x (invalid %s data)", r.Data, TypeToString(r.Type))
	}
	return value
}

// MessageFromJSON reconstructs a DNS message from its mitmweb representation.
// It does not consume value or its nested objects. Invalid fields or RDATA return
// an error without a partial message; display-only size/status fields are ignored.
func MessageFromJSON(value *omap.Map[any]) (*Message, error) {
	if value == nil {
		return nil, fmt.Errorf("nil DNS JSON message")
	}
	d := state.NewDecoder(value.Clone(), "DNSMessage JSON")
	m := &Message{
		ID: int(d.Int("id")), Query: d.Bool("query"),
		AuthoritativeAnswer: d.Bool("authoritative_answer"), Truncation: d.Bool("truncation"),
		RecursionDesired: d.Bool("recursion_desired"), RecursionAvailable: d.Bool("recursion_available"),
	}
	var err error
	m.OpCode, err = OpCodeFromString(d.String("op_code"))
	if err != nil {
		return nil, err
	}
	m.ResponseCode, err = ResponseCodeFromString(d.String("response_code"))
	if err != nil {
		return nil, err
	}
	m.Questions, err = state.ListOf(d.Any("questions"), questionFromJSON)
	if err != nil {
		return nil, err
	}
	for i, section := range []*[]ResourceRecord{&m.Answers, &m.Authorities, &m.Additionals} {
		*section, err = state.ListOf(d.Any([]string{"answers", "authorities", "additionals"}[i]), recordFromJSON)
		if err != nil {
			return nil, err
		}
	}
	if value.Has("timestamp") {
		m.Timestamp = d.OptFloat("timestamp")
		if m.Timestamp != nil && *m.Timestamp == 0 {
			m.Timestamp = nil
		}
	}
	if err := d.Err(); err != nil {
		return nil, err
	}
	return m, nil
}

func questionFromJSON(value any) (Question, error) {
	object, err := state.AsDict(value)
	if err != nil {
		return Question{}, err
	}
	d := state.NewDecoder(object.Clone(), "DNS question JSON")
	q := Question{Name: d.String("name")}
	q.Type, err = TypeFromString(d.String("type"))
	if err != nil {
		return Question{}, err
	}
	q.Class, err = ClassFromString(d.String("class"))
	if err != nil {
		return Question{}, err
	}
	return q, d.Err()
}

func recordFromJSON(value any) (ResourceRecord, error) {
	object, err := state.AsDict(value)
	if err != nil {
		return ResourceRecord{}, err
	}
	d := state.NewDecoder(object.Clone(), "DNS resource JSON")
	r := ResourceRecord{Name: d.String("name"), TTL: int(d.Int("ttl"))}
	r.Type, err = TypeFromString(d.String("type"))
	if err != nil {
		return ResourceRecord{}, err
	}
	r.Class, err = ClassFromString(d.String("class"))
	if err != nil {
		return ResourceRecord{}, err
	}
	data := d.Any("data")
	if err := d.Err(); err != nil {
		return ResourceRecord{}, err
	}
	text, isText := data.(string)
	if isText && len(text) > maxWireSize*4 {
		return ResourceRecord{}, &limitError{resource: "record JSON text", limit: maxWireSize * 4}
	}
	switch r.Type {
	case TypeA, TypeAAAA:
		var address netip.Addr
		address, err = netip.ParseAddr(text)
		if err == nil && (r.Type == TypeA && address.Is4() || r.Type == TypeAAAA && address.Is6()) {
			if r.Type == TypeA {
				r.SetIPv4Address(address)
			} else {
				r.SetIPv6Address(address)
			}
			return r, nil
		}
	case TypeNS, TypeCNAME, TypePTR:
		if isText {
			err = r.SetDomainName(text)
			if err == nil {
				return r, nil
			}
		}
	case TypeTXT:
		if isText {
			if len(text) > maxWireSize {
				return ResourceRecord{}, &limitError{resource: "TXT RDATA", limit: maxWireSize}
			}
			r.SetText(text)
			return r, nil
		}
	case TypeHTTPS:
		if !isText {
			r.Data, err = httpsFromJSON(data)
			return r, err
		}
	}
	if !isText {
		return ResourceRecord{}, fmt.Errorf("DNS record data must be text or an HTTPS object")
	}
	text = strings.TrimPrefix(text, "0x")
	text, _, _ = strings.Cut(text, " (")
	r.Data, err = hex.DecodeString(text)
	if err == nil && len(r.Data) > maxWireSize {
		return ResourceRecord{}, &limitError{resource: "record data", limit: maxWireSize}
	}
	return r, err
}

func httpsFromJSON(value any) ([]byte, error) {
	object, err := state.AsDict(value)
	if err != nil {
		return nil, err
	}
	d := state.NewDecoder(object.Clone(), "HTTPS record JSON")
	record := HTTPSRecord{TargetName: d.String("target_name"), Priority: int(d.Int("priority")), Params: []HTTPSParam{}}
	if err := d.Err(); err != nil {
		return nil, err
	}
	for _, key := range object.Keys() {
		if key == "target_name" || key == "priority" {
			continue
		}
		typ, err := strconv.Atoi(key)
		for i, name := range svcParamNames {
			if strings.EqualFold(key, name) {
				typ, err = i, nil
				break
			}
		}
		if err != nil || typ < 0 || typ > 65535 {
			return nil, fmt.Errorf("unknown HTTPS service parameter %q", key)
		}
		value, _ := object.Get(key)
		text, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("HTTPS parameter %q must be text", key)
		}
		if len(text) > maxWireSize*4 {
			return nil, &limitError{resource: "HTTPS parameter JSON text", limit: maxWireSize * 4}
		}
		bytes, err := strutil.EscapedStrToBytes(text)
		if err != nil {
			return nil, err
		}
		record.Params = append(record.Params, HTTPSParam{Key: uint16(typ), Value: bytes})
	}
	return PackHTTPS(record)
}
