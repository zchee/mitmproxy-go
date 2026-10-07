// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package dns holds mitmproxy's DNS data model: messages, questions and
// resource records, and the protocol constants with their display names.
//
// Record data is kept as raw bytes. Pack and Unpack provide the wire codec,
// with domain-name and HTTPS/SVCB views over the record data. The serialised
// state matches mitmproxy's flow format 21.
package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/flow/state"
	"github.com/zchee/mitmproxy-go/internal/stateutil"
)

// DefaultTTL is the TTL, in seconds, upstream gives records it creates.
const DefaultTTL = 60

// Question is one entry of a message's question section.
type Question struct {
	Name  string
	Type  int
	Class int
}

// String returns the question's name.
func (q Question) String() string {
	return q.Name
}

// GetState returns q's serialised state.
func (q Question) GetState() *state.Map {
	m := state.NewMap(3)
	m.Set("name", q.Name)
	m.Set("type", int64(q.Type))
	m.Set("class_", int64(q.Class))
	return m
}

// QuestionFromState returns a Question built from a state dictionary,
// consuming it.
func QuestionFromState(v any) (Question, error) {
	m, err := state.AsDict(v)
	if err != nil {
		return Question{}, fmt.Errorf("%s.set_state: %w", "Question", err)
	}
	d := state.NewDecoder(m, "Question")
	q := Question{Name: d.String("name"), Type: int(d.Int("type")), Class: int(d.Int("class_"))}
	return q, d.Finish()
}

// ResourceRecord is one entry of an answer, authority or additional
// section. Data holds the record data as it appears on the wire.
type ResourceRecord struct {
	Name  string
	Type  int
	Class int
	TTL   int
	Data  []byte
}

// A returns an IPv4 address record in class IN.
func A(name string, ip netip.Addr, ttl int) ResourceRecord {
	b := ip.As4()
	return ResourceRecord{Name: name, Type: TypeA, Class: ClassIN, TTL: ttl, Data: b[:]}
}

// AAAA returns an IPv6 address record in class IN.
func AAAA(name string, ip netip.Addr, ttl int) ResourceRecord {
	b := ip.As16()
	return ResourceRecord{Name: name, Type: TypeAAAA, Class: ClassIN, TTL: ttl, Data: b[:]}
}

// TXT returns a text record in class IN whose data is text's UTF-8 bytes,
// as upstream builds it.
func TXT(name, text string, ttl int) ResourceRecord {
	return ResourceRecord{Name: name, Type: TypeTXT, Class: ClassIN, TTL: ttl, Data: []byte(text)}
}

// Text returns the record data as UTF-8 text.
func (r *ResourceRecord) Text() (string, error) {
	if !utf8.Valid(r.Data) {
		return "", errors.New("record data is not valid UTF-8")
	}
	return string(r.Data), nil
}

// SetText sets the record data to text's UTF-8 bytes.
func (r *ResourceRecord) SetText(text string) {
	r.Data = []byte(text)
}

// IPv4Address returns the record data as an IPv4 address. It fails unless
// the data is exactly four bytes.
func (r *ResourceRecord) IPv4Address() (netip.Addr, error) {
	if len(r.Data) != 4 {
		return netip.Addr{}, fmt.Errorf("expected 4 bytes of IPv4 address data, got %d", len(r.Data))
	}
	return netip.AddrFrom4([4]byte(r.Data)), nil
}

// SetIPv4Address sets the record data to the four bytes of ip.
func (r *ResourceRecord) SetIPv4Address(ip netip.Addr) {
	b := ip.As4()
	r.Data = b[:]
}

// IPv6Address returns the record data as an IPv6 address. It fails unless
// the data is exactly sixteen bytes.
func (r *ResourceRecord) IPv6Address() (netip.Addr, error) {
	if len(r.Data) != 16 {
		return netip.Addr{}, fmt.Errorf("expected 16 bytes of IPv6 address data, got %d", len(r.Data))
	}
	return netip.AddrFrom16([16]byte(r.Data)), nil
}

// SetIPv6Address sets the record data to the sixteen bytes of ip.
func (r *ResourceRecord) SetIPv6Address(ip netip.Addr) {
	b := ip.As16()
	r.Data = b[:]
}

// GetState returns r's serialised state.
func (r *ResourceRecord) GetState() *state.Map {
	m := state.NewMap(5)
	m.Set("name", r.Name)
	m.Set("type", int64(r.Type))
	m.Set("class_", int64(r.Class))
	m.Set("ttl", int64(r.TTL))
	m.Set("data", stateutil.Bytes(r.Data))
	return m
}

// ResourceRecordFromState returns a ResourceRecord built from a state
// dictionary, consuming it.
func ResourceRecordFromState(v any) (ResourceRecord, error) {
	m, err := state.AsDict(v)
	if err != nil {
		return ResourceRecord{}, fmt.Errorf("ResourceRecord.set_state: %w", err)
	}
	d := state.NewDecoder(m, "ResourceRecord")
	r := ResourceRecord{
		Name:  d.String("name"),
		Type:  int(d.Int("type")),
		Class: int(d.Int("class_")),
		TTL:   int(d.Int("ttl")),
		Data:  d.Bytes("data"),
	}
	return r, d.Finish()
}

// Clone returns a deep copy of r.
func (r ResourceRecord) Clone() ResourceRecord {
	r.Data = slices.Clone(r.Data)
	return r
}

// Message is a DNS message. Field comments follow RFC 1035.
type Message struct {
	// ID is assigned by the program that generates a query and copied into
	// the response.
	ID int
	// Query reports whether the message is a query rather than a response.
	Query bool
	// OpCode is the kind of query, copied into the response.
	OpCode int
	// AuthoritativeAnswer reports, in a response, that the responding name
	// server is an authority for the domain name in question.
	AuthoritativeAnswer bool
	// Truncation reports that the message was truncated.
	Truncation bool
	// RecursionDesired asks the name server to pursue the query
	// recursively; it is copied into the response.
	RecursionDesired bool
	// RecursionAvailable reports, in a response, whether the name server
	// supports recursive queries.
	RecursionAvailable bool
	// Reserved must be zero in queries and responses.
	Reserved int
	// ResponseCode is set in responses.
	ResponseCode int
	// Questions carry what is being asked.
	Questions []Question
	// Answers is the first resource record section.
	Answers []ResourceRecord
	// Authorities is the second resource record section.
	Authorities []ResourceRecord
	// Additionals is the third resource record section.
	Additionals []ResourceRecord
	// Timestamp is when the message was sent or received.
	Timestamp *float64
}

// String lists the names of every question and the data of every record,
// one per line, separated by "\r\n" as upstream does. Records whose data
// needs the wire codec to display are shown in hexadecimal.
func (m *Message) String() string {
	var lines []string
	for _, q := range m.Questions {
		lines = append(lines, q.String())
	}
	for _, sec := range [][]ResourceRecord{m.Answers, m.Authorities, m.Additionals} {
		for i := range sec {
			lines = append(lines, sec[i].displayData())
		}
	}
	return strings.Join(lines, "\r\n")
}

// displayData renders the record data the way upstream's str() does for
// the types that need no wire codec.
func (r *ResourceRecord) displayData() string {
	invalid := fmt.Sprintf("0x%x (invalid %s data)", r.Data, TypeToString(r.Type))
	switch r.Type {
	case TypeA:
		ip, err := r.IPv4Address()
		if err != nil {
			return invalid
		}
		return ip.String()
	case TypeAAAA:
		ip, err := r.IPv6Address()
		if err != nil {
			return invalid
		}
		return ip.String()
	case TypeTXT:
		s, err := r.Text()
		if err != nil {
			return invalid
		}
		return s
	}
	return fmt.Sprintf("0x%x", r.Data)
}

// Question returns the only question of the message. DNS practically
// supports one question at a time; it reports false when there are none or
// several.
func (m *Message) Question() (Question, bool) {
	if len(m.Questions) == 1 {
		return m.Questions[0], true
	}
	return Question{}, false
}

// Size returns the total size of the record data in all three resource
// record sections.
func (m *Message) Size() int {
	n := 0
	for _, sec := range [][]ResourceRecord{m.Answers, m.Authorities, m.Additionals} {
		for _, r := range sec {
			n += len(r.Data)
		}
	}
	return n
}

// Fail returns an error response to m with the given response code. The
// code must not be NOERROR.
func (m *Message) Fail(responseCode int) (*Message, error) {
	if responseCode == ResponseCodeNOERROR {
		return nil, errors.New("response_code must be an error code")
	}
	return m.respond(responseCode, false, []ResourceRecord{}), nil
}

// Succeed returns a successful response to m carrying answers.
func (m *Message) Succeed(answers []ResourceRecord) *Message {
	return m.respond(ResponseCodeNOERROR, true, answers)
}

func (m *Message) respond(rcode int, recursionAvailable bool, answers []ResourceRecord) *Message {
	now := stateutil.Now()
	return &Message{
		Timestamp:          &now,
		ID:                 m.ID,
		OpCode:             m.OpCode,
		RecursionDesired:   m.RecursionDesired,
		RecursionAvailable: recursionAvailable,
		ResponseCode:       rcode,
		Questions:          slices.Clone(m.Questions),
		Answers:            answers,
		Authorities:        []ResourceRecord{},
		Additionals:        []ResourceRecord{},
	}
}

// GetState returns m's serialised state.
func (m *Message) GetState() *state.Map {
	s := state.NewMap(14)
	s.Set("id", int64(m.ID))
	s.Set("query", m.Query)
	s.Set("op_code", int64(m.OpCode))
	s.Set("authoritative_answer", m.AuthoritativeAnswer)
	s.Set("truncation", m.Truncation)
	s.Set("recursion_desired", m.RecursionDesired)
	s.Set("recursion_available", m.RecursionAvailable)
	s.Set("reserved", int64(m.Reserved))
	s.Set("response_code", int64(m.ResponseCode))
	qs := make([]any, len(m.Questions))
	for i, q := range m.Questions {
		qs[i] = q.GetState()
	}
	s.Set("questions", qs)
	s.Set("answers", recordsState(m.Answers))
	s.Set("authorities", recordsState(m.Authorities))
	s.Set("additionals", recordsState(m.Additionals))
	s.Set("timestamp", stateutil.Opt(m.Timestamp))
	return s
}

func recordsState(rs []ResourceRecord) []any {
	out := make([]any, len(rs))
	for i := range rs {
		out[i] = rs[i].GetState()
	}
	return out
}

// SetState replaces m's fields with those in s, consuming s. On error m is
// left unchanged.
func (m *Message) SetState(s *state.Map) error {
	d := state.NewDecoder(s, "DNSMessage")
	n := Message{
		ID:                  int(d.Int("id")),
		Query:               d.Bool("query"),
		OpCode:              int(d.Int("op_code")),
		AuthoritativeAnswer: d.Bool("authoritative_answer"),
		Truncation:          d.Bool("truncation"),
		RecursionDesired:    d.Bool("recursion_desired"),
		RecursionAvailable:  d.Bool("recursion_available"),
		Reserved:            int(d.Int("reserved")),
		ResponseCode:        int(d.Int("response_code")),
	}
	n.Questions = decodeList(d, "questions", QuestionFromState)
	n.Answers = decodeList(d, "answers", ResourceRecordFromState)
	n.Authorities = decodeList(d, "authorities", ResourceRecordFromState)
	n.Additionals = decodeList(d, "additionals", ResourceRecordFromState)
	n.Timestamp = d.OptFloat("timestamp")
	if err := d.Finish(); err != nil {
		return err
	}
	*m = n
	return nil
}

func decodeList[T any](d *state.Decoder, key string, f func(any) (T, error)) []T {
	v := d.Any(key)
	if d.Err() != nil {
		return nil
	}
	l, err := state.ListOf(v, f)
	if err != nil {
		d.Fail(fmt.Errorf("field %q: %w", key, err))
	}
	return l
}

// MessageFromState returns a new Message built from s, consuming s.
func MessageFromState(s *state.Map) (*Message, error) {
	m := &Message{}
	if err := m.SetState(s); err != nil {
		return nil, err
	}
	return m, nil
}

// Clone returns a deep copy of m.
func (m *Message) Clone() *Message {
	out := *m
	out.Questions = slices.Clone(m.Questions)
	out.Answers = cloneRecords(m.Answers)
	out.Authorities = cloneRecords(m.Authorities)
	out.Additionals = cloneRecords(m.Additionals)
	if m.Timestamp != nil {
		ts := *m.Timestamp
		out.Timestamp = &ts
	}
	return &out
}

func cloneRecords(rs []ResourceRecord) []ResourceRecord {
	if rs == nil {
		return nil
	}
	out := make([]ResourceRecord, len(rs))
	for i, r := range rs {
		out[i] = r.Clone()
	}
	return out
}
