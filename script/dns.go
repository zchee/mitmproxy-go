// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package script

import (
	"errors"
	"fmt"
	"net/netip"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"

	"github.com/zchee/mitmproxy-go/dns"
)

type dnsValue struct {
	*object
	i       *invocation
	message *dns.Message
}
type recordValue struct {
	*object
	i      *invocation
	record *dns.ResourceRecord
}

func wrapQuestion(i *invocation, q *dns.Question) starlark.Value {
	return &object{kind: "dns_question", check: i.modelCheck, names: []string{"name", "type", "class"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "name":
			return starlark.String(q.Name), nil
		case "type":
			return starlark.MakeInt(q.Type), nil
		case "class":
			return starlark.MakeInt(q.Class), nil
		}
		return nil, nil
	}, set: func(name string, value starlark.Value) error {
		if name == "name" {
			x, err := stringValue(value)
			if err == nil {
				q.Name = x
			}
			return err
		}
		n, err := dnsInteger(value)
		if err != nil {
			return err
		}
		switch name {
		case "type":
			q.Type = n
		case "class":
			q.Class = n
		default:
			return fmt.Errorf("dns_question.%s is read-only", name)
		}
		return nil
	}}
}

func dnsInteger(value starlark.Value) (int, error) {
	n, err := intValue(value)
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 65535 {
		return 0, errors.New("DNS integer is outside 0..65535")
	}
	return n, nil
}

func wrapRecord(i *invocation, r *dns.ResourceRecord) starlark.Value {
	v := &recordValue{i: i, record: r}
	v.object = &object{kind: "dns_record", check: i.modelCheck, names: []string{"name", "type", "class", "ttl", "data", "text", "ipv4_address", "ipv6_address"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "name":
			return starlark.String(r.Name), nil
		case "type":
			return starlark.MakeInt(r.Type), nil
		case "class":
			return starlark.MakeInt(r.Class), nil
		case "ttl":
			return starlark.MakeInt(r.TTL), nil
		case "data":
			return starlark.Bytes(r.Data), nil
		case "text":
			text, err := r.Text()
			return starlark.String(text), err
		case "ipv4_address":
			ip, err := r.IPv4Address()
			return starlark.String(ip.String()), err
		case "ipv6_address":
			ip, err := r.IPv6Address()
			return starlark.String(ip.String()), err
		}
		return nil, nil
	}, set: func(name string, value starlark.Value) error {
		switch name {
		case "name":
			x, err := stringValue(value)
			if err == nil {
				r.Name = x
			}
			return err
		case "data":
			x, err := bytesValue(value)
			if err == nil {
				r.Data = x
			}
			return err
		case "type", "class":
			n, err := dnsInteger(value)
			if err == nil {
				if name == "type" {
					r.Type = n
				} else {
					r.Class = n
				}
			}
			return err
		case "ttl":
			n, err := intValue(value)
			if err != nil {
				return err
			}
			if n < 0 || uint64(n) > 1<<32-1 {
				return errors.New("TTL is outside unsigned 32-bit range")
			}
			r.TTL = n
			return nil
		case "text":
			x, err := stringValue(value)
			if err == nil {
				r.SetText(x)
			}
			return err
		case "ipv4_address", "ipv6_address":
			text, err := stringValue(value)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(text)
			if err != nil {
				return err
			}
			if name == "ipv4_address" {
				if !ip.Is4() {
					return errors.New("IPv4 address required")
				}
				r.SetIPv4Address(ip)
			} else {
				if !ip.Is6() {
					return errors.New("IPv6 address required")
				}
				r.SetIPv6Address(ip)
			}
			return nil
		}
		return fmt.Errorf("dns_record.%s is read-only", name)
	}}
	return v
}

func nativeRecords(value starlark.Value) ([]dns.ResourceRecord, error) {
	seq, ok := value.(starlark.Indexable)
	if !ok || seq.Len() > conversionLimit {
		return nil, errors.New("bounded DNS record sequence required")
	}
	out := make([]dns.ResourceRecord, seq.Len())
	for n := range seq.Len() {
		r, ok := seq.Index(n).(*recordValue)
		if !ok {
			return nil, errors.New("DNS record required")
		}
		if err := r.i.modelCheck(); err != nil {
			return nil, err
		}
		out[n] = r.record.Clone()
	}
	return out, nil
}

func wrapDNS(i *invocation, m *dns.Message) starlark.Value {
	if m == nil {
		return starlark.None
	}
	v := &dnsValue{i: i, message: m}
	v.object = &object{kind: "dns_message", check: i.modelCheck, names: []string{"id", "query", "op_code", "authoritative_answer", "truncation", "recursion_desired", "recursion_available", "reserved", "response_code", "question", "questions", "answers", "authorities", "additionals", "succeed", "fail"}, get: func(name string) (starlark.Value, error) {
		switch name {
		case "id":
			return starlark.MakeInt(m.ID), nil
		case "query":
			return starlark.Bool(m.Query), nil
		case "op_code":
			return starlark.MakeInt(m.OpCode), nil
		case "reserved":
			return starlark.MakeInt(m.Reserved), nil
		case "response_code":
			return starlark.MakeInt(m.ResponseCode), nil
		case "authoritative_answer":
			return starlark.Bool(m.AuthoritativeAnswer), nil
		case "truncation":
			return starlark.Bool(m.Truncation), nil
		case "recursion_desired":
			return starlark.Bool(m.RecursionDesired), nil
		case "recursion_available":
			return starlark.Bool(m.RecursionAvailable), nil
		case "question":
			if len(m.Questions) != 1 {
				return starlark.None, nil
			}
			return wrapQuestion(i, &m.Questions[0]), nil
		case "questions":
			values := make([]starlark.Value, len(m.Questions))
			for n := range m.Questions {
				values[n] = wrapQuestion(i, &m.Questions[n])
			}
			return starlark.NewList(values), nil
		case "answers", "authorities", "additionals":
			var records []dns.ResourceRecord
			switch name {
			case "answers":
				records = m.Answers
			case "authorities":
				records = m.Authorities
			case "additionals":
				records = m.Additionals
			}
			values := make([]starlark.Value, len(records))
			for n := range records {
				values[n] = wrapRecord(i, &records[n])
			}
			return starlark.NewList(values), nil
		case "succeed":
			return builtin("dns.succeed", i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var value starlark.Value
				if err := starlark.UnpackArgs("dns.succeed", args, kwargs, "answers", &value); err != nil {
					return nil, err
				}
				records, err := nativeRecords(value)
				if err != nil {
					return nil, err
				}
				return wrapDNS(i, m.Succeed(records)), nil
			}), nil
		case "fail":
			return builtin("dns.fail", i.modelCheck, func(_ *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var code int
				if err := starlark.UnpackArgs("dns.fail", args, kwargs, "response_code", &code); err != nil {
					return nil, err
				}
				message, err := m.Fail(code)
				if err != nil {
					return nil, err
				}
				return wrapDNS(i, message), nil
			}), nil
		}
		return nil, nil
	}, set: func(name string, value starlark.Value) error {
		switch name {
		case "answers", "authorities", "additionals":
			records, err := nativeRecords(value)
			if err != nil {
				return err
			}
			switch name {
			case "answers":
				m.Answers = records
			case "authorities":
				m.Authorities = records
			case "additionals":
				m.Additionals = records
			}
			return nil
		case "id", "op_code", "reserved", "response_code":
			n, err := dnsInteger(value)
			if err != nil {
				return err
			}
			switch name {
			case "id":
				m.ID = n
			case "op_code":
				m.OpCode = n
			case "reserved":
				m.Reserved = n
			case "response_code":
				m.ResponseCode = n
			}
			return nil
		case "query", "authoritative_answer", "truncation", "recursion_desired", "recursion_available":
			x, err := boolValue(value)
			if err != nil {
				return err
			}
			switch name {
			case "query":
				m.Query = x
			case "authoritative_answer":
				m.AuthoritativeAnswer = x
			case "truncation":
				m.Truncation = x
			case "recursion_desired":
				m.RecursionDesired = x
			case "recursion_available":
				m.RecursionAvailable = x
			}
			return nil
		}
		return fmt.Errorf("dns_message.%s is read-only", name)
	}}
	return v
}

func dnsLibrary(g *capabilities) starlark.Value {
	records := starlark.StringDict{"DEFAULT_TTL": starlark.MakeInt(60)}
	for _, kind := range []string{"A", "AAAA", "TXT"} {
		records[kind] = builtin("dns.ResourceRecord."+kind, g.check, func(thread *starlark.Thread, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			i, err := threadInvocation(thread)
			if err != nil {
				return nil, err
			}
			var name, data string
			ttl := 60
			if err := starlark.UnpackArgs(kind, args, kwargs, "name", &name, "data", &data, "ttl?", &ttl); err != nil {
				return nil, err
			}
			if ttl < 0 || uint64(ttl) > 1<<32-1 {
				return nil, errors.New("TTL is outside unsigned 32-bit range")
			}
			var record dns.ResourceRecord
			if kind == "TXT" {
				record = dns.TXT(name, data, ttl)
			} else {
				ip, err := netip.ParseAddr(data)
				if err != nil {
					return nil, err
				}
				if kind == "A" {
					if !ip.Is4() {
						return nil, errors.New("IPv4 address required")
					}
					record = dns.A(name, ip, ttl)
				} else {
					if !ip.Is6() {
						return nil, errors.New("IPv6 address required")
					}
					record = dns.AAAA(name, ip, ttl)
				}
			}
			return wrapRecord(i, &record), nil
		})
	}
	return &starlarkstruct.Module{Name: "dns", Members: starlark.StringDict{
		"ResourceRecord": &starlarkstruct.Module{Name: "ResourceRecord", Members: records},
		"types":          &starlarkstruct.Module{Name: "types", Members: starlark.StringDict{"A": starlark.MakeInt(dns.TypeA), "AAAA": starlark.MakeInt(dns.TypeAAAA), "TXT": starlark.MakeInt(dns.TypeTXT)}},
		"classes":        &starlarkstruct.Module{Name: "classes", Members: starlark.StringDict{"IN": starlark.MakeInt(1)}},
		"response_codes": &starlarkstruct.Module{Name: "response_codes", Members: starlark.StringDict{"NOERROR": starlark.MakeInt(0), "NXDOMAIN": starlark.MakeInt(3)}},
	}}
}
