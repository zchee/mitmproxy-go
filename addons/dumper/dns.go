// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dumper

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/zchee/mitmproxy-go/dns"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/pyrepr"
	"github.com/zchee/mitmproxy-go/internal/strutil"
	"github.com/zchee/mitmproxy-go/internal/vtcodes"
)

// echoDNSQuery prints the query summary line: the client, the opcode and
// question type, and the question name.
func (d *Dumper) echoDNSQuery(f *flow.DNSFlow) error {
	var question dns.Question
	if len(f.Request.Questions) > 0 {
		question = f.Request.Questions[0]
	}
	questionType := dns.TypeToString(question.Type)
	color := "red"
	switch questionType {
	case "A":
		color = "green"
	case "AAAA":
		color = "magenta"
	}
	desc := d.style("DNS "+dns.OpCodeToString(f.Request.OpCode)+" ("+questionType+")", vtcodes.Style{FG: color})
	name := d.style(question.Name, vtcodes.Style{Bold: new(true)})
	return d.echo(d.fmtClient(f)+": "+desc+" "+name, 0, vtcodes.Style{})
}

// recordData renders upstream's str(ResourceRecord), including the Python
// dictionary representation of decoded HTTPS parameters.
func recordData(r *dns.ResourceRecord) string {
	invalid := func() string {
		return fmt.Sprintf("0x%x (invalid %s data)", r.Data, dns.TypeToString(r.Type))
	}
	switch r.Type {
	case dns.TypeA:
		ip, err := r.IPv4Address()
		if err != nil {
			return invalid()
		}
		return ip.String()
	case dns.TypeAAAA:
		ip, err := r.IPv6Address()
		if err != nil {
			return invalid()
		}
		return ip.String()
	case dns.TypeTXT:
		s, err := r.Text()
		if err != nil {
			return invalid()
		}
		return s
	case dns.TypeNS, dns.TypeCNAME, dns.TypePTR:
		name, err := r.DomainName()
		if err != nil {
			return invalid()
		}
		return name
	case dns.TypeHTTPS:
		record, err := dns.UnpackHTTPS(r.Data)
		if err != nil {
			return invalid()
		}
		out := pyrepr.AppendStr([]byte("{'target_name': "), record.TargetName)
		out = strconv.AppendInt(append(out, ", 'priority': "...), int64(record.Priority), 10)
		paramNames := [...]string{"mandatory", "alpn", "no_default_alpn", "port", "ipv4hint", "ech", "ipv6hint"}
		for _, param := range record.Params {
			out = append(out, ", "...)
			if int(param.Key) < len(paramNames) {
				out = pyrepr.AppendStr(out, paramNames[param.Key])
			} else {
				out = strconv.AppendUint(out, uint64(param.Key), 10)
			}
			out = pyrepr.AppendStr(append(out, ": "...), strutil.BytesToEscapedStr(param.Value, false, false))
		}
		return string(append(out, '}'))
	}
	return fmt.Sprintf("0x%x", r.Data)
}

// DNSResponse prints a matching answered DNS flow: the query line, then
// the answers, or the response code when there are none.
func (d *Dumper) DNSResponse(_ context.Context, f *flow.DNSFlow) error {
	if f.Response == nil || !d.match(f) {
		return nil
	}
	if err := d.echoDNSQuery(f); err != nil {
		return err
	}
	arrows := d.style(" <<", vtcodes.Style{Bold: new(true)})
	var answers string
	if len(f.Response.Answers) > 0 {
		rendered := make([]string, len(f.Response.Answers))
		for i := range f.Response.Answers {
			rendered[i] = d.style(recordData(&f.Response.Answers[i]), vtcodes.Style{FG: "bright_blue"})
		}
		answers = strings.Join(rendered, ", ")
	} else {
		answers = d.style(dns.ResponseCodeToString(f.Response.ResponseCode), vtcodes.Style{FG: "red"})
	}
	return d.echo(arrows+" "+answers, 0, vtcodes.Style{})
}

// DNSError prints a matching failed DNS flow: the query line, then the
// error message.
func (d *Dumper) DNSError(_ context.Context, f *flow.DNSFlow) error {
	if f.Error == nil || !d.match(f) {
		return nil
	}
	if err := d.echoDNSQuery(f); err != nil {
		return err
	}
	msg := strutil.EscapeControlCharacters(f.Error.Msg, true)
	return d.echo(" << "+msg, 0, vtcodes.Style{FG: "red", Bold: new(true)})
}
