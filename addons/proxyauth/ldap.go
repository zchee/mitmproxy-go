// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package proxyauth

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"github.com/zchee/mitmproxy-go/options"
)

type ldapConfig struct {
	address      string
	tls          bool
	bindDN       string
	bindPassword string
	subtree      string
	filterKey    string
}

func parseLDAPSpec(spec string) (*ldapConfig, error) {
	invalid := func(field string) (*ldapConfig, error) {
		return nil, options.Errorf("Invalid LDAP specification: %s", field)
	}
	parts := strings.Split(spec, ":")
	if len(parts) != 5 && len(parts) != 6 {
		return invalid("field count")
	}
	if parts[0] != "ldap" && parts[0] != "ldaps" {
		return invalid("scheme")
	}
	port := 389
	if parts[0] == "ldaps" {
		port = 636
	}
	offset := 2
	if len(parts) == 6 {
		var err error
		port, err = strconv.Atoi(parts[2])
		if err != nil || port < 1 || port > 65535 {
			return invalid("port")
		}
		offset++
	}
	subtree, query, hasQuery := strings.Cut(parts[offset+2], "?")
	key := "cn"
	if hasQuery {
		name, value, ok := strings.Cut(query, "=")
		if !ok || name != "search_filter_key" || strings.ContainsAny(value, "=?") {
			return invalid("search filter")
		}
		key = value
	}
	return &ldapConfig{
		address: net.JoinHostPort(parts[1], strconv.Itoa(port)), tls: parts[0] == "ldaps",
		bindDN: parts[offset], bindPassword: parts[offset+1], subtree: subtree, filterKey: key,
	}, nil
}

func (c *ldapConfig) searchFilter(username string) string {
	return "(" + c.filterKey + "=" + ldap.EscapeFilter(username) + ")"
}

func (c *ldapConfig) check(ctx context.Context, username, password string) (bool, error) {
	if username == "" || password == "" {
		return false, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	service, closeService, err := c.dial(ctx)
	if err != nil {
		return false, err
	}
	defer closeService()
	if err := service.Bind(c.bindDN, c.bindPassword); err != nil {
		return false, err
	}
	searchCtx, stopSearch := context.WithCancel(ctx)
	defer stopSearch()
	results := service.SearchAsync(searchCtx, ldap.NewSearchRequest(c.subtree, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 1, 10, false, c.searchFilter(username), []string{"1.1"}, nil), 0)
	var dn string
	for results.Next() {
		if entry := results.Entry(); entry != nil {
			dn = entry.DN
			break
		}
	}
	stopSearch()
	if dn == "" {
		return false, results.Err()
	}
	user, closeUser, err := c.dial(ctx)
	if err != nil {
		return false, err
	}
	defer closeUser()
	if err := user.Bind(dn, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (c *ldapConfig) dial(ctx context.Context) (*ldap.Conn, func(), error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", c.address)
	if err != nil {
		return nil, nil, err
	}
	// Cancel closes the raw socket, including during a synchronous Bind, so
	// the connection's context bounds every operation, not only SearchAsync.
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	cleanup := func() { stop(); _ = raw.Close() }
	deadline, _ := ctx.Deadline()
	if err := raw.SetDeadline(deadline); err != nil {
		cleanup()
		return nil, nil, err
	}
	conn := raw
	if c.tls {
		host, _, _ := net.SplitHostPort(c.address)
		secure := tls.Client(raw, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		if err := secure.HandshakeContext(ctx); err != nil {
			cleanup()
			return nil, nil, err
		}
		conn = secure
	}
	client := ldap.NewConn(&limitedLDAPConn{Conn: conn, reader: io.LimitedReader{R: conn, N: 1 << 20}}, c.tls)
	client.Start()
	return client, func() { cleanup(); _ = client.Close() }, nil
}

// Each fresh connection has its own budget, so a service search or a user bind
// cannot make the BER decoder consume more than 1 MiB of received data.
type limitedLDAPConn struct {
	net.Conn
	reader io.LimitedReader
}

// Read reads LDAP response bytes through the bounded reader.
func (c *limitedLDAPConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
