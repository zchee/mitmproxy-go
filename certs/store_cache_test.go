// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	key, ca, err := CreateCA("mitmproxy", "mitmproxy", 1024)
	if err != nil {
		t.Fatal(err)
	}
	return &Store{defaultPrivateKey: key, defaultCA: ca, defaultChainCerts: []*Cert{ca}, cap: storeCap}
}

func getTestCert(t *testing.T, store *Store, name string, sans []GeneralName) *Entry {
	t.Helper()
	entry, err := store.GetCert(name, sans, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestStoreCacheIdentity(t *testing.T) {
	store := testStore(t)
	sans := []GeneralName{DNSName("one.example"), DNSName("two.example")}
	first, err := store.GetCert("foo.com", sans, "First", "https://first.example/crl")
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		cn       string
		sans     []GeneralName
		wantSame bool
	}{
		"success: ordered SAN identity":     {cn: "foo.com", sans: slices.Clone(sans), wantSame: true},
		"success: different CN":             {cn: "bar.com", sans: sans},
		"success: different SAN order":      {cn: "foo.com", sans: []GeneralName{sans[1], sans[0]}},
		"success: different SAN type":       {cn: "foo.com", sans: []GeneralName{URIName("one.example"), sans[1]}},
		"success: different SAN boundaries": {cn: "foo.com", sans: []GeneralName{DNSName("one.exampletwo.example")}},
		"success: different SANs":           {cn: "foo.com", sans: []GeneralName{DNSName("*.bar.com")}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := store.GetCert(tt.cn, tt.sans, "Second", "https://second.example/crl")
			if err != nil {
				t.Fatal(err)
			}
			if (got == first) != tt.wantSame {
				t.Errorf("cache hit = %t, want %t", got == first, tt.wantSame)
			}
			if tt.wantSame && (got.Cert.Organization() != "First" || !slices.Equal(got.Cert.CRLDistributionPoints(), []string{"https://first.example/crl"})) {
				t.Error("organization or CRL URL changed on cache hit")
			}
		})
	}
	withoutCN := getTestCert(t, store, "", nil)
	if withoutCN.Cert.CN() != "" {
		t.Error("absent CN was not preserved")
	}
	if withoutCN != getTestCert(t, store, "", []GeneralName{}) {
		t.Error("nil and empty SANs differ")
	}
	sans[0] = DNSName("changed.example")
	if first != getTestCert(t, store, "foo.com", []GeneralName{DNSName("one.example"), DNSName("two.example")}) {
		t.Error("caller mutation changed cache identity")
	}
}

func TestStoreGeneratedNamesAreNotAliases(t *testing.T) {
	store := testStore(t)
	first := getTestCert(t, store, "foo.com", []GeneralName{DNSName("*.bar.com")})
	second := getTestCert(t, store, "foo.bar.com", nil)
	third := getTestCert(t, store, "bar.com", nil)
	changed := getTestCert(t, store, "foo.bar.com", []GeneralName{DNSName("*.baz.com")})
	if first == second || first == third || second == changed {
		t.Error("generated names unexpectedly registered as aliases")
	}
	if diff := gocmp.Diff([]GeneralName{DNSName("*.baz.com")}, changed.Cert.AltNames(), gocmp.Comparer(func(a, b GeneralName) bool { return a == b })); diff != "" {
		t.Errorf("SAN change (-want +got):\n%s", diff)
	}
}

func TestStoreLookupOrder(t *testing.T) {
	tests := map[string]struct {
		cn         string
		sans       []GeneralName
		configured []string
		want       string
	}{
		"success: exact CN before wildcard and SAN":    {cn: "sub.example.com", sans: []GeneralName{DNSName("san.test")}, configured: []string{"sub.example.com", "*.example.com", "san.test", "*"}, want: "sub.example.com"},
		"success: nearest wildcard before ancestor":    {cn: "sub.example.com", configured: []string{"*.example.com", "*.com", "*"}, want: "*.example.com"},
		"success: ancestor wildcard before SAN":        {cn: "sub.example.com", sans: []GeneralName{DNSName("san.test")}, configured: []string{"*.com", "san.test", "*"}, want: "*.com"},
		"success: SAN order precedes specificity":      {sans: []GeneralName{DNSName("first.example.com"), DNSName("second.test")}, configured: []string{"*.com", "second.test", "*"}, want: "*.com"},
		"success: exact IP SAN":                        {sans: []GeneralName{IPAddress(netip.MustParseAddr("127.0.0.1"))}, configured: []string{"127.0.0.1", "*.0.0.1", "*"}, want: "127.0.0.1"},
		"success: IP SAN has no wildcard":              {sans: []GeneralName{IPAddress(netip.MustParseAddr("127.0.0.1"))}, configured: []string{"*.0.0.1", "*"}, want: "*"},
		"success: URI SAN has no wildcard":             {sans: []GeneralName{URIName("https://sub.example.com")}, configured: []string{"*.example.com", "*"}, want: "*"},
		"success: email SAN has no wildcard":           {sans: []GeneralName{EmailName("user@sub.example.com")}, configured: []string{"*.example.com", "*"}, want: "*"},
		"success: CN string expands even for IP text":  {cn: "127.0.0.1", configured: []string{"*.0.0.1", "*"}, want: "*.0.0.1"},
		"success: case-sensitive names":                {cn: "UPPER.EXAMPLE", configured: []string{"upper.example", "*"}, want: "*"},
		"success: wildcard does not match base domain": {cn: "example.com", configured: []string{"*.example.com", "*"}, want: "*"},
	}
	base := testStore(t)
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			store := &Store{defaultPrivateKey: base.defaultPrivateKey, defaultCA: base.defaultCA, cap: storeCap}
			entries := make(map[string]*Entry)
			for _, name := range tt.configured {
				entry := &Entry{Cert: base.defaultCA, PrivateKey: base.defaultPrivateKey}
				store.AddCert(entry, name)
				entries[name] = entry
			}
			if got := getTestCert(t, store, tt.cn, tt.sans); got != entries[tt.want] {
				t.Errorf("lookup did not choose %q", tt.want)
			}
		})
	}
}

func TestStoreAddCert(t *testing.T) {
	store := testStore(t)
	sans := []GeneralName{DNSName("san.test"), IPAddress(netip.MustParseAddr("::1")), URIName("https://uri.test"), EmailName("user@test")}
	entry := getTestCert(t, store, "common.test", sans)
	store.AddCert(entry, "alias.test")
	for _, name := range []string{"common.test", "san.test", "::1", "https://uri.test", "user@test", "alias.test"} {
		if got := getTestCert(t, store, name, nil); got != entry {
			t.Errorf("name %q not registered", name)
		}
	}
	replacement := &Entry{Cert: store.defaultCA, PrivateKey: store.defaultPrivateKey}
	store.AddCert(replacement, "alias.test")
	if got := getTestCert(t, store, "alias.test", nil); got != replacement {
		t.Error("last configured alias did not win")
	}
	cached := getTestCert(t, store, "unmatched", nil)
	store.AddCert(replacement, "*")
	if got := getTestCert(t, store, "unmatched", nil); got == cached {
		t.Error("generated cache beat global wildcard")
	}
	if got := getTestCert(t, store, "common.test", sans); got != entry {
		t.Error("global wildcard beat exact CN")
	}
	if got := getTestCert(t, store, "unmatched", nil); got != replacement {
		t.Error("global wildcard did not win")
	}
}

func TestStoreExpire(t *testing.T) {
	store := testStore(t)
	store.cap = 3
	one := getTestCert(t, store, "one.com", nil)
	two := getTestCert(t, store, "two.com", nil)
	three := getTestCert(t, store, "three.com", nil)
	store.AddCert(one, "alias.com")
	if getTestCert(t, store, "one.com", nil) != one {
		t.Fatal("cache hit changed entry")
	}
	four := getTestCert(t, store, "four.com", nil)
	if len(store.generated) != 3 || len(store.expireQueue) != 3 {
		t.Fatalf("cache size = %d, queue = %d; want 3 each", len(store.generated), len(store.expireQueue))
	}
	if getTestCert(t, store, "two.com", nil) != two || getTestCert(t, store, "three.com", nil) != three || getTestCert(t, store, "four.com", nil) != four {
		t.Error("FIFO retained the wrong entries")
	}
	if getTestCert(t, store, "alias.com", nil) == one {
		t.Error("eviction retained alias of expired entry")
	}
	if getTestCert(t, store, "one.com", nil) == one {
		t.Error("hit refreshed FIFO position")
	}
}

func TestStoreConcurrent(t *testing.T) {
	store := testStore(t)
	const count = 50
	entries := make([]*Entry, count)
	var wg sync.WaitGroup
	for i := range count {
		wg.Go(func() {
			entry, err := store.GetCert("shared.test", []GeneralName{DNSName("shared.test")}, "", "")
			if err != nil {
				t.Error(err)
				return
			}
			entries[i] = entry
			store.AddCert(entry, fmt.Sprintf("alias-%d", i))
			_ = store.DefaultChainCerts()
		})
	}
	wg.Wait()
	for i, entry := range entries {
		if entry != entries[0] {
			t.Errorf("request %d generated a duplicate entry", i)
		}
	}
	if len(store.expireQueue) != 1 {
		t.Errorf("generated %d entries, want 1", len(store.expireQueue))
	}
}

func TestStoreGenerationFailure(t *testing.T) {
	store := testStore(t)
	if _, err := store.GetCert("bad", []GeneralName{IPAddress(netip.Addr{})}, "", ""); err == nil {
		t.Fatal("invalid SAN accepted")
	}
	if len(store.generated) != 0 || len(store.expireQueue) != 0 {
		t.Error("failed generation entered cache")
	}
	if _, err := new(Store).GetCert("example.test", nil, "", ""); err == nil {
		t.Error("uninitialized store accepted generation")
	}
}
