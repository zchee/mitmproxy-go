// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package releasecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	json "encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/releasecheck/releasetest"
)

type versionFamily struct {
	source    Source
	documents map[Target]Provenance
	archives  map[Target][]byte
	license   [sha256.Size]byte
}

func versionFixture(t *testing.T, experimental bool) versionFamily {
	t.Helper()
	fixture := releasetest.Load(t, experimental)
	expectedVersion := fixture.PlainGoVersion
	if experimental {
		expectedVersion += "-X:simd,runtimesecret"
	}
	family := versionFamily{
		source:    Source{Tag: releasetest.Tag, Commit: fixture.Commit, Tree: fixture.Tree, GoVersion: expectedVersion},
		documents: make(map[Target]Provenance), archives: make(map[Target][]byte), license: sha256.Sum256(fixture.License),
	}
	for _, target := range Targets() {
		stem, err := ArchiveRoot(releasetest.Tag, target)
		if err != nil {
			t.Fatal(err)
		}
		var p Provenance
		if err := json.Unmarshal(fixture.Files[stem+".provenance.json"], &p); err != nil {
			t.Fatal(err)
		}
		family.documents[target] = p
		family.archives[target] = fixture.Files[stem+".tar.gz"]
	}
	return family
}

func (family versionFamily) validate() error {
	for _, target := range Targets() {
		p := family.documents[target]
		if err := ValidateProvenance(p, family.source, []string{modulePath}); err != nil {
			return err
		}
		if err := ValidateArchive(bytes.NewReader(family.archives[target]), p, family.license); err != nil {
			return err
		}
	}
	return nil
}

func TestReleaseGoVersion(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"host_independent_plain": {func(t *testing.T) {
				family := versionFixture(t, false)
				fixture := releasetest.Load(t, false)
				if diff := gocmp.Diff(fixture.PlainGoVersion, fixture.GoVersion); diff != "" {
					t.Fatalf("plain fixture compiler (-expected +embedded):\n%s", diff)
				}
				if err := family.validate(); err != nil {
					t.Fatal(err)
				}
			}},
			"host_independent_experiments": {func(t *testing.T) {
				family := versionFixture(t, true)
				fixture := releasetest.Load(t, true)
				if diff := gocmp.Diff(fixture.PlainGoVersion+"-X:simd,runtimesecret", fixture.GoVersion); diff != "" {
					t.Fatalf("experimental fixture compiler (-expected +embedded): %s", diff)
				}
				if err := family.validate(); err != nil {
					t.Fatal(err)
				}
				family.source.GoVersion = fixture.PlainGoVersion
				if err := family.validate(); err == nil {
					t.Fatal("experiment suffix was normalized away")
				}
			}},
			"six_documents_agree": {func(t *testing.T) {
				family := versionFixture(t, false)
				if len(family.documents) != 6 || len(family.archives) != 6 {
					t.Fatalf("incomplete family: %+v", family)
				}
				var count int
				for _, p := range family.documents {
					count += len(p.Binaries)
				}
				if count != 18 {
					t.Fatalf("binary count=%d, want 18", count)
				}
				if err := family.validate(); err != nil {
					t.Fatal(err)
				}
			}},
			"six_documents_disagree": {func(t *testing.T) {
				family := versionFixture(t, false)
				target := Targets()[5]
				p := family.documents[target]
				p.GoVersion = "go1.26.0"
				family.documents[target] = p
				if err := family.validate(); err == nil {
					t.Fatal("one disagreeing document accepted")
				}
			}},
			"embedded_version_mismatch": {func(t *testing.T) {
				family := versionFixture(t, false)
				old := family.source.GoVersion
				family.source.GoVersion = "go1.26.0"
				for target, p := range family.documents {
					p.GoVersion = family.source.GoVersion
					for i := range p.Binaries {
						p.Binaries[i].BuildInfo = strings.Replace(p.Binaries[i].BuildInfo, ": "+old+"\n", ": "+p.GoVersion+"\n", 1)
					}
					family.documents[target] = p
				}
				if err := family.validate(); err == nil || !strings.Contains(err.Error(), "embedded Go version") {
					t.Fatalf("actual executable mismatch not detected: %v", err)
				}
			}},
			"family_agrees_wrong_expected_version": {func(t *testing.T) {
				family := versionFixture(t, false)
				if err := family.validate(); err != nil {
					t.Fatal(err)
				}
				family.source.GoVersion = "go1.26.0"
				if err := family.validate(); err == nil {
					t.Fatal("self-consistent family overrode independently asserted compiler")
				}
			}},
			"trusted_source_mismatch": {func(t *testing.T) {
				family := versionFixture(t, false)
				family.source.Commit = strings.Repeat("c", 40)
				if err := family.validate(); err == nil {
					t.Fatal("wrong trusted source accepted")
				}
				family = versionFixture(t, false)
				family.source.Tree = strings.Repeat("d", 40)
				if err := family.validate(); err == nil {
					t.Fatal("wrong trusted tree accepted")
				}
			}},
			"metadata_bounds": {releaseVersionBounds},
			"retained_input_unchanged": {func(t *testing.T) {
				fixture := releasetest.Load(t, false)
				before := make(map[string][sha256.Size]byte)
				for name, data := range fixture.Files {
					before[name] = sha256.Sum256(data)
				}
				family := versionFixture(t, false)
				if err := family.validate(); err != nil {
					t.Fatal(err)
				}
				after := make(map[string][sha256.Size]byte)
				for name, data := range fixture.Files {
					after[name] = sha256.Sum256(data)
				}
				if diff := gocmp.Diff(before, after); diff != "" {
					t.Fatalf("retained family changed (-before +after):\n%s", diff)
				}
				if len(after) != 13 {
					t.Fatalf("retained file count=%d, want 13", len(after))
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func releaseVersionBounds(t *testing.T) {
	p, entries, license := releaseFixture(t, Target{"linux", "amd64"})
	for _, size := range []int64{-1, 512<<20 + 1} {
		var output bytes.Buffer
		compressed := gzip.NewWriter(&output)
		archive := tar.NewWriter(compressed)
		header := entries[2].header
		header.Size = size
		if size < 0 {
			// A negative size is invalid even to the standard archive writer.
			if err := archive.WriteHeader(&header); err == nil {
				t.Fatal("negative size accepted by tar writer")
			}
			_ = archive.Close()
			_ = compressed.Close()
			continue
		}
		if err := archive.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if err := compressed.Close(); err != nil {
			t.Fatal(err)
		}
		if err := ValidateArchive(bytes.NewReader(output.Bytes()), p, license); err == nil || !strings.Contains(err.Error(), "unexpected archive member") {
			t.Fatalf("size bound not enforced before reading member: %v", err)
		}
	}
	tests := map[string]struct{ body []byte }{
		"non_go":    {[]byte("not a Go executable")},
		"truncated": {entries[2].body[:16]},
	}
	for name, tt := range tests {
		changed := slices.Clone(entries)
		body := tt.body
		changed[2].body, changed[2].header.Size = body, int64(len(body))
		changedP := p
		changedP.Binaries = slices.Clone(p.Binaries)
		changedP.Binaries[0].SHA256 = fmt.Sprintf("%x", sha256.Sum256(body))
		if err := ValidateArchive(bytes.NewReader(releaseTar(t, changed)), changedP, license); err == nil {
			t.Fatalf("invalid executable %q accepted", name)
		}
	}
}
