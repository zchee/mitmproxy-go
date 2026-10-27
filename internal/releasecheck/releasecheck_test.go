// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package releasecheck

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestReleaseArtifacts(t *testing.T) {
	t.Run("contracts", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"tag_valid":       {releaseTagValid},
			"tag_invalid":     {releaseTagInvalid},
			"test_no_publish": {releaseTestNoPublish},
			"matrix":          {releaseMatrix},
			"archive_members": {releaseArchiveMembers},
			"checksums":       {releaseChecksums},
			"missing_extra":   {releaseMissingExtra},
			"provenance":      {releaseProvenance},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
}

func releaseTagValid(t *testing.T) {
	for _, tag := range []string{"v1.2.3", "v0.0.0", "v1.2.3-rc.1", "v1.2.3+build.42", "v0.0.0-test.local", "v0.0.0-test.proof1", "v1.2.3-" + strings.Repeat("a", 57)} {
		if err := ValidateTag(tag); err != nil {
			t.Errorf("ValidateTag(%q): %v", tag, err)
		}
	}
}

func releaseTagInvalid(t *testing.T) {
	for _, tag := range []string{"", "1.2.3", "v1.2", "v1.2.3-", "v1.2.3+", "v1.2.3\n", "v1.2.3\r\nheader", "v1.2.3 rc.1", "v1.2.3\t", "v1.2.3-rc-1", "v1.2.3;exit", "v1.2.3/parent", "v1.2.3-" + strings.Repeat("a", 58)} {
		if err := ValidateTag(tag); err == nil {
			t.Errorf("accepted invalid release tag %q", tag)
		}
	}
}

func releaseTestNoPublish(t *testing.T) {
	for _, tag := range []string{"v0.0.0-test.local", "v0.0.0-test.proof1", "v0.0.0-test.local+build", "not-a-version"} {
		if PublishAllowed(tag) {
			t.Errorf("public publication allowed for %q", tag)
		}
	}
	if !PublishAllowed("v1.2.3") {
		t.Error("valid non-test release refused")
	}
}

func releaseMatrix(t *testing.T) {
	want := []Target{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"}, {"windows", "arm64"}}
	if diff := gocmp.Diff(want, Targets()); diff != "" {
		t.Fatalf("matrix (-want +got):\n%s", diff)
	}
	files, err := ExpectedFiles("v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 12 || !slices.IsSorted(files) {
		t.Fatalf("expected exactly six archives and six metadata documents: %v", files)
	}
	var executables int
	for _, target := range Targets() {
		names, err := BinaryNames(target)
		if err != nil {
			t.Fatal(err)
		}
		root, err := ArchiveRoot("v1.2.3", target)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(files, root+".tar.gz") || !slices.Contains(files, root+".provenance.json") {
			t.Fatalf("missing target files for %+v", target)
		}
		for _, name := range names {
			if strings.HasSuffix(name, ".exe") != (target.GOOS == "windows") {
				t.Errorf("wrong executable suffix: %+v %s", target, name)
			}
			executables++
		}
	}
	if executables != 18 {
		t.Errorf("executable count=%d, want 18", executables)
	}
	if _, err := BinaryNames(Target{"freebsd", "amd64"}); err == nil {
		t.Error("unfrozen platform accepted")
	}
}

type releaseEntry struct {
	header tar.Header
	body   []byte
}

func releaseFixture(t *testing.T, target Target) (Provenance, []releaseEntry, [sha256.Size]byte) {
	t.Helper()
	source := Source{Tag: "v1.2.3", Commit: strings.Repeat("a", 40), Tree: strings.Repeat("b", 40), GoVersion: "go1.27.3"}
	flags, err := LDFlags(source.Tag)
	if err != nil {
		t.Fatal(err)
	}
	p := Provenance{Source: source, Target: target, CGOEnabled: "0", LDFlags: flags, ModuleVersions: []string{modulePath, "example.org/dependency v1.2.3"}}
	root, err := ArchiveRoot(p.Tag, target)
	if err != nil {
		t.Fatal(err)
	}
	license := []byte("test archive license\n")
	entries := []releaseEntry{
		{header: tar.Header{Name: root + "/", Typeflag: tar.TypeDir, Mode: 0o755}},
		{header: tar.Header{Name: root + "/LICENSE", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(license))}, body: license},
	}
	names, err := BinaryNames(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		body := []byte("executable fixture: " + name)
		digest := sha256.Sum256(body)
		info := fmt.Sprintf("%s: %s\n\tpath\t%s/cmd/%s\n\tbuild\t-trimpath=true\n\tbuild\tCGO_ENABLED=0\n\tbuild\tGOOS=%s\n\tbuild\tGOARCH=%s\n\tbuild\tvcs.revision=%s\n\tbuild\tvcs.modified=false\n", name, source.GoVersion, modulePath, strings.TrimSuffix(name, ".exe"), target.GOOS, target.GOARCH, source.Commit)
		p.Binaries = append(p.Binaries, Binary{Name: name, SHA256: hex.EncodeToString(digest[:]), BuildInfo: info})
		entries = append(entries, releaseEntry{header: tar.Header{Name: root + "/" + name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body))}, body: body})
	}
	return p, entries, sha256.Sum256(license)
}

func releaseTar(t *testing.T, entries []releaseEntry) []byte {
	t.Helper()
	var output bytes.Buffer
	compressed := gzip.NewWriter(&output)
	archive := tar.NewWriter(compressed)
	for _, entry := range entries {
		if err := archive.WriteHeader(&entry.header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func releaseArchiveMembers(t *testing.T) {
	for _, target := range Targets() {
		p, entries, license := releaseFixture(t, target)
		if err := ValidateArchive(bytes.NewReader(releaseTar(t, entries)), p, license); err != nil {
			t.Fatalf("valid %s/%s archive: %v", target.GOOS, target.GOARCH, err)
		}
	}
	p, entries, license := releaseFixture(t, Target{"linux", "amd64"})
	for _, alter := range []func([]releaseEntry) []releaseEntry{
		func(entries []releaseEntry) []releaseEntry { return entries[:len(entries)-1] },
		func(entries []releaseEntry) []releaseEntry { return append(entries, entries[1]) },
		func(entries []releaseEntry) []releaseEntry { entries[1].header.Name = "/LICENSE"; return entries },
		func(entries []releaseEntry) []releaseEntry { entries[1].header.Name = "../LICENSE"; return entries },
		func(entries []releaseEntry) []releaseEntry {
			entries[1].header.Typeflag = tar.TypeSymlink
			entries[1].header.Linkname = "LICENSE"
			entries[1].header.Size = 0
			entries[1].body = nil
			return entries
		},
		func(entries []releaseEntry) []releaseEntry {
			entries[1].body = bytes.Repeat([]byte{'x'}, len(entries[1].body))
			return entries
		},
		func(entries []releaseEntry) []releaseEntry { entries[1].header.Name += ".extra"; return entries },
	} {
		if err := ValidateArchive(bytes.NewReader(releaseTar(t, alter(slices.Clone(entries)))), p, license); err == nil {
			t.Error("invalid archive member set accepted")
		}
	}
	data := releaseTar(t, entries)
	if err := ValidateArchive(bytes.NewReader(data[:len(data)-1]), p, license); err == nil {
		t.Error("truncated compressed archive accepted")
	}
}

func releaseDigests(t *testing.T) (map[string][sha256.Size]byte, []string) {
	t.Helper()
	names, err := ExpectedFiles("v1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	digests := make(map[string][sha256.Size]byte)
	for _, name := range names {
		digests[name] = sha256.Sum256([]byte(name))
	}
	return digests, names
}

func releaseChecksums(t *testing.T) {
	digests, names := releaseDigests(t)
	manifest, err := ChecksumManifest(digests, names)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateChecksums(manifest, digests, names); err != nil {
		t.Fatal(err)
	}
	slices.Reverse(names)
	again, err := ChecksumManifest(digests, names)
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(string(manifest), string(again)); diff != "" {
		t.Errorf("non-deterministic checksums (-want +got):\n%s", diff)
	}
	changed := bytes.Clone(manifest)
	changed[0] = 'x'
	if err := ValidateChecksums(changed, digests, names); err == nil {
		t.Error("wrong checksum accepted")
	}
}

func releaseMissingExtra(t *testing.T) {
	digests, names := releaseDigests(t)
	manifest, err := ChecksumManifest(digests, names)
	if err != nil {
		t.Fatal(err)
	}
	missing := names[0]
	saved := digests[missing]
	delete(digests, missing)
	if _, err := ChecksumManifest(digests, names); err == nil {
		t.Error("missing file accepted")
	}
	digests[missing] = saved
	digests["extra"] = saved
	if _, err := ChecksumManifest(digests, names); err == nil {
		t.Error("extra file accepted")
	}
	delete(digests, "extra")
	duplicate := slices.Clone(names)
	duplicate[1] = duplicate[0]
	if _, err := ChecksumManifest(digests, duplicate); err == nil {
		t.Error("duplicate expected file accepted")
	}
	first, _, _ := bytes.Cut(manifest, []byte{'\n'})
	if err := ValidateChecksums(append(bytes.Clone(manifest), append(first, '\n')...), digests, names); err == nil {
		t.Error("duplicate checksum entry accepted")
	}
}

func releaseProvenance(t *testing.T) {
	p, _, _ := releaseFixture(t, Target{"linux", "amd64"})
	if err := ValidateProvenance(p, p.Source, p.ModuleVersions); err != nil {
		t.Fatal(err)
	}
	experimental := p
	experimental.GoVersion += "-X:simd,runtimesecret,mapsplitgroup"
	experimental.Binaries = slices.Clone(p.Binaries)
	for i := range experimental.Binaries {
		experimental.Binaries[i].BuildInfo = strings.Replace(experimental.Binaries[i].BuildInfo, ": "+p.GoVersion+"\n", ": "+experimental.GoVersion+"\n", 1)
	}
	if err := ValidateProvenance(experimental, experimental.Source, p.ModuleVersions); err != nil {
		t.Fatalf("experimental runtime version: %v", err)
	}
	for _, alter := range []func(*Provenance){
		func(p *Provenance) { p.Tag = "v9.9.9" },
		func(p *Provenance) { p.Commit = strings.Repeat("c", 40) },
		func(p *Provenance) { p.Tree = strings.Repeat("c", 40) },
		func(p *Provenance) { p.GoVersion = "go1.26.0" },
		func(p *Provenance) { p.CGOEnabled = "1" },
		func(p *Provenance) { p.LDFlags = "-s -w" },
		func(p *Provenance) { p.ModuleVersions = []string{"unexpected v1.0.0"} },
		func(p *Provenance) { p.Binaries = p.Binaries[:2] },
		func(p *Provenance) {
			p.Binaries[0].BuildInfo = strings.ReplaceAll(p.Binaries[0].BuildInfo, "vcs.modified=false", "vcs.modified=true")
		},
		func(p *Provenance) { p.Binaries[0].SHA256 = "not a digest" },
		func(p *Provenance) {
			p.Binaries[0].BuildInfo = strings.Replace(p.Binaries[0].BuildInfo, ": "+p.GoVersion+"\n", ": go0\n", 1)
		},
		func(p *Provenance) {
			p.Binaries[0].BuildInfo = strings.Replace(p.Binaries[0].BuildInfo, p.Binaries[0].Name+": ", "other: ", 1)
		},
		func(p *Provenance) { p.Binaries[0].BuildInfo = "\t" + p.GoVersion + "\n" + p.Binaries[0].BuildInfo },
	} {
		changed := p
		changed.Binaries = slices.Clone(p.Binaries)
		alter(&changed)
		if err := ValidateProvenance(changed, p.Source, p.ModuleVersions); err == nil {
			t.Error("incorrect source or build provenance accepted")
		}
	}
}
