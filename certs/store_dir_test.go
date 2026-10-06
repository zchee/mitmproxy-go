// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package certs

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

func verifyTestLeaf(t *testing.T, store *Store, name string) {
	t.Helper()
	entry, err := store.GetCert(name, []GeneralName{DNSName(name)}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(store.DefaultCA().X509())
	if _, err := entry.Cert.X509().Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Fatalf("issued leaf does not verify under the stored CA: %v", err)
	}
}

func TestFromStoreCreate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "confdir")
	store, err := FromStore(dir, "mitmproxy", 2048, nil)
	if err != nil {
		t.Fatal(err)
	}

	names := []string{
		"mitmproxy-ca.pem",
		"mitmproxy-ca.p12",
		"mitmproxy-ca-cert.pem",
		"mitmproxy-ca-cert.cer",
		"mitmproxy-ca-cert.p12",
		"mitmproxy-dhparam.pem",
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var created []string
	for _, entry := range entries {
		created = append(created, entry.Name())
	}
	slices.Sort(created)
	wantNames := slices.Clone(names)
	slices.Sort(wantNames)
	if !slices.Equal(created, wantNames) {
		t.Errorf("directory holds %q, want %q", created, wantNames)
	}

	caRaw, err := os.ReadFile(filepath.Join(dir, "mitmproxy-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(caRaw)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		t.Fatal("mitmproxy-ca.pem does not start with a PKCS#1 private key")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Errorf("private key in mitmproxy-ca.pem is not PKCS#1: %v", err)
	}
	fileCA, err := ParseCert(rest)
	if err != nil {
		t.Fatal(err)
	}
	if !fileCA.Equal(store.DefaultCA()) {
		t.Error("certificate in mitmproxy-ca.pem is not the store CA")
	}

	certPEM, err := os.ReadFile(filepath.Join(dir, "mitmproxy-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(certPEM, store.DefaultCA().PEM()) {
		t.Error("mitmproxy-ca-cert.pem is not the CA certificate PEM")
	}
	cer, err := os.ReadFile(filepath.Join(dir, "mitmproxy-ca-cert.cer"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cer, certPEM) {
		t.Error("mitmproxy-ca-cert.cer differs from mitmproxy-ca-cert.pem")
	}
	dhparam, err := os.ReadFile(filepath.Join(dir, "mitmproxy-dhparam.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dhparam, []byte(DefaultDHParam)) {
		t.Error("mitmproxy-dhparam.pem is not DefaultDHParam")
	}

	if runtime.GOOS != "windows" {
		// A regular file measures the existing umask without changing it.
		probe := filepath.Join(t.TempDir(), "public-mode")
		if err := os.WriteFile(probe, nil, 0o666); err != nil { //nolint:gosec // Measure the public-file mode after the process umask.
			t.Fatal(err)
		}
		publicInfo, err := os.Stat(probe)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			info, err := os.Stat(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			wantMode := publicInfo.Mode().Perm()
			if name == "mitmproxy-ca.pem" || name == "mitmproxy-ca.p12" || name == "mitmproxy-dhparam.pem" {
				wantMode &= 0o600
			}
			if info.Mode().Perm() != wantMode {
				t.Errorf("%s mode = %v, want %v under the process umask", name, info.Mode().Perm(), wantMode)
			}
		}
	}

	if store.DefaultChainFile() != "" {
		t.Errorf("ChainFile = %q, want empty for a single-certificate CA file", store.DefaultChainFile())
	}
	if chain := store.DefaultChainCerts(); len(chain) != 1 || !chain[0].Equal(store.DefaultCA()) {
		t.Errorf("default chain = %d certificates, want the CA alone", len(chain))
	}
	crl, err := x509.ParseRevocationList(store.DefaultCRL())
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(store.DefaultCA().X509()); err != nil {
		t.Errorf("default CRL is not signed by the CA: %v", err)
	}
	if store.cap != storeCap {
		t.Errorf("generated-certificate capacity = %d, want %d", store.cap, storeCap)
	}
	verifyTestLeaf(t, store, "foo.test")

	reloaded, err := FromStore(dir, "mitmproxy", 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded.DefaultCA().Equal(store.DefaultCA()) {
		t.Error("reloading the directory changed the CA identity")
	}
	verifyTestLeaf(t, reloaded, "bar.test")
}

func TestFromStoreExistingConfdir(t *testing.T) {
	dir := testutil.FixturePath(t, "mitmproxy/confdir")
	before, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := FromStore(dir, "mitmproxy", 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseCert(testutil.Fixture(t, "mitmproxy/confdir/mitmproxy-ca-cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !store.DefaultCA().Equal(want) {
		t.Error("loaded CA is not the fixture CA")
	}
	if store.DefaultChainFile() != "" {
		t.Errorf("ChainFile = %q, want empty", store.DefaultChainFile())
	}
	// The fixture CA expired in 2016, so no instant satisfies a full chain
	// verification of a freshly issued leaf; the CA signature and the
	// issued name are checked directly, as mitmproxy still issues from it.
	entry, err := store.GetCert("example.test", []GeneralName{DNSName("example.test")}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := entry.Cert.X509().CheckSignatureFrom(store.DefaultCA().X509()); err != nil {
		t.Errorf("issued leaf is not signed by the fixture CA: %v", err)
	}
	if err := entry.Cert.X509().VerifyHostname("example.test"); err != nil {
		t.Errorf("issued leaf does not cover the requested name: %v", err)
	}
	after, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Errorf("loading an existing directory changed it from %d to %d entries", len(before), len(after))
	}
}

func TestFromStoreChainFile(t *testing.T) {
	source := t.TempDir()
	if _, err := FromStore(source, "mitmproxy", 2048, nil); err != nil {
		t.Fatal(err)
	}
	caRaw, err := os.ReadFile(filepath.Join(source, "mitmproxy-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	caFile := filepath.Join(dir, "mitmproxy-ca.pem")
	if err := os.WriteFile(caFile, caRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := FromStore(dir, "mitmproxy", 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.DefaultChainFile() != "" || len(store.DefaultChainCerts()) != 1 {
		t.Errorf("single certificate: ChainFile = %q with %d chain certificates, want no chain file", store.DefaultChainFile(), len(store.DefaultChainCerts()))
	}

	if err := os.WriteFile(caFile, append(slices.Clone(caRaw), caRaw...), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err = FromStore(dir, "mitmproxy", 2048, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.DefaultChainFile() != caFile || len(store.DefaultChainCerts()) != 2 {
		t.Errorf("two certificates: ChainFile = %q with %d chain certificates, want %q with 2", store.DefaultChainFile(), len(store.DefaultChainCerts()), caFile)
	}
}

func TestFromFilesMissingDHParam(t *testing.T) {
	dir := t.TempDir()
	if _, err := FromStore(dir, "mitmproxy", 2048, nil); err != nil {
		t.Fatal(err)
	}
	dhparamFile := filepath.Join(dir, "mitmproxy-dhparam.pem")
	if err := os.Remove(dhparamFile); err != nil {
		t.Fatal(err)
	}
	if _, err := FromFiles(filepath.Join(dir, "mitmproxy-ca.pem"), dhparamFile, nil); err != nil {
		t.Fatal(err)
	}
	dhparam, err := os.ReadFile(dhparamFile)
	if err != nil {
		t.Fatalf("missing DH parameter file was not recreated: %v", err)
	}
	if !bytes.Equal(dhparam, []byte(DefaultDHParam)) {
		t.Error("recreated DH parameter file is not DefaultDHParam")
	}
}

func TestFromFilesPathErrors(t *testing.T) {
	caFile := testutil.FixturePath(t, "mitmproxy/confdir/mitmproxy-ca.pem")
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct{ ca, dh string }{
		"error: missing CA":           {ca: filepath.Join(t.TempDir(), "missing.pem"), dh: filepath.Join(t.TempDir(), "dh.pem")},
		"error: DH path under a file": {ca: caFile, dh: filepath.Join(parentFile, "dh.pem")},
		"error: missing DH parent":    {ca: caFile, dh: filepath.Join(t.TempDir(), "missing", "dh.pem")},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			store, err := FromFiles(tt.ca, tt.dh, nil)
			if _, ok := errors.AsType[*os.PathError](err); !ok || store != nil {
				t.Fatalf("FromFiles returned store=%t, error=%v; want nil store and filesystem error", store != nil, err)
			}
		})
	}
}

func TestCreateStorePreservesExistingFiles(t *testing.T) {
	tests := map[string]struct{ name string }{
		"success: existing CA PEM":        {name: "mitmproxy-ca.pem"},
		"success: existing key bundle":    {name: "mitmproxy-ca.p12"},
		"success: existing DH parameters": {name: "mitmproxy-dhparam.pem"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tt.name)
			want := []byte("existing store file must not be overwritten")
			if err := os.WriteFile(path, want, 0o600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := root.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := createStore(root, "mitmproxy", 2048); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Errorf("existing store file changed (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFromStoreRefusesWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows file modes do not describe directory ACL write access")
	}
	tests := map[string]struct{ mode os.FileMode }{
		"error: group writable": {mode: 0o770},
		"error: world writable": {mode: 0o707},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, tt.mode); err != nil {
				t.Fatal(err)
			}
			store, err := FromStore(dir, "mitmproxy", 2048, nil)
			want := fmt.Sprintf("certs: configuration directory %s is writable by other users (mode %s); refusing to write the CA", dir, tt.mode)
			if err == nil || err.Error() != want || store != nil {
				t.Fatalf("FromStore() returned store=%t, error=%v, want (nil, %q)", store != nil, err, want)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("refused directory received %d store files", len(entries))
			}
		})
	}
}

func TestStoreWritesStayInVerifiedDirectory(t *testing.T) {
	tests := map[string]struct{ name string }{
		"success: private CA":    {name: "mitmproxy-ca.pem"},
		"success: DH parameters": {name: "mitmproxy-dhparam.pem"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			parent := t.TempDir()
			dir := filepath.Join(parent, "confdir")
			verified := filepath.Join(parent, "verified")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := root.Close(); err != nil {
					t.Error(err)
				}
			})
			if err := checkStoreDirectory(root); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(dir, verified); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0o777); err != nil { //nolint:gosec // Deliberately unsafe replacement used to exercise the directory boundary.
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" {
				if err := os.Chmod(dir, 0o777); err != nil { //nolint:gosec // Ignore the process umask for the adversarial replacement.
					t.Fatal(err)
				}
			}
			want := []byte("verified directory only")
			if err := writeStoreFile(root, tt.name, want, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, tt.name)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("replacement directory received a file: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(verified, tt.name))
			if err != nil {
				t.Fatal(err)
			}
			if diff := gocmp.Diff(want, got); diff != "" {
				t.Errorf("pinned-directory file (-want +got):\n%s", diff)
			}
		})
	}
}

func TestStoreExclusiveWriteRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	const name = "mitmproxy-ca.pem"
	target := filepath.Join(t.TempDir(), "target")
	want := []byte("existing target")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	if err := writeStoreFile(root, name, []byte("replacement"), 0o600); err == nil {
		t.Fatal("exclusive write accepted a symlink")
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff(want, got); diff != "" {
		t.Errorf("symlink target changed (-want +got):\n%s", diff)
	}
}

func TestFromFilesEncrypted(t *testing.T) {
	caFile := testutil.FixturePath(t, "mitmproxy/mitmproxy.pem")
	dhparamFile := filepath.Join(t.TempDir(), "dhparam.pem")

	if _, err := FromFiles(caFile, dhparamFile, nil); !errors.Is(err, ErrPassphraseRequired) {
		t.Fatalf("error = %v, want ErrPassphraseRequired", err)
	}

	store, err := FromFiles(caFile, dhparamFile, []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseCert(testutil.Fixture(t, "mitmproxy/mitmproxy.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !store.DefaultCA().Equal(want) {
		t.Error("loaded certificate is not the fixture certificate")
	}
}
