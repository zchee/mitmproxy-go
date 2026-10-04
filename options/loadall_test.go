// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package options

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

// TestLoadAllPrecedence reproduces the order of mitmproxy's tools/main.py:
// passed flags > config.yml > config.yaml > --set > defaults.
func TestLoadAllPrecedence(t *testing.T) {
	tests := map[string]struct {
		setSpecs    []string
		yaml        string // content of config.yaml; empty means absent
		yml         string // content of config.yml; empty means absent
		passedFlags map[string]any
		want        *int
	}{
		"success: passed flag wins": {
			setSpecs:    []string{"listen_port=1"},
			yaml:        "listen_port: 2\n",
			yml:         "listen_port: 3\n",
			passedFlags: map[string]any{"listen_port": 4},
			want:        new(4),
		},
		"success: config.yml without flags": {
			setSpecs:    []string{"listen_port=1"},
			yaml:        "listen_port: 2\n",
			yml:         "listen_port: 3\n",
			passedFlags: map[string]any{},
			want:        new(3),
		},
		"success: config.yaml without config.yml": {
			setSpecs: []string{"listen_port=1"},
			yaml:     "listen_port: 2\n",
			want:     new(2),
		},
		"success: --set without config files": {
			setSpecs: []string{"listen_port=1"},
			want:     new(1),
		},
		"success: default without any source": {
			want: nil,
		},
		"success: absent flag does not override config": {
			setSpecs:    []string{"listen_port=1"},
			yml:         "listen_port: 3\n",
			passedFlags: map[string]any{"listen_host": "127.0.0.1"},
			want:        new(3),
		},
		"success: nil flag value is ignored": {
			yml:         "listen_port: 3\n",
			passedFlags: map[string]any{"listen_port": nil},
			want:        new(3),
		},
		"success: typed nil flag value is ignored": {
			yml:         "listen_port: 3\n",
			passedFlags: map[string]any{"listen_port": (*int)(nil), "cert_passphrase": (*string)(nil)},
			want:        new(3),
		},
		"success: unknown flag name is ignored": {
			yml:         "listen_port: 3\n",
			passedFlags: map[string]any{"no_such_option": 1},
			want:        new(3),
		},
		"success: config.yml null resets to None": {
			setSpecs: []string{"listen_port=1"},
			yml:      "listen_port:\n",
			want:     nil,
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.yaml != "" {
				writeFile(t, filepath.Join(dir, "config.yaml"), tt.yaml)
			}
			if tt.yml != "" {
				writeFile(t, filepath.Join(dir, "config.yml"), tt.yml)
			}
			m := New()
			if err := m.LoadAll(t.Context(), tt.setSpecs, dir, tt.passedFlags); err != nil {
				t.Fatalf("LoadAll: %v", err)
			}
			if diff := gocmp.Diff(tt.want, m.OptInt("listen_port")); diff != "" {
				t.Errorf("listen_port mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLoadAllSequenceAndBoolSpecs(t *testing.T) {
	m := New()
	mustAdd(t, m, "anticache", TypeBool, false, "help")
	if err := m.LoadAll(t.Context(), []string{"ignore_hosts=a", "ignore_hosts=b", "anticache"}, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	if diff := gocmp.Diff([]string{"a", "b"}, m.Seq("ignore_hosts")); diff != "" {
		t.Errorf("ignore_hosts (-want +got):\n%s", diff)
	}
	if !m.Bool("anticache") {
		t.Error("--set anticache did not set true")
	}
	if err := m.LoadAll(t.Context(), []string{"anticache=toggle"}, t.TempDir(), nil); err != nil {
		t.Fatal(err)
	}
	if m.Bool("anticache") {
		t.Error("--set anticache=toggle did not flip true to false")
	}
}

func TestLoadAllDefersUnknownSpecs(t *testing.T) {
	m := New()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "config.yaml"), "anticache: true\n")
	if err := m.LoadAll(t.Context(), []string{"stream_large_bodies=1m"}, dir, nil); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"stream_large_bodies": Unparsed{"1m"}, "anticache": true}
	if diff := gocmp.Diff(want, m.Deferred()); diff != "" {
		t.Errorf("Deferred (-want +got):\n%s", diff)
	}
	mustAdd(t, m, "anticache", TypeBool, false, "help")
	mustAdd(t, m, "stream_large_bodies", TypeOptStr, nil, "help")
	if err := m.ProcessDeferred(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !m.Bool("anticache") {
		t.Error("deferred anticache not applied")
	}
	if got := m.OptStr("stream_large_bodies"); got == nil || *got != "1m" {
		t.Errorf("stream_large_bodies = %v, want 1m", got)
	}
}

func TestLoadAllConfdir(t *testing.T) {
	t.Run("success: confdir option set by --set", func(t *testing.T) {
		dir := t.TempDir()
		writeFile(t, filepath.Join(dir, "config.yaml"), "listen_port: 2\n")
		m := New()
		if err := m.LoadAll(t.Context(), []string{"confdir=" + dir}, "", nil); err != nil {
			t.Fatal(err)
		}
		if got := m.OptInt("listen_port"); got == nil || *got != 2 {
			t.Errorf("listen_port = %v, want 2 from the --set confdir", got)
		}
	})
	t.Run("success: tilde expands to the home directory", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		writeFile(t, filepath.Join(home, "config.yml"), "listen_port: 3\n")
		m := New()
		if err := m.LoadAll(t.Context(), nil, "~", nil); err != nil {
			t.Fatal(err)
		}
		if got := m.OptInt("listen_port"); got == nil || *got != 3 {
			t.Errorf("listen_port = %v, want 3 from ~/config.yml", got)
		}
	})
	t.Run("success: default confdir without the option", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		conf := filepath.Join(home, ".mitmproxy")
		if err := os.MkdirAll(conf, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(conf, "config.yaml"), "x: 5\n")
		m := NewManager()
		mustAdd(t, m, "x", TypeInt, 0, "help")
		if err := m.LoadAll(t.Context(), nil, "", nil); err != nil {
			t.Fatal(err)
		}
		if got := m.Int("x"); got != 5 {
			t.Errorf("x = %d, want 5 from %s", got, ConfDir)
		}
	})
}

func TestLoadAllErrors(t *testing.T) {
	t.Run("error: malformed --set", func(t *testing.T) {
		err := New().LoadAll(t.Context(), []string{"listen_port=abc"}, t.TempDir(), nil)
		requireOptionsError(t, err, "Failed to parse option listen_port: not an integer: abc")
	})
	t.Run("error: invalid config file names the file", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yml")
		writeFile(t, path, "listen_port: [\n")
		err := New().LoadAll(t.Context(), nil, dir, nil)
		requireOptionsError(t, err, "Error reading "+path+": Config error")
	})
	t.Run("error: flag of the wrong type", func(t *testing.T) {
		err := New().LoadAll(t.Context(), nil, t.TempDir(), map[string]any{"listen_port": "8080"})
		var typeErr *TypeError
		if !errors.As(err, &typeErr) || !strings.Contains(err.Error(), "listen_port") {
			t.Fatalf("LoadAll = %v, want *TypeError for listen_port", err)
		}
	})
}
