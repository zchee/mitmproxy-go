// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package web

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	json "encoding/json/v2"
	"errors"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	gocmp "github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/filter"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/flowio"
	"github.com/zchee/mitmproxy-go/flowio/flowjson"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/version"
)

func viewerTestFiles(t *testing.T, flows []flow.Flow) map[string][]byte {
	t.Helper()
	files, err := viewerFiles(t.Context(), flows, "")
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func viewerTestStage(t *testing.T, files map[string][]byte) *viewerExport {
	t.Helper()
	e, err := newViewerExport(filepath.Join(t.TempDir(), "viewer"), files)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := e.close(); err != nil {
			t.Error(err)
		}
	})
	return e
}

func viewerRead(t *testing.T, root *os.Root, name string) []byte {
	t.Helper()
	body, err := root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func viewerFlowFile(t *testing.T, flows []flow.Flow) string {
	t.Helper()
	name := filepath.Join(t.TempDir(), "input.mitm")
	file, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	writer := flowio.NewWriter(file)
	for _, f := range flows {
		if err := writer.Add(f); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return name
}

func configureViewer(t *testing.T, m *Master, destination, rfile string) {
	t.Helper()
	if err := m.Do(t.Context(), func(ctx context.Context) error {
		return m.Options.Update(ctx, map[string]any{"web_static_viewer": destination, "rfile": rfile})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestWebStaticViewer(t *testing.T) {
	if phase := os.Getenv("MITMPROXY_TEST_VIEWER_PHASE"); phase != "" {
		viewerChild(t, phase)
		return
	}
	t.Run("upstream", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"test_save_static": {run: func(t *testing.T) {
				files, err := viewerStaticFiles()
				if err != nil {
					t.Fatal(err)
				}
				e := viewerTestStage(t, files)
				if err := e.stage.Mkdir("static", 0o700); err != nil {
					t.Fatal(err)
				}
				if err := e.stage.WriteFile("static/stale", []byte("old owned subtree"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := e.write(t.Context(), files); err != nil {
					t.Fatal(err)
				}
				entries, err := fs.ReadDir(e.stage.FS(), ".")
				if err != nil {
					t.Fatal(err)
				}
				var names []string
				for _, entry := range entries {
					if entry.Name() != viewerMarker {
						names = append(names, entry.Name())
					}
				}
				if diff := gocmp.Diff([]string{"index.html", "static"}, names); diff != "" {
					t.Fatal(diff)
				}
				if got := string(viewerRead(t, e.stage, "static/static.js")); got != "MITMWEB_STATIC = true;" {
					t.Fatalf("static flag=%q", got)
				}
				for name, body := range files {
					if diff := gocmp.Diff(body, viewerRead(t, e.stage, name)); diff != "" {
						t.Fatalf("asset %s: %s", name, diff)
					}
				}
				if _, err := e.stage.Lstat("static/stale"); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("stale subtree survived: %v", err)
				}
			}},
			"test_save_filter_help": {run: func(t *testing.T) {
				files := viewerTestFiles(t, nil)
				e := viewerTestStage(t, files)
				if err := e.write(t.Context(), files); err != nil {
					t.Fatal(err)
				}
				want, err := json.Marshal(struct {
					Commands []filter.HelpEntry `json:"commands"`
				}{filter.Help()}, jsontext.SpaceAfterColon(true), jsontext.SpaceAfterComma(true))
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(want, viewerRead(t, e.stage, "filter-help.json")); diff != "" {
					t.Fatal(diff)
				}
			}},
			"test_save_settings": {run: func(t *testing.T) {
				e := viewerTestStage(t, map[string][]byte{})
				if err := e.saveSettings(t.Context()); err != nil {
					t.Fatal(err)
				}
				var got map[string]string
				if err := json.Unmarshal(viewerRead(t, e.stage, "settings.json"), &got); err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(map[string]string{"version": version.Version}, got); diff != "" {
					t.Fatal(diff)
				}
			}},
			"test_save_flows": {run: func(t *testing.T) {
				flows := []flow.Flow{testflow.TFlow(), testflow.TFlow(testflow.WithResponse)}
				files := viewerTestFiles(t, flows)
				e := viewerTestStage(t, files)
				if err := e.write(t.Context(), files); err != nil {
					t.Fatal(err)
				}
				values := make([]any, 0, len(flows))
				for _, f := range flows {
					v, err := flowjson.Flow(f)
					if err != nil {
						t.Fatal(err)
					}
					values = append(values, v)
				}
				want, err := json.Marshal(values, jsontext.SpaceAfterColon(true), jsontext.SpaceAfterComma(true))
				if err != nil {
					t.Fatal(err)
				}
				if diff := gocmp.Diff(want, viewerRead(t, e.stage, "flows.json")); diff != "" {
					t.Fatal(diff)
				}
			}},
			"test_save_flows_content": {run: func(t *testing.T) {
				flows := []flow.Flow{testflow.TFlow(), testflow.TFlow(testflow.WithResponse)}
				files := viewerTestFiles(t, flows)
				e := viewerTestStage(t, files)
				if err := e.write(t.Context(), files); err != nil {
					t.Fatal(err)
				}
				entries, err := fs.ReadDir(e.stage.FS(), "flows")
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != len(flows) {
					t.Fatalf("flow directories=%d", len(entries))
				}
				for _, f := range flows {
					for _, part := range []string{"request", "response"} {
						prefix := "flows/" + f.Common().ID + "/" + part + "/"
						var pretty map[string]string
						if err := json.Unmarshal(viewerRead(t, e.stage, prefix+"content/Auto.json"), &pretty); err != nil {
							t.Fatal(err)
						}
						if diff := gocmp.Diff([]string{"description", "syntax_highlight", "text", "view_name"}, slices.Sorted(maps.Keys(pretty))); diff != "" {
							t.Fatal(diff)
						}
						message, err := httpMessage(f, part)
						if err != nil {
							if string(viewerRead(t, e.stage, prefix+"content.data")) != "No content." {
								t.Fatal("missing response raw fallback")
							}
							if diff := gocmp.Diff(map[string]string{"text": "No content.", "syntax_highlight": "none", "view_name": "/", "description": ""}, pretty); diff != "" {
								t.Fatal(diff)
							}
						} else {
							want, err := message.Content()
							if err != nil {
								t.Fatal(err)
							}
							if diff := gocmp.Diff(want, viewerRead(t, e.stage, prefix+"content.data")); diff != "" {
								t.Fatal(diff)
							}
						}
					}
				}
				empty := testflow.TFlow()
				empty.Request.SetContent([]byte{})
				emptyFiles := viewerTestFiles(t, []flow.Flow{empty})
				if len(emptyFiles["flows/"+empty.ID+"/request/content.data"]) != 0 {
					t.Fatal("present empty body changed")
				}
				empty.Request.RawContent = nil
				if _, err := viewerFiles(t.Context(), []flow.Flow{empty}, ""); err == nil {
					t.Fatal("missing content was silently exported as an empty body")
				}
			}},
			"test_static_viewer": {run: func(t *testing.T) {
				// Unlike upstream's existing tmpdir destination, publication uses an
				// absent child. The real input flow file is an unrelated sibling.
				f := testflow.TFlow(testflow.WithResponse)
				rfile := viewerFlowFile(t, []flow.Flow{f})
				destination := filepath.Join(filepath.Dir(rfile), "viewer")
				m := newWebMaster(t)
				configureViewer(t, m, destination, rfile)
				if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("configure performed file I/O: %v", err)
				}
				done := startWebMaster(t, m)
				if err := m.StaticViewer.Wait(t.Context()); err != nil {
					t.Fatal(err)
				}
				root, err := os.OpenRoot(destination)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := root.Close(); err != nil {
						t.Error(err)
					}
				}()
				for _, name := range []string{"index.html", "static", "flows"} {
					if _, err := root.Stat(name); err != nil {
						t.Fatal(err)
					}
				}
				if err := validateViewerFiles(root, viewerTestFiles(t, []flow.Flow{f}), ""); err != nil {
					t.Fatal(err)
				}
				if _, err := root.Lstat("settings.json"); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("export invented settings.json: %v", err)
				}
				stopWebMaster(t, m, done)
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
	t.Run("write_contract", func(t *testing.T) {
		tests := map[string]struct{ run func(*testing.T) }{
			"staged_publish": {run: func(t *testing.T) {
				files := viewerTestFiles(t, []flow.Flow{testflow.TFlow(testflow.WithResponse)})
				e := viewerTestStage(t, files)
				if info, err := e.stage.Stat("."); err != nil || info.Mode().Perm() != 0o700 {
					t.Fatalf("private stage: %v %v", info, err)
				}
				if err := e.write(t.Context(), files); err != nil {
					t.Fatal(err)
				}
				if _, err := e.parent.Lstat(e.destination); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("visible partial export: %v", err)
				}
				if err := validateViewerFiles(e.stage, files, viewerMarker); err != nil {
					t.Fatal(err)
				}
				name := e.name
				if err := e.publish(t.Context(), files); err != nil {
					t.Fatal(err)
				}
				if _, err := e.parent.Lstat(name); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("stage survived publication: %v", err)
				}
				root, err := e.parent.OpenRoot(e.destination)
				if err != nil {
					t.Fatal(err)
				}
				if err := validateViewerFiles(root, files, ""); err != nil {
					_ = root.Close()
					t.Fatal(err)
				}
				if _, err := root.Lstat(viewerMarker); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("ownership marker in payload: %v", err)
				}
				if err := root.Close(); err != nil {
					t.Fatal(err)
				}
			}},
			"existing_destination_refused": {run: func(t *testing.T) {
				files := viewerTestFiles(t, nil)
				for _, kind := range []string{"empty", "populated", "file", "symlink", "export"} {
					parent := t.TempDir()
					dest := filepath.Join(parent, "viewer")
					switch kind {
					case "file":
						if err := os.WriteFile(dest, []byte("untouched"), 0o600); err != nil {
							t.Fatal(err)
						}
					case "symlink":
						if err := os.Symlink(parent, dest); err != nil {
							t.Fatal(err)
						}
					case "export":
						if err := exportViewer(t.Context(), dest, nil, ""); err != nil {
							t.Fatal(err)
						}
					default:
						if err := os.Mkdir(dest, 0o700); err != nil {
							t.Fatal(err)
						}
						if kind == "populated" {
							if err := os.WriteFile(filepath.Join(dest, "sentinel"), []byte("untouched"), 0o600); err != nil {
								t.Fatal(err)
							}
						}
					}
					before, err := os.Lstat(dest)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := newViewerExport(dest, files); !errors.Is(err, fs.ErrExist) {
						t.Fatalf("%s destination was not refused: %v", kind, err)
					}
					after, err := os.Lstat(dest)
					if err != nil || !os.SameFile(before, after) {
						t.Fatalf("%s destination changed: %v", kind, err)
					}
					if kind == "populated" {
						body, err := os.ReadFile(filepath.Join(dest, "sentinel"))
						if err != nil || string(body) != "untouched" {
							t.Fatalf("sentinel changed: %v", err)
						}
					}
				}
			}},
			"write_failure_cleanup": {run: func(t *testing.T) {
				files := viewerTestFiles(t, nil)
				e := viewerTestStage(t, files)
				parent, name, dest := e.parent.Name(), e.name, e.destination
				if err := e.stage.Mkdir("index.html", 0o700); err != nil {
					t.Fatal(err)
				}
				if err := e.write(t.Context(), files); err == nil {
					t.Fatal("real directory/file collision succeeded")
				}
				if err := e.close(); err != nil {
					t.Fatal(err)
				}
				for _, path := range []string{name, dest} {
					if _, err := os.Lstat(filepath.Join(parent, path)); !errors.Is(err, fs.ErrNotExist) {
						t.Fatalf("failed export left %s: %v", path, err)
					}
				}
				cancelled, cancel := context.WithCancel(t.Context())
				cancel()
				if err := exportViewer(cancelled, filepath.Join(parent, "canceled"), nil, ""); !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation result: %v", err)
				}
				entries, err := os.ReadDir(parent)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("cancellation left staging: %v", entries)
				}
			}},
			"rename_collision": {run: func(t *testing.T) {
				files := viewerTestFiles(t, nil)
				e := viewerTestStage(t, files)
				if err := e.write(t.Context(), files); err != nil {
					t.Fatal(err)
				}
				if err := e.parent.Mkdir(e.destination, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := e.parent.WriteFile(e.destination+"/sentinel", []byte("other owner"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := e.publish(t.Context(), files); !errors.Is(err, fs.ErrExist) {
					t.Fatalf("rename collision result: %v", err)
				}
				if e.published {
					t.Fatal("collision reported published")
				}
				if got := string(viewerRead(t, e.parent, e.destination+"/sentinel")); got != "other owner" {
					t.Fatalf("destination was replaced: %q", got)
				}
			}},
			"recovery": {run: func(t *testing.T) {
				for _, phase := range []string{"partial", "complete", "unmarked", "mismatch", "published"} {
					dest := filepath.Join(t.TempDir(), "viewer")
					viewerCrash(t, phase, dest)
					beforeEntries, err := os.ReadDir(filepath.Dir(dest))
					if err != nil || len(beforeEntries) != 1 {
						t.Fatalf("crash inventory: %v %v", beforeEntries, err)
					}
					remnant := filepath.Join(filepath.Dir(dest), beforeEntries[0].Name())
					before, err := os.Lstat(remnant)
					if err != nil {
						t.Fatal(err)
					}
					err = exportViewer(t.Context(), dest, nil, "")
					switch phase {
					case "published":
						if !errors.Is(err, fs.ErrExist) {
							t.Fatalf("published recovery did not refuse overwrite: %v", err)
						}
					case "unmarked", "mismatch":
						after, statErr := os.Lstat(remnant)
						if statErr != nil || !os.SameFile(before, after) {
							t.Fatalf("unverified remnant was altered: %v", statErr)
						}
						if _, statErr := os.Lstat(dest); !errors.Is(statErr, fs.ErrNotExist) {
							t.Fatalf("unverified remnant became visible: %v", statErr)
						}
						if err == nil {
							t.Fatal("unverified crash remnant was guessed owned")
						}
						continue
					default:
						if err != nil {
							t.Fatalf("%s recovery: %v", phase, err)
						}
					}
					root, err := os.OpenRoot(dest)
					if err != nil {
						t.Fatal(err)
					}
					if err := validateViewerFiles(root, viewerTestFiles(t, nil), ""); err != nil {
						_ = root.Close()
						t.Fatal(err)
					}
					if err := root.Close(); err != nil {
						t.Fatal(err)
					}
					entries, err := os.ReadDir(filepath.Dir(dest))
					if err != nil {
						t.Fatal(err)
					}
					if len(entries) != 1 || entries[0].Name() != "viewer" {
						t.Fatalf("recovery retained stage: %v", entries)
					}
				}
			}},
		}
		for name, tt := range tests {
			t.Run(name, tt.run)
		}
	})
	tests := map[string]struct{ run func(*testing.T) }{
		"coalesced_startup": {run: func(t *testing.T) {
			m := newWebMaster(t)
			rfile := viewerFlowFile(t, nil)
			parent := t.TempDir()
			configureViewer(t, m, filepath.Join(parent, "obsolete"), rfile)
			configureViewer(t, m, filepath.Join(parent, "latest"), rfile)
			done := startWebMaster(t, m)
			if err := m.StaticViewer.Wait(t.Context()); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(parent, "obsolete")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("obsolete pending export ran: %v", err)
			}
			if _, err := os.Stat(filepath.Join(parent, "latest", "index.html")); err != nil {
				t.Fatal(err)
			}
			configureViewer(t, m, "", rfile)
			configureViewer(t, m, filepath.Join(parent, "latest"), rfile)
			if err := m.StaticViewer.Wait(t.Context()); err != nil {
				t.Fatalf("identical already-published input re-exported: %v", err)
			}
			stopWebMaster(t, m, done)
		}},
		"startup_failure": {run: func(t *testing.T) {
			m := newWebMaster(t)
			dest := filepath.Join(t.TempDir(), "viewer")
			configureViewer(t, m, dest, filepath.Join(t.TempDir(), "missing.mitm"))
			if err := m.Run(t.Context()); err == nil {
				t.Fatal("errorcheck accepted the startup export failure")
			}
			if err := m.StaticViewer.Wait(t.Context()); err == nil {
				t.Fatal("startup observation lost the export failure")
			}
			select {
			case <-m.Ready():
				t.Fatal("failed startup export published Ready")
			default:
			}
		}},
		"runtime_failure": {run: func(t *testing.T) {
			m := newWebMaster(t)
			done := startWebMaster(t, m)
			dest := filepath.Join(t.TempDir(), "viewer")
			configureViewer(t, m, dest, filepath.Join(t.TempDir(), "missing.mitm"))
			if err := m.StaticViewer.Wait(t.Context()); err == nil {
				t.Fatal("runtime failure was not observed")
			}
			select {
			case err := <-done:
				t.Fatalf("runtime export stopped the proxy: %v", err)
			default:
			}
			if value := m.Options.OptStr("web_static_viewer"); value == nil || *value != dest {
				t.Fatal("runtime export failure rolled back the option")
			}
			if err := m.eventLogs.Flush(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := m.Do(t.Context(), func(context.Context) error {
				found := false
				for _, entry := range m.Events.Entries() {
					if strings.Contains(entry.Msg, "Static viewer export failed") {
						found = true
					}
				}
				if !found {
					return errors.New("export failure did not reach eventstore")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			stopWebMaster(t, m, done)
		}},
		"active_stage": {run: func(t *testing.T) {
			files := viewerTestFiles(t, nil)
			e := viewerTestStage(t, files)
			if _, err := newViewerExport(filepath.Join(e.parent.Name(), e.destination), files); err == nil {
				t.Fatal("active stage was recovered/deleted")
			}
			if _, err := e.stage.Lstat(viewerMarker); err != nil {
				t.Fatal(err)
			}
		}},
		"invalid_flow_path": {run: func(t *testing.T) {
			f := testflow.TFlow()
			f.ID = "../../outside"
			dest := filepath.Join(t.TempDir(), "viewer")
			if err := exportViewer(t.Context(), dest, []flow.Flow{f}, ""); err == nil {
				t.Fatal("unsafe flow ID exported")
			}
			if _, err := os.Lstat(dest); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("invalid flow left destination: %v", err)
			}
		}},
		"escaping_symlink": {run: func(t *testing.T) {
			files := viewerTestFiles(t, []flow.Flow{testflow.TFlow()})
			e := viewerTestStage(t, files)
			outside := t.TempDir()
			if err := e.stage.Symlink(outside, "flows"); err != nil {
				t.Fatal(err)
			}
			if err := e.write(t.Context(), files); err == nil {
				t.Fatal("write escaped private root")
			}
			entries, err := os.ReadDir(outside)
			if err != nil || len(entries) != 0 {
				t.Fatalf("outside contents changed: %v %v", entries, err)
			}
		}},
	}
	for name, tt := range tests {
		t.Run(name, tt.run)
	}
}

func viewerCrash(t *testing.T, phase, destination string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWebStaticViewer$", "-test.count=1")
	cmd.Env = append(os.Environ(), "MITMPROXY_TEST_VIEWER_PHASE="+phase, "MITMPROXY_TEST_VIEWER_DESTINATION="+destination)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if output, err := cmd.Output(); err != nil {
		t.Fatalf("crash boundary %s: %v\n%s\n%s", phase, err, output, stderr.String())
	}
}

func viewerChild(t *testing.T, phase string) {
	t.Helper()
	files := viewerTestFiles(t, nil)
	e, err := newViewerExport(os.Getenv("MITMPROXY_TEST_VIEWER_DESTINATION"), files)
	if err != nil {
		t.Fatal(err)
	}
	if phase == "partial" {
		err = e.stage.WriteFile("index.html", []byte("incomplete"), 0o600)
	} else {
		err = e.write(t.Context(), files)
	}
	if err != nil {
		t.Fatal(err)
	}
	if phase == "unmarked" {
		if err := e.stage.Remove(viewerMarker); err != nil {
			t.Fatal(err)
		}
	}
	if phase == "mismatch" {
		if err := e.marker.Truncate(0); err != nil {
			t.Fatal(err)
		}
		if _, err := e.marker.WriteAt([]byte(`{"version":1,"uid":-1,"destination":"other","stage":"other"}`), 0); err != nil {
			t.Fatal(err)
		}
	}
	if phase == "published" {
		if err := e.publish(t.Context(), files); err != nil {
			t.Fatal(err)
		}
	}
	// Exit at a real process boundary without deferred cleanup. Parent recovery
	// must distinguish incomplete hidden staging from a complete visible export.
	os.Exit(0)
}
