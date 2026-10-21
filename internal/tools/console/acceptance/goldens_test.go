// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package acceptance_test

import (
	json "encoding/json/v2"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"
	teatest "github.com/charmbracelet/x/exp/teatest/v2"
	gocmp "github.com/google/go-cmp/cmp"
)

var candidateDirectory = flag.String("console-candidates", "", "write unreviewed frame candidates to an existing absolute directory; never use in CI")

type styleControl struct {
	Row    int    `json:"row"`
	Column int    `json:"column"`
	SGR    string `json:"sgr"`
}

type framePresentation struct {
	Styles    []styleControl `json:"styles"`
	Cursor    *tea.Cursor    `json:"cursor"`
	AltScreen bool           `json:"alt_screen"`
}

func frameCells(t *testing.T, view tea.View, width, height int) string {
	t.Helper()
	lines := strings.Split(strings.ReplaceAll(ansi.Strip(view.Content), "\r\n", "\n"), "\n")
	if len(lines) != height {
		t.Fatalf("frame has %d rows, want %d", len(lines), height)
	}
	for row, line := range lines {
		cells := ansi.StringWidth(line)
		if cells > width {
			t.Fatalf("frame row %d has %d cells, exceeds %d: %q", row, cells, width, line)
		}
		lines[row] = line + strings.Repeat(" ", width-cells)
	}
	return strings.Join(lines, "\n")
}

func presentation(view tea.View) framePresentation {
	result := framePresentation{Cursor: view.Cursor, AltScreen: view.AltScreen}
	for row, line := range strings.Split(view.Content, "\n") {
		column := 0
		var state byte
		for len(line) > 0 {
			sequence, width, consumed, next := ansi.DecodeSequence(line, state, nil)
			if consumed == 0 {
				break
			}
			if strings.HasPrefix(sequence, "\x1b[") && strings.HasSuffix(sequence, "m") {
				result.Styles = append(result.Styles, styleControl{Row: row, Column: column, SGR: sequence})
			}
			column += width
			line, state = line[consumed:], next
		}
	}
	return result
}

func TestConsoleGoldens(t *testing.T) {
	if os.Getenv("CI") != "" {
		if update := flag.Lookup("update"); *candidateDirectory != "" || update != nil && update.Value.String() == "true" {
			t.Fatal("frame generation is forbidden in CI")
		}
	}
	t.Run("frames", func(t *testing.T) {
		states := map[string]struct{}{"flowlist": {}, "flowview": {}, "commander": {}}
		for state := range states {
			t.Run(state, func(t *testing.T) {
				sizes := map[string]struct{ width, height int }{"80x24": {80, 24}, "200x50": {200, 50}}
				for size, dimensions := range sizes {
					t.Run(size, func(t *testing.T) {
						if state == "commander" && size == "80x24" {
							tests := map[string]struct {
								header string
								want   bool
							}{
								"short wait":       {header: "goroutine 1 [chan receive]:", want: true},
								"long wait":        {header: "goroutine 1 [chan receive, 1 minutes]:", want: true},
								"longer wait":      {header: "goroutine 1 [chan receive, 12 minutes]:", want: true},
								"different state":  {header: "goroutine 1 [chan send, 1 minutes]:"},
								"unknown duration": {header: "goroutine 1 [chan receive, unknown]:"},
							}
							for name, test := range tests {
								stack := test.header + "\ngithub.com/charmbracelet/x/exp/teatest/v2.NewTestModel.func2()\n\t/module/teatest.go:168 +0x0"
								if got := isSignalListener(stack); got != test.want {
									t.Errorf("listener header %s: got %v, want %v", name, got, test.want)
								}
								if isSignalListener(strings.Replace(stack, "teatest.go:168", "teatest.go:169", 1)) || isSignalListener(strings.Replace(stack, "NewTestModel.func2()", "NewTestModel.func1()", 1)) {
									t.Errorf("listener header %s accepted a different function or source site", name)
								}
							}
						}
						view, transcript := captureFrame(t, state, dimensions.width, dimensions.height)
						frame := frameCells(t, view, dimensions.width, dimensions.height)
						styles := presentation(view)
						if len(styles.Styles) == 0 || !view.AltScreen {
							t.Fatal("assembled view lost trusted palette styling or alternate-screen declaration")
						}
						// A changed cell or removed row must not disappear during normalization.
						changed := strings.Replace(frame, "example.com", "example.con", 1)
						if changed == frame || gocmp.Diff(frame, changed) == "" {
							t.Fatal("frame comparison did not detect a displaced content marker")
						}
						if gocmp.Diff(frame, strings.Join(strings.Split(frame, "\n")[1:], "\n")) == "" {
							t.Fatal("frame comparison did not detect an omitted line")
						}
						if *candidateDirectory != "" {
							if !filepath.IsAbs(*candidateDirectory) {
								t.Fatal("candidate directory must be absolute")
							}
							root := filepath.Join(*candidateDirectory, state, size)
							requireNoError(t, os.MkdirAll(root, 0o700))
							metadata, err := json.Marshal(styles)
							requireNoError(t, err)
							for name, data := range map[string][]byte{
								"frame.txt":         []byte(frame),
								"frame.escaped.txt": fmt.Appendf(nil, "%q\n", view.Content),
								"frame.ansi.txt":    []byte(view.Content),
								"presentation.json": metadata,
								"transcript.ansi":   transcript,
							} {
								requireNoError(t, os.WriteFile(filepath.Join(root, name), data, 0o600))
							}
							t.Logf("UNREVIEWED candidates only: %s", root)
							return
						}
						teatest.RequireEqualOutput(t, []byte(frame))
						path := filepath.Join("testdata", "presentation", state+"-"+size+".json")
						if update := flag.Lookup("update"); update != nil && update.Value.String() == "true" {
							metadata, err := json.Marshal(styles)
							requireNoError(t, err)
							file, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o600)
							requireNoError(t, err)
							_, writeErr := file.Write(metadata)
							closeErr := file.Close()
							requireNoError(t, writeErr)
							requireNoError(t, closeErr)
							requireNoError(t, os.Chmod(path, 0o600))
						}
						data, err := os.ReadFile(path)
						requireNoError(t, err)
						var expected framePresentation
						requireNoError(t, json.Unmarshal(data, &expected))
						if diff := gocmp.Diff(expected, styles); diff != "" {
							t.Fatalf("presentation styles/cursor (-want +got):\n%s", diff)
						}
					})
				}
			})
		}
	})
}
