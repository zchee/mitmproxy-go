// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package cmdline

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/zchee/mitmproxy-go/options"
)

func TestCompletionScripts(t *testing.T) {
	tests := map[string]struct {
		shell     string
		validator []string
	}{
		"success: bash":       {"bash", []string{"bash", "-n"}},
		"success: zsh":        {"zsh", []string{"zsh", "-n"}},
		"success: fish":       {"fish", []string{"fish", "-n"}},
		"success: powershell": {"powershell", []string{"pwsh", "-NoProfile", "-NonInteractive", "-Command", `$tokens=$null; $errors=$null; [void][System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$tokens, [ref]$errors); if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }`}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cmd := New(options.New(), "test")
			cmd.RunE = func(*cobra.Command, []string) error { t.Fatal("completion must not start the proxy"); return nil }
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs([]string{"completion", tt.shell})
			if err := cmd.ExecuteContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			// Cobra's generators all ask this runtime protocol for flag names.
			for _, required := range []string{"mitmdump", "__complete"} {
				if !strings.Contains(out.String(), required) {
					t.Fatalf("%s script lacks %q:\n%s", tt.shell, required, out.String())
				}
			}
			t.Run("syntax", func(t *testing.T) {
				validator, err := exec.LookPath(tt.validator[0])
				if err != nil {
					t.Skipf("shell syntax check requires %s: %v", tt.validator[0], err)
				}
				check := exec.CommandContext(t.Context(), validator, tt.validator[1:]...)
				check.Stdin = strings.NewReader(out.String())
				if output, err := check.CombinedOutput(); err != nil {
					t.Fatalf("%s completion syntax: %v\n%s", tt.shell, err, output)
				}
			})
		})
	}
}

func TestCompletionListsEveryFlag(t *testing.T) {
	cmd := New(testOptions(t), "test")
	var out, stderr bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"__complete", "--"})
	if err := cmd.ExecuteContext(t.Context()); err != nil {
		t.Fatal(err)
	}
	completed := make(map[string]bool)
	for line := range strings.SplitSeq(out.String(), "\n") {
		name, _, _ := strings.Cut(line, "\t")
		completed[strings.TrimSuffix(name, "=")] = true
	}
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if !flag.Hidden && !completed["--"+flag.Name] {
			t.Errorf("completion missing --%s:\n%s\n%s", flag.Name, out.String(), stderr.String())
		}
	})
}
