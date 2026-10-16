// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package highlight

import (
	"crypto/sha256"
	"encoding/hex"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type goldenChunk struct {
	Tag  string `json:"tag"`
	Text string `json:"text"`
}

type highlightCase struct {
	ID       string
	Language string
	Digest   string
	Text     string
	Lines    int
	Expected []Chunk
}

type exemptionKey struct {
	Digest   string
	Language string
	Line     int
}

type lineFragment struct {
	Tag       string
	Text      string
	EndsChunk bool
}

func readHighlightCorpus(root string) ([]highlightCase, error) {
	manifestBytes, err := os.ReadFile(filepath.Join(root, "inputs", "manifest.json"))
	if err != nil {
		return nil, err
	}
	manifestDigest := sha256.Sum256(manifestBytes)
	if hex.EncodeToString(manifestDigest[:]) != "8e50a63a3aa183ee61ba5c8261170243d0fcbbe498763cc57c04e572697b8390" {
		return nil, errors.New("frozen highlight input manifest differs")
	}
	var manifest struct {
		Version int `json:"schema_version"`
		Inputs  []struct {
			ID       string `json:"id"`
			Language string `json:"language"`
			Path     string `json:"path"`
			Digest   string `json:"sha256"`
			Lines    int    `json:"physical_lines"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, err
	}
	goldenBytes, err := os.ReadFile(filepath.Join(root, "goldens.json"))
	if err != nil {
		return nil, err
	}
	var goldens struct {
		Version int `json:"schema_version"`
		Oracle  struct {
			Distribution string `json:"distribution"`
			Version      string `json:"version"`
		} `json:"oracle"`
		Languages []string `json:"languages"`
		Tags      []string `json:"tags"`
		Cases     []struct {
			ID            string        `json:"id"`
			Language      string        `json:"language"`
			Digest        string        `json:"input_sha256"`
			Lines         int           `json:"physical_lines"`
			Reconstructed bool          `json:"reconstruction_equal"`
			Chunks        []goldenChunk `json:"chunks"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(goldenBytes, &goldens); err != nil {
		return nil, err
	}
	ids := []string{"css_debug", "css_highlight", "javascript_debug", "javascript_highlight", "xml_debug", "xml_highlight", "yaml_highlight", "css_real_200", "javascript_real_200", "xml_real_200", "yaml_real_200"}
	if manifest.Version != 1 || goldens.Version != 1 || len(manifest.Inputs) != len(ids) || len(goldens.Cases) != len(ids) {
		return nil, errors.New("highlight corpus version or identity count differs")
	}
	if goldens.Oracle.Distribution != "mitmproxy_rs" || goldens.Oracle.Version != "0.12.11" || !slices.Equal(goldens.Languages, Languages()) || !slices.Equal(goldens.Tags, Tags()) {
		return nil, errors.New("highlight oracle or vocabulary differs")
	}
	cases := make([]highlightCase, 0, len(ids))
	for i, input := range manifest.Inputs {
		golden := goldens.Cases[i]
		if input.ID != ids[i] || golden.ID != input.ID || golden.Language != input.Language || golden.Digest != input.Digest || golden.Lines != input.Lines || !golden.Reconstructed {
			return nil, fmt.Errorf("highlight corpus binding differs for %q", ids[i])
		}
		if !slices.Contains(Languages()[:4], input.Language) || filepath.Base(input.Path) != input.Path {
			return nil, fmt.Errorf("invalid input metadata for %q", input.ID)
		}
		data, err := os.ReadFile(filepath.Join(root, "inputs", input.Path))
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != input.Digest || physicalLines(string(data)) != input.Lines {
			return nil, fmt.Errorf("input digest or physical lines differ for %q", input.ID)
		}
		item := highlightCase{ID: input.ID, Language: input.Language, Digest: input.Digest, Text: string(data), Lines: input.Lines}
		var reconstructed strings.Builder
		for _, chunk := range golden.Chunks {
			if chunk.Tag != "" && !slices.Contains(Tags(), chunk.Tag) {
				return nil, fmt.Errorf("unknown golden tag %q for %q", chunk.Tag, input.ID)
			}
			item.Expected = append(item.Expected, Chunk{Tag: chunk.Tag, Text: chunk.Text})
			reconstructed.WriteString(chunk.Text)
		}
		if reconstructed.String() != item.Text {
			return nil, fmt.Errorf("golden reconstruction differs for %q", input.ID)
		}
		cases = append(cases, item)
	}
	return cases, nil
}

func physicalLines(text string) int {
	lines := strings.Count(text, "\n")
	if text != "" && !strings.HasSuffix(text, "\n") {
		lines++
	}
	return lines
}

func chunkLines(chunks []Chunk) [][]lineFragment {
	var lines [][]lineFragment
	line := 0
	for _, chunk := range chunks {
		remaining := len(chunk.Text)
		for part := range strings.SplitAfterSeq(chunk.Text, "\n") {
			if part == "" {
				continue
			}
			remaining -= len(part)
			for len(lines) <= line {
				lines = append(lines, nil)
			}
			lines[line] = append(lines[line], lineFragment{Tag: chunk.Tag, Text: part, EndsChunk: remaining == 0})
			if strings.HasSuffix(part, "\n") {
				line++
			}
		}
	}
	return lines
}

func validateExemptions(text string, cases []highlightCase) (map[exemptionKey]bool, error) {
	exempt := make(map[exemptionKey]bool)
	totals := make(map[string]int)
	used := make(map[string]int)
	for _, item := range cases {
		totals[item.Language] += item.Lines
	}
	row := 0
	for line := range strings.SplitSeq(text, "\n") {
		row++
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 || strings.TrimSpace(fields[3]) == "" {
			return nil, fmt.Errorf("exemption row %d requires digest, language, line and reason", row)
		}
		digest, err := hex.DecodeString(fields[0])
		if err != nil || len(digest) != sha256.Size || strings.ToLower(fields[0]) != fields[0] {
			return nil, fmt.Errorf("invalid exemption digest at row %d", row)
		}
		physicalLine, err := strconv.Atoi(fields[2])
		if err != nil || physicalLine < 1 {
			return nil, fmt.Errorf("invalid exemption line at row %d", row)
		}
		key := exemptionKey{Digest: fields[0], Language: fields[1], Line: physicalLine}
		if exempt[key] {
			return nil, fmt.Errorf("duplicate exemption at row %d", row)
		}
		matches := 0
		for _, item := range cases {
			if item.Digest != key.Digest || item.Language != key.Language {
				continue
			}
			matches++
			if key.Line > item.Lines {
				return nil, fmt.Errorf("exemption beyond %q at row %d", item.ID, row)
			}
			for _, fragment := range chunkLines(item.Expected)[key.Line-1] {
				if fragment.Tag == "name" || fragment.Tag == "string" {
					return nil, fmt.Errorf("exemption intersects %s in %q at row %d", fragment.Tag, item.ID, row)
				}
			}
		}
		if matches == 0 {
			return nil, fmt.Errorf("stale or mismatched exemption at row %d", row)
		}
		used[key.Language] += matches
		if used[key.Language] > totals[key.Language]/20 {
			return nil, fmt.Errorf("exemptions exceed %s line budget", key.Language)
		}
		exempt[key] = true
	}
	return exempt, nil
}

func compareHighlight(item highlightCase, actual []Chunk, exempt map[exemptionKey]bool) error {
	var reconstructed strings.Builder
	for _, chunk := range actual {
		if chunk.Text == "" {
			return fmt.Errorf("%s contains an empty source span", item.ID)
		}
		reconstructed.WriteString(chunk.Text)
	}
	if reconstructed.String() != item.Text {
		return fmt.Errorf("%s source reconstruction differs", item.ID)
	}
	hasExemption := false
	for key := range exempt {
		if key.Digest == item.Digest && key.Language == item.Language {
			hasExemption = true
		}
	}
	if !hasExemption {
		if diff := cmp.Diff(item.Expected, actual); diff != "" {
			return fmt.Errorf("%s chunks differ (-want +got):\n%s", item.ID, diff)
		}
		return nil
	}
	expectedLines, actualLines := chunkLines(item.Expected), chunkLines(actual)
	if len(expectedLines) != item.Lines || len(actualLines) != item.Lines {
		return fmt.Errorf("%s physical line count differs", item.ID)
	}
	for line, expected := range expectedLines {
		key := exemptionKey{Digest: item.Digest, Language: item.Language, Line: line + 1}
		if exempt[key] {
			for _, fragment := range expected {
				if fragment.Tag == "name" || fragment.Tag == "string" {
					return fmt.Errorf("%s protected line %d cannot be exempted", item.ID, line+1)
				}
			}
			continue
		}
		if diff := cmp.Diff(expected, actualLines[line]); diff != "" {
			return fmt.Errorf("%s line %d differs (-want +got):\n%s", item.ID, line+1, diff)
		}
	}
	return nil
}

func TestHighlightGoldens(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "highlight")
	cases, err := readHighlightCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	exempt, err := readHighlightExemptions(root, cases)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range cases {
		group := "upstream"
		if strings.HasSuffix(item.ID, "_real_200") {
			group = "samples"
		}
		t.Run(group+"/"+item.ID, func(t *testing.T) {
			actual, err := Highlight(item.Text, item.Language)
			if err != nil {
				t.Fatal(err)
			}
			if err := compareHighlight(item, actual, exempt); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func readHighlightExemptions(root string, cases []highlightCase) (map[exemptionKey]bool, error) {
	text, err := os.ReadFile(filepath.Join(root, "EXEMPTIONS"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return validateExemptions(string(text), cases)
}

func TestHighlightExemptions(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "highlight")
	cases, err := readHighlightCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readHighlightExemptions(root, cases); err != nil {
		t.Fatal(err)
	}
}

func TestExemptionRules(t *testing.T) {
	text := strings.Repeat("plain\n", 20)
	digest := sha256.Sum256([]byte(text))
	plain := highlightCase{ID: "plain", Language: "yaml", Digest: hex.EncodeToString(digest[:]), Text: text, Lines: 20, Expected: []Chunk{{Text: text}}}
	name := plain
	name.Expected = []Chunk{{Tag: "name", Text: "plain\n"}, {Text: strings.Repeat("plain\n", 19)}}
	stringValue := plain
	stringValue.Expected = []Chunk{{Tag: "string", Text: "plain\nplain\n"}, {Text: strings.Repeat("plain\n", 18)}}
	row := func(line int) string { return fmt.Sprintf("%s\tyaml\t%d\treason", plain.Digest, line) }
	tests := map[string]struct {
		text      string
		cases     []highlightCase
		wantError bool
	}{
		"empty":                     {cases: []highlightCase{plain}},
		"comments":                  {text: "# none\n", cases: []highlightCase{plain}},
		"at limit":                  {text: row(1), cases: []highlightCase{plain}},
		"above limit":               {text: row(1) + "\n" + row(2), cases: []highlightCase{plain}, wantError: true},
		"duplicate":                 {text: row(1) + "\n" + row(1), cases: []highlightCase{plain}, wantError: true},
		"out of range":              {text: row(21), cases: []highlightCase{plain}, wantError: true},
		"zero":                      {text: row(0), cases: []highlightCase{plain}, wantError: true},
		"negative":                  {text: row(-1), cases: []highlightCase{plain}, wantError: true},
		"missing reason":            {text: strings.TrimSuffix(row(1), "reason"), cases: []highlightCase{plain}, wantError: true},
		"invalid digest":            {text: "invalid\tyaml\t1\treason", cases: []highlightCase{plain}, wantError: true},
		"stale digest":              {text: strings.Repeat("0", 64) + "\tyaml\t1\treason", cases: []highlightCase{plain}, wantError: true},
		"wrong language":            {text: strings.Replace(row(1), "\tyaml\t", "\txml\t", 1), cases: []highlightCase{plain}, wantError: true},
		"name span":                 {text: row(1), cases: []highlightCase{name}, wantError: true},
		"multiline string span":     {text: row(2), cases: []highlightCase{stringValue}, wantError: true},
		"shared digest at limit":    {text: row(1), cases: []highlightCase{plain, plain}},
		"shared digest above limit": {text: row(1) + "\n" + row(2), cases: []highlightCase{plain, plain}, wantError: true},
	}
	for testName, tt := range tests {
		t.Run(testName, func(t *testing.T) {
			_, err := validateExemptions(tt.text, tt.cases)
			if (err != nil) != tt.wantError {
				t.Fatalf("validateExemptions error = %v, want error %v", err, tt.wantError)
			}
		})
	}
}

func TestGoldenComparison(t *testing.T) {
	tests := map[string]struct {
		expected  []Chunk
		actual    []Chunk
		exempt    bool
		wantError bool
	}{
		"identical":                       {expected: []Chunk{{Text: "one\ntwo\n"}}, actual: []Chunk{{Text: "one\ntwo\n"}}},
		"token boundary matters":          {expected: []Chunk{{Text: "one\ntwo\n"}}, actual: []Chunk{{Text: "one\n"}, {Text: "two\n"}}, wantError: true},
		"allowed first line":              {expected: []Chunk{{Tag: "number", Text: "one\n"}, {Text: "two\n"}}, actual: []Chunk{{Text: "one\n"}, {Text: "two\n"}}, exempt: true},
		"unexempted line differs":         {expected: []Chunk{{Text: "one\n"}, {Text: "two\n"}}, actual: []Chunk{{Text: "one\n"}, {Tag: "number", Text: "two\n"}}, exempt: true, wantError: true},
		"name cannot be waived":           {expected: []Chunk{{Tag: "name", Text: "one\n"}, {Text: "two\n"}}, actual: []Chunk{{Text: "one\n"}, {Text: "two\n"}}, exempt: true, wantError: true},
		"string cannot be waived":         {expected: []Chunk{{Tag: "string", Text: "one\n"}, {Text: "two\n"}}, actual: []Chunk{{Text: "one\n"}, {Text: "two\n"}}, exempt: true, wantError: true},
		"reconstruction cannot be waived": {expected: []Chunk{{Text: "one\ntwo\n"}}, actual: []Chunk{{Text: "other\ntwo\n"}}, exempt: true, wantError: true},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			item := highlightCase{ID: "example", Language: "yaml", Digest: "digest", Text: "one\ntwo\n", Lines: 2, Expected: tt.expected}
			exempt := map[exemptionKey]bool{}
			if tt.exempt {
				exempt[exemptionKey{Digest: item.Digest, Language: item.Language, Line: 1}] = true
			}
			err := compareHighlight(item, tt.actual, exempt)
			if (err != nil) != tt.wantError {
				t.Fatalf("compareHighlight error = %v, want error %v", err, tt.wantError)
			}
		})
	}
}

func TestPhysicalLines(t *testing.T) {
	tests := map[string]struct {
		text string
		want int
	}{
		"empty":               {"", 0},
		"unterminated":        {"one", 1},
		"terminated":          {"one\n", 1},
		"empty physical line": {"\n", 1},
		"crlf":                {"one\r\ntwo\r\n", 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if got := physicalLines(tt.text); got != tt.want {
				t.Fatalf("physicalLines(%q)=%d, want %d", tt.text, got, tt.want)
			}
		})
	}
}
