// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package local

import (
	"fmt"
	"strconv"
	"strings"
)

// EncodeInterceptSpec validates and normalizes native interception rules.
// Nonempty rules end with an exclusion of ownPID; an existing normalized
// trailing exclusion is retained without duplication. Empty rules disable interception.
// It returns an error for empty comma-separated patterns or empty exclusions.
func EncodeInterceptSpec(spec string, ownPID uint32) (*InterceptConf, error) {
	actions, err := parseInterceptSpec(spec)
	if err != nil {
		return nil, err
	}
	if len(actions) != 0 {
		exclusion := "!" + strconv.FormatUint(uint64(ownPID), 10)
		if actions[len(actions)-1] != exclusion {
			actions = append(actions, exclusion)
		}
	}
	return &InterceptConf{Actions: actions}, nil
}

// DescribeSpec validates spec and returns the native redirector's description.
// It describes only the supplied rules, without adding an own-process exclusion.
// Invalid patterns return the original spec in the upstream error message.
func DescribeSpec(spec string) (string, error) {
	actions, err := parseInterceptSpec(spec)
	if err != nil {
		return "", err
	}
	if len(actions) == 0 {
		return "Intercept nothing.", nil
	}
	var description strings.Builder
	for i, action := range actions {
		if i != 0 {
			description.WriteByte(' ')
		}
		pattern, excluded := strings.CutPrefix(action, "!")
		if excluded {
			description.WriteString("Exclude ")
		} else {
			description.WriteString("Include ")
		}
		if _, err := strconv.ParseUint(pattern, 10, 32); err == nil {
			description.WriteString("PID ")
			description.WriteString(pattern)
			description.WriteByte('.')
		} else {
			description.WriteString("processes matching \"")
			description.WriteString(pattern)
			description.WriteString("\".")
		}
	}
	return description.String(), nil
}

// UnavailableReason returns the native local mode's informational availability text.
// An empty result means available. Linux launch must still attempt sudo rather
// than treating a non-root result as a startup prohibition.
func UnavailableReason(goos string, euid int) string {
	switch goos {
	case "darwin", "windows":
		return ""
	case "linux":
		if euid != 0 {
			return "mitmproxy is not running as root."
		}
		return ""
	default:
		return "Local redirect mode is not supported on " + goos
	}
}

func parseInterceptSpec(spec string) ([]string, error) {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return nil, nil
	}
	actions := make([]string, 0, strings.Count(trimmed, ",")+2)
	for value := range strings.SplitSeq(trimmed, ",") {
		pattern, excluded := strings.CutPrefix(strings.TrimSpace(value), "!")
		pattern = strings.TrimSpace(pattern)
		if pattern == "" {
			return nil, fmt.Errorf("invalid intercept spec: %s", spec)
		}
		// Rust's unsigned integer parser accepts a leading plus, unlike ParseUint.
		unsigned, _ := strings.CutPrefix(pattern, "+")
		if pid, err := strconv.ParseUint(unsigned, 10, 32); err == nil {
			pattern = strconv.FormatUint(pid, 10)
		}
		if excluded {
			pattern = "!" + pattern
		}
		actions = append(actions, pattern)
	}
	return actions, nil
}
