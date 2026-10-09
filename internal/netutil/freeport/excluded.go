// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package freeport

import (
	"fmt"
	"strconv"
	"strings"
)

type portRange struct {
	first int
	last  int
}

func parseExcludedPorts(output string) ([]portRange, error) {
	var ranges []portRange
	inTable := false
	for line := range strings.SplitSeq(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) == 2 && strings.Trim(fields[0], "-") == "" && strings.Trim(fields[1], "-") == "" {
			inTable = true
			continue
		}
		if !inTable {
			continue
		}
		if len(fields) > 2 && fields[0] == "*" && fields[1] == "-" {
			continue
		}
		if len(fields) != 2 && (len(fields) != 3 || fields[2] != "*") {
			return nil, fmt.Errorf("invalid excluded port range: %q", line)
		}
		first, firstErr := strconv.Atoi(fields[0])
		last, lastErr := strconv.Atoi(fields[1])
		if firstErr != nil || lastErr != nil || first < 0 || last > 65535 || first > last {
			return nil, fmt.Errorf("invalid excluded port range: %q", line)
		}
		ranges = append(ranges, portRange{first, last})
	}
	if !inTable {
		return nil, fmt.Errorf("excluded port range table missing")
	}
	return ranges, nil
}

func inPortRanges(port int, ranges []portRange) bool {
	for _, excluded := range ranges {
		if port >= excluded.first && port <= excluded.last {
			return true
		}
	}
	return false
}
