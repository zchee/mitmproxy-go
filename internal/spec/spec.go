// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package spec parses separator-delimited flow modification options.
package spec

import (
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/zchee/mitmproxy-go/filter"
)

// Parse parses [/flow-filter]/subject/replacement, using the first Unicode
// character as the separator. Two parameters match every flow; three parse
// the first parameter with filter.Parse. Separators after the third parameter
// remain part of the replacement. Empty or incomplete options return an error;
// invalid flow filters return the filter package's ParseError.
func Parse(option string) (filter.Expr, string, string, error) {
	if option == "" {
		return nil, "", "", errors.New("Invalid number of parameters (2 or 3 are expected)") //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
	_, size := utf8.DecodeRuneInString(option)
	parts := strings.SplitN(option[size:], option[:size], 3)
	switch len(parts) {
	case 2:
		return filter.MatchAll, parts[0], parts[1], nil
	case 3:
		expr, err := filter.Parse(parts[0])
		if err != nil {
			return nil, "", "", err
		}
		return expr, parts[1], parts[2], nil
	default:
		return nil, "", "", errors.New("Invalid number of parameters (2 or 3 are expected)") //nolint:staticcheck // Preserve upstream's user-facing diagnostic.
	}
}
