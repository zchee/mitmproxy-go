// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build ignore

package dumper

import (
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
)

func (d *Dumper) contentviewMetadata(f flow.Flow) (contentviews.Metadata, error) {
	metadata := contentviews.Metadata{Flow: f}
	configured := d.options.OptStr("protobuf_definitions")
	if configured == nil || *configured == "" {
		return metadata, nil
	}
	path := *configured
	if strings.HasPrefix(path, "~") {
		end := strings.IndexFunc(path, func(r rune) bool { return r < 128 && os.IsPathSeparator(byte(r)) })
		if end < 0 {
			end = len(path)
		}
		var home string
		var err error
		if end == 1 {
			home, err = os.UserHomeDir()
		} else {
			var account *user.User
			account, err = user.Lookup(path[1:end])
			if err == nil {
				home = account.HomeDir
			}
		}
		if err != nil {
			return metadata, fmt.Errorf("expand protobuf definitions path: %w", err)
		}
		if end < len(path) {
			home = strings.TrimRightFunc(home, func(r rune) bool { return r < 128 && os.IsPathSeparator(byte(r)) })
		}
		path = home + path[end:]
	}
	metadata.ProtobufDefinitions = path
	return metadata, nil
}

func (d *Dumper) prettifyContentview(message any, f flow.Flow, registry *contentviews.Registry) contentviews.Result {
	metadata, err := d.contentviewMetadata(f)
	if err != nil {
		return contentviews.Result{Text: err.Error(), SyntaxHighlight: "error", Err: err}
	}
	return contentviews.PrettifyMessageWithMetadata(message, metadata, d.options.Str("dumper_default_contentview"), registry, 0)
}
