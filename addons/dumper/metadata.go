// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package dumper

import (
	"github.com/zchee/mitmproxy-go/contentviews"
	"github.com/zchee/mitmproxy-go/flow"
)

func (d *Dumper) contentviewMetadata(f flow.Flow) contentviews.Metadata {
	metadata := contentviews.Metadata{Flow: f}
	if configured := d.options.OptStr("protobuf_definitions"); configured != nil {
		metadata.ProtobufDefinitions = *configured
	}
	return metadata
}

func (d *Dumper) prettifyContentview(message any, f flow.Flow, registry *contentviews.Registry) contentviews.Result {
	return contentviews.PrettifyMessageWithMetadata(message, d.contentviewMetadata(f), d.options.Str("dumper_default_contentview"), registry, 0)
}
