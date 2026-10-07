// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

// Package local contains the native redirector's IPC wire messages.
// The schema is vendored unchanged from mitmproxy-rs commit
// 51fe2b7c5aa8439c162abb665db61c6669d146d6, src/ipc/mitmproxy_ipc.proto.
package local

//go:generate sh -c "tmp=$DOLLAR(mktemp -d); trap 'rm -rf \"$DOLLAR{tmp}\"' EXIT; GOBIN=$DOLLAR{tmp} go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.12 && protoc --plugin=protoc-gen-go=$DOLLAR{tmp}/protoc-gen-go --go_out=$DOLLAR{tmp} --go_opt=paths=source_relative --go_opt=Mmitmproxy_ipc.proto=github.com/zchee/mitmproxy-go/internal/local mitmproxy_ipc.proto && { printf '// Copyright 2026 The mitmproxy-go Authors.\n// SPDX-License-Identifier: MIT\n\n'; cat $DOLLAR{tmp}/mitmproxy_ipc.pb.go; } > mitmproxy_ipc.pb.go"
