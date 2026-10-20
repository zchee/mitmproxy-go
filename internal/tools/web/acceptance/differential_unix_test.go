// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build difftest && unix

package acceptance_test

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/zchee/mitmproxy-go/internal/testutil"
)

type webCapturedReply struct {
	Status      int
	ContentType string
	Body        []byte
}

func TestMitmwebDifferential(t *testing.T) {
	recordPythonWebProvenance(t)
	binary := buildWebExecutable(t)
	artifacts := filepath.Join(filepath.Dir(testutil.FixturePath(t, ".")), "_test", "web-differential")
	if override := os.Getenv("MITMPROXY_TEST_WEB_ARTIFACTS"); override != "" {
		artifacts = override
	}
	if !filepath.IsAbs(artifacts) {
		t.Fatal("differential artifacts must use an absolute owned path")
	}
	t.Setenv("MITMPROXY_TEST_WEB_ARTIFACTS", artifacts)
	tests := map[string]struct{}{"live_flows_add": {}}
	for name := range tests {
		t.Run(name, func(t *testing.T) { testLiveWebFlows(t, binary) })
	}
}

func captureWebReply(t *testing.T, client *http.Client, tuple webInputTuple, route string) webCapturedReply {
	t.Helper()
	status, contentType, raw, err := requestWeb(t.Context(), client, tuple, http.MethodGet, route, nil)
	if err != nil {
		t.Fatalf("endpoint %s: %v", route, err)
	}
	return webCapturedReply{Status: status, ContentType: contentType, Body: raw}
}
