// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

//go:build (difftest || browser) && unix

package acceptance_test

import (
	"encoding/json/jsontext"
	json "encoding/json/v2"
)

func expectedWebListener(raw []byte) bool {
	var state struct {
		Servers map[string]struct {
			IsRunning   bool               `json:"is_running"`
			ListenAddrs [][]jsontext.Value `json:"listen_addrs"`
		} `json:"servers"`
	}
	if err := json.Unmarshal(raw, &state); err != nil {
		return false
	}
	server, exists := state.Servers["regular@127.0.0.1:18080"]
	if !exists || !server.IsRunning {
		return false
	}
	for _, address := range server.ListenAddrs {
		if len(address) == 2 && string(address[0]) == `"127.0.0.1"` && string(address[1]) == "18080" {
			return true
		}
	}
	return false
}
