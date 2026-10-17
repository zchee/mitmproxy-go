// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package contentviewsdraft

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/contentviews"
)

func mqttVectors() map[string]struct {
	data []byte
	text string
} {
	tests := map[string]struct {
		data []byte
		text string
	}{
		"PINGREQ":     {[]byte{0xc0, 0}, "[PINGREQ]"},
		"PINGRESP":    {[]byte{0xd0, 0}, "[PINGRESP]"},
		"SUBACK":      {[]byte{0x90, 0}, "Packet type SUBACK is not supported yet!"},
		"UNSUBSCRIBE": {[]byte{0xa0, 0}, "Packet type UNSUBSCRIBE is not supported yet!"},
		"SUBSCRIBE": {
			[]byte("\x82\x31\x00\x03\x00\x2cxxxx/yy/zzzzzz/56:6F:5E:6A:01:05/messages/in\x01"),
			"[SUBSCRIBE] sent topic filters: 'xxxx/yy/zzzzzz/56:6F:5E:6A:01:05/messages/in'",
		},
		"PUBLISH": {
			[]byte("\x32\x9a\x01\x00\x2dxxxx/yy/zzzzzz/56:6F:5E:6A:01:05/messages/out\x00\x04" + `{"body":{"parameters":null},"header":{"from":"56:6F:5E:6A:01:05","messageId":"connected","type":"event"}}`),
			`[PUBLISH] '{"body":{"parameters":null},"header":{"from":"56:6F:5E:6A:01:05","messageId":"connected","type":"event"}}' to topic 'xxxx/yy/zzzzzz/56:6F:5E:6A:01:05/messages/out'`,
		},
		"CONNECT": {
			[]byte("\x10\xba\x01\x00\x04MQTT\x04\x06\x00\x1e\x00\x1156:6F:5E:6A:01:05\x00-" + "xxxx/yy/zzzzzz/56:6F:5E:6A:01:05/messages/out" + "\x00l" + `{"body":{"parameters":null},"header":{"from":"56:6F:5E:6A:01:05","messageId":"disconnected","type":"event"}}`),
			"[CONNECT]\n\nClient Id: 56:6F:5E:6A:01:05\nWill Topic: xxxx/yy/zzzzzz/56:6F:5E:6A:01:05/messages/out\nWill Message: " + `{"body":{"parameters":null},"header":{"from":"56:6F:5E:6A:01:05","messageId":"disconnected","type":"event"}}` + "\nUser Name: None\nPassword: None\n",
		},
	}
	return tests
}

func TestMQTT(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("test_view_mqtt", func(t *testing.T) {
			for name, tt := range mqttVectors() {
				t.Run(name, func(t *testing.T) {
					got, err := (MQTT{}).Prettify(tt.data, contentviews.Metadata{})
					if err != nil {
						t.Fatal(err)
					}
					if diff := cmp.Diff(tt.text, got); diff != "" {
						t.Fatal(diff)
					}
				})
			}
		})
		t.Run("test_mqtt_malformed", func(t *testing.T) {
			t.Run("c0ffffffff", func(t *testing.T) {
				if _, err := (MQTT{}).Prettify([]byte{0xc0, 0xff, 0xff, 0xff, 0xff}, contentviews.Metadata{}); err == nil {
					t.Fatal("malformed remaining length accepted")
				}
			})
		})
	})
}

func TestMQTTMalformed(t *testing.T) {
	tests := map[string]struct{ data []byte }{
		"empty":                {},
		"missing length":       {[]byte{0xc0}},
		"truncated varint":     {[]byte{0xc0, 0x80}},
		"declared body":        {[]byte{0xc0, 1}},
		"trailing body":        {[]byte{0xc0, 0, 1}},
		"short publish field":  {[]byte{0x30, 1, 0}},
		"missing publish id":   {[]byte{0x32, 3, 0, 1, 'a'}},
		"missing publish data": {[]byte{0x30, 3, 0, 1, 'a'}},
		"short connect":        {[]byte{0x10, 0}},
		"short subscribe":      {[]byte{0x82, 1, 0}},
		"missing topic qos":    {[]byte{0x82, 5, 0, 1, 0, 1, 'a'}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := (MQTT{}).Prettify(tt.data, contentviews.Metadata{}); err == nil {
				t.Fatal("malformed packet accepted")
			}
		})
	}
}

func TestMQTTBounds(t *testing.T) {
	budget := &viewBudget{view: "MQTT"}
	text, err := mqttConnect([]byte{0, 4, 'M', 'Q', 'T', 'T', 4, 0, 0, 0, 0, 4, 'N', 'o', 'n', 'e'}, budget)
	if err != nil || budget.bytes != len(text) {
		t.Fatalf("literal None accounting: text=%q err=%v budget=%d", text, err, budget.bytes)
	}
	budget = &viewBudget{view: "MQTT", bytes: maxViewBytes - 1}
	if _, err := mqttPublish([]byte{0, 1, 'a', 'b'}, 0, budget); err == nil {
		t.Fatal("publish ignored output limit")
	}
	budget = &viewBudget{view: "MQTT", nodes: maxViewNodes}
	if _, err := mqttSubscribe([]byte{0, 1, 0, 1, 'a', 0}, budget); err == nil {
		t.Fatal("subscription ignored node limit")
	}
}

func FuzzMQTT(f *testing.F) {
	for _, tt := range mqttVectors() {
		f.Add(tt.data)
	}
	f.Add([]byte{0xc0, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		text, err := (MQTT{}).Prettify(data, contentviews.Metadata{})
		if err == nil && len(text) > maxViewBytes {
			t.Fatal("output exceeds resource bound")
		}
	})
}
