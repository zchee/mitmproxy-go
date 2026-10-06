// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package layer

import (
	"sync"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
)

func TestConsumptionReceipt(t *testing.T) {
	tests := map[string]struct {
		original int
		consume  bool
	}{
		"buffered append":                  {original: 129, consume: true},
		"streamed expansion fully written": {original: 1024, consume: true},
		"streamed deliberate drop":         {original: 256, consume: true},
		"padding only":                     {original: 17, consume: true},
		"empty data":                       {consume: true},
		"cancelled outstanding input":      {original: 4096},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			r, err := NewConsumptionReceipt(tt.original)
			if err != nil {
				t.Fatal(err)
			}
			var contract ConsumptionReceipt = r
			if contract.OriginalBytes() != tt.original {
				t.Fatal("original flow-controlled length changed")
			}
			select {
			case <-r.Done():
				t.Fatal("receipt completed before consumption")
			default:
			}
			var first bool
			if tt.consume {
				first = contract.Complete()
			} else {
				first = contract.Invalidate()
			}
			if !first || r.Consumed() != tt.consume {
				t.Fatalf("first=%v consumed=%v, want consumed=%v", first, r.Consumed(), tt.consume)
			}
			select {
			case <-r.Done():
			default:
				t.Fatal("terminal receipt did not wake owner")
			}
			if contract.Complete() || contract.Invalidate() {
				t.Fatal("receipt settled twice")
			}
		})
	}
	if _, err := NewConsumptionReceipt(-1); err == nil {
		t.Fatal("negative flow-controlled length accepted")
	}
}

func TestReceiptConcurrentSettlement(t *testing.T) {
	r, err := NewConsumptionReceipt(128)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan bool, 100)
	var wg sync.WaitGroup
	for i := range 100 {
		wg.Go(func() {
			<-start
			if i%2 == 0 {
				results <- r.Complete()
			} else {
				results <- r.Invalidate()
			}
		})
	}
	close(start)
	wg.Wait()
	close(results)
	winners := 0
	for won := range results {
		if won {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("terminal winners=%d, want1", winners)
	}
	select {
	case <-r.Done():
	default:
		t.Fatal("terminal receipt did not wake owner")
	}
}

func TestEndpointIdentityAndBudgetSnapshot(t *testing.T) {
	a := StreamIdentity{Endpoint: "origin-a", Stream: 1}
	b := StreamIdentity{Endpoint: "origin-b", Stream: 1}
	if a == b {
		t.Fatal("two endpoints with stream1 share a routing identity")
	}
	d := EndpointDescriptor{Identity: a.Endpoint, ConnectionID: "connection-a", Protocol: "h2", FromClient: false}
	copy := d
	d.ConnectionID = "changed"
	if copy.ConnectionID != "connection-a" {
		t.Fatal("descriptor snapshot aliased mutable metadata")
	}
	if ReceiveBudgetBytes != 128<<20 {
		t.Fatal("receive budget is not128MiB per endpoint direction")
	}
	snapshot := BudgetSnapshot{Granted: 127 << 20, Maximum: 128 << 20}
	got := snapshot
	snapshot.Granted = 0
	if diff := gocmp.Diff(BudgetSnapshot{Granted: 127 << 20, Maximum: 128 << 20}, got); diff != "" {
		t.Fatalf("budget value snapshot (-want +got):\n%s", diff)
	}
}
