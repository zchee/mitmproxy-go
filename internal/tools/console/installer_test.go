// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package console

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/internal/tools/console/internal/contract"
)

func verifyInstallerRecovery(t *testing.T) {
	t.Helper()
	b, _ := testBridge(t)
	tests := map[string]struct{ far bool }{"unaccepted state is ignored": {}, "far-ahead credit survives the gap": {far: true}}
	for name, test := range tests {
		controller := NewController()
		var effects contract.EffectsMsg
		count := 2
		if test.far {
			count = EffectCapacity + 1
		}
		mustConsole(t, b.Do(t.Context(), func(ctx context.Context) error {
			for index := range count {
				if index == EffectCapacity && !controller.Retire(effects[0].Sequence) {
					t.Fatal("could not release the oldest credit")
				}
				if err := controller.Apply(ctx, contract.Action{Kind: "layout", Value: "vertical"}, nil); err != nil {
					return err
				}
				effects = append(effects, <-controller.Mailbox())
			}
			return nil
		}))
		installer := NewInstaller(controller)
		if !test.far {
			if !controller.Retire(effects[0].Sequence) {
				t.Fatal("could not retire the first effect")
			}
			before := installer.State()
			forged := effects[0]
			forged.State.Layout = "horizontal"
			if installed := installer.Install(contract.EffectsMsg{forged}); len(installed) != 0 || cmp.Diff(before, installer.State()) != "" || installer.sequence != forged.Sequence {
				t.Fatalf("%s: unaccepted effect changed state or stranded its cursor", name)
			}
			if installed := installer.Install(effects[1:]); len(installed) != 1 || installed[0].Sequence != 2 || installer.State().Layout != "vertical" {
				t.Fatalf("%s: following accepted effect did not install", name)
			}
		} else {
			last := effects[len(effects)-1]
			if installed := installer.Install(contract.EffectsMsg{last}); len(installed) != 0 || len(installer.pending) != 1 {
				t.Fatalf("%s: far-ahead effect was dropped or overtook its gap", name)
			}
			installed := installer.Install(effects[:len(effects)-1])
			if len(installed) != EffectCapacity || installed[0].Sequence != 2 || installed[len(installed)-1].Sequence != last.Sequence {
				t.Fatalf("%s: gap closure did not install all accepted effects in order", name)
			}
		}
		if len(installer.Install(effects)) != 0 || len(installer.pending) != 0 || len(controller.pending) != 0 || len(controller.credits) != 0 {
			t.Fatalf("%s: duplicate installation or retained credit", name)
		}
	}
}
