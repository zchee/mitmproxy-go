// Copyright 2026 The mitmproxy-go Authors.
// SPDX-License-Identifier: MIT

package keymap_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"strings"
	"testing"
	"unicode"

	"github.com/google/go-cmp/cmp"

	"github.com/zchee/mitmproxy-go/command"
	"github.com/zchee/mitmproxy-go/flow"
	"github.com/zchee/mitmproxy-go/internal/testutil/testflow"
	"github.com/zchee/mitmproxy-go/internal/tools/console"
	"github.com/zchee/mitmproxy-go/internal/tools/console/keymap"
)

func TestConsoleDefaultBindings(t *testing.T) {
	t.Run("upstream", func(t *testing.T) {
		t.Run("test_commands_exist", func(t *testing.T) {
			m, err := console.New(t.Context(), console.Config{Stdout: io.Discard, Stderr: io.Discard})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := m.Close(context.WithoutCancel(t.Context())); err != nil {
					t.Error(err)
				}
			})
			if err := m.Do(t.Context(), func(ctx context.Context) error {
				m.View.Add(ctx, []flow.Flow{testflow.TFlow()})
				bindings := keymap.Defaults()
				if len(bindings) != 80 {
					t.Fatalf("binding count=%d, want 80", len(bindings))
				}
				for _, binding := range bindings {
					parsed, _ := m.Commands.ParsePartial(ctx, strings.TrimSpace(binding.Command))
					if len(parsed) == 0 {
						t.Fatalf("empty binding: %q", binding.Command)
					}
					var args []string
					for _, token := range parsed[1:] {
						if token.Type != command.SpaceType {
							args = append(args, command.Unquote(token.Value))
						}
					}
					if err := m.Commands.Prepare(ctx, command.Unquote(parsed[0].Value), args); err != nil {
						t.Fatalf("invalid real-registry binding %q: %v", binding.Command, err)
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	})
	// Fingerprints were extracted from the pinned Python AST, not the Go table.
	expected := map[string]string{
		"commonkey_global/colon":      "56564bdc5b2ad9c73e777848fbcecefe42531921078a9023d7fc4f530c2f7ecc",
		"flowlist_flowview/semicolon": "fe01c97b155a29dab8a64ecaabb925785432b11f3ee30aa9126f293eefba11da",
		"global/question":             "e25c386a19228f47dd1fbbe4f13f80736903b06b0504951b22a3676910200f88",
		"global/upper_b":              "af41560d31f65914d3aac8ad6933bdb6e4e48ae598751ae2f9719d3ca64a849b",
		"global/upper_c":              "4936a7131c2b30b2eb233ff830d897447b68c88d83edbc95c516cb95c44ca9ca",
		"global/upper_k":              "a00cea9ec22c8afa1d6eefbf364330314c9e2d90315266a4c0f62be5075f0b62",
		"commonkey_global/upper_o":    "b09e8a632f5050d88d95d6fc2b8c20bbfcc636122a6bd9386af6be634ea60a34",
		"commonkey_global/upper_e":    "7d5c4f5e514fd0b9093d7ba4301efb92cf9f94b36fc364cafa25f5ff1dbc2760",
		"global/upper_q":              "77fa2a172cd0baa5e2f4812a311806b369da64f521a5b443817adafd394430db",
		"commonkey_global/q":          "a4b4c096de2ada9c23bcda0506c63faa2005546b12ceab6096efbe1326a7f86b",
		"commonkey_global/esc":        "874c980fae4947b99914b568875e8da2eddddceecc924fb0c7f055d49ad76e72",
		"global/upper_h":              "3ea95f1f4892f99327bb54d83328544ccd8d58433748e07bc57235257902336c",
		"global/minus":                "5623c3215be99426b0a19e53849ce58042e2392c8d0527b4804b45e00c036997",
		"global/ctrl_right":           "71322ec0209078fcc059bfe3919be5313ab7db9147eb5c7d9ac105654ebd4eff",
		"global/ctrl_left":            "49a73e8d7ece71f49eef4ff867ff4ce727051c96dd17de84759a915eecdf48d1",
		"global/shift_tab":            "699c537c3c29008909e88aada7ca2fe6ef3921a42bd9bb23b7ca680df29eb951",
		"global/upper_p":              "d59beedfbe4bafc5ae3e20ed5bbc409333911559c874fef435f6582b845d6fd2",
		"help/question":               "66223d2850b86f94aa22812b806e4177c91c6f9dd715817bbb23a125f0bfff3e",
		"global/g":                    "783bb2f8026c9e634b042717ecf7a764837bfd1e336c982f195f15e15352d303",
		"global/upper_g":              "9c74533579e6bde4b69a6e7b49ff0409958bfca25a910af87c261933cf387cdb",
		"global/k":                    "e1af37f119f05e8362813febf344352feef116fce9e19f8485690a94a249082c",
		"global/j":                    "5066e72561df2e1e6a175b481ab9c5f261c8bac926da09e422e84a145dea908e",
		"global/l":                    "39be70162c46bc1c98cf7339b8635840a1ecabaa21632adc6e415bbcb1914438",
		"global/h":                    "cb60cd9b36ff59201edf142c099b48ff5e4a3187284518b8f323df456481ea03",
		"commonkey_global/tab":        "d50bc354c57d7ba1fb3e97489a20c8cd596e93626e11e7d59f374a0e926ffe94",
		"commonkey_global/enter":      "084095633ede1ff0b4e72511d3b72cc68bb215188414b29e58c325763015f3c1",
		"global/space":                "6e23a4ef98f70a20a93c0cca7ba4db0cc1f934b9d3d3f3bb0fbf08cd97a9311c",
		"global/ctrl_f":               "cfb8afbd6d9261294eea209eb7f705cec717f2e59bbb4b379ea15b689b95fc83",
		"global/ctrl_b":               "ba6446e070a8e131440b932c0ff71d5a8c694e5960d8532ace7f6f06d288c54f",
		"global/upper_i":              "b29f89924ae02ac4b674ead49c983050799c81a88e42326a80945eb86192f24c",
		"global/i":                    "73dda1284cc38dc7801fa623f91ce7b28721cfd418d5d4408ffb11064998ef3c",
		"global/upper_w":              "8824794fa7e3daa920f5509e261efd0c66ab9c6cf3e8f3b356d8ffd9865417ac",
		"flowlist_flowview/upper_a":   "430fa620f4f26735754208b5a44a28d90f48ca224f147760bc7900093a077f07",
		"flowlist_flowview/a":         "7b885e925f9beb6e81046352108ec58b44f422d1d11a3b2a83dcbd4de4238d46",
		"flowlist_flowview/b":         "25ecd337be343f31d87a6b2e8f9de712f8137eb7abbd38bca28b9234b042f610",
		"flowlist_flowview/d":         "7cd3f4b352319e94701b6ee2e92adfcb4f68f4429fe3b9d131d75a6d4532f772",
		"flowlist_flowview/upper_d":   "9a1249bd2a942c6a0823a6f1cdf28961ef82eac4b2cf7bc0a64f356304d4b5e3",
		"flowlist_flowview/x":         "5d758752eaebf4baeee38fdb18d78cd3fea6db1a96ebe4b03a67bdb5368a251a",
		"flowlist/f":                  "ed34a2cdb6d418fab7815c294531a92c940bbffa5f658942abc49b1efead594a",
		"flowlist_flowview/upper_f":   "83424946f506d4903b2ce293a8cd0b777678b3e2588cf4008d0956a9177bd6d5",
		"flowlist_flowview/ctrl_l":    "72d174ee8a8634b7e30c16c86c88c4265993b6b0e3481734ee8b1203cf48fd93",
		"flowlist/upper_l":            "f037ccd1c78286062c87ab36291f0ac7cb3ae6683da9561deb6861326c4abe86",
		"flowlist/m":                  "bcd29f61c914aa9e5bbeda02694f734747f89d07f4b5b67e9828a59a960a482e",
		"flowlist/upper_m":            "3cf967a597dad353dcc0288d9c1d25bd60220cf6258838ad616dd888cac211fa",
		"flowlist/n":                  "97e20a5e8bc2de3312845c9b8c04d18e10213a6d911b7c3378ffab9676c07832",
		"flowlist/o":                  "3c9b345cbc8d863f215ae360715f984db1729c778a69bd8624d9a0b6f56ceff2",
		"flowlist_flowview/r":         "61b20e221d39379e683bf6431267d283a4573b89fa5bbf2abdcc30c2a5c88a5a",
		"flowlist/upper_s":            "3933b11dc1f97fce9877f539e42d00bab691827957bffa41fcf64e4ee7d862bd",
		"flowlist/v":                  "3ae261934c54948dba5a26776f58943a6facdcf2b2f48bdb6231af6ad8604d8b",
		"flowlist/upper_u":            "5516be1baf9477f864715e43163eb28220dc0c5d61f520e80e3ea18a82eb0193",
		"flowlist/w":                  "1e4f34be645a1a4a1d4b7af63686daafab11925195e294dfd00dbacb0f315f56",
		"flowlist_flowview/upper_v":   "f16ba58090122b22ec49caf98eb6ff5717df5a78f27671560ba33b344515cce4",
		"flowlist/upper_x":            "87d655125e8aebc26e036cce377ffb849055854aba823db05a9876d279869e68",
		"flowlist/z":                  "2c254a100a0a3d68fec044c7126382c2b874ab0c69db1a93f5ab33cf8838d130",
		"flowlist/upper_z":            "e1e2240253e559a9c372518b9784399de613b91c70acbcc94cee2a9904216bea",
		"flowlist_flowview/pipe":      "7c5eb808621301fa28d381582fb006714e0e80c7b4130fea48ee4e61cc51cfa3",
		"flowlist_flowview/e":         "62b84f8a976822d0f61cc1260334df06f60138f49d9cf1761b34b020f014e7d6",
		"flowview/f":                  "a4de64d43ef3b70d21941adcd7bfa353d2807cae95cd82457ccd73ad6cfebe91",
		"flowview/w":                  "b4248811cdc96de673fb917614ed628ce0e3e242ff69c02ee4f7c56dcefdc234",
		"flowview/space":              "95c4c16402149ab9741948feb158441f8108ed60fad4bf295897ef89f702d39b",
		"flowview/v":                  "08cf9c462b1612b1f7b16db6ff1246080f101833da8dd9ea6ddf037c19e1043a",
		"flowview/p":                  "e5721434b26d97bf603e65195f314fd4d408273a6306250dd166d16147400169",
		"flowview/m":                  "55a5cf731da04360f0ea8720e7e3ea9fabe0cc734fd1eaac0ade8a273c74a928",
		"flowview/z":                  "ac944f5c53c6381b1857194fafbe180355636d6adca89ba7ce9562694ed41c30",
		"options/upper_l":             "2973ea2b9e7ea2b7eae7ea99af5292452e9fbf2ef37831e640838c69ca91a757",
		"options/upper_s":             "a3b2b4990570b5a6fca1af50ed9f861fc86098e2aad16a3bd58df3d32d258aa2",
		"options/upper_d":             "b01116814d9a39b9b319a27186fb29bd4943eb294d37ce6ba56f115546396d04",
		"options/d":                   "c914b244b5f9c7e97d58d7c7b60049adfec91a6ea1c5a926f04d7539997486f3",
		"grideditor/a":                "5f8b92daaf9ecec57c8843b328926a9ce4fd41d67d89d6887366b20c27357849",
		"grideditor/upper_a":          "1d1816fb148e53c098c417ee9847a8199fd2ea02a57cec63a5c343a0dd1ce3e7",
		"grideditor/d":                "c0ec74b6e357238a71513364e8b0bc2eacedb3b4fcaac7d221c5e4cd7fe64030",
		"grideditor/r":                "c5b1da3a2007760327968132064fa03ff540b7631a4a5644cedcd0c13a6d5303",
		"grideditor/upper_r":          "c2958e7ea3e288c77f7da6460cb3b900c548ec0a8dcd99e81812eea89e6761d8",
		"grideditor/e":                "3451eaf550305622909ca0dba99590657b3b8980b8a7b3f62f4e21b9fb86aef6",
		"grideditor/w":                "41ec81e2ed6627a6824253cf784d14dd5e7e883c7c5020bde01f5afa009bfcb9",
		"eventlog/z":                  "76e80e191576d052c4fc241366d9cea1da54059439f04e897551c9cb44b7f1ef",
		"keybindings/a":               "3d7a519aba4cea0e0369636b1c1a763951c6d7bca06453ec87529fdc74c51657",
		"keybindings/d":               "78e92373293aa58492f57ad5b4d95c01d557525cb251155c434e802d53e3b160",
		"keybindings/x":               "aa2be66d03137996b34374cb2634ace53b1a3cc63814b85707b01eed95546475",
		"keybindings/enter":           "eeef7ac1902e0426e6e071d3bf467d5553a109e1a2c622920fbf2d14c33092de",
	}
	bindings := keymap.Defaults()
	if len(bindings) != 80 || len(expected) != 80 {
		t.Fatal("default binding cardinality changed")
	}
	k := keymap.NewDefault(nil)
	tests := map[string]struct {
		binding     keymap.Binding
		fingerprint string
	}{}
	for _, b := range bindings {
		key := b.Key
		switch key {
		case ":":
			key = "colon"
		case ";":
			key = "semicolon"
		case "?":
			key = "question"
		case "-":
			key = "minus"
		case "|":
			key = "pipe"
		default:
			if len(key) == 1 && unicode.IsUpper(rune(key[0])) {
				key = "upper_" + strings.ToLower(key)
			} else {
				key = strings.ReplaceAll(key, " ", "_")
			}
		}
		name := strings.Join(b.Contexts, "_") + "/" + key
		fingerprint, ok := expected[name]
		if !ok {
			t.Fatalf("unexpected binding %s", name)
		}
		tests[name] = struct {
			binding     keymap.Binding
			fingerprint string
		}{b, fingerprint}
	}
	t.Run("bindings", func(t *testing.T) {
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				b := tt.binding
				fields := append([]string{b.Key, b.Command}, b.Contexts...)
				fields = append(fields, b.Help)
				got := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(fields, "\x00"))))
				if diff := cmp.Diff(tt.fingerprint, got); diff != "" {
					t.Fatalf("pinned source key/command/contexts/help differ: %s", diff)
				}
				for _, ctx := range b.Contexts {
					actual, ok := k.Get(ctx, b.KeySpec())
					if !ok {
						t.Fatalf("missing %s/%s", ctx, b.Key)
					}
					if actual.Command != b.Command || actual.Help != b.Help {
						t.Fatalf("installed binding differs: %+v", actual)
					}
					if command, ok := k.Handle(ctx, b.KeySpec(), true); !ok || command != b.Command {
						t.Fatal("context lookup/translation differs")
					}
				}
			})
		}
	})
}
