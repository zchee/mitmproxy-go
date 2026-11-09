# Console fixture verification

The retained 200x50 flowlist, flowview and commander cell goldens and presentation JSON were verified against v12.3.1 by independent source-layout review on 2026-11-03; historical generation attribution is unchanged. The review compared all upstream console sources between 3368a0a and v12.3.1 (only a quickhelp.py docstring typo changed), checked the 12 retained frame/presentation files against execution base e77dcd3f, compared fresh v12.3.1 Python 80x24 frames with retained measurements and tracked goldens, and inspected passing receipts for all six Go cell/presentation checks. The historical attribution in golden-provenance.json remains unchanged; its stale file digests and byte lengths for flowlist and commander presentation JSON at both sizes were corrected by the current-byte verification recorded below. No Python 200x50 regenerator exists; this verification does not establish Python-regenerated 200x50 output or native/browser terminal acceptance.

## Command record

Writing time from `date`: 2026-11-03 21:45:02 JST. Commands run from the Go repository root. `UPSTREAM` names an upstream mitmproxy checkout containing both commits; `OUTPUT_DIR` names an empty output directory outside the checkout.

Source comparison:

```sh
git -C "$UPSTREAM" diff 3368a0a06ae6195aad817a1ece1aaeb6fe0353a1 51c1d6b2d8d3367a773411eb7a3eeccec82b3ea7 -- mitmproxy/tools/console
```

Go cell/presentation checks:

```sh
go test -race -count=1 -cpu=1 -timeout=30m -json -run '^TestConsoleGoldens$' ./internal/tools/console/acceptance
```

Go live-oracle comparison:

```sh
go test -tags difftest -race -count=1 -cpu=1 -timeout=30m -json -run '^TestConsoleOracle$' ./internal/tools/console/acceptance
```

Tracked Python adapter, fixed source inputs and exact settings for the three 80x24 states:

```sh
for state in flowlist flowview commander; do
  case "$state" in
    flowlist) keys='' ;;
    flowview) keys='<enter>' ;;
    commander) keys=':console.view.flow ' ;;
  esac
  mkdir -p "$OUTPUT_DIR/$state-work"
  TZ=UTC PYTHONDONTWRITEBYTECODE=1 uv run --quiet --python 3.13 --script internal/tools/console/acceptance/testdata/oracle.py \
    --flows internal/tools/console/acceptance/testdata/console.mitm \
    --reference testdata/mitmproxy/tools/console/conftest.py \
    --work-dir "$OUTPUT_DIR/$state-work" --keys "$keys" \
    --set console_default_contentview=raw \
    --set console_palette=solarized_dark \
    --set console_palette_transparent=true \
    --set console_flowlist_layout=default \
    --set console_layout=single \
    --set console_layout_headers=true \
    --set console_quickhelp_visible=true \
    --set console_focus_follow=false \
    --set listen_host=127.0.0.1 --set listen_port=8080
done
```

Python script checks:

```sh
uv run --quiet --python 3.13 --script internal/tools/console/acceptance/testdata/test_oracle.py -rA
```

```sh
uv run --quiet --python 3.13 --script internal/tools/console/acceptance/testdata/test_qa_capture.py -rA
```

## Current-byte verification

The four flowlist/commander presentation digests and byte lengths were refreshed by direct measurement of the tracked files after presentation-only revisions 8a0b4f2 and 8bdcc65. This verifies current bytes; it is not regeneration, a new layout review or a new 200x50 Python oracle. No frame, presentation byte or historical attribution changed.

To repeat the measurement from `internal/tools/console/acceptance`:

```sh
for path in testdata/presentation/flowlist-80x24.json testdata/presentation/flowlist-200x50.json testdata/presentation/commander-80x24.json testdata/presentation/commander-200x50.json; do
  shasum -a 256 "$path"
  wc -c "$path"
done
```

Verification time from `date`: 2026-11-10 00:45:28 JST.
