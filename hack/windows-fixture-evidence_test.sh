#!/usr/bin/env bash
# Darwin contract check for the native producer's process and evidence handling.
set -euo pipefail
root="$(git rev-parse --show-toplevel)"
wrapper="$root/hack/windows-fixture-evidence.ps1"
out="${1:?pass an output directory; receipts are retained}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"
printf './fixture\t^TestFixture$\t-\n./later\t^TestFixture$\t-\n' >| "$out/manifest.txt"
cat >| "$out/fake-go" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
if [[ " $* " == *' -list '* ]]; then
  [[ "$FAKE_MODE" == empty ]] || printf 'TestFixture\nok fixture\n'
  exit 0
fi
if [[ "$FAKE_MODE" == aggregate ]]; then
  if [[ "${*: -1}" == ./fixture ]]; then
    sleep 1.8
    FAKE_MODE=pass
  else
    FAKE_MODE=cutoff
  fi
fi
for ((i=0; i<60; i++)); do
  printf '{"Action":"run","Package":"fixture","Test":"TestFixture"}\n'
  if [[ "$FAKE_MODE" == cutoff ]]; then
    # A live grandchild owns the output pipe; tree termination must kill it too.
    sleep 30 &
    printf '%s\n' "$!" >| "$FAKE_CHILD_PID_FILE"
    wait
  fi
  printf '{"Action":"%s","Package":"fixture","Test":"TestFixture"}\n' "$FAKE_MODE"
done
printf '{"Action":"%s","Package":"fixture"}\n' "$FAKE_MODE"
[[ "$FAKE_MODE" != fail ]]
FAKE
chmod +x "$out/fake-go"
export FAKE_CHILD_PID_FILE="$out/child.pid"
run_case() {
  local mode="$1" expected_test="$2" expected_finalize="$3" budget="$4"
  export FAKE_MODE="$mode"
  local dir="$out/$mode" test_status=0 finalize_status=0
  date '+%Y-%m-%d %H:%M:%S %Z'
  pwsh -NoProfile -File "$wrapper" -EvidenceDirectory "$dir" -Manifest "$out/manifest.txt" -GoExecutable "$out/fake-go" -BudgetSeconds "$budget" || test_status=$?
  # Finalization follows failure as well as success, then publication consumes it.
  pwsh -NoProfile -File "$wrapper" -Mode Finalize -EvidenceDirectory "$dir" || finalize_status=$?
  [[ "$test_status" == "$expected_test" && "$finalize_status" == "$expected_finalize" ]]
  [[ -s "$dir/SHA256SUMS" && -s "$dir/result.txt" ]]
  (cd "$dir" && shasum -a 256 -c SHA256SUMS)
  printf 'publication-ready test=%s finalization=%s mode=%s\n' "$test_status" "$finalize_status" "$mode"
}
run_case pass 0 0 30
run_case fail 1 1 30
run_case skip 0 0 30
run_case cutoff 1 1 5
run_case empty 1 1 30
# This checks only the child we launched, never other processes' command lines.
child="$(<"$out/child.pid")"
if kill -0 "$child" 2>/dev/null; then
  printf 'cutoff left a child alive: %s\n' "$child" >&2
  exit 1
fi
run_case aggregate 1 1 5
child="$(<"$out/child.pid")"
if kill -0 "$child" 2>/dev/null; then
  printf 'aggregate cutoff left a child alive: %s\n' "$child" >&2
  exit 1
fi
for kind in absent blank; do
  manifest="$out/$kind.txt"
  [[ "$kind" != blank ]] || printf '# No intended tests\n' >| "$manifest"
  status=0
  pwsh -NoProfile -File "$wrapper" -EvidenceDirectory "$out/$kind" -Manifest "$manifest" -GoExecutable "$out/fake-go" || status=$?
  [[ "$status" == 1 ]]
  status=0
  pwsh -NoProfile -File "$wrapper" -Mode Finalize -EvidenceDirectory "$out/$kind" || status=$?
  [[ "$status" == 1 && -s "$out/$kind/SHA256SUMS" ]]
done
export PROOF_DIRECTORY="$out"
# PowerShell owns these variables; Bash must pass them without expansion.
# shellcheck disable=SC2016
pwsh -NoProfile -Command '
  $Directory = $env:PROOF_DIRECTORY
  $ErrorActionPreference = "Stop"
  foreach ($mode in @("pass", "fail", "skip")) {
    $rows = @(Get-Content -Raw "$Directory/$mode/tallies.json" | ConvertFrom-Json)
    if ($rows.Count -ne 2) { throw "Missing identities: $mode" }
    foreach ($row in $rows) {
      if ($row.ObservedCompletions -ne 60 -or $row.Counts.$mode -ne 60) { throw "Wrong counts: $mode" }
    }
  }
  $commands = @(Get-Content -Raw "$Directory/cutoff/commands.json" | ConvertFrom-Json)
  if ($commands[0].Status -ne "INCOMPLETE" -or $commands[1].Reason -ne "not started") { throw "Cutoff falsely completed" }
  if ($commands[0].Reason -notmatch "process tree terminated") { throw "Missing interruption status" }
  $row = @(Get-Content -Raw "$Directory/cutoff/tallies.json" | ConvertFrom-Json)[0]
  if ($row.Status -ne "INCOMPLETE" -or $row.ObservedCompletions -ne 0 -or $row.Counts.Run -ne 1) { throw "Partial counts lost" }
  $commands = @(Get-Content -Raw "$Directory/aggregate/commands.json" | ConvertFrom-Json)
  if ($commands[0].Status -ne "PASS" -or $commands[1].Status -ne "INCOMPLETE") { throw "Serial aggregate cutoff failed" }
  foreach ($mode in @("cutoff", "aggregate")) {
    $elapsed = [double](Get-Content "$Directory/$mode/aggregate-elapsed-seconds.txt")
    if ($elapsed -ge 5) { throw "Aggregate budget exceeded: $elapsed" }
  }
  "PASS: counts, aggregate cutoff, partial logs, tree cleanup, finalization on failure"
'
