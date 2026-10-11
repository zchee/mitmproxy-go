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
count=20
pattern='^Test'
inventory=false
while (($#)); do
  case "$1" in
    -count=*) count="${1#-count=}" ;;
    -list) inventory=true; shift; pattern="$1" ;;
    -run) shift; pattern="$1" ;;
  esac
  package="$1"
  shift
done
names=(TestFixture)
if [[ "$package" == ./internal/netutil/freeport ]]; then
  names+=(TestWindowsFixture)
  [[ "$FAKE_MODE" != union-missing ]] || names+=(TestUncovered)
fi
if [[ "$inventory" == true ]]; then
  for name in "${names[@]}"; do
    [[ "$FAKE_MODE" == empty || ! "$name" =~ $pattern ]] || printf '%s\n' "$name"
  done
  printf 'ok fixture\n'
  exit 0
fi
if [[ "$FAKE_MODE" == aggregate ]]; then
  if [[ "$package" == ./fixture ]]; then
    sleep 1.8
    FAKE_MODE=pass
  else
    FAKE_MODE=cutoff
  fi
fi
case "$FAKE_MODE" in default-column | explicit-count | union-pass | union-missing) FAKE_MODE=pass ;; esac
for name in "${names[@]}"; do
  [[ "$name" =~ $pattern ]] || continue
  for ((i=0; i<count*3; i++)); do
    printf '{"Action":"run","Package":"fixture","Test":"%s"}\n' "$name"
    if [[ "$FAKE_MODE" == cutoff ]]; then
      # A live grandchild owns the output pipe; tree termination must kill it too.
      sleep 30 &
      printf '%s\n' "$!" >| "$FAKE_CHILD_PID_FILE"
      wait
    fi
    printf '{"Action":"%s","Package":"fixture","Test":"%s"}\n' "$FAKE_MODE" "$name"
  done
done
printf '{"Action":"%s","Package":"fixture"}\n' "$FAKE_MODE"
[[ "$FAKE_MODE" != fail ]]
FAKE
chmod +x "$out/fake-go"
export FAKE_CHILD_PID_FILE="$out/child.pid"
run_case() {
  local mode="$1" expected_test="$2" expected_finalize="$3" budget="$4"
  export FAKE_MODE="$mode"
  local dir="$out/$mode" manifest="${5:-$out/manifest.txt}" test_status=0 finalize_status=0
  date '+%Y-%m-%d %H:%M:%S %Z'
  pwsh -NoProfile -File "$wrapper" -EvidenceDirectory "$dir" -Manifest "$manifest" -GoExecutable "$out/fake-go" -BudgetSeconds "$budget" || test_status=$?
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
printf './fixture\t^TestFixture$\t-\t-\n' >| "$out/default-count.txt"
run_case default-column 0 0 30 "$out/default-count.txt"
printf './fixture\t^TestFixture$\t-\t1\n./later\t^TestFixture$\t-\t2\n' >| "$out/explicit-count.txt"
run_case explicit-count 0 0 30 "$out/explicit-count.txt"
printf './internal/netutil/freeport\t^TestFixture$\t-\t20\n./internal/netutil/freeport\t^TestWindowsFixture$\t-\t1\n' >| "$out/freeport.txt"
run_case union-pass 0 0 30 "$out/freeport.txt"
run_case union-missing 1 1 30 "$out/freeport.txt"
grep -q 'Freeport manifest rows do not cover the full test inventory' "$out/union-missing/interruption.log"
[[ ! -e "$out/union-missing/package-0.jsonl" && ! -e "$out/union-missing/package-1.jsonl" ]]
for count in 0 -1 1.5 invalid 2147483648; do
  manifest="$out/invalid-count-$count.txt"
  printf './fixture\t^TestFixture$\t-\t%s\n' "$count" >| "$manifest"
  status=0
  pwsh -NoProfile -File "$wrapper" -EvidenceDirectory "$out/invalid-count-$count" -Manifest "$manifest" -GoExecutable "$out/fake-go" || status=$?
  [[ "$status" == 1 ]]
  grep -q 'Invalid manifest count' "$out/invalid-count-$count/interruption.log"
  [[ ! -e "$out/invalid-count-$count/package-0.jsonl" ]]
done
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
      if ($row.ObservedCompletions -ne 60 -or $row.Counts.$mode -ne 60 -or $row.Count -ne 20 -or $row.ExpectedOrdinaryExecutions -ne 60) { throw "Wrong counts: $mode" }
    }
  }
  foreach ($mode in @("default-column", "explicit-count", "union-pass")) {
    $commands = @(Get-Content -Raw "$Directory/$mode/commands.json" | ConvertFrom-Json)
    $tallies = @(Get-Content -Raw "$Directory/$mode/tallies.json" | ConvertFrom-Json)
    $expectedCounts = switch ($mode) {
      "default-column" { @(20) }
      "explicit-count" { @(1, 2) }
      "union-pass" { @(20, 1) }
    }
    if ($commands.Count -ne $expectedCounts.Count -or $tallies.Count -ne $expectedCounts.Count) { throw "Missing count rows: $mode" }
    $summary = Get-Content -Raw "$Directory/$mode/summary.txt"
    for ($index = 0; $index -lt $commands.Count; $index++) {
      $command = $commands[$index]
      $count = $expectedCounts[$index]
      $tally = @($tallies | Where-Object { $_.Package -eq $command.Package -and $_.Test -in $command.Identities })[0]
      if ($command.Count -ne $count -or $command.ExpectedOrdinaryExecutions -ne $count * 3 -or "-count=$count" -notin $command.Arguments) { throw "Wrong expanded command count: $mode" }
      foreach ($flag in @("-race", "-cpu=1,2,8", "-timeout=60m")) {
        if ($flag -notin $command.Arguments) { throw "Missing ordinary test option: $flag" }
      }
      if ($tally.Count -ne $count -or $tally.ExpectedOrdinaryExecutions -ne $count * 3 -or $tally.ObservedCompletions -ne $count * 3 -or $tally.Counts.Pass -ne $count * 3) { throw "Wrong per-row tally: $mode" }
      $summaryRow = "$($command.Package) | $($command.Pattern) | $count | 1,2,8 | $($count * 3) | PASS"
      if (-not $summary.Contains($summaryRow)) { throw "Missing row count summary: $mode" }
    }
  }
  $commands = @(Get-Content -Raw "$Directory/union-missing/commands.json" | ConvertFrom-Json)
  if (@($commands | Where-Object { $_.Status -ne "INCOMPLETE" }).Count) { throw "Uncovered freeport identity falsely completed" }
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
  "PASS: per-row counts, freeport union coverage, aggregate cutoff, partial logs, tree cleanup, finalization on failure"
'
