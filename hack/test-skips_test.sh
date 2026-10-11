#!/usr/bin/env bash
set -euo pipefail

script="${PWD}/hack/test-skips.sh"
directory="$(mktemp -d "${TMPDIR:-/tmp}/test-skips-contract.XXXXXX")"
trap 'rm -rf "${directory}"' EXIT
bash -n "${script}"

# go test -json emits separate output and terminal events. These fixtures keep
# that shape while interleaving packages and tests to exercise correlation.
cat >|"${directory}/events.json" <<'JSON'
{"Action":"start","Package":"github.com/zchee/mitmproxy-go/internal/local"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/internal/local","Test":"TestLinuxNative","Output":"=== RUN   TestLinuxNative\n"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/internal/privfile","Test":"TestSame","Output":"    privfile_unix_test.go:35: cannot create a foreign-owned file: operation not permitted\n"}
{"Action":"output","Package":"example.test/other","Test":"TestSame","Output":"    unknown_test.go:7: unknown reason with quote \" and slash \\ and unicode é 😀\n"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/internal/local","Test":"TestLinuxNative","Output":"    linux_test.go:110: synthetic peer uses Unix datagrams and a Unix shell\n"}
{"Action":"skip","Package":"example.test/other","Test":"TestSame","Elapsed":0}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/internal/local","Test":"TestLinuxNative","Elapsed":0}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/internal/privfile","Test":"TestSame","Elapsed":0}
{"Output":"    artifacts_test.go:283: real-network artifact verification requires MITMPROXY_TEST_REDIRECTOR_DOWNLOAD=1\n","Test":"TestAcquirePinnedArtifacts","Package":"github.com/zchee/mitmproxy-go/internal/local","Action":"output"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/internal/local","Test":"TestAcquirePinnedArtifacts","Elapsed":0}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/internal/proxy/modeserver","Test":"TestStandaloneDNSWireTransports/IPv6_TCP","Output":"    dns_standalone_test.go:39: IPv6 unavailable: address family not supported\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/internal/proxy/modeserver","Test":"TestStandaloneDNSWireTransports/IPv6_TCP","Elapsed":0}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/internal/tools/cmdline","Test":"TestCompletionScripts/success:_fish/syntax","Output":"    completion_test.go:48: shell syntax check requires fish: exec: \"fish\": executable file not found in $PATH\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/internal/tools/cmdline","Test":"TestCompletionScripts/success:_fish/syntax","Elapsed":0}
{"Action":"output","Package":"example.test/other","Test":"TestNotAnOSGuard","Output":"    unknown_test.go:8: synthetic peer uses Unix datagrams and a Unix shell\n"}
{"Action":"skip","Package":"example.test/other","Test":"TestNotAnOSGuard","Elapsed":0}
{"Action":"output","Package":"example.test/other","Test":"TestMissingOutput","Output":"    unknown_test.go:9: output is present but the reason is not approved\n"}
{"Action":"skip","Package":"example.test/other","Test":"TestMissingOutput","Elapsed":0}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/addons/cut","Test":"TestPrivateOutputPaths/error:_foreign_owner_refused","Output":"    private_output_test.go:51: cannot create a foreign-owned file: chown /tmp/TestPrivateOutputPathserror_foreign_owner_refused123/001/output: operation not permitted\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/addons/cut","Test":"TestPrivateOutputPaths/error:_foreign_owner_refused"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/options","Test":"TestPyJoinWindows","Output":"    yaml_test.go:366: drive letters and UNC volumes exist only on Windows\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/options","Test":"TestPyJoinWindows"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/flowio","Test":"TestDifferentialMigrate/mitmproxy/flows/websocket.mitm","Output":"    difftest_test.go:32: differential test: build with -tags difftest to run it\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/flowio","Test":"TestDifferentialMigrate/mitmproxy/flows/websocket.mitm"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/addons/save","Test":"TestPrivateOutputPaths/error:_foreign_owner_refused","Output":"    private_output_test.go:56: POSIX ownership is not available on Windows\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/addons/save","Test":"TestPrivateOutputPaths/error:_foreign_owner_refused"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/certs","Test":"TestFromStoreRefusesWritableDirectory","Output":"    store_dir_test.go:318: Windows file modes do not describe directory ACL write access\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/certs","Test":"TestFromStoreRefusesWritableDirectory"}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/addons/commandhistory","Test":"TestFailures/permission","Output":"    commandhistory_test.go:221: POSIX write permissions require a non-root user\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/addons/commandhistory","Test":"TestFailures/permission"}
{"Action":"output","Package":"example.test/other","Test":"TestWindowsName","Output":"=== RUN   TestWindowsName\n    windows_test.go:7: earlier Windows log\n    windows_test.go:8: unclassified skip\n--- SKIP: TestWindowsName (0.00s)\n"}
{"Action":"skip","Package":"example.test/other","Test":"TestWindowsName"}
{"Action":"output","Package":"example.test/other","Test":"TestPlatformMessage","Output":"    guard_test.go:8: requires GOOS=darwin\n"}
{"Action":"skip","Package":"example.test/other","Test":"TestPlatformMessage"}
{"Action":"output","Package":"example.test/empty","Output":"?\texample.test/empty\t[no test files]\n"}
{"Action":"skip","Package":"example.test/empty","Elapsed":0}
JSON
cat >|"${directory}/goos.json" <<'JSON'
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/internal/local","Test":"TestLinuxNative","Output":"    linux_test.go:110: synthetic peer uses Unix datagrams and a Unix shell\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/internal/local","Test":"TestLinuxNative"}
JSON

fail() {
  printf 'test-skips contract: %s\n' "$*" >&2; exit 1
}

reader="${TEST_SKIPS_AWK:-awk}"
summary="${directory}/summary.md"
TEST_SKIPS_AWK="${reader}" TEST_SKIPS_ENFORCE=0 GITHUB_STEP_SUMMARY="${summary}" \
  bash "${script}" <"${directory}/events.json" >|"${directory}/report.log"
for expected in '| GOOS | 5 |' '| environment | 2 |' '| privilege | 3 |' \
  '| capability | 2 |' '| unknown | 4 |' '| no test files (packages) | 1 |' \
  'test-skips: enforce=0 non-GOOS=11 accepted=10 rejected=6 invalid-events=0'; do
  grep -Fq "${expected}" "${summary}" || fail "missing summary count: ${expected}"
done
grep -Fq 'TestStandaloneDNSWireTransports/IPv6_TCP' "${summary}"
grep -Fq 'TestCompletionScripts/success:_fish/syntax' "${summary}"
grep -Fq 'test-skips: unknown example.test/other TestSame' "${directory}/report.log"
grep -Fq 'test-skips: unknown example.test/other TestWindowsName' "${directory}/report.log"
grep -Fq 'test-skips: privilege github.com/zchee/mitmproxy-go/addons/commandhistory TestFailures/permission' "${directory}/report.log"
grep -Fq 'test-skips: privilege github.com/zchee/mitmproxy-go/internal/privfile TestSame' "${directory}/report.log"
grep -Fq 'unknown reason with quote " and slash \ and unicode é 😀' "${directory}/report.log"
if TEST_SKIPS_AWK="${reader}" TEST_SKIPS_ENFORCE=1 bash "${script}" \
  <"${directory}/events.json" >|"${directory}/enforce.log"; then
  fail 'enforcing mode accepted a non-allowlisted test skip'
else
  [[ $? == 1 ]] || fail 'enforcing rejection lost its exit status'
fi
TEST_SKIPS_AWK="${reader}" TEST_SKIPS_ENFORCE=1 bash "${script}" \
  <"${directory}/goos.json" >|"${directory}/goos.log"
if TEST_SKIPS_AWK="${reader}" TEST_SKIPS_ENFORCE=invalid bash "${script}" \
  <"${directory}/goos.json" >|"${directory}/invalid-mode.log" 2>&1; then
  fail 'invalid enforcing mode was accepted'
else
  [[ $? == 2 ]] || fail 'invalid enforcing mode did not fail configuration'
fi
if printf '%s\n' '{"Action":"skip","Test":"truncated"' |
  TEST_SKIPS_AWK="${reader}" bash "${script}" >|"${directory}/invalid-json.log" 2>&1; then
  fail 'malformed event was accepted'
else
  [[ $? == 2 ]] || fail 'malformed event did not fail parsing'
fi
# A successful reader must not hide a failing go test producer.
if (
  printf '%s\n' '{"Action":"pass","Package":"example.test/failed"}'; exit 7
) |
  TEST_SKIPS_AWK="${reader}" TEST_SKIPS_ENFORCE=0 bash "${script}" >|"${directory}/producer.log"; then
  fail 'pipeline hid a failing producer'
else
  [[ $? == 7 ]] || fail 'pipeline changed the producer exit status'
fi
assert_reader() {
  local name="$1" expected="$2" mode="$3" platform="$4" input="$5" status=0
  GOOS="${platform}" TEST_SKIPS_AWK="${reader}" TEST_SKIPS_ENFORCE="${mode}" \
    bash "${script}" < "${input}" >| "${directory}/${name}.log" 2>&1 || status=$?
  if [[ "${status}" != "${expected}" ]]; then
    cat "${directory}/${name}.log" >&2
    fail "${name}: exit ${status}, want ${expected}"
  fi
}

write_skip() {
  jq -nc --arg package "$1" --arg test "$2" --arg reason "$3" '
    {Action:"output",Package:$package,Test:$test,Output:("    fixture_test.go:9: " + $reason + "\n")},
    {Action:"skip",Package:$package,Test:$test}
  ' >| "$4"
}

native="$(go env GOOS)"
row=0
while IFS=$'\t' read -r package test class reason platform; do
  [[ "${package}" != \#* ]] || continue
  row=$((row + 1))
  reason="${reason//<temp-path>/\/tmp\/TestPrivateOutputPaths123\/001\/output}"
  reason="${reason//<PATH>/\$PATH}"
  write_skip "${package}" "${test}" "${reason}" "${directory}/row.json"
  target="${native}"
  [[ "${platform}" != windows ]] || target=windows
  assert_reader "allowed-${row}" 0 on "${target}" "${directory}/row.json"
  grep -Fq "test-skips: ${class} ${package} ${test}" "${directory}/allowed-${row}.log" || fail 'accepted row classification differs from its rule'
  grep -Fq "test-skips: accepted rule=exact-row:${package}/${test}" "${directory}/allowed-${row}.log" || fail 'accepted row has no exact rule identity'
  write_skip "${package}.unknown" "${test}" "${reason}" "${directory}/row.json"
  assert_reader "wrong-package-${row}" 1 on "${target}" "${directory}/row.json"
  write_skip "${package}" "${test}_renamed" "${reason}" "${directory}/row.json"
  assert_reader "renamed-${row}" 1 on "${target}" "${directory}/row.json"
  write_skip "${package}" "${test}" "${reason} changed" "${directory}/row.json"
  assert_reader "changed-reason-${row}" 1 on "${target}" "${directory}/row.json"
  printf 'PASS: exact row %s %s; changed identity/package/reason rejected\n' "${package}" "${test}"
done < "${PWD}/hack/test-skips-allowlist.tsv"
[[ "${row}" == 43 ]] || fail "allowlist set size ${row}, want 43"
[[ "$(awk -F'\t' '$4 == "differential test: build with -tags difftest to run it" {n++} END {print n}' hack/test-skips-allowlist.tsv)" == 26 ]] || fail 'difftest set must contain exactly 26 identities'

write_skip github.com/zchee/mitmproxy-go/flowio TestDifferentialMigrate/mitmproxy/flows/websocket.mitm/new 'differential test: build with -tags difftest to run it' "${directory}/row.json"
assert_reader new-difftest-descendant 1 on "${native}" "${directory}/row.json"
write_skip github.com/zchee/mitmproxy-go/internal/local TestWindowsPipeFixture 'subprocess fixture is launched by the Windows contract cases' "${directory}/row.json"
assert_reader windows-only-guard 1 on linux "${directory}/row.json"
for validator in zsh fish pwsh; do
  shell="${validator}"
  [[ "${validator}" != pwsh ]] || shell=powershell
  write_skip github.com/zchee/mitmproxy-go/internal/tools/cmdline "TestCompletionScripts/success:_${shell}/syntax" "shell syntax check requires ${validator}: exec: \"${validator}\": executable file not found in %PATH%" "${directory}/row.json"
  assert_reader "windows-path-${validator}" 0 on windows "${directory}/row.json"
  write_skip github.com/zchee/mitmproxy-go/internal/tools/cmdline "TestCompletionScripts/success:_${shell}/syntax" "shell syntax check requires ${validator}: permission denied" "${directory}/row.json"
  assert_reader "unapproved-validator-error-${validator}" 1 on "${native}" "${directory}/row.json"
done
# shellcheck disable=SC2016 # The diagnostic contains a literal PATH variable name.
write_skip github.com/zchee/mitmproxy-go/internal/tools/cmdline TestCompletionScripts/success:_bash/syntax 'shell syntax check requires bash: exec: "bash": executable file not found in $PATH' "${directory}/row.json"
assert_reader missing-bash 1 on "${native}" "${directory}/row.json"
for test in TestBothListenerDualStack TestStandaloneDNSWireTransports/IPv6_TCP TestBoundPacketFactoryRollback TestDualStack TestDualStackPortCollision; do
  write_skip github.com/zchee/mitmproxy-go/internal/proxy/modeserver "${test}" 'IPv6 unavailable: address family not supported' "${directory}/row.json"
  assert_reader "missing-capability-${test//\//_}" 1 on "${native}" "${directory}/row.json"
done
for reason in \
  'cannot create a foreign-owned file: chown /TestPrivateOutputPaths123/001/output: operation not permitted' \
  'cannot create a foreign-owned file: chown /var/folders/test/T/TestPrivateOutputPaths123/001/output: operation not permitted' \
  'cannot create a foreign-owned file: chown /tmp/TestForeignOwner123/001/foreign: operation not permitted'; do
  write_skip github.com/zchee/mitmproxy-go/addons/cut TestPrivateOutputPaths/error:_foreign_owner_refused "${reason}" "${directory}/row.json"
  assert_reader generated-path 0 on "${native}" "${directory}/row.json"
done
for reason in \
  'cannot create a foreign-owned file: operation not permitted' \
  'cannot create a foreign-owned file: chmod /tmp/TestPrivateOutputPaths123/001/output: operation not permitted' \
  'cannot create a foreign-owned file: chown /tmp/TestPrivateOutputPaths123/001/output: permission denied' \
  'cannot create a foreign-owned file: chown /tmp/unrelated/output: operation not permitted'; do
  write_skip github.com/zchee/mitmproxy-go/addons/cut TestPrivateOutputPaths/error:_foreign_owner_refused "${reason}" "${directory}/row.json"
  assert_reader changed-foreign-owner-error 1 on "${native}" "${directory}/row.json"
done
for mode in false off 0 true on 1; do
  expected=0
  [[ "${mode}" != true && "${mode}" != on && "${mode}" != 1 ]] || expected=1
  write_skip example.test/other TestUnknown 'unapproved skip' "${directory}/row.json"
  assert_reader "mode-${mode}" "${expected}" "${mode}" "${native}" "${directory}/row.json"
done
for event in \
  '{"Action":"skip","Action":"skip","Package":"example.test/other","Test":"TestUnknown"}' \
  '{"Action":"skip","Package":"example.test/other","Test":"TestUnknown","Elapsed":01}' \
  '{"Action":"skip","Package":"example.test/other","Test":true}' \
  '{"Action":"skip","Test":"TestUnknown"}' \
  '{"Action":"skip","Package":"example.test/other","Test":"TestUnknown"}'; do
  printf '%s\n' "${event}" >| "${directory}/row.json"
  assert_reader invalid-event-report 2 off "${native}" "${directory}/row.json"
  assert_reader invalid-event-enforced 2 on "${native}" "${directory}/row.json"
done
printf '%s\n' '{"Action":"skip","Package":"example.test/unknown"}' >| "${directory}/row.json"
assert_reader unknown-package-skip 1 on "${native}" "${directory}/row.json"

# Successful producer/reader commands cannot hide a failed tee consumer.
if printf '%s\n' '{"Action":"pass","Package":"example.test/passed"}' |
  TEST_SKIPS_AWK="${reader}" TEST_SKIPS_ENFORCE=on bash "${script}" | (cat >/dev/null; exit 9); then
  fail 'pipeline hid failing tee consumer'
else
  [[ $? == 9 ]] || fail 'pipeline changed tee consumer status'
fi
printf 'test-skips correlation, exact allowlisting and exit-status contracts PASS\n'
