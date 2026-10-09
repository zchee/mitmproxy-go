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
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/internal/tools/cmdline","Test":"TestCompletionScripts/success:_fish/syntax","Output":"    completion_test.go:48: shell syntax check requires fish: executable file not found\n"}
{"Action":"skip","Package":"github.com/zchee/mitmproxy-go/internal/tools/cmdline","Test":"TestCompletionScripts/success:_fish/syntax","Elapsed":0}
{"Action":"output","Package":"example.test/other","Test":"TestNotAnOSGuard","Output":"    unknown_test.go:8: synthetic peer uses Unix datagrams and a Unix shell\n"}
{"Action":"skip","Package":"example.test/other","Test":"TestNotAnOSGuard","Elapsed":0}
{"Action":"skip","Package":"example.test/other","Test":"TestMissingOutput","Elapsed":0}
{"Action":"output","Package":"github.com/zchee/mitmproxy-go/addons/cut","Test":"TestPrivateOutputPaths/error:_foreign_owner_refused","Output":"    private_output_test.go:51: cannot create a foreign-owned file: operation not permitted\n"}
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
  'test-skips: enforce=0 non-GOOS=11 invalid-events=0'; do
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
  fail 'enforcing mode accepted a non-GOOS test skip'
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
printf 'test-skips correlation, classification and exit-status contracts PASS\n'
