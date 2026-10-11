#!/usr/bin/env bash
set -euo pipefail

runner="${1:-${PWD}/hack/network-gate.sh}"
output="${2:-${PWD}/_test/network-gate/input-tests}"
required=(HTTP_LOAD_TAG HTTP_LOAD_PACKAGE HTTP_LOAD_ENV_NAME HTTP_LOAD_ENV_VALUE
  HTTP_TRANSFER_TEST HTTP_UNRELATED_TEST HTTP3_TRANSFER_TEST HTTP3_UNRELATED_TEST
  HTTP_HEAP_TEST HTTP_SMALL_FRAME_HEAP_TEST
  HTTP_SSE_TEST WS_GATE_RUNNER WS_CASE_MANIFEST WS_GATE_CONFIG)
fixture=()
for name in "${required[@]}"; do
  fixture+=("${name}=present")
done
for name in "${required[@]}"; do
  if result="$(env "${fixture[@]}" "${name}=" NETWORK_GATE_OUTPUT="${output}/${name}" bash "${runner}" 2>&1)"; then
    printf 'FAIL: missing %s was accepted\n' "${name}" >&2
    exit 1
  fi
  if [[ "${result}" != *"network-gate: missing required input ${name}"* ]]; then
    printf 'FAIL: missing %s did not identify its input\n%s\n' "${name}" "${result}" >&2
    exit 1
  fi
  printf 'PASS: missing %s fails closed\n' "${name}"
done

netem_required=(HTTP_LOAD_TAG HTTP_LOAD_PACKAGE HTTP_LOAD_ENV_NAME HTTP_LOAD_ENV_VALUE HTTP_NETEM_TEST)
fixture+=(HTTP_NETEM_TEST=present)
for name in "${netem_required[@]}"; do
  if result="$(env "${fixture[@]}" "${name}=" NETWORK_GATE_OUTPUT="${output}/netem-${name}" bash "${runner}" --netem 2>&1)"; then
    printf 'FAIL: netem missing %s was accepted\n' "${name}" >&2
    exit 1
  fi
  [[ "${result}" == *"network-gate: missing required input ${name}"* ]] || exit 1
  printf 'PASS: netem missing %s fails closed\n' "${name}"
done

# Only transcript/command outcomes are injected; no network service is replaced.
# shellcheck source=hack/netem-gate.sh
source "$(dirname "${runner}")/netem-gate.sh"
mkdir -p "${output}/contracts"
records='[
  {phase:"setup"}, {phase:"direct-handshake"}, {phase:"direct-warmup"},
  {phase:"direct-transfer",leg:"direct",stream:3,expected_bytes:268435456,window:16777216},
  {phase:"direct-complete",bytes:268435456,duration_ns:1000000000},
  {phase:"proxy-setup-warmup"},
  {phase:"proxy-transfer",leg:"proxy",stream:3,expected_bytes:268435456,window:16777216},
  {phase:"measurement-complete",outcome:"pass",stream:3,expected_bytes:268435456,
   window:16777216,direct_bytes:268435456,proxy_bytes:268435456,
   direct_duration_ns:1000000000,proxy_duration_ns:1000000000,ratio:1}
]'
timeout_record='{phase:"measured-transfer-timeout",outcome:"measured-transfer-timeout",leg:"direct",
  last_phase:"direct-transfer",stream:3,expected_bytes:268435456,window:16777216,
  actual_bytes:"unavailable",direct_bytes:"unavailable",proxy_bytes:"unavailable",progress_bytes:123,elapsed_ns:30000000000,
  direct_duration_ns:"unavailable",proxy_duration_ns:"unavailable",ratio:"unavailable"}'

write_transcript() {
  local expression="$1" status="$2" destination="$3" outcome
  jq -nc "${records} | ${expression}" >| "${destination}.json"
  jq -r '.[] | "    http2_load_netem_test.go:1: NETEM " + tojson' "${destination}.json" >| "${destination}"
  outcome="$(jq -r 'try .[-1].outcome catch "invalid"' "${destination}.json")"
  if [[ "${status}" == 0 ]]; then
    printf '    --- PASS: TestHTTP2LoadNetem/success (1.00s)\n--- PASS: TestHTTP2LoadNetem (1.00s)\nPASS\n' >> "${destination}"
  else
    case "${outcome}" in
      below-floor) printf '    http2_load_netem_test.go:1: proxy/direct throughput = 0.500000, want at least 0.8\n' >> "${destination}" ;;
      measured-transfer-timeout) printf '    http2_load_netem_test.go:1: netem measured transfer did not complete\n' >> "${destination}" ;;
    esac
    printf '    --- FAIL: TestHTTP2LoadNetem/success (1.00s)\n--- FAIL: TestHTTP2LoadNetem (1.00s)\nFAIL\n' >> "${destination}"
  fi
}

check_transcript() {
  local name="$1" expected="$2" expression="$3" producer="$4" consumer="${5:-0}" restoration="${6:-0}"
  local log="${output}/contracts/${name}.log" classification=invalid
  write_transcript "${expression}" "${producer}" "${log}"
  if netem_classify "${log}" "${producer}" "${consumer}" "${restoration}" >| "${log}.receipt" 2>| "${log}.error"; then
    classification="$(jq -r '.classification' "${log}.receipt")"
  fi
  [[ "${classification}" == "${expected}" ]] || {
    printf 'FAIL: %s classification=%s want=%s\n' "${name}" "${classification}" "${expected}" >&2
    return 1
  }
  printf 'PASS: %s classification=%s\n' "${name}" "${expected}"
}

below='.[-1].outcome="below-floor" | .[-1].proxy_duration_ns=2000000000 | .[-1].ratio=0.5'
direct_timeout=".[0:4] + [${timeout_record}]"
proxy_timeout=".[0:7] + [${timeout_record} | .leg=\"proxy\" | .last_phase=\"proxy-transfer\" | .direct_duration_ns=1000000000 | .direct_bytes=268435456]"
check_transcript pass pass '.' 0
check_transcript below-floor retryable "${below}" 1
check_transcript direct-timeout retryable "${direct_timeout}" 1
check_transcript proxy-timeout retryable "${proxy_timeout}" 1
for phase in setup direct-handshake direct-warmup proxy-setup-warmup protocol; do
  check_transcript "failure-${phase}" invalid ".[0:3] + [{phase:\"${phase}\",outcome:\"failed\"}]" 1
done
check_transcript absent-bytes invalid "${below} | del(.[-1].proxy_bytes)" 1
check_transcript absent-duration invalid "${below} | del(.[-1].direct_duration_ns)" 1
check_transcript zero-duration invalid "${below} | .[-1].proxy_duration_ns=0" 1
check_transcript wrong-bytes invalid "${below} | .[-1].direct_bytes=0" 1
check_transcript wrong-window invalid "${below} | .[3].window=65535" 1
check_transcript wrong-ratio invalid "${below} | .[-1].ratio=0.1" 1
check_transcript duplicate-phase invalid "${below} | .[0:1]+.[0:8]" 1
check_transcript out-of-order invalid "${below} | .[1:2]+.[0:1]+.[2:8]" 1
check_transcript contradictory-outcome invalid "${below} | .[-1].outcome=\"pass\"" 1
check_transcript invalid-first-status invalid '.' 1
check_transcript command-timeout invalid "${direct_timeout}" 124
check_transcript unavailable-progress invalid "${direct_timeout} | .[-1].progress_bytes=\"unavailable\"" 1
check_transcript fabricated-duration invalid "${direct_timeout} | .[-1].direct_duration_ns=0" 1
check_transcript malformed-receipt invalid "${below} | .[-1]=\"not-an-object\"" 1
check_transcript restoration-failure invalid "${below}" 1 0 1
check_transcript tee-failure invalid "${below}" 1 1
check_transcript producer-failure invalid '.' 2
for injected in \
  '    http2_load_netem_test.go:1: unexpected protocol failure' \
  '    http2_load_test.go:1: cleanup failed' \
  '    --- SKIP: TestHTTP2LoadNetem/success (0.00s)' \
  '    http2_load_netem_test.go:1: NETEM invalid-json'; do
  log="${output}/contracts/injected.log"
  write_transcript "${below}" 1 "${log}"
  printf '%s\n' "${injected}" >> "${log}"
  if netem_classify "${log}" 1 0 0 >/dev/null 2>&1; then
    printf 'FAIL: injected failure accepted: %s\n' "${injected}" >&2
    exit 1
  fi
  printf 'PASS: injected failure rejected\n'
done

check_policy() (
  local name="$1" first="$2" retry="$3" expected_status="$4" expected_attempts="$5" status=0
  output="${output}/contracts/policy-${name}"
  mkdir -p "${output}"
  : >| "${output}/calls"
  netem_attempt() {
    local classification="${first}"
    [[ "$1" != retry ]] || classification="${retry}"
    printf '%s\n' "$1" >> "${output}/calls"
    [[ "${classification}" != invalid && "${classification}" != upload-failure ]] || return 1
    mkdir -p "${output}/$1"
    jq -n --arg classification "${classification}" '{classification:$classification}' >| "${output}/$1/receipt.json"
  }
  netem_policy "${output}" >| "${output}/policy.log" || status=$?
  [[ "${status}" == "${expected_status}" ]] || exit 1
  [[ "$(wc -l < "${output}/calls" | tr -d ' ')" == "${expected_attempts}" ]] || exit 1
  if [[ "${first}" == retryable && "${retry}" == pass && "${status}" == 0 ]]; then
    grep -Fx 'accepted flaky measurement under the approved two-attempt policy' "${output}/policy.log" >/dev/null
  fi
  printf 'PASS: policy %s\n' "${name}"
)
check_policy first-pass pass invalid 0 1
check_policy below-retry-pass retryable pass 0 2
check_policy timeout-retry-pass retryable pass 0 2
check_policy two-failures retryable retryable 1 2
check_policy invalid-first invalid pass 1 1
check_policy invalid-retry retryable invalid 1 2
check_policy upload-failure upload-failure pass 1 1
