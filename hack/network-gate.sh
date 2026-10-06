#!/usr/bin/env bash
set -euo pipefail

output="${NETWORK_GATE_OUTPUT:-${PWD}/_test/network-gate}"
mkdir -p "${output}"
output="$(realpath "${output}")"
exec > >(tee "${output}/runner.log") 2>&1
set -x
date -u '+%Y-%m-%dT%H:%M:%SZ'

fail() {
  printf 'network-gate: %s\n' "$*" >&2
  exit 1
}

required=(HTTP_LOAD_TAG HTTP_LOAD_PACKAGE HTTP_LOAD_ENV_NAME HTTP_LOAD_ENV_VALUE
  HTTP_TRANSFER_TEST HTTP_UNRELATED_TEST HTTP_HEAP_TEST HTTP_SMALL_FRAME_HEAP_TEST
  HTTP_SSE_TEST HTTP_NETEM_TEST WS_GATE_RUNNER WS_CASE_MANIFEST WS_GATE_CONFIG)
for name in "${required[@]}"; do
  [[ -n "${!name:-}" ]] || fail "missing required input ${name}"
done
[[ "$(uname -s)" == Linux ]] || fail 'isolated measurements require Linux'
[[ "${HTTP_LOAD_ENV_NAME}" =~ ^[A-Z_][A-Z_0-9]*$ ]] || fail 'invalid load-gate environment name'
[[ -f "${WS_GATE_RUNNER}" ]] || fail 'missing WebSocket harness'
[[ -s "${WS_CASE_MANIFEST}" ]] || fail 'missing or empty frozen Autobahn case manifest'
[[ -s "${WS_GATE_CONFIG}" ]] || fail 'missing pinned Autobahn configuration'
command -v jq >/dev/null || fail 'missing JSON summary validator jq'
report="${output}/autobahn"
[[ ! -e "${report}" && ! -L "${report}" ]] || fail 'Autobahn report directory must be fresh'

readonly image='crossbario/autobahn-testsuite@sha256:519915fb568b04c9383f70a1c405ae3ff44ab9e35835b085239c258b6fac3074'
printf '%s\n' "${image}" >| "${output}/autobahn-image.txt"
cp "${WS_CASE_MANIFEST}" "${output}/autobahn-expected-cases.json"
cp "${WS_GATE_CONFIG}" "${output}/autobahn-config.json"
go version
jq --version
ip -Version
tc -Version
sysctl --version
docker version
docker info
docker pull "${image}"
docker image inspect "${image}" >| "${output}/autobahn-image-inspect.json"
sudo -n true

binary="${output}/http-load.test"
go test -tags "${HTTP_LOAD_TAG}" -c -o "${binary}" "${HTTP_LOAD_PACKAGE}"
tests=("${HTTP_TRANSFER_TEST}" "${HTTP_UNRELATED_TEST}" "${HTTP_HEAP_TEST}"
  "${HTTP_SMALL_FRAME_HEAP_TEST}" "${HTTP_SSE_TEST}" "${HTTP_NETEM_TEST}")
for test_name in "${tests[@]}"; do
  [[ "${test_name}" =~ ^Test[A-Za-z0-9_]+$ ]] || fail "invalid top-level test name ${test_name}"
  "${binary}" -test.list "^${test_name}$" | grep -Fx -- "${test_name}" ||
    fail "required load test ${test_name} is absent under tag ${HTTP_LOAD_TAG}"
done

namespace="mitmproxy-network-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
namespace_created=0
netem_installed=0
rmem_before=''
wmem_before=''

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  restore_status=0
  if ((namespace_created)); then
    sudo ip -n "${namespace}" -details addr show >| "${output}/addresses-final.txt" 2>&1
    sudo ip netns exec "${namespace}" ss -tinm >| "${output}/sockets-final.txt" 2>&1
    sudo ip netns exec "${namespace}" tc -s qdisc show dev lo >| "${output}/qdisc-final.txt" 2>&1
    if ((netem_installed)); then
      sudo ip netns exec "${namespace}" tc qdisc del dev lo root || restore_status=1
    fi
    if [[ -n "${rmem_before}" ]]; then
      sudo ip netns exec "${namespace}" sysctl -w "net.ipv4.tcp_rmem=${rmem_before}" || restore_status=1
    fi
    if [[ -n "${wmem_before}" ]]; then
      sudo ip netns exec "${namespace}" sysctl -w "net.ipv4.tcp_wmem=${wmem_before}" || restore_status=1
    fi
    sudo ip netns exec "${namespace}" tc qdisc show dev lo >| "${output}/qdisc-restored.txt" 2>&1
    sudo ip netns exec "${namespace}" sysctl net.ipv4.tcp_rmem net.ipv4.tcp_wmem >| "${output}/sysctls-restored.txt" 2>&1
    sudo ip netns del "${namespace}" || restore_status=1
  fi
  printf 'network-gate: result=%d restoration=%d\n' "${status}" "${restore_status}"
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  if ((restore_status)); then
    exit 1
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ ! -e "/run/netns/${namespace}" ]] || fail 'network namespace already exists'
namespace_created=1
sudo ip netns add "${namespace}"
sudo ip -n "${namespace}" link set lo up
sudo ip netns exec "${namespace}" tc qdisc show dev lo >| "${output}/qdisc-before.txt"
sudo ip netns exec "${namespace}" sysctl net.ipv4.tcp_rmem net.ipv4.tcp_wmem >| "${output}/sysctls-before.txt"
rmem_before="$(sudo ip netns exec "${namespace}" sysctl -n net.ipv4.tcp_rmem)"
wmem_before="$(sudo ip netns exec "${namespace}" sysctl -n net.ipv4.tcp_wmem)"

run_test() {
  label="$1"
  test_name="$2"
  deadline="$3"
  log="${output}/${label}.log"
  sudo timeout --signal=QUIT --kill-after=15s "${deadline}" \
    ip netns exec "${namespace}" \
    env "${HTTP_LOAD_ENV_NAME}=${HTTP_LOAD_ENV_VALUE}" NETWORK_GATE_OUTPUT="${output}" \
    "${binary}" -test.run "^${test_name}$" -test.count=1 -test.parallel=1 \
    -test.timeout "${deadline}" -test.v 2>&1 | tee "${log}"
  if grep -Eq -- '^[[:space:]]*--- SKIP:' "${log}"; then
    fail "required scenario ${test_name} was skipped"
  fi
  grep -Eq -- "^--- PASS: ${test_name} " "${log}" || fail "required scenario ${test_name} did not pass"
}

# Each measurement owns its process and heap; no scenarios run concurrently.
run_test transfer "${HTTP_TRANSFER_TEST}" 120s
run_test unrelated-response "${HTTP_UNRELATED_TEST}" 120s
run_test heap-stalls "${HTTP_HEAP_TEST}" 300s
run_test heap-small-frames "${HTTP_SMALL_FRAME_HEAP_TEST}" 300s
run_test sse-latency "${HTTP_SSE_TEST}" 120s

read -r rmem_min rmem_default _ <<< "${rmem_before}"
read -r wmem_min wmem_default _ <<< "${wmem_before}"
sudo ip netns exec "${namespace}" sysctl -w "net.ipv4.tcp_rmem=${rmem_min} ${rmem_default} 67108864"
sudo ip netns exec "${namespace}" sysctl -w "net.ipv4.tcp_wmem=${wmem_min} ${wmem_default} 67108864"
netem_installed=1
sudo ip netns exec "${namespace}" tc qdisc add dev lo root netem delay 50ms
sudo ip netns exec "${namespace}" tc -s qdisc show dev lo >| "${output}/qdisc-netem.txt"
sudo ip netns exec "${namespace}" sysctl net.ipv4.tcp_rmem net.ipv4.tcp_wmem >| "${output}/sysctls-netem.txt"
run_test netem-whole-transfer "${HTTP_NETEM_TEST}" 600s

# The WebSocket harness owns its Docker topology and echo/proxy lifetimes.
# It verifies report equality with the frozen manifest and pinned config.
timeout --signal=TERM --kill-after=15s 2100s bash "${WS_GATE_RUNNER}" "${report}" \
  2>&1 | tee "${output}/autobahn-runner.log"
[[ -s "${report}/summary.json" ]] || fail 'missing Autobahn success summary'
expected="$(jq -e '.cases | length | select(. > 0)' "${WS_CASE_MANIFEST}")"
jq -e -s --arg image "${image}" --argjson expected "${expected}" '
  length == 1 and (.[0] |
    .image == $image and .total == $expected and
    .verified == .total and .failed == 0 and .report == "clients/index.json")
' "${report}/summary.json" || fail 'incomplete Autobahn success summary'
