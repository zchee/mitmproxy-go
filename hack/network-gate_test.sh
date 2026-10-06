#!/usr/bin/env bash
set -euo pipefail

runner="${1:-${PWD}/hack/network-gate.sh}"
output="${2:-${PWD}/_test/network-gate/input-tests}"
required=(HTTP_LOAD_TAG HTTP_LOAD_PACKAGE HTTP_LOAD_ENV_NAME HTTP_LOAD_ENV_VALUE
  HTTP_TRANSFER_TEST HTTP_UNRELATED_TEST HTTP_HEAP_TEST HTTP_SMALL_FRAME_HEAP_TEST
  HTTP_SSE_TEST HTTP_NETEM_TEST WS_GATE_RUNNER WS_CASE_MANIFEST WS_GATE_CONFIG)
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
