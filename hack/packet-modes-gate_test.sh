#!/usr/bin/env bash
# The generated shim and source-contract strings intentionally preserve dollar signs.
# shellcheck disable=SC2016
set -euo pipefail

script="${PWD}/hack/packet-modes-gate.sh"
bash -n "${script}"
# An unavailable privilege must be a hard failure before any host mutation.
directory="$(mktemp -d "${TMPDIR:-/tmp}/packet-gate-contract.XXXXXX")"
trap 'rm -rf "${directory}"' EXIT
mkdir -p "${directory}/bin"
for name in ip sudo curl timeout stat go; do
  printf '#!/usr/bin/env bash\nexit 1\n' >| "${directory}/bin/${name}"
  chmod +x "${directory}/bin/${name}"
done
printf '#!/usr/bin/env bash\nif [[ "$1" == -s ]]; then printf "Linux\\n"; else printf "x86_64\\n"; fi\n' >| "${directory}/bin/uname"
chmod +x "${directory}/bin/uname"
if PATH="${directory}/bin:${PATH}" PACKET_GATE_OUTPUT="${directory}/logs" bash "${script}" >| "${directory}/failure.log" 2>&1; then
  printf 'gate accepted a failing sudo probe\n' >&2
  exit 1
fi
grep -Fq 'passwordless sudo is required' "${directory}/failure.log"
if grep -Fq 'PACKET MODES PASS' "${directory}/failure.log"; then
  printf 'gate reported success after prerequisite failure\n' >&2
  exit 1
fi
for contract in 'trap cleanup EXIT' "trap 'exit 130' INT" "trap 'exit 143' TERM" \
  'run_test TestWireGuardExecutable user' 'run_test TestTunCreated root' \
  'run_test TestTunPersistent user' 'required scenario ${name} was skipped' \
  'required evidence ${log} is missing'; do
  grep -Fq "${contract}" "${script}"
done
printf 'packet gate orchestration PASS\n'
