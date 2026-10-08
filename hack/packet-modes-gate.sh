#!/usr/bin/env bash
set -euo pipefail

output="${PACKET_GATE_OUTPUT:-${PWD}/_test/packet-modes}"
mkdir -p "${output}"
output="$(realpath "${output}")"
exec > >(tee "${output}/runner.log") 2>&1

fail() {
  printf 'packet-modes: %s\n' "$*" >&2
  exit 1
}

[[ "$(uname -s)" == Linux ]] || fail 'privileged packet acceptance requires Linux'
[[ "$(uname -m)" == x86_64 ]] || fail 'required WireGuard fixture requires amd64'
for command in ip sudo curl timeout stat go; do
  command -v "${command}" >/dev/null || fail "missing required command ${command}"
done
sudo -n true || fail 'passwordless sudo is required'
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] || fail 'cgroup v2 is required'
[[ -c /dev/net/tun ]] || fail 'kernel TUN device is missing'
[[ -x testdata/wg-test-client/linux-x86_64 ]] || fail 'WireGuard client artifact is missing'
[[ -s testdata/wg-test-client/test.conf ]] || fail 'WireGuard fixture configuration is missing'

uname -a
ip -Version
sudo --version
stat -fc 'cgroup: %T' /sys/fs/cgroup
go version
date -u '+%Y-%m-%dT%H:%M:%SZ'

runner="$(id -un)"
[[ "$(id -u)" != 0 ]] || fail 'gate launcher must be the unprivileged runner user'
binary="${output}/mitmdump"
tests="${output}/packet-modes.test"
go build -o "${binary}" ./cmd/mitmdump
go test -tags packetmodes -c -o "${tests}" ./internal/proxy/packetmodetest
for name in TestWireGuardExecutable TestTunCreated TestTunPersistent; do
  "${tests}" -test.list "^${name}$" | grep -Fx "${name}" || fail "required test ${name} is missing"
done

namespace="mitmproxy-packet-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
namespace_created=0
hosts_changed=0
host_marker="mitmproxy-packet-$$"
sysctls="${output}/sysctls-before.txt"
: >| "${sysctls}"
cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  restored=0
  if ((namespace_created)); then
    pids="$(sudo ip netns pids "${namespace}")"
    while IFS= read -r pid; do
      [[ -n "${pid}" ]] || continue
      sudo kill -TERM "${pid}" || restored=1
    done <<< "${pids}"
    while read -r path value; do
      [[ -n "${path}" ]] || continue
      sudo ip netns exec "${namespace}" sh -c 'printf "%s\n" "$2" > "$1"' sh "${path}" "${value}" || restored=1
    done < "${sysctls}"
    sudo ip -n "${namespace}" -details address show >| "${output}/interfaces-final.txt" 2>&1
    sudo ip -n "${namespace}" link del tun0 || restored=1
    sudo ip -n "${namespace}" link del packet0 || restored=1
    sudo ip netns del "${namespace}" || restored=1
  fi
  if ((hosts_changed)); then
    sudo sed -i "/# ${host_marker}$/d" /etc/hosts || restored=1
  fi
  printf 'packet-modes: result=%d restoration=%d\n' "${status}" "${restored}"
  date -u '+%Y-%m-%dT%H:%M:%SZ'
  if ((restored)); then
    exit 1
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ ! -e "/run/netns/${namespace}" ]] || fail 'network namespace already exists'
sudo ip netns add "${namespace}"
namespace_created=1
sudo ip -n "${namespace}" link set lo up
sudo ip -n "${namespace}" link add packet0 type dummy
sudo ip -n "${namespace}" address add 192.0.2.2/24 dev packet0
sudo ip -n "${namespace}" link set packet0 up
sudo ip netns exec "${namespace}" ip tuntap add dev tun0 mode tun user "${runner}"
sudo ip -n "${namespace}" link set tun0 mtu 1400
# Avoid kernel-generated link-local addresses appearing on the first attachment.
sudo ip -n "${namespace}" link set tun0 addrgenmode none
sudo ip -n "${namespace}" address add 169.254.0.1/32 dev tun0
sudo ip -n "${namespace}" link set tun0 up
# Snapshot every potentially adjusted interface value inside the private namespace.
sudo ip netns exec "${namespace}" sh -c '
  for directory in /proc/sys/net/ipv4/conf/*; do
    for name in rp_filter route_localnet accept_local; do
      printf "%s %s\n" "$directory/$name" "$(cat "$directory/$name")"
    done
  done
' >| "${sysctls}"
sudo ip netns exec "${namespace}" sysctl -w net.ipv4.conf.all.rp_filter=2 net.ipv4.conf.tun0.rp_filter=2 net.ipv4.conf.tun0.route_localnet=1 net.ipv4.conf.tun0.accept_local=1
if grep -Eq '(^|[[:space:]])example\.test([[:space:]]|$)' /etc/hosts; then
  fail 'example.test already exists in hosts; refusing to overwrite it'
fi
hosts_changed=1
printf '192.0.2.2 example.test # %s\n' "${host_marker}" | sudo tee -a /etc/hosts

run_test() {
  name=$1
  privilege=$2
  log="${output}/${name}.log"
  launch=(sudo timeout --signal=QUIT --kill-after=15s 180s ip netns exec "${namespace}")
  if [[ "${privilege}" == user ]]; then
    launch+=(sudo -u "${runner}")
  fi
  "${launch[@]}" env PACKET_GATE_ROOT="${PWD}" PACKET_GATE_OUTPUT="${output}" PACKET_GATE_BINARY="${binary}" \
    "${tests}" -test.run "^${name}$" -test.count=1 -test.parallel=1 -test.timeout 150s -test.v 2>&1 | tee "${log}"
  if grep -Eq '^[[:space:]]*--- SKIP:' "${log}"; then
    fail "required scenario ${name} was skipped"
  fi
  grep -Eq "^--- PASS: ${name} " "${log}" || fail "required scenario ${name} did not pass"
}

run_test TestWireGuardExecutable user
run_test TestTunCreated root
run_test TestTunPersistent user
for log in wireguard-client.log wireguard-proxy.log tun-created-proxy.log tun-attach-first.log tun-attach-second.log; do
  [[ -s "${output}/${log}" ]] || fail "required evidence ${log} is missing"
done
printf 'PACKET MODES PASS\n'
