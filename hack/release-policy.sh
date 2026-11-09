#!/usr/bin/env bash
# Derive the release compiler only from the committed, clean source checkout.
set -euo pipefail
export LC_ALL=C

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

command="${1:-}"
root="${2:-}"
case "$command:$#" in
  go-version:2 | verify-toolchain:3) ;;
  *) fail 'usage: release-policy.sh go-version ABSOLUTE_SOURCE | verify-toolchain ABSOLUTE_SOURCE EXPECTED_GO_VERSION' ;;
esac
[[ "$root" = /* ]] || fail 'source root must be absolute'
[[ -d "$root" ]] || fail 'source root must be a directory'
[[ -z "$(git -C "$root" rev-parse --show-prefix)" ]] || fail 'source root must be the checkout root'
[[ -z "$(git -C "$root" status --porcelain)" ]] || fail 'source checkout must be clean'
module="$(git -C "$root" show HEAD:go.mod)"
version=''
while IFS= read -r line; do
  if [[ "$line" =~ ^[[:space:]]*go[[:space:]] ]]; then
    [[ -z "$version" ]] || fail 'duplicate go directive'
    [[ "$line" =~ ^[[:space:]]*go[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)([[:space:]]*(//.*)?)$ ]] || fail 'invalid plain Go version in go.mod'
    version="${BASH_REMATCH[1]}"
  fi
done <<< "$module"
[[ -n "$version" ]] || fail 'go.mod has no go directive'

if [[ "$command" = verify-toolchain ]]; then
  [[ "$3" = "go$version" ]] || fail 'expected Go version differs from trusted go.mod'
  [[ -z "$(go env GOEXPERIMENT)" ]] || fail 'release Go experiments must be empty'
  actual="$(go version)"
  [[ "$actual" = "go version go$version "* ]] || fail 'selected compiler differs from trusted go.mod'
  platform="${actual#"go version go$version "}"
  [[ "$platform" =~ ^[a-z0-9]+/[a-z0-9]+$ ]] || fail 'selected compiler is not plain Go'
fi
printf '%s\n' "$version"
