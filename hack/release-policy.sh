#!/usr/bin/env bash
# Shared release compiler, signer and artifact membership checks.
set -euo pipefail
export LC_ALL=C

fail() {
  printf '%s\n' "$1" >&2
  exit 1
}

verify_tag() {
  local root="$1" tag="$2" policy="$3" object expected actual home
  command -v git >/dev/null || fail 'git is required'
  command -v gpg >/dev/null || fail 'gpg is required'
  [[ "$tag" =~ ^[A-Za-z0-9.+-]+$ ]] || fail 'invalid artifact tag'
  git check-ref-format "refs/tags/$tag" || fail 'invalid tag ref'
  object="$(git -C "$root" rev-parse --verify "refs/tags/$tag")" || fail 'tag ref is missing'
  [[ "$(git -C "$root" cat-file -t "$object")" = tag ]] || fail 'release tag must be annotated and signed'
  IFS= read -r expected < "$policy" || fail 'cannot read signing policy'
  expected="${expected#\# Primary fingerprint: }"
  [[ "$expected" =~ ^[A-F0-9]{40}$ ]] || fail 'invalid approved signer fingerprint'
  home="$(mktemp -d "${TMPDIR:-/tmp}/release-verification.XXXXXXXX")"
  verification_home="$home"
  trap 'rm -rf -- "$verification_home"' EXIT
  chmod 700 "$home"
  git -C "$root" cat-file tag "$object" > "$home/tag" || fail 'cannot read tag object'
  actual="$(awk '/^$/{exit} /^tag /{print substr($0,5)}' "$home/tag")"
  [[ "$actual" = "$tag" ]] || fail 'signed tag name differs from ref'
  gpg --homedir "$home" --no-options --no-autostart --batch --import "$policy" >/dev/null 2>&1 || fail 'cannot import public signing policy'
  actual="$(gpg --homedir "$home" --no-options --batch --with-colons --list-keys | awk -F: '$1=="pub"{primary=1;next} primary && $1=="fpr"{print $10;primary=0}')"
  [[ "$actual" = "$expected" ]] || fail 'public key differs from approved signer fingerprint'
  awk -v body="$home/payload" -v signature="$home/signature" '
    /^-----BEGIN PGP SIGNATURE-----$/ { signing = 1 }
    { if (signing) print > signature; else print > body }
    END { if (!signing) exit 1 }
  ' "$home/tag" || fail 'tag signature verification failed'
  gpg --homedir "$home" --no-options --no-autostart --batch --status-fd 3 --verify "$home/signature" "$home/payload" 3> "$home/status" > /dev/null 2> "$home/diagnostic" || fail 'tag signature verification failed'
  awk -v expected="$expected" '
    $1 == "[GNUPG:]" && $2 == "VALIDSIG" {
      valid++
      if (NF != 12 || $12 != expected) invalid = 1
    }
    $1 == "[GNUPG:]" && $2 == "GOODSIG" { good++ }
    $1 == "[GNUPG:]" && $2 ~ /^(EXPKEYSIG|EXPSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED)$/ { invalid = 1 }
    END { if (valid != 1 || good != 1 || invalid) exit 1 }
  ' "$home/status" || fail 'tag signer or signature status is not approved'
}

core_members() {
  local root="$1" tag="$2" goos goarch name
  local names=(SHA256SUMS) files
  [[ "$tag" =~ ^[A-Za-z0-9.+-]+$ ]] || fail 'invalid artifact tag'
  [[ -d "$root" && ! -L "$root" ]] || fail 'core directory is missing or linked'
  for goos in linux darwin windows; do
    for goarch in amd64 arm64; do
      name="mitmproxy-go_${tag}_${goos}_${goarch}"
      names+=("$name.tar.gz" "$name.provenance.json")
    done
  done
  shopt -s nullglob dotglob
  files=("$root"/*)
  [[ "${#files[@]}" -eq 13 ]] || fail 'core file count must be exactly 13'
  for name in "${names[@]}"; do
    [[ -f "$root/$name" && ! -L "$root/$name" ]] || fail 'core member is missing or non-regular'
  done
  printf '%s\n' "${names[@]}"
}

sidecar_members() {
  local core="$1" sidecars="$2" tag="$3" name names files
  names="$(core_members "$core" "$tag")" || exit 1
  [[ -d "$sidecars" && ! -L "$sidecars" ]] || fail 'signature directory is missing or linked'
  shopt -s nullglob dotglob
  files=("$sidecars"/*)
  [[ "${#files[@]}" -eq 13 ]] || fail 'signature file count must be exactly 13'
  while IFS= read -r name; do
    [[ -s "$sidecars/$name.sigstore.json" && -f "$sidecars/$name.sigstore.json" && ! -L "$sidecars/$name.sigstore.json" ]] || fail 'signature member is missing, empty or non-regular'
    printf '%s\n' "$name.sigstore.json"
  done <<< "$names"
}

verify_publication() {
  local root="$1" core="$2" sidecars="$3" tag="$4" compiler="$5" commit="$6" names name identity
  names="$(core_members "$core" "$tag")" || exit 1
  sidecar_members "$core" "$sidecars" "$tag" >/dev/null
  go -C "$root" run ./internal/releasecheck/cmd/releasecheck verify "$core" "$tag" --go-version "$compiler" --source-root "$root"
  identity="https://github.com/zchee/mitmproxy-go/.github/workflows/release.yaml@refs/tags/$tag"
  while IFS= read -r name; do
    cosign verify-blob --bundle "$sidecars/$name.sigstore.json" --certificate-identity "$identity" --certificate-oidc-issuer https://token.actions.githubusercontent.com "$core/$name"
    gh attestation verify "$core/$name" --repo zchee/mitmproxy-go --signer-workflow zchee/mitmproxy-go/.github/workflows/release.yaml --cert-identity "$identity" --cert-oidc-issuer https://token.actions.githubusercontent.com --source-ref "refs/tags/$tag" --source-digest "$commit" --deny-self-hosted-runners
  done <<< "$names"
}

command="${1:-}"
case "$command:$#" in
  verify-tag:4) verify_tag "$2" "$3" "$4"; exit ;;
  core-members:3) core_members "$2" "$3"; exit ;;
  sidecar-members:4) sidecar_members "$2" "$3" "$4"; exit ;;
  verify-publication:7) verify_publication "$2" "$3" "$4" "$5" "$6" "$7"; exit ;;
esac
root="${2:-}"
case "$command:$#" in
  go-version:2 | verify-toolchain:3) ;;
  *) fail 'usage: release-policy.sh go-version ABSOLUTE_SOURCE | verify-toolchain ABSOLUTE_SOURCE EXPECTED_GO_VERSION' ;;
esac
[[ "$root" = /* ]] || fail 'source root must be absolute'
[[ -d "$root" ]] || fail 'source root must be a directory'
prefix="$(git -C "$root" rev-parse --show-prefix)" || fail 'cannot read source root'
[[ -z "$prefix" ]] || fail 'source root must be the checkout root'
status="$(git -C "$root" status --porcelain)" || fail 'cannot read source status'
[[ -z "$status" ]] || fail 'source checkout must be clean'
module="$(git -C "$root" show HEAD:go.mod)" || fail 'cannot read committed go.mod'
version=''
while IFS= read -r line; do
  [[ ! "$line" =~ ^[[:space:]]*toolchain([[:space:]]|$) ]] || fail 'toolchain directives are not allowed for releases'
  if [[ "$line" =~ ^[[:space:]]*go[[:space:]] ]]; then
    [[ -z "$version" ]] || fail 'duplicate go directive'
    [[ "$line" =~ ^[[:space:]]*go[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)([[:space:]]*(//.*)?)$ ]] || fail 'invalid plain Go version in go.mod'
    version="${BASH_REMATCH[1]}"
  fi
done <<< "$module"
[[ -n "$version" ]] || fail 'go.mod has no go directive'

if [[ "$command" = verify-toolchain ]]; then
  [[ "$3" = "go$version" ]] || fail 'expected Go version differs from trusted go.mod'
  experiments="$(go env GOEXPERIMENT)" || fail 'cannot read Go experiments'
  [[ -z "$experiments" ]] || fail 'release Go experiments must be empty'
  actual="$(go version)" || fail 'cannot read selected compiler version'
  [[ "$actual" = "go version go$version "* ]] || fail 'selected compiler differs from trusted go.mod'
  platform="${actual#"go version go$version "}"
  [[ "$platform" =~ ^[a-z0-9]+/[a-z0-9]+$ ]] || fail 'selected compiler is not plain Go'
fi
printf '%s\n' "$version"
