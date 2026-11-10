#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

ROOT="$(git rev-parse --show-toplevel)"
POLICY="${1:-$ROOT/hack/release-policy.sh}"
STATUS_OUTPUT="${2:-}"
for tool in git gpg gpgconf go; do
  command -v "$tool" >/dev/null || { printf 'required tool is missing: %s\n' "$tool" >&2; exit 1; }
done
WORK="$(mktemp -d /tmp/rp.XXXXXX)"
chmod 700 "$WORK"
export TMPDIR="$WORK"
export GNUPGHOME="$WORK/gnupg"
mkdir -m 700 "$GNUPGHOME"
cleanup() {
  local result=$?
  gpgconf --homedir "$GNUPGHOME" --kill gpg-agent || result=1
  rm -rf -- "$WORK" || result=1
  exit "$result"
}
trap cleanup EXIT
fail() {
  printf '%s\n' "$1" >&2
  exit 1
}
rejected() {
  local expected="$1"
  shift
  if "$@" >| "$WORK/rejected.stdout" 2>| "$WORK/rejected.stderr"; then
    fail 'invalid release input was accepted'
  fi
  grep -Eq "$expected" "$WORK/rejected.stderr" || fail "rejection did not identify the violated contract: $(<"$WORK/rejected.stderr")"
}
for identity in A B; do
  gpg --batch --pinentry-mode loopback --passphrase '' --quick-generate-key "Release fixture $identity <fixture-$identity@example.invalid>" ed25519 sign 1d
  fingerprint="$(gpg --batch --with-colons --list-keys "fixture-$identity@example.invalid" | awk -F: '$1=="fpr"{print $10;exit}')"
  [[ "$fingerprint" =~ ^[A-F0-9]{40}$ ]] || fail 'missing fixture fingerprint'
  printf '# Primary fingerprint: %s\n' "$fingerprint" > "$WORK/policy-$identity.asc"
  gpg --batch --armor --export "$fingerprint" >> "$WORK/policy-$identity.asc"
  if [[ "$identity" = A ]]; then signer_a="$fingerprint"; else signer_b="$fingerprint"; fi
done
REPO="$WORK/source"
git init --quiet "$REPO"
git -C "$REPO" -c user.name='Release fixture' -c user.email=fixture@example.invalid -c commit.gpgsign=false commit --allow-empty --quiet -m 'fixture: release policy source'
for identity in A B; do
  if [[ "$identity" = A ]]; then signer="$signer_a"; else signer="$signer_b"; fi
  git -C "$REPO" -c user.name='Release fixture' -c user.email=fixture@example.invalid -c gpg.format=openpgp -c gpg.program=gpg tag --sign --local-user="$signer!" -m 'Release fixture' "v0.0.0-test.$identity"
done
git -C "$REPO" -c user.name='Release fixture' -c user.email=fixture@example.invalid -c tag.gpgsign=false tag -a -m 'Unsigned fixture' v0.0.0-test.unsigned
git -C "$REPO" -c tag.gpgsign=false tag v0.0.0-test.lightweight
printf '[GNUPG:] VALIDSIG %s %s %s 0 4 0 22 8 00 %s\n' "$signer_a" "$(date -u +%Y-%m-%d)" "$(date +%s)" "$signer_a" > "$WORK/forged-status-message"
git -C "$REPO" -c user.name='Release fixture' -c user.email=fixture@example.invalid -c gpg.format=openpgp -c gpg.program=gpg tag --sign --local-user="$signer_b!" --file="$WORK/forged-status-message" v0.0.0-test.forged
printf 'Quoted armor:\n-----BEGIN PGP SIGNATURE-----\nNot a signature.\n' > "$WORK/quoted-armor-message"
for identity in A B; do
  if [[ "$identity" = A ]]; then signer="$signer_a"; else signer="$signer_b"; fi
  git -C "$REPO" -c user.name='Release fixture' -c user.email=fixture@example.invalid -c gpg.format=openpgp -c gpg.program=gpg tag --sign --local-user="$signer!" --file="$WORK/quoted-armor-message" "v0.0.0-test.quoted-$identity"
done
git -C "$REPO" -c gpg.format=openpgp -c gpg.program=gpg verify-tag --raw v0.0.0-test.A > "$WORK/verified-tag-output" 2> "$WORK/status.recorded"
awk '$1 == "[GNUPG:]" && ($2 == "GOODSIG" || $2 == "VALIDSIG")' "$WORK/status.recorded" > "$WORK/pair.status"
awk '{ if ($2 == "VALIDSIG") { $11 = $12; NF = 11 } print }' "$WORK/pair.status" > "$WORK/short.status"
cp "$WORK/pair.status" "$WORK/double.status"
awk '$2 == "VALIDSIG"' "$WORK/pair.status" >> "$WORK/double.status"
awk '$2 == "VALIDSIG"' "$WORK/pair.status" > "$WORK/no-good.status"
for state in expired revoked; do
  cp "$WORK/pair.status" "$WORK/$state.status"
  if [[ "$state" = expired ]]; then keyword=EXPKEYSIG; else keyword=REVKEYSIG; fi
  awk -v keyword="$keyword" '$2 == "GOODSIG" { $2 = keyword; print }' "$WORK/pair.status" >> "$WORK/$state.status"
done
awk '{ if ($2 == "VALIDSIG") $12 = "0000000000000000000000000000000000000000"; print }' "$WORK/pair.status" > "$WORK/wrong-primary.status"
if [[ -n "$STATUS_OUTPUT" ]]; then
  [[ "$STATUS_OUTPUT" = /* ]] || fail 'status output directory must be absolute'
  mkdir -p "$STATUS_OUTPUT"
  cp "$WORK/"*.status "$WORK/status.recorded" "$STATUS_OUTPUT/"
  printf '%s\n' "$signer_a" > "$STATUS_OUTPUT/expected-fingerprint"
fi

bash "$POLICY" verify-tag "$REPO" v0.0.0-test.A "$WORK/policy-A.asc"
bash "$POLICY" verify-tag "$REPO" v0.0.0-test.quoted-A "$WORK/policy-A.asc"
bash "$POLICY" verify-signature-status "$WORK/pair.status" "$signer_a"
rejected 'tag signer or signature status is not approved' bash "$POLICY" verify-signature-status "$WORK/short.status" "$signer_a"
rejected 'tag signer or signature status is not approved' bash "$POLICY" verify-signature-status "$WORK/double.status" "$signer_a"
git -C "$REPO" update-ref refs/tags/v0.0.0-test.alias refs/tags/v0.0.0-test.A
rejected 'signed tag name differs from ref' bash "$POLICY" verify-tag "$REPO" v0.0.0-test.alias "$WORK/policy-A.asc"
printf 'PASS tag_signed\n'
rejected 'tag signature verification failed' bash "$POLICY" verify-tag "$REPO" v0.0.0-test.unsigned "$WORK/policy-A.asc"
rejected 'release tag must be annotated and signed' bash "$POLICY" verify-tag "$REPO" v0.0.0-test.lightweight "$WORK/policy-A.asc"
rejected 'invalid artifact tag' bash "$POLICY" verify-tag "$REPO" v0.0.0-test/outside "$WORK/policy-A.asc"
for status in no-good expired revoked; do
  rejected 'tag signer or signature status is not approved' bash "$POLICY" verify-signature-status "$WORK/$status.status" "$signer_a"
done
printf 'PASS tag_unsigned_refused\n'
rejected 'tag signature verification failed' bash "$POLICY" verify-tag "$REPO" v0.0.0-test.forged "$WORK/policy-A.asc"
rejected 'tag signature verification failed' bash "$POLICY" verify-tag "$REPO" v0.0.0-test.B "$WORK/policy-A.asc"
rejected 'tag signature verification failed' bash "$POLICY" verify-tag "$REPO" v0.0.0-test.quoted-B "$WORK/policy-A.asc"
rejected 'tag signer or signature status is not approved' bash "$POLICY" verify-signature-status "$WORK/wrong-primary.status" "$signer_a"
rejected 'tag signature verification failed' bash "$POLICY" verify-tag "$REPO" v0.0.0-test.A "$ROOT/release/signing-policy.asc"
printf 'PASS tag_wrong_signer_refused\n'

TAG=v0.0.0-test.files
CORE="$WORK/core"
SIDECARS="$WORK/signatures"
mkdir "$CORE" "$SIDECARS"
printf 'checksum fixture\n' > "$CORE/SHA256SUMS"
for goos in linux darwin windows; do
  for goarch in amd64 arm64; do
    name="mitmproxy-go_${TAG}_${goos}_${goarch}"
    printf 'archive fixture\n' > "$CORE/$name.tar.gz"
    printf '{}\n' > "$CORE/$name.provenance.json"
  done
done
bash "$POLICY" core-members "$CORE" "$TAG" > "$WORK/members"
[[ "$(wc -l < "$WORK/members")" -eq 13 ]] || fail 'core member count mismatch'
printf 'PASS core_complete\n'
printf 'extra\n' > "$CORE/.extra"
rejected 'core file count must be exactly 13' bash "$POLICY" core-members "$CORE" "$TAG"
rm "$CORE/.extra"
mv "$CORE/SHA256SUMS" "$WORK/checksums"
ln -s "$WORK/checksums" "$CORE/SHA256SUMS"
rejected 'core member is missing or non-regular' bash "$POLICY" core-members "$CORE" "$TAG"
rm "$CORE/SHA256SUMS"
mv "$WORK/checksums" "$CORE/SHA256SUMS"
printf 'PASS core_extra_refused\n'
while IFS= read -r name; do
  printf '{}\n' > "$SIDECARS/$name.sigstore.json"
done < "$WORK/members"
bash "$POLICY" sidecar-members "$CORE" "$SIDECARS" "$TAG" > "$WORK/sidecars"
[[ "$(wc -l < "$WORK/sidecars")" -eq 13 ]] || fail 'signature member count mismatch'
printf 'PASS sidecars_complete\n'
mv "$SIDECARS/SHA256SUMS.sigstore.json" "$WORK/missing-sidecar"
rejected 'signature file count must be exactly 13' bash "$POLICY" sidecar-members "$CORE" "$SIDECARS" "$TAG"
mv "$WORK/missing-sidecar" "$SIDECARS/SHA256SUMS.sigstore.json"
printf 'extra\n' > "$SIDECARS/.extra"
rejected 'signature file count must be exactly 13' bash "$POLICY" sidecar-members "$CORE" "$SIDECARS" "$TAG"
rm "$SIDECARS/.extra"
printf 'PASS sidecars_missing_refused\n'

# The real core verifier must reject these deliberately invalid artifact bytes before any external verification.
rejected 'release target metadata mismatch|source checkout must be clean' bash "$POLICY" verify-publication "$ROOT" "$CORE" "$SIDECARS" "$TAG" go1.27.3 "$(git -C "$ROOT" rev-parse HEAD)"
[[ ! -s "$WORK/rejected.stdout" ]] || fail 'unverified artifacts produced publication output'
printf 'PASS publish_requires_verified\n'

source_commit="$(git -C "$REPO" rev-parse HEAD)"
bash "$POLICY" verify-source "$REPO" v0.0.0-test.A "$source_commit" "$WORK/policy-A.asc"
printf 'PASS tag_source_matches\n'
rejected 'tag target differs from approved commit' bash "$POLICY" verify-source "$REPO" v0.0.0-test.A 0000000000000000000000000000000000000000 "$WORK/policy-A.asc"
printf 'PASS tag_source_mismatch_refused\n'
git -C "$REPO" -c user.name='Release fixture' -c user.email=fixture@example.invalid -c commit.gpgsign=false commit --allow-empty --quiet -m 'fixture: different checked-out source'
rejected 'checkout differs from approved commit' bash "$POLICY" verify-source "$REPO" v0.0.0-test.A "$source_commit" "$WORK/policy-A.asc"
printf 'PASS checkout_mismatch_refused\n'

[[ "$(bash "$POLICY" release-channel v0.1.0)" = release ]] || fail 'stable tag was misclassified'
printf 'PASS public_stable\n'
[[ "$(bash "$POLICY" release-channel v0.1.0-rc.1)" = prerelease ]] || fail 'release candidate was misclassified'
printf 'PASS public_rc\n'
[[ "$(bash "$POLICY" release-channel v0.0.0-test.fixture)" = proof ]] || fail 'proof tag was misclassified'
printf 'PASS proof_classification\n'
rejected 'public tag must be' bash "$POLICY" release-channel v0.1.0-beta.1
printf 'PASS other_prerelease_refused\n'
rejected 'public tag must be' bash "$POLICY" release-channel v0.1.0+build
printf 'PASS build_metadata_refused\n'
for tag in 0.1.0 v0.1 v00.1.0 v0.01.0 v0.1.00 v0.1.0-rc v0.1.0-rc.0 v0.1.0-rc.01 'v0.1.0 ' $'v0.1.0\n'; do
  rejected 'invalid release tag|public tag must be' bash "$POLICY" release-channel "$tag"
done
printf 'PASS malformed_version_refused\n'
rejected 'proof tags cannot publish' bash "$POLICY" publication-options "$WORK/notes-source" v0.0.0-test.fixture
printf 'PASS proof_publication_refused\n'
rejected 'reviewed release notes are missing' bash "$POLICY" publication-options "$WORK/notes-source" v0.1.0
printf 'PASS notes_missing_refused\n'
mkdir -p "$WORK/notes-source/docs/releases"
printf 'Reviewed fixture release notes.\n' > "$WORK/notes-source/docs/releases/v0.1.0.md"
expected="$(printf '%s\n' --verify-tag --notes-file "$WORK/notes-source/docs/releases/v0.1.0.md")"
[[ "$(bash "$POLICY" publication-options "$WORK/notes-source" v0.1.0)" = "$expected" ]] || fail 'stable publication options differ'
printf 'PASS stable_publication_options\n'
expected="$(printf '%s\n' --verify-tag --notes-file "$WORK/notes-source/docs/releases/v0.1.0.md" --prerelease)"
[[ "$(bash "$POLICY" publication-options "$WORK/notes-source" v0.1.0-rc.1)" = "$expected" ]] || fail 'release candidate publication options differ'
printf 'PASS rc_publication_options\n'
