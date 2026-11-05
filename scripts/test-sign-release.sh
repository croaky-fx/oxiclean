#!/usr/bin/env bash
# Exercise scripts/sign-release.sh against a fake `gh` and throwaway keys.
# Needs bash, minisign and sha256sum; touches nothing outside a temp directory
# and never talks to GitHub.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
script=$here/sign-release.sh
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
failures=0

pass() { echo "ok   - $1"; }
fail() {
  echo "FAIL - $1" >&2
  failures=$((failures + 1))
}
# check "what" command...: the command must succeed.
check() {
  local what=$1
  shift
  if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi
}

# Two throwaway key pairs: "release" is the one minisign.pub would hold.
mkdir -p "$tmp/keys"
for name in release other; do
  minisign -G -W -f -p "$tmp/keys/$name.pub" -s "$tmp/keys/$name.key" >/dev/null
done
printf 'untrusted comment: not generated yet\n' >"$tmp/keys/placeholder.pub"
cat "$tmp/keys/other.pub" "$tmp/keys/release.pub" >"$tmp/keys/rotated.pub"

# A `gh` that serves $FAKE_RELEASE for $FAKE_TAG, says whether it is a draft
# (FAKE_DRAFT) and records uploads.
mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'GH'
#!/usr/bin/env bash
set -euo pipefail
echo "gh $*" >>"$FAKE_LOG"
[[ ${1:-} == release ]] || exit 2
action=$2
tag=$3
shift 3
[[ $tag == "$FAKE_TAG" ]] || { echo "release not found" >&2; exit 1; }
case $action in
  view)
    # Only the one field, and only for this repository.
    [[ " $* " == *" --repo test/repo --json isDraft --jq .isDraft "* ]] || { echo "unexpected arguments: $*" >&2; exit 2; }
    [[ -z ${FAKE_FAIL_VIEW:-} ]] || { echo "HTTP 502" >&2; exit 1; }
    # FAKE_DRAFT holds one answer per call; the last one repeats.
    n=$(cat "$FAKE_STATE" 2>/dev/null || echo 0)
    read -ra answers <<<"${FAKE_DRAFT:-true}"
    i=$n
    ((i < ${#answers[@]})) || i=$((${#answers[@]} - 1))
    echo $((n + 1)) >"$FAKE_STATE"
    echo "${answers[$i]}"
    ;;
  download)
    [[ -z ${FAKE_FAIL_DOWNLOAD:-} ]] || { echo "download refused" >&2; exit 1; }
    dir= pattern=
    while (($#)); do
      case $1 in
        --dir) dir=$2; shift 2 ;;
        --pattern) pattern=$2; shift 2 ;;
        --repo) shift 2 ;;
        *) shift ;;
      esac
    done
    for f in "$FAKE_RELEASE"/*; do
      [[ -e $f ]] || continue
      # shellcheck disable=SC2254
      case $(basename "$f") in $pattern) cp "$f" "$dir/" ;; esac
    done
    ;;
  upload)
    [[ -z ${FAKE_FAIL_UPLOAD:-} ]] || { echo "upload refused" >&2; exit 1; }
    files=()
    while (($#)); do
      case $1 in
        --repo) shift 2 ;;
        --clobber) shift ;;
        *) files+=("$1"); shift ;;
      esac
    done
    cp "${files[@]}" "$FAKE_UPLOADED/"
    ;;
  *) exit 2 ;;
esac
GH
chmod +x "$tmp/bin/gh"

assets=(oxiclean-x86_64-linux-gnu oxiclean-x86_64-linux-musl oxiclean-aarch64-linux-gnu oxiclean-aarch64-linux-musl)
fresh_release() {
  rm -rf "$tmp/release"
  mkdir -p "$tmp/release"
  for a in "${assets[@]}"; do
    printf '\177ELF pretend binary %s\n' "$a" >"$tmp/release/$a"
  done
}

# sign KEY PUB ARGS...: run the script; stdin is whatever the caller redirects.
sign() {
  local key=$1 pub=$2
  shift 2
  rm -rf "$tmp/uploaded"
  mkdir -p "$tmp/uploaded"
  : >"$tmp/gh.log"
  rm -f "$tmp/gh.state"
  PATH="$tmp/bin:$PATH" FAKE_TAG=v9.9.9 FAKE_RELEASE="$tmp/release" \
    FAKE_UPLOADED="$tmp/uploaded" FAKE_LOG="$tmp/gh.log" FAKE_STATE="$tmp/gh.state" \
    MINISIGN_KEY=$key MINISIGN_PUB=$pub REPO=test/repo "$script" "$@"
}
# sign_y KEY PUB ARGS...: the same, with a "y" waiting for the question.
sign_y() { echo y | sign "$@"; }
uploaded() { ls -A "$tmp/uploaded" | tr '\n' ' '; }
nothing_uploaded() { [[ -z $(ls -A "$tmp/uploaded") ]]; }
gh_untouched() { [[ ! -s $tmp/gh.log ]]; }

release_key=$tmp/keys/release.key
release_pub=$tmp/keys/release.pub

# ── a good run ──
fresh_release
if sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1; then pass "signs a good release"; else
  fail "signs a good release"
  cat "$tmp/out" >&2
fi
[[ "$(uploaded)" == "SHA256SUMS SHA256SUMS.minisig " ]] && pass "uploads the list and its signature, nothing else" ||
  fail "uploads the list and its signature, nothing else (got: $(uploaded))"
check "the list matches the binaries" bash -c "cd '$tmp/release' && sha256sum -c --strict '$tmp/uploaded/SHA256SUMS'"
[[ $(wc -l <"$tmp/uploaded/SHA256SUMS") -eq 4 ]] && pass "the list has exactly four entries" || fail "the list has exactly four entries"
comment=$(minisign -V -H -Q -p "$release_pub" -m "$tmp/uploaded/SHA256SUMS" -x "$tmp/uploaded/SHA256SUMS.minisig" 2>/dev/null || true)
[[ $comment == "oxiclean 9.9.9" ]] && pass "the signature verifies and names the release" ||
  fail "the signature verifies and names the release (got: '$comment')"
check "the list is in sha256sum format, two spaces" grep -qE '^[0-9a-f]{64}  oxiclean-[a-z0-9_]+-linux-(gnu|musl)$' "$tmp/uploaded/SHA256SUMS"
calls=$(awk '{print $3}' "$tmp/gh.log" | tr '\n' ' ')
[[ $calls == "view download view upload " ]] && pass "checks for a draft before downloading and again before uploading" ||
  fail "checks for a draft before downloading and again before uploading (got: $calls)"
grep -q 'release upload .*--clobber' "$tmp/gh.log" && pass "uploads with --clobber, so a draft can be signed again" ||
  fail "uploads with --clobber, so a draft can be signed again"

# ── asking first ──
fresh_release
if echo y | sign "$release_key" "$release_pub" v9.9.9 >/dev/null 2>&1; then pass "signs when told yes"; else fail "signs when told yes"; fi
nothing_uploaded && fail "uploads after yes" || pass "uploads after yes"
for answer in n "" nope; do
  if echo "$answer" | sign "$release_key" "$release_pub" v9.9.9 >/dev/null 2>&1; then fail "refuses to sign on '$answer'"; else pass "refuses to sign on '$answer'"; fi
  nothing_uploaded && pass "uploads nothing on '$answer'" || fail "uploads nothing on '$answer'"
done
if sign "$release_key" "$release_pub" v9.9.9 </dev/null >/dev/null 2>&1; then fail "refuses to sign with no one to ask"; else pass "refuses to sign with no one to ask"; fi
nothing_uploaded && pass "uploads nothing with no one to ask" || fail "uploads nothing with no one to ask"

# ── the wrong key ──
if sign_y "$tmp/keys/other.key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1; then fail "refuses a key that minisign.pub does not hold"; else pass "refuses a key that minisign.pub does not hold"; fi
grep -q "does not verify" "$tmp/out" && pass "says why" || fail "says why"
nothing_uploaded && pass "uploads nothing with the wrong key" || fail "uploads nothing with the wrong key"

# ── several keys in minisign.pub (a rotation) ──
if sign_y "$release_key" "$tmp/keys/rotated.pub" v9.9.9 >/dev/null 2>&1; then pass "accepts a key that is one of several"; else fail "accepts a key that is one of several"; fi
nothing_uploaded && fail "uploads with several keys" || pass "uploads with several keys"

# ── no key in minisign.pub yet ──
if sign_y "$release_key" "$tmp/keys/placeholder.pub" v9.9.9 >"$tmp/out" 2>&1; then fail "refuses when minisign.pub holds no key"; else pass "refuses when minisign.pub holds no key"; fi
gh_untouched && pass "does not even download then" || fail "does not even download then"

# ── what the release holds ──
fresh_release
rm "$tmp/release/oxiclean-aarch64-linux-musl"
if sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1; then fail "refuses a release missing a binary"; else pass "refuses a release missing a binary"; fi
grep -q "oxiclean-aarch64-linux-musl" "$tmp/out" && pass "names the missing binary" || fail "names the missing binary"
nothing_uploaded && pass "uploads nothing then" || fail "uploads nothing then"

fresh_release
printf '#!/bin/sh\necho not elf\n' >"$tmp/release/oxiclean-x86_64-linux-gnu"
if sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1; then fail "refuses a binary that is not an ELF file"; else pass "refuses a binary that is not an ELF file"; fi
nothing_uploaded && pass "uploads nothing for a non-ELF binary" || fail "uploads nothing for a non-ELF binary"

fresh_release
: >"$tmp/release/oxiclean-x86_64-linux-musl"
if sign_y "$release_key" "$release_pub" v9.9.9 >/dev/null 2>&1; then fail "refuses an empty binary"; else pass "refuses an empty binary"; fi

fresh_release
printf 'extra\n' >"$tmp/release/oxiclean-extra"
printf 'stale\n' >"$tmp/release/SHA256SUMS"
if sign_y "$release_key" "$release_pub" v9.9.9 >/dev/null 2>&1; then pass "ignores extra assets and a stale list"; else fail "ignores extra assets and a stale list"; fi
grep -q "extra\|stale" "$tmp/uploaded/SHA256SUMS" && fail "signs only the four binaries" || pass "signs only the four binaries"

# ── tags ──
fresh_release
for tag in v9.9 9.9.9 v9.9.9-rc1 v09.9.9 v1.2.3.4 vv9.9.9 v1.2.x v9.9.9_ ""; do
  if sign_y "$release_key" "$release_pub" "$tag" >/dev/null 2>&1; then fail "refuses the tag '$tag'"; else pass "refuses the tag '$tag'"; fi
  gh_untouched && pass "touches nothing for '$tag'" || fail "touches nothing for '$tag'"
done
if sign_y "$release_key" "$release_pub" v9.9.8 >"$tmp/out" 2>&1; then fail "fails for a release that does not exist"; else pass "fails for a release that does not exist"; fi
grep -q "could not read" "$tmp/out" && pass "says it could not read the release" || fail "says it could not read the release"
nothing_uploaded && pass "uploads nothing then" || fail "uploads nothing then"
fresh_release
if (export FAKE_FAIL_DOWNLOAD=1; sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1); then fail "fails when the download fails"; else pass "fails when the download fails"; fi
grep -q "could not download" "$tmp/out" && pass "says the download failed" || fail "says the download failed"
nothing_uploaded && pass "uploads nothing after a failed download" || fail "uploads nothing after a failed download"
# Even with a "yes" waiting on stdin, an option nobody defined is refused.
if echo y | sign "$release_key" "$release_pub" v9.9.9 --maybe >/dev/null 2>&1; then fail "refuses an unknown option"; else pass "refuses an unknown option"; fi
nothing_uploaded && pass "uploads nothing for an unknown option" || fail "uploads nothing for an unknown option"
# Signing always asks. The old way of answering for yourself is refused like any
# other option, with a "yes" waiting on stdin all the same.
if echo y | sign "$release_key" "$release_pub" v9.9.9 --yes >/dev/null 2>&1; then fail "refuses --yes: signing always asks"; else pass "refuses --yes: signing always asks"; fi
nothing_uploaded && pass "uploads nothing for --yes" || fail "uploads nothing for --yes"
gh_untouched && pass "touches nothing for --yes" || fail "touches nothing for --yes"
if echo y | sign "$release_key" "$release_pub" v9.9.9 extra >/dev/null 2>&1; then fail "refuses a second argument"; else pass "refuses a second argument"; fi
gh_untouched && pass "touches nothing for a second argument" || fail "touches nothing for a second argument"

# ── only a draft ──
# A published release is what clients verify against: its files are never replaced.
fresh_release
if (export FAKE_DRAFT=false; sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1); then fail "refuses a release that is already published"; else pass "refuses a release that is already published"; fi
grep -q "already published" "$tmp/out" && pass "says it is published" || fail "says it is published"
nothing_uploaded && pass "uploads nothing to a published release" || fail "uploads nothing to a published release"
grep -qE 'release (download|upload)' "$tmp/gh.log" && fail "downloads nothing for a published release" || pass "downloads nothing for a published release"

fresh_release
if (export FAKE_FAIL_VIEW=1; sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1); then fail "refuses when GitHub will not say whether it is a draft"; else pass "refuses when GitHub will not say whether it is a draft"; fi
grep -q "could not read" "$tmp/out" && pass "says it could not read the release" || fail "says it could not read the release"
grep -qE 'release (download|upload)' "$tmp/gh.log" && fail "downloads nothing when it cannot tell" || pass "downloads nothing when it cannot tell"

fresh_release
if (export FAKE_DRAFT=maybe; sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1); then fail "refuses an answer that is neither true nor false"; else pass "refuses an answer that is neither true nor false"; fi
grep -qE 'release (download|upload)' "$tmp/gh.log" && fail "downloads nothing for an unclear answer" || pass "downloads nothing for an unclear answer"

# Published by someone else, or by hand, while the key's password was being typed.
fresh_release
if (export FAKE_DRAFT="true false"; sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1); then fail "refuses a release published while it was being signed"; else pass "refuses a release published while it was being signed"; fi
grep -q "published while" "$tmp/out" && pass "says it was published meanwhile" || fail "says it was published meanwhile"
nothing_uploaded && pass "uploads nothing then" || fail "uploads nothing then"

# ── an upload that fails is a failure ──
fresh_release
if (export FAKE_FAIL_UPLOAD=1; sign_y "$release_key" "$release_pub" v9.9.9 >"$tmp/out" 2>&1); then fail "reports a failed upload"; else pass "reports a failed upload"; fi
grep -q "could not upload" "$tmp/out" && pass "says the upload failed" || fail "says the upload failed"

if ((failures > 0)); then
  echo "$failures check(s) failed" >&2
  exit 1
fi
echo "all checks passed"
