#!/usr/bin/env bash
# Sign the checksum list of a draft release: the step between "CI built it" and
# "people can install it". See RELEASING.md.
#
#   scripts/sign-release.sh vX.Y.Z [--yes]
#
# Downloads the four binaries the Release workflow attached to the draft, writes
# their SHA256SUMS, signs it with the offline release key, checks the signature
# against minisign.pub, and uploads SHA256SUMS and SHA256SUMS.minisig to the
# draft. Publishing is a separate, deliberate step. No downloaded binary is ever
# run: the machine holding the signing key has no business executing them.
#
# Environment:
#   MINISIGN_KEY   secret key file          (default: ~/.minisign/oxiclean.key)
#   MINISIGN_PUB   public key(s) to check   (default: minisign.pub in this repo)
#   REPO           owner/name               (default: croaky-fx/oxiclean)
set -euo pipefail

repo=${REPO:-croaky-fx/oxiclean}
key=${MINISIGN_KEY:-$HOME/.minisign/oxiclean.key}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
pub=${MINISIGN_PUB:-$root/minisign.pub}
# Exactly the files the updater looks for; the release workflow builds these.
assets=(
  oxiclean-x86_64-linux-gnu
  oxiclean-x86_64-linux-musl
  oxiclean-aarch64-linux-gnu
  oxiclean-aarch64-linux-musl
)

die() {
  echo "sign-release: $*" >&2
  exit 1
}

tag=${1:-}
yes=${2:-}
# The same shape the updater insists on: three plain numbers, no suffix.
num='(0|[1-9][0-9]{0,8})'
[[ $tag =~ ^v$num\.$num\.$num$ ]] || die "usage: $0 vX.Y.Z [--yes]   (a plain version tag)"
[[ -z $yes || $yes == --yes ]] || die "usage: $0 vX.Y.Z [--yes]"
version=${tag#v}

for tool in gh minisign sha256sum; do
  command -v "$tool" >/dev/null || die "$tool is required"
done
[[ -f $key ]] || die "secret key $key not found (set MINISIGN_KEY)"
[[ -f $pub ]] || die "$pub not found"

# Public keys, one per line, as the updater reads the same file.
keys=()
while IFS= read -r line; do
  line=${line#"${line%%[![:space:]]*}"}
  line=${line%"${line##*[![:space:]]}"}
  [[ -z $line || $line == "untrusted comment:"* ]] || keys+=("$line")
done <"$pub"
((${#keys[@]} > 0)) || die "$pub holds no key yet: generate one first (see RELEASING.md)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

gh release download "$tag" --repo "$repo" --dir "$work" --pattern 'oxiclean-*' ||
  die "could not download the assets of $tag from $repo"

for asset in "${assets[@]}"; do
  [[ -s $work/$asset ]] || die "the draft has no $asset"
  magic=$(head -c 4 "$work/$asset" | od -An -tx1 | tr -d ' \n')
  [[ $magic == 7f454c46 ]] || die "$asset is not an ELF file"
done

(cd "$work" && sha256sum "${assets[@]}" >SHA256SUMS)
echo
cat "$work/SHA256SUMS"
echo
echo "Compare these with the \"Record the checksum\" step of each build job in the"
echo "Actions run for $tag before signing: the signature vouches for exactly this list."
if [[ $yes != --yes ]]; then
  read -r -p "Sign it as 'oxiclean $version'? [y/N] " answer || answer=
  [[ $answer == [yY] || $answer == [yY][eE][sS] ]] || die "not signed"
fi

minisign -S -s "$key" -m "$work/SHA256SUMS" -x "$work/SHA256SUMS.minisig" -t "oxiclean $version"

# Check what was just made the way a client will: against the public key in the
# repository, as a prehashed signature (the only kind the updater accepts),
# and with the release name the updater requires in the comment.
signed=
for k in "${keys[@]}"; do
  if comment=$(minisign -V -H -Q -P "$k" -m "$work/SHA256SUMS" -x "$work/SHA256SUMS.minisig" 2>/dev/null); then
    signed=$comment
    break
  fi
done
[[ -n $signed ]] || die "the signature does not verify against $pub: is MINISIGN_KEY the key that file holds?"
[[ $signed == "oxiclean $version" ]] || die "the signed comment is '$signed', expected 'oxiclean $version'"

gh release upload "$tag" --repo "$repo" --clobber "$work/SHA256SUMS" "$work/SHA256SUMS.minisig" ||
  die "could not upload the signature to $tag"

echo
echo "Signed and uploaded. Check the draft, then publish it:"
echo "  gh release edit $tag --repo $repo --draft=false"
