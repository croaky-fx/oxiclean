# Releasing OxiClean

A release has two halves: CI builds four binaries, and the maintainer signs
their checksum list by hand, offline. `oxiclean --update` installs only what the
signing key has vouched for, so a release without the second half cannot be
installed by it. This file is the whole procedure.

## What a client checks

Every release carries `SHA256SUMS` (a plain `sha256sum` list of the four
binaries) and `SHA256SUMS.minisig`, a [minisign](https://jedisct1.github.io/minisign/)
signature of that list. `oxiclean --update` goes ahead only when all of this
holds:

1. The signature verifies against a public key built into the running binary
   from `minisign.pub`. Prehashed signatures only; the legacy format is refused.
2. The signed *trusted comment* reads exactly `oxiclean X.Y.Z`, `X.Y.Z` is the
   version of the release being installed, and it is newer than the running
   version. A genuine old release replayed as "latest" is refused.
3. The downloaded binary hashes to the digest the signed list gives for its name.
4. Only then is it looked at as a program: it must be an ELF file, and running
   it with `--version` (cleaned environment, 10-second limit) must print exactly
   `oxiclean X.Y.Z`.

The release notes it shows are *not* signed. They come from the GitHub API, are
stripped of terminal control sequences, and are labelled as unsigned.

With no key in `minisign.pub`, `--update` refuses to run: a build never installs
on faith.

## One-time setup: the signing key

Do this once, on a machine you trust, before the first signed release.

```sh
mkdir -p ~/.minisign
minisign -G -p minisign.pub.new -s ~/.minisign/oxiclean.key
mv minisign.pub.new minisign.pub
```

- Pick a strong password when asked, and never pass `-W` (it stores the key
  unencrypted).
- Don't add `-f`. Without it the command stops if the secret key already exists,
  which is what you want: an existing key is never overwritten.
- Back the secret key up offline, with its password kept somewhere else. If it
  is lost, see [Rotating or losing the key](#rotating-or-losing-the-key).
- Keep it off GitHub: not in the repository and not in Actions secrets. Signing
  is offline so that a compromised repository or CI cannot also sign.
- Commit `minisign.pub`. It is the only file that goes in the repository. Then
  `cargo test --locked release_builds_must_ship_an_update_key -- --ignored`
  must pass; the Release workflow runs the same test before building.

## Making a release

1. Raise the version everywhere: `version` in `Cargo.toml` (run `cargo build` so
   `Cargo.lock` follows), `pkgver` in `PKGBUILD`, and a section in
   `CHANGELOG.md`. It must be higher than every earlier release; clients never
   install an equal or older version.
2. Commit, then tag `vX.Y.Z` (exactly the `Cargo.toml` version) and push the tag.
3. The *Release* workflow checks that the tag matches `Cargo.toml` and that
   `minisign.pub` holds a key, builds the four binaries and attaches them to a
   **draft** release. GitHub's "latest release" never includes drafts, so
   neither `oxiclean --update` nor `install.sh` can see it yet.
4. On the machine with the secret key (needs `gh`, logged in, plus `minisign`
   and `sha256sum`):

   ```sh
   scripts/sign-release.sh vX.Y.Z
   ```

   It downloads the four binaries (it never runs them), prints their checksums
   and waits. Compare them with the ones the build jobs recorded in the "Record
   the checksum" step of the workflow run, then answer `y`. It signs the list as
   `oxiclean X.Y.Z`, verifies the result the way a client will (against
   `minisign.pub`, prehashed), and uploads `SHA256SUMS` and `SHA256SUMS.minisig`
   to the draft. Set `MINISIGN_KEY` if the secret key is not at
   `~/.minisign/oxiclean.key`.
5. Optionally download a binary from the draft and run `--version` on a scratch
   machine.
6. Publish: `gh release edit vX.Y.Z --repo croaky-fx/oxiclean --draft=false`.

If anything changes after you signed (a binary rebuilt, say), the old signature
no longer matches: rebuild, then run the script again; it replaces the signature
on the draft. Once a release is published, treat it as final and never replace
its files. Fix forward with a higher version.

## Checking a release by hand

You don't need oxiclean to check one:

```sh
base=https://github.com/croaky-fx/oxiclean/releases/download/vX.Y.Z
curl -fLO "$base/SHA256SUMS"
curl -fLO "$base/SHA256SUMS.minisig"
curl -fLO "$base/oxiclean-x86_64-linux-gnu"
minisign -V -H -p minisign.pub -m SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

`minisign` prints the trusted comment, which should read `oxiclean X.Y.Z`. If
`minisign.pub` holds more than one key, `-p` only reads the first; pass the key
line itself with `-P RWQ...` to check against the others.

## Rotating or losing the key

`minisign.pub` may hold several keys (paste the new `minisign.pub` under the old
one); a release is accepted if any of them verifies it.

- **Planned rotation.** In release N, add the new public key beside the old one
  and sign with the *old* key: every client that updates to N then trusts both.
  Sign N+1 and later with the new key. When nobody should still be on anything
  older than N, drop the old key.
- **Lost key.** The updater cannot move installs to a new key, because it only
  accepts keys it already carries. Publish a release that embeds a new key and
  have people reinstall it by hand (`install.sh`, or the package manager). From
  then on it updates normally.
- **Leaked key.** To publish something clients accept, an attacker needs the key
  *and* a way to put files in the releases, but don't count on the second.
  Rotate at once, signing the release that introduces the new key with the old
  one (the only signature existing installs will follow), and say so in the
  release notes.

## What this does not cover

- `install.sh`, the first install, still downloads over HTTPS without checking
  the signature. It is the bootstrap path and the next thing to harden.
- Clients up to and including 1.8.0 have the old updater, which checks nothing:
  they get the first signed release through it. Every update after that is
  verified.
- A signature means "the maintainer vouches for these bytes", not "these bytes
  were built from this source". Comparing checksums in step 4 catches tampering
  between the build and the signing, not a compromised build.
- Someone who can only intercept the network can stop an update (the updater
  fails closed) but cannot make it install a different binary.

## Testing the tooling

`scripts/test-sign-release.sh` runs `sign-release.sh` end to end against
throwaway keys and a fake `gh`. It needs `minisign` installed, never touches the
network or your real key, and runs in CI. The updater's own tests (`cargo test`)
use real minisign-made signatures. Neither needs the production key.
