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
# 1. A private place for the key, and a check that nothing is there yet
mkdir -p ~/.minisign && chmod 700 ~/.minisign
ls ~/.minisign/oxiclean.key ~/.minisign/oxiclean.pub 2>/dev/null && echo "STOP: a key already exists"

# 2. Generate the pair. You are asked for a password.
minisign -G -p ~/.minisign/oxiclean.pub -s ~/.minisign/oxiclean.key
chmod 600 ~/.minisign/oxiclean.key
chmod 644 ~/.minisign/oxiclean.pub

# 3. Try it before relying on it: sign a scratch file, then verify it.
t=$(mktemp -d); echo test > "$t/f"
minisign -S -s ~/.minisign/oxiclean.key -m "$t/f" -x "$t/f.minisig" -t "oxiclean 0.0.0"
minisign -V -H -p ~/.minisign/oxiclean.pub -m "$t/f" -x "$t/f.minisig"
rm -r "$t"

# 4. Back the key up (next section), then put the public key in the repository.
install -m 644 ~/.minisign/oxiclean.pub minisign.pub
cmp ~/.minisign/oxiclean.pub minisign.pub
```

- Pick a strong password, and never pass `-W` (it stores the key unencrypted).
- Don't add `-f`. Without it the command stops if the secret key already exists,
  which is what you want: an existing key is never overwritten.
- If the key lives somewhere else, set `MINISIGN_KEY` when you sign;
  `scripts/sign-release.sh` looks for `~/.minisign/oxiclean.key`.
- Keep it off GitHub: not in the repository and not in Actions secrets. Signing is
  offline so that a compromised repository or CI cannot also sign.

### Backing the key up

The secret key file is already encrypted with its password. A lost key means every
install has to be redone by hand (see [Rotating or losing the key](#rotating-or-losing-the-key)),
so keep copies.

1. Copy `~/.minisign/oxiclean.key` to at least two offline media that are different
   devices (two USB sticks, say), kept apart from this machine and from each other.
   Never overwrite a file that is already there (`test -e "$dest/oxiclean.key" ||
   cp …`), and run `sync`. A FAT or exFAT stick has no file permissions, so the
   password is all that protects the key on it: treat the sticks like the key.
2. Check each copy. Compare it with the original using `sha256sum`, then repeat
   step 3 above with `-s` pointing at the copy. A backup you have never signed with
   is a guess. That first check may have been read from the cache, so plug each
   stick in again later and compare the checksum once more.
3. Keep the password somewhere else (a password manager, or on paper), not next to
   the key.
4. Write down the key ID, which is on the first line of `minisign.pub`, outside this
   machine too. It is what you compare against if you ever doubt a file. Copy
   `oxiclean.pub` next to the key as well: it is public, and
   `minisign -R -s oxiclean.key -p oxiclean.pub` can rebuild it from the secret key
   anyway.

### The public key

Commit `minisign.pub`. It is the only file that goes in the repository. Then
`cargo test --locked release_builds_must_ship_an_update_key -- --ignored` must pass;
the Release workflow runs the same test before building.

## Making a release

1. Raise the version everywhere: `version` in `Cargo.toml` (run `cargo build` so
   `Cargo.lock` follows), `pkgver` in `PKGBUILD`, and a section in
   `CHANGELOG.md` (the `[Unreleased]` section becomes the new version's). It must be
   higher than every earlier release; clients never install an equal or older
   version.
2. Commit, run `cargo test --locked -- --ignored` (the two checks only a release
   runs; the second needs the network), then tag `vX.Y.Z` (exactly the `Cargo.toml`
   version) and push the tag.
3. The *Release* workflow checks that the tag matches `Cargo.toml` and that
   `minisign.pub` holds a key, builds the four binaries and attaches them to a
   **draft** release. GitHub's "latest release" never includes drafts, so
   neither `oxiclean --update` nor `install.sh` can see it yet.
4. On the machine with the secret key (needs `gh`, logged in, plus `minisign`
   and `sha256sum`):

   ```sh
   scripts/sign-release.sh vX.Y.Z
   ```

   It works on a draft only and stops at once if the release is already
   published. It downloads the four binaries (it never runs them), prints their
   checksums and waits. Compare them with the ones the build jobs recorded in the
   "Record the checksum" step of the workflow run, then answer `y`. No option
   answers for you: the signature says that you compared them. It signs the list
   as `oxiclean X.Y.Z`, verifies the result the way a client will (against
   `minisign.pub`, prehashed), checks once more that the release is still a
   draft, and uploads `SHA256SUMS` and `SHA256SUMS.minisig` to it. Set
   `MINISIGN_KEY` if the secret key is not at `~/.minisign/oxiclean.key`.
5. Optionally download a binary from the draft and run `--version` on a scratch
   machine.
6. Add the release notes, which the workflow leaves empty (what a user will
   notice, shorter than the changelog section), then publish:

   ```sh
   gh release edit vX.Y.Z --repo croaky-fx/oxiclean --notes-file notes.md
   gh release edit vX.Y.Z --repo croaky-fx/oxiclean --draft=false
   ```

If anything changes after you signed (a binary rebuilt, say), the old signature
no longer matches: rebuild, then run the script again; it replaces the signature
on the draft. Once a release is published, treat it as final and never replace
its files; the script refuses to touch one. Fix forward with a higher version.

## The AUR package

The AUR package is built from source at the release tag (`git+…#tag=v$pkgver`,
`sha256sums=('SKIP')`). It never downloads the signed binaries, so the signature
plays no part in it, and `--update` refuses to replace a binary that pacman owns.
It is updated by hand, once the release is published:

1. Work in the AUR clone (`~/oxiclean-aur`), not in this repository: `makepkg`
   makes `src/` and `pkg/` in the directory it runs in, and `src/` is the Rust
   source here. Copy `PKGBUILD` over from this repository, where `pkgver` was
   raised when you made the release. The AUR holds the same file.
2. Refresh the metadata: `makepkg --printsrcinfo > .SRCINFO`.
3. Build it once in a clean chroot (`pkgctl build`, from devtools), or with plain
   `makepkg`, and read what `namcap` says. `check()` runs the whole test suite.
4. Commit as `upgpkg: oxiclean X.Y.Z-1: what changed` and `git push`. The push is
   authenticated by the SSH key registered with the AUR account; nothing is
   signed.

The tag has to be on GitHub before the push, or the package cannot be built. For
a fix to the PKGBUILD alone, raise `pkgrel` and leave `pkgver`.

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
