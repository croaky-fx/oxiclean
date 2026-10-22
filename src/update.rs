// ═══════════════════════════════════════════════════
//  Self-update — `oxiclean --update`
// ═══════════════════════════════════════════════════
//
// Checks GitHub for a newer release, shows its notes, and (with consent)
// swaps the running binary for the new one.
//
// What gets downloaded is about to run — as root, when the binary lives in
// /usr/local/bin — so it is trusted only after a key we ship has vouched for
// it. Hard rules baked in here:
//
// * **Signed, not merely downloaded.** Each release carries `SHA256SUMS` and a
//   minisign signature of it. The signature is checked against the public key
//   embedded from `minisign.pub`; the checksum list then pins every asset to
//   exact bytes. TLS shows that we reached GitHub, not that the maintainer
//   published what we received.
// * **The signature names the release.** Its signed "trusted comment" must read
//   `oxiclean X.Y.Z`, equal the release being installed, and be newer than the
//   running binary, so a genuine old release replayed as "latest" is refused.
// * **Verify, then run.** Nothing downloaded is executed until the signature
//   and the checksum have passed. `--version` then confirms the build suits this
//   machine (libc flavour) and reports exactly the signed version.
// * **Nothing for anyone else to swap.** The download stays in memory. The files
//   we write are created exclusively (O_EXCL), in a private 0700 directory or
//   beside the target, and a privileged install receives its bytes on a pipe, so
//   root never reads a file an unprivileged process could have changed.
// * **Bounded.** https only; every request has a deadline and a size cap that
//   counts the bytes we actually keep, not only the bytes on the wire.
// * **Never self-update a package-manager install.** If pacman/dpkg owns the
//   binary, updating in place corrupts their file database and gets clobbered
//   on the next system upgrade. We detect this and point at the right command.
// * **Atomic replacement, ETXTBSY-safe.** You cannot open a *running*
//   executable for writing (Linux returns ETXTBSY), so `cp`/`install` would
//   fail. The only safe swap is `rename(2)` over the target — the new binary is
//   written to a temp file *in the same directory* and renamed into place.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use colored::Colorize;
use minisign_verify::{Error as SignatureError, PublicKey, Signature};
use ring::digest;
use serde::Deserialize;

use crate::detect::Privilege;
use crate::utils;

const REPO: &str = "croaky-fx/oxiclean";
const API_LATEST: &str = "https://api.github.com/repos/croaky-fx/oxiclean/releases/latest";

/// The public keys a release must be signed with: the repository's
/// `minisign.pub`, built into the binary. Several keys (the old and the new one
/// during a rotation) are just several `minisign.pub` files pasted together. With
/// no key at all the updater refuses to run, so a build never installs on faith.
const EMBEDDED_KEYS: &str = include_str!("../minisign.pub");

/// Names of the two signed-release assets besides the binaries themselves.
const SUMS_NAME: &str = "SHA256SUMS";
const SIG_NAME: &str = "SHA256SUMS.minisig";

// A response larger than its cap is an error, never a truncated success. The
// caps are generous for what these files are (a release is a few MB), tight
// enough that nothing hostile can fill memory.
const MAX_API_BYTES: u64 = 1 << 20;
const MAX_SUMS_BYTES: u64 = 64 << 10;
const MAX_SIG_BYTES: u64 = 4 << 10;
const MAX_BINARY_BYTES: u64 = 64 << 20;

/// Deadline for a whole request, DNS to last byte. A server that stalls or
/// trickles gets cut off instead of hanging the run forever.
const META_TIMEOUT: Duration = Duration::from_secs(30);
const BINARY_TIMEOUT: Duration = Duration::from_secs(300);
/// How long the downloaded binary gets to answer `--version`.
const CHECK_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Deserialize)]
struct Release {
    tag_name: String,
    body: Option<String>,
}

// ── pure, testable helpers ──────────────────────────

/// Parse `1.4.2` or `v1.4.2` into `(major, minor, patch)`.
fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch = it
        .next()
        .unwrap_or("0")
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or(0);
    Some((major, minor, patch))
}

/// True only if `latest` is strictly newer than `current`.
fn is_newer(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// Map the compile-time target arch to a release-asset token, or `None` for
/// architectures we don't publish prebuilt binaries for.
fn asset_arch() -> Option<&'static str> {
    match std::env::consts::ARCH {
        "x86_64" => Some("x86_64"),
        "aarch64" => Some("aarch64"),
        _ => None,
    }
}

/// Detect libc by looking for the musl loader file — pure `std::fs`, no shell,
/// nothing non-POSIX. Defaults to `gnu` when no musl loader is present.
fn detect_libc() -> &'static str {
    if let Ok(entries) = std::fs::read_dir("/lib") {
        for e in entries.flatten() {
            if let Some(name) = e.file_name().to_str() {
                if name.starts_with("libc.musl-") || name.starts_with("ld-musl-") {
                    return "musl";
                }
            }
        }
    }
    "gnu"
}

/// The first four bytes of every ELF file are `0x7F E L F`.
fn is_elf(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x7f, b'E', b'L', b'F'])
}

/// `MAJOR.MINOR.PATCH` and nothing else: three decimal numbers, no sign, no
/// leading zeros, no suffix. [`parse_version`] is lenient on purpose (it reads
/// our own compiled-in version); this is for text that came off the network and
/// is about to go into a URL and a comparison.
fn strict_version(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split('.').collect();
    let plain = parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.len() <= 9
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        });
    plain.then(|| s.to_string())
}

/// `v1.9.0` or `1.9.0` → `1.9.0`; anything else (a pre-release tag included)
/// is `None`.
fn release_version(tag: &str) -> Option<String> {
    strict_version(tag.strip_prefix('v').unwrap_or(tag))
}

/// The release a signature vouches for. Its trusted comment is exactly
/// `oxiclean X.Y.Z`; anything looser could be a signature made for something
/// else with the same key.
fn signed_version(trusted_comment: &str) -> Option<String> {
    strict_version(trusted_comment.strip_prefix("oxiclean ")?)
}

/// One line of text from the network, safe to print: tabs become spaces and
/// everything in [`utils::is_terminal_hazard`] disappears. Release notes are free text
/// from an API; without this a hostile one could repaint the screen or move the
/// cursor over the prompt that asks for consent.
fn sanitize_line(line: &str) -> String {
    line.chars()
        .map(|c| if c == '\t' { ' ' } else { c })
        .filter(|c| !utils::is_terminal_hazard(*c))
        .collect()
}

/// Remote text squeezed into a short single-line fragment for an error message.
fn printable(s: &str) -> String {
    let clean = sanitize_line(s);
    if clean.chars().count() > 60 {
        format!("{}…", clean.chars().take(60).collect::<String>())
    } else {
        clean
    }
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}

/// 64 lowercase hex digits → the 32 bytes of a SHA-256 digest.
fn hex_to_sha256(s: &str) -> Option<[u8; 32]> {
    let digits = s.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(digits.chunks(2)) {
        *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
    }
    Some(out)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A file name the checksum list may carry: what a release asset is called.
/// No separators, so an entry can never point outside the download directory.
fn is_asset_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 100
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
}

/// One line of `sha256sum` output: 64 lowercase hex digits, then two spaces
/// (text mode) or a space and `*` (binary mode), then the file name.
fn parse_sums_line(line: &str) -> Option<([u8; 32], &str)> {
    let hash = hex_to_sha256(line.get(..64)?)?;
    let rest = line.get(64..)?;
    let name = rest
        .strip_prefix("  ")
        .or_else(|| rest.strip_prefix(" *"))?;
    is_asset_name(name).then_some((hash, name))
}

/// Why a release was not trusted. Each variant is a different way for the
/// signed material to fail, so the tests can insist on the *right* refusal.
#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    /// This build carries no public key to check anything against.
    NoKeys,
    /// The n-th (1-based) built-in key is not a valid minisign public key.
    BadKey(usize),
    /// The signature file is not a minisign signature at all.
    UnreadableSignature,
    /// No built-in key verifies the signature over the checksum list.
    BadSignature(&'static str),
    /// Validly signed, but the signed comment does not name a release.
    UnnamedRelease(String),
    /// Validly signed for one release while another is being offered.
    WrongRelease { signed: String, tag: String },
    /// Validly signed, but not newer than what is installed: a rollback.
    NotNewer { signed: String, current: String },
    /// The signed checksum list is not a well-formed `sha256sum` file.
    BadManifest(String),
    /// The signed checksum list has no entry for this platform's binary.
    NoAsset(String),
    /// The downloaded bytes are not the ones the signed list names.
    HashMismatch,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Refusal::NoKeys => write!(
                f,
                "this build has no release-signing key, so it cannot check a download"
            ),
            Refusal::BadKey(n) => write!(
                f,
                "release-signing key #{n} built into this binary is malformed"
            ),
            Refusal::UnreadableSignature => {
                write!(f, "the release's signature file is not a minisign signature")
            }
            Refusal::BadSignature(why) => {
                write!(f, "the release is not signed by a trusted key ({why})")
            }
            Refusal::UnnamedRelease(comment) => write!(
                f,
                "the signature does not say which release it is for (signed comment: '{comment}')"
            ),
            Refusal::WrongRelease { signed, tag } => write!(
                f,
                "the signature is for {signed}, but the release on offer is {tag}"
            ),
            Refusal::NotNewer { signed, current } => write!(
                f,
                "the signed release {signed} is not newer than the installed {current} (refusing a rollback)"
            ),
            Refusal::BadManifest(why) => write!(f, "the signed checksum list is malformed ({why})"),
            Refusal::NoAsset(name) => {
                write!(f, "the signed checksum list has no entry for {name}")
            }
            Refusal::HashMismatch => {
                write!(f, "the download does not match its signed checksum")
            }
        }
    }
}

/// The key lines of `minisign.pub` text: everything that is neither blank nor
/// an `untrusted comment:` line.
fn keys_in(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .collect()
}

/// A release that passed [`verify_release`]: the version the signature names
/// and the digest the signed list gives for this platform's binary.
#[derive(Debug)]
struct Verified {
    version: String,
    sha256: [u8; 32],
}

/// Decide whether the checksum list `sums` and its signature `sig` may be
/// believed for a release tagged `tag_version`, and read this platform's digest
/// out of it. Everything the network handed us is untrusted until this returns
/// `Ok`, and nothing in `sums` is even parsed before the signature has passed.
///
/// In order: some key verifies the signature (prehashed minisign only); its
/// signed comment names a release; that release is the one being offered; it is
/// newer than `current`; and the list holds exactly one well-formed entry for
/// `asset`. The comment is covered by minisign's global signature, so it cannot
/// be edited without the key.
fn verify_release(
    keys: &[&str],
    current: &str,
    tag_version: &str,
    asset: &str,
    sums: &[u8],
    sig: &[u8],
) -> Result<Verified, Refusal> {
    if keys.is_empty() {
        return Err(Refusal::NoKeys);
    }
    let signature = std::str::from_utf8(sig)
        .ok()
        .and_then(|text| Signature::decode(text).ok())
        .ok_or(Refusal::UnreadableSignature)?;

    let mut why = "it was signed by a key this build does not trust";
    let mut verified = false;
    for (i, encoded) in keys.iter().enumerate() {
        let key = PublicKey::from_base64(encoded).map_err(|_| Refusal::BadKey(i + 1))?;
        match key.verify(sums, &signature, false) {
            Ok(()) => {
                verified = true;
                break;
            }
            // Somebody else's signature: nothing to learn, try the next key.
            Err(SignatureError::UnexpectedKeyId) => {}
            Err(SignatureError::UnexpectedAlgorithm | SignatureError::UnsupportedAlgorithm) => {
                why = "it is not a prehashed minisign signature (sign without -l)"
            }
            Err(_) => why = "the checksum list does not match its signature",
        }
    }
    if !verified {
        return Err(Refusal::BadSignature(why));
    }

    let comment = signature.trusted_comment();
    let signed =
        signed_version(comment).ok_or_else(|| Refusal::UnnamedRelease(printable(comment)))?;
    if signed != tag_version {
        return Err(Refusal::WrongRelease {
            signed,
            tag: tag_version.to_string(),
        });
    }
    if !is_newer(current, &signed) {
        return Err(Refusal::NotNewer {
            signed,
            current: current.to_string(),
        });
    }

    let manifest =
        std::str::from_utf8(sums).map_err(|_| Refusal::BadManifest("not text".to_string()))?;
    Ok(Verified {
        version: signed,
        sha256: find_digest(manifest, asset)?,
    })
}

/// The digest `manifest` gives for `asset`. The whole list has to be well formed
/// (a malformed or duplicated line anywhere is a refusal, not something to skip
/// past) and `asset` has to appear exactly once, by its full name.
fn find_digest(manifest: &str, asset: &str) -> Result<[u8; 32], Refusal> {
    let mut seen = HashSet::new();
    let mut found = None;
    for line in manifest.lines() {
        let (hash, name) = parse_sums_line(line).ok_or_else(|| {
            Refusal::BadManifest(format!("unrecognised line '{}'", printable(line)))
        })?;
        if !seen.insert(name) {
            return Err(Refusal::BadManifest(format!("'{name}' is listed twice")));
        }
        if name == asset {
            found = Some(hash);
        }
    }
    found.ok_or_else(|| Refusal::NoAsset(asset.to_string()))
}

/// Result of asking a package manager whether it owns a path.
enum Ownership {
    /// The package manager owns this file — do not self-update.
    Owned,
    /// The package manager is installed and cleanly reports it does not own it.
    NotOwned,
    /// The tool isn't installed at all — it simply can't own anything here.
    Absent,
    /// The tool is installed but the query errored (locked/corrupt DB,
    /// unexpected exit) — we genuinely can't tell, so fail closed.
    Errored,
}

/// Ask `tool` (with `args`) whether it owns `exe`. `pacman -Qo` and `dpkg -S`
/// both exit 0 when owned and exit 1 when they cleanly don't own the path.
/// An installed tool exiting some other way is `Errored` (fail closed); a tool
/// that isn't installed is `Absent` (it can't be managing this binary).
///
/// Resolved through a trusted system path rather than `$PATH`. This query is a
/// safety gate — a shadowed `pacman` that simply exits 1 would report
/// `NotOwned`, and we would then overwrite a package-manager-owned binary and
/// corrupt its database. A tool we cannot resolve to a trusted location is
/// `Absent`, matching "not installed".
fn query_owner(tool: &str, args: &[&str], exe: &Path) -> Ownership {
    let Some(tool_path) = utils::resolve_trusted(tool) else {
        return Ownership::Absent;
    };
    match Command::new(&tool_path)
        .args(args)
        .arg(exe)
        .env("PATH", utils::trusted_path())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(s) if s.success() => Ownership::Owned,
        Ok(s) if s.code() == Some(1) => Ownership::NotOwned,
        _ => Ownership::Errored,
    }
}

/// If a system package manager owns `exe` — or is installed but its query
/// failed — return the command the user should run instead. `None` means every
/// package manager present cleanly disowned the binary, so self-update is safe.
fn managed_by(exe: &Path) -> Option<String> {
    // Each probe's ownership tool exits 0 when it owns the path and 1 when it
    // cleanly doesn't — the exact contract `query_owner` relies on. We include
    // pacman, dpkg, and rpm because those are the ecosystems oxiclean is (or
    // could realistically be) packaged for. apk and xbps are deliberately
    // *excluded*: their "not owned" exit codes aren't reliably 1 (so a clean
    // miss could be misread as Errored and needlessly block a legitimate
    // self-update), `xbps-query -o` is a pattern/regex search rather than an
    // exact-path lookup, and there is no oxiclean package for either distro to
    // guard against. Add them only once a real package exists and their exit
    // semantics are verified.
    let probes: &[(&str, &[&str], &str)] = &[
        (
            "pacman",
            &["-Qo"],
            "paru -Syu oxiclean   (or: sudo pacman -Syu)",
        ),
        (
            "dpkg",
            &["-S"],
            "sudo apt update && sudo apt install --only-upgrade oxiclean",
        ),
        ("rpm", &["-qf"], "sudo dnf upgrade oxiclean"),
    ];
    for (tool, args, cmd) in probes {
        match query_owner(tool, args, exe) {
            Ownership::Owned => return Some(cmd.to_string()),
            Ownership::Errored => {
                return Some(format!(
                    "your package manager ({tool} query failed — refusing to overwrite a possibly-managed binary)"
                ))
            }
            Ownership::NotOwned | Ownership::Absent => {}
        }
    }
    None
}

// ── networking ──────────────────────────────────────

fn user_agent() -> String {
    format!("oxiclean/{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FetchError {
    /// The server answered 404.
    NotFound,
    /// Anything else: no route, timeout, TLS, another status, too large.
    Failed(String),
}

impl FetchError {
    fn describe(self) -> String {
        match self {
            FetchError::NotFound => "not found (404)".to_string(),
            FetchError::Failed(why) => why,
        }
    }
}

/// Where bytes come from. The real source is [`Http`]; the tests hand in canned
/// answers, so every decision below can be exercised without a network.
trait Fetch {
    /// GET `url`. The body must be at most `limit` bytes — counted after any
    /// decoding, so it is what we would hold in memory — and must arrive
    /// within `within`, or it is an error rather than a partial success.
    fn get(
        &self,
        url: &str,
        accept: &str,
        limit: u64,
        within: Duration,
    ) -> Result<Vec<u8>, FetchError>;
}

struct Http {
    agent: ureq::Agent,
}

impl Http {
    /// The updater itself only ever talks https, so a redirect to plain http
    /// (a downgrade) fails too. The tests are the one caller that passes
    /// `false`, to reach a server on localhost.
    fn new(https_only: bool) -> Http {
        Http::build(https_only, true)
    }

    fn build(https_only: bool, use_env_proxy: bool) -> Http {
        let mut config = ureq::Agent::config_builder()
            .https_only(https_only)
            .max_redirects(5)
            .user_agent(user_agent());
        if !use_env_proxy {
            config = config.proxy(None);
        }
        Http {
            agent: config.build().into(),
        }
    }
}

fn fetch_error(e: ureq::Error) -> FetchError {
    match e {
        ureq::Error::StatusCode(404) => FetchError::NotFound,
        other => FetchError::Failed(other.to_string()),
    }
}

impl Fetch for Http {
    fn get(
        &self,
        url: &str,
        accept: &str,
        limit: u64,
        within: Duration,
    ) -> Result<Vec<u8>, FetchError> {
        let mut response = self
            .agent
            .get(url)
            .header("Accept", accept)
            .config()
            .timeout_global(Some(within))
            .build()
            .call()
            .map_err(fetch_error)?;
        // ureq's own limit counts bytes on the wire, below any content decoder,
        // so on its own it would not stop a small compressed body from
        // inflating without bound. Taking from the decoded reader bounds what we
        // actually keep: at most `limit` bytes are accepted, one more is an error.
        let mut reader = response.body_mut().with_config().limit(limit + 1).reader();
        let mut body = Vec::new();
        reader
            .by_ref()
            .take(limit + 1)
            .read_to_end(&mut body)
            .map_err(|e| FetchError::Failed(e.to_string()))?;
        if body.len() as u64 > limit {
            return Err(FetchError::Failed(format!(
                "the response is larger than the {limit}-byte limit"
            )));
        }
        Ok(body)
    }
}

// ── checking a release ──────────────────────────────

/// Everything needed to install a release that has been fully vetted.
#[derive(Debug)]
struct Plan {
    version: String,
    asset: String,
    url: String,
    sha256: [u8; 32],
    notes: String,
}

#[derive(Debug)]
enum Checked {
    UpToDate,
    Available(Plan),
}

#[derive(Debug, PartialEq, Eq)]
enum UpdateError {
    /// Could not reach or read GitHub.
    Fetch(String),
    /// The latest release carries a tag we cannot read as `X.Y.Z`.
    BadTag(String),
    /// The release has no checksum list or signature at all.
    Unsigned,
    /// The signed material did not pass.
    Refused(Refusal),
    /// The release has no binary for this platform.
    Missing(String),
    /// The bytes match their checksum but are not an executable.
    NotABinary,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpdateError::Fetch(why) => write!(f, "{why}"),
            UpdateError::BadTag(tag) => write!(
                f,
                "the latest release is tagged '{tag}', which is not a plain X.Y.Z version"
            ),
            UpdateError::Unsigned => write!(
                f,
                "the release has no signed checksum list ({SUMS_NAME} with {SIG_NAME}), so it cannot be trusted"
            ),
            UpdateError::Refused(why) => write!(f, "{why}"),
            UpdateError::Missing(asset) => write!(f, "the release has no {asset} binary"),
            UpdateError::NotABinary => write!(f, "the downloaded file is not a Linux binary"),
        }
    }
}

/// Ask GitHub for the latest release and, if it is newer than `current`,
/// fetch its checksum list and signature and vet them for `asset`.
///
/// The tag in the API answer is not trusted: it only decides what to *ask* for,
/// and the signature has to name the same release (see [`verify_release`]).
fn check(
    net: &dyn Fetch,
    keys: &[&str],
    current: &str,
    asset: &str,
    api: &str,
    download_base: &str,
) -> Result<Checked, UpdateError> {
    let answer = net
        .get(
            api,
            "application/vnd.github+json",
            MAX_API_BYTES,
            META_TIMEOUT,
        )
        .map_err(|e| UpdateError::Fetch(e.describe()))?;
    let release: Release = serde_json::from_slice(&answer)
        .map_err(|e| UpdateError::Fetch(format!("unexpected answer from GitHub: {e}")))?;
    let version = release_version(&release.tag_name)
        .ok_or_else(|| UpdateError::BadTag(printable(&release.tag_name)))?;
    if !is_newer(current, &version) {
        return Ok(Checked::UpToDate);
    }

    // The tag has just been checked to be digits and dots, so it is safe in a URL.
    let base = format!("{download_base}/{}", release.tag_name);
    let signed_part = |name: &str, limit: u64| {
        net.get(
            &format!("{base}/{name}"),
            "application/octet-stream",
            limit,
            META_TIMEOUT,
        )
        .map_err(|e| match e {
            FetchError::NotFound => UpdateError::Unsigned,
            FetchError::Failed(why) => UpdateError::Fetch(why),
        })
    };
    let sums = signed_part(SUMS_NAME, MAX_SUMS_BYTES)?;
    let sig = signed_part(SIG_NAME, MAX_SIG_BYTES)?;
    let verified = verify_release(keys, current, &version, asset, &sums, &sig)
        .map_err(UpdateError::Refused)?;

    Ok(Checked::Available(Plan {
        version: verified.version,
        asset: asset.to_string(),
        url: format!("{base}/{asset}"),
        sha256: verified.sha256,
        notes: release.body.unwrap_or_default(),
    }))
}

/// Download the binary a vetted [`Plan`] names and hold it to the signed digest.
/// What comes back is in memory only, and is exactly the bytes that were signed.
fn acquire(net: &dyn Fetch, plan: &Plan) -> Result<Vec<u8>, UpdateError> {
    let bytes = net
        .get(
            &plan.url,
            "application/octet-stream",
            MAX_BINARY_BYTES,
            BINARY_TIMEOUT,
        )
        .map_err(|e| match e {
            FetchError::NotFound => UpdateError::Missing(plan.asset.clone()),
            FetchError::Failed(why) => UpdateError::Fetch(why),
        })?;
    if digest::digest(&digest::SHA256, &bytes).as_ref() != plan.sha256.as_slice() {
        return Err(UpdateError::Refused(Refusal::HashMismatch));
    }
    if !is_elf(&bytes) {
        return Err(UpdateError::NotABinary);
    }
    Ok(bytes)
}

// ── staging and install ─────────────────────────────

/// A name nobody else can have picked ahead of us: our pid and 64 random bits
/// (`RandomState` is seeded by the OS). Creation is exclusive anyway, so this
/// only keeps a squatter from making the run fail.
fn unique_name(prefix: &str) -> String {
    use std::hash::{BuildHasher, Hasher};
    let random = std::collections::hash_map::RandomState::new()
        .build_hasher()
        .finish();
    format!("{prefix}.{}.{random:016x}", std::process::id())
}

/// Create `path` holding `bytes`, owner-only, failing if anything — a file or a
/// symlink, dangling or not — is already there (`O_EXCL` never follows a link).
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(path)?;
    if let Err(e) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(e);
    }
    Ok(())
}

/// A fresh directory only we can enter, under the temp dir.
fn private_dir() -> io::Result<PathBuf> {
    let base = std::env::temp_dir();
    for _ in 0..16 {
        let dir = base.join(unique_name("oxiclean-update"));
        match fs::DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not find an unused name for a private directory",
    ))
}

/// A file this process wrote to disk, deleted again on drop unless it was
/// moved into place.
struct Staged {
    path: PathBuf,
    /// The private directory made for it, if any.
    dir: Option<PathBuf>,
    keep: bool,
}

impl Staged {
    /// Write `bytes` next to the file they will replace, so that the final
    /// `rename(2)` stays on one filesystem and is atomic.
    fn beside(dir: &Path, bytes: &[u8]) -> io::Result<Staged> {
        let path = dir.join(format!(".{}", unique_name("oxiclean.new")));
        write_new(&path, bytes)?;
        Ok(Staged {
            path,
            dir: None,
            keep: false,
        })
    }

    /// Write `bytes` into a private directory, for a destination we cannot write
    /// to ourselves: there the file is only run once as a check, and root gets
    /// the bytes by another route.
    fn private(bytes: &[u8]) -> io::Result<Staged> {
        let dir = private_dir()?;
        let path = dir.join("oxiclean");
        if let Err(e) = write_new(&path, bytes) {
            let _ = fs::remove_dir(&dir);
            return Err(e);
        }
        Ok(Staged {
            path,
            dir: Some(dir),
            keep: false,
        })
    }

    /// Make it executable and `rename(2)` it over `target`.
    fn persist(mut self, target: &Path) -> io::Result<()> {
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755))?;
        fs::rename(&self.path, target)?;
        self.keep = true;
        Ok(())
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
        if let Some(dir) = &self.dir {
            let _ = fs::remove_dir(dir);
        }
    }
}

/// Run `binary args…` and require it to print exactly `expected`.
///
/// The child gets an empty environment but for the trusted `PATH`, no stdin,
/// and `within` to finish; past that it is killed. Only ever called on bytes
/// that already passed the signature and checksum.
fn self_check(
    binary: &Path,
    args: &[&str],
    expected: &str,
    within: Duration,
) -> Result<(), String> {
    let mut child = Command::new(binary)
        .args(args)
        .env_clear()
        .env("PATH", utils::trusted_path())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| match e.kind() {
            io::ErrorKind::PermissionDenied => format!(
                "it could not be run ({e}); is its directory mounted noexec? Point TMPDIR at another one"
            ),
            _ => format!("it could not be run ({e})"),
        })?;
    // What it prints is read on a thread of its own. Waiting for the child to
    // exit and only then reading would let a descendant that outlives it, still
    // holding the pipe open, keep us here for as long as it likes.
    let Some(stdout) = child.stdout.take() else {
        return Err("its output could not be captured".to_string());
    };
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut answer = Vec::new();
        let _ = stdout.take(4096).read_to_end(&mut answer);
        let _ = send.send(answer);
    });
    let deadline = Instant::now() + within;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("it did not answer within {within:?}"));
            }
            Err(e) => return Err(format!("it could not be waited for ({e})")),
        }
    };
    if !status.success() {
        return Err(format!("it exited with {status}"));
    }
    // Once it has exited its output ends, unless something it started still
    // holds the pipe: that is not a version banner either.
    let Ok(answer) = receive.recv_timeout(Duration::from_secs(1)) else {
        return Err("its output did not end when it did".to_string());
    };
    let answer = String::from_utf8_lossy(&answer);
    let answer = answer.trim();
    if answer != expected {
        return Err(format!(
            "it reports '{}' instead of '{expected}'",
            printable(answer)
        ));
    }
    Ok(())
}

/// How a step of the install ends: `Err` holds what to tell the person.
type Outcome = Result<(), String>;

/// Replace `target` with `bytes`.
///
/// Where we may write beside the target, the bytes are staged there, passed
/// through `check`, and `rename`d into place: atomic, and what was checked is
/// what is installed. Where we may not, they are staged privately for `check`,
/// and `privileged` installs them. Either way the one thing `check` and the
/// installer see is the same in-memory buffer.
fn install(
    bytes: &[u8],
    target: &Path,
    check: &dyn Fn(&Path) -> Outcome,
    privileged: &dyn Fn(&[u8], &Path) -> Outcome,
) -> Outcome {
    let dir = target.parent().unwrap_or_else(|| Path::new("/"));
    match Staged::beside(dir, bytes) {
        Ok(staged) => {
            check(&staged.path)?;
            staged
                .persist(target)
                .map_err(|e| format!("could not replace {}: {e}", target.display()))
        }
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
            let staged =
                Staged::private(bytes).map_err(|e| format!("could not stage the download: {e}"))?;
            check(&staged.path)?;
            privileged(bytes, target)
        }
        Err(e) => Err(format!("cannot write next to {}: {e}", target.display())),
    }
}

/// What root runs to install `$1`, handed its directory `$2` and the number of
/// bytes `$3` to expect, with the binary itself on stdin.
///
/// The paths arrive as positional parameters, never spliced into the script, so
/// no file name can become code. The temp file is made by `mktemp` (exclusive,
/// random, inside the target's own directory, which is not ours to write), and
/// the length check refuses a short read, so an interrupted transfer can never
/// be renamed into place as a truncated binary.
const PRIVILEGED_INSTALL: &str = r#"set -eu
umask 077
dst=$1
dir=$2
want=$3
tmp=$(mktemp "$dir/.oxiclean.new.XXXXXX")
trap 'rm -f "$tmp"' EXIT
cat > "$tmp"
got=$(wc -c < "$tmp" | tr -d ' ')
[ "$got" = "$want" ] || { echo "oxiclean-install: received $got of $want bytes" >&2; exit 1; }
chmod 755 "$tmp"
mv -f "$tmp" "$dst"
"#;

/// The arguments `sh` is run with to carry out [`PRIVILEGED_INSTALL`].
fn install_script_args<'a>(dst: &'a str, dir: &'a str, length: &'a str) -> [&'a str; 6] {
    [
        "-c",
        PRIVILEGED_INSTALL,
        "oxiclean-install",
        dst,
        dir,
        length,
    ]
}

/// Install `bytes` over `target` as root, through sudo or doas.
fn privileged_install(bytes: &[u8], target: &Path) -> Result<(), String> {
    let (Some(dst), Some(dir)) = (target.to_str(), target.parent().and_then(Path::to_str)) else {
        return Err("the install path is not valid UTF-8".to_string());
    };
    let privilege = crate::detect::find_privilege();
    if matches!(privilege, Privilege::None) {
        return Err(format!(
            "{dir} needs root and neither sudo nor doas is available"
        ));
    }
    let length = bytes.len().to_string();
    let args = install_script_args(dst, dir, &length);
    if utils::elevate_with_input(privilege, "sh", &args, bytes) {
        Ok(())
    } else {
        Err(format!(
            "{dir} is not writable by you, and installing there as root did not succeed"
        ))
    }
}

// ── entry point ─────────────────────────────────────

fn download_base() -> String {
    format!("https://github.com/{REPO}/releases/download")
}

/// A failure phrased for the person at the terminal. Trouble reaching GitHub
/// says what was being attempted; everything else is a decision not to proceed.
fn explain(e: &UpdateError, doing: &str) -> String {
    match e {
        UpdateError::Fetch(why) => format!("{doing} ({why})"),
        other => format!("not updating: {other}"),
    }
}

/// Run the `--update` flow. Returns a process exit code.
pub fn run(yes: bool) -> i32 {
    let current = env!("CARGO_PKG_VERSION");

    let exe = match std::env::current_exe().and_then(|p| p.canonicalize()) {
        Ok(p) => p,
        Err(e) => {
            utils::error(&format!("cannot locate own binary: {e}"));
            return 1;
        }
    };

    if let Some(cmd) = managed_by(&exe) {
        utils::section("Update");
        utils::info(&format!(
            "Installed by a package manager ({})",
            exe.display()
        ));
        utils::info(&format!("Update it with:  {}", cmd.bold()));
        return 0;
    }

    utils::section("Update");
    let keys = keys_in(EMBEDDED_KEYS);
    if keys.is_empty() {
        utils::error(&format!("not updating: {}", Refusal::NoKeys));
        utils::info(&format!(
            "Install the latest release by hand from https://github.com/{REPO}/releases, or build from source"
        ));
        return 1;
    }
    let Some(arch) = asset_arch() else {
        utils::error(&format!(
            "no prebuilt binary for {} — build from source: cargo install --git https://github.com/{REPO}",
            std::env::consts::ARCH
        ));
        return 1;
    };
    let asset = format!("oxiclean-{arch}-linux-{}", detect_libc());

    let net = Http::new(true);
    let plan = match check(&net, &keys, current, &asset, API_LATEST, &download_base()) {
        Ok(Checked::UpToDate) => {
            utils::success(&format!("You're on the latest version ({current})"));
            return 0;
        }
        Ok(Checked::Available(plan)) => plan,
        Err(e) => {
            utils::error(&explain(&e, "couldn't check for updates"));
            return 1;
        }
    };
    utils::success("Release signature verified");

    utils::plain(&format!(
        "  {} {} {} {}",
        "Update available:".bold(),
        current.yellow(),
        "→".dimmed(),
        plan.version.green().bold()
    ));
    let notes = plan.notes.trim();
    if !notes.is_empty() && !utils::is_quiet() {
        utils::plain("");
        utils::plain(&format!(
            "  {}",
            "Release notes, as published on GitHub (not covered by the signature):".dimmed()
        ));
        for line in notes.lines() {
            utils::plain(&format!("  {}", sanitize_line(line)));
        }
        utils::plain("");
    }

    if !yes && !utils::confirm(&format!("Upgrade to {}? [y/N]:", plan.version)) {
        utils::info("Update cancelled");
        return 0;
    }

    utils::info(&format!("Downloading {}...", plan.asset));
    let bytes = match acquire(&net, &plan) {
        Ok(bytes) => bytes,
        Err(e) => {
            utils::error(&explain(&e, "download failed"));
            return 1;
        }
    };
    utils::success(&format!(
        "Checksum matches the signed list ({}…)",
        &to_hex(&plan.sha256)[..12]
    ));

    let expected = format!("oxiclean {}", plan.version);
    let self_check_it = |path: &Path| {
        self_check(path, &["--version"], &expected, CHECK_TIMEOUT)
            .map_err(|why| {
                format!("the downloaded binary failed its self-check: {why} — libc mismatch?")
            })
            .map(|()| utils::success(&format!("Self-check passed ({expected})")))
    };
    utils::info(&format!("Installing to {}...", exe.display()));
    if let Err(e) = install(&bytes, &exe, &self_check_it, &privileged_install) {
        utils::error(&format!("install failed ({e})"));
        return 1;
    }

    utils::success(&format!("Updated {current} → {}", plan.version));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_version() {
        assert_eq!(parse_version("1.4.2"), Some((1, 4, 2)));
        assert_eq!(parse_version("v1.4.2"), Some((1, 4, 2)));
        assert_eq!(parse_version(" 1.4.2 "), Some((1, 4, 2)));
        assert_eq!(parse_version("1.4"), Some((1, 4, 0)));
        assert_eq!(parse_version("2.0.0"), Some((2, 0, 0)));
        assert_eq!(parse_version("garbage"), None);
        assert_eq!(parse_version(""), None);
    }

    #[test]
    fn test_is_newer() {
        assert!(is_newer("1.4.1", "1.4.2"));
        assert!(is_newer("1.4.2", "1.5.0"));
        assert!(is_newer("1.9.9", "2.0.0"));
        assert!(!is_newer("1.4.2", "1.4.2"));
        assert!(!is_newer("1.4.2", "1.4.1"));
        assert!(!is_newer("2.0.0", "1.9.9"));
        // Unparseable input must never claim an update is available.
        assert!(!is_newer("1.4.2", "garbage"));
    }

    #[test]
    fn test_asset_arch_is_supported_on_this_host() {
        // CI and dev machines are x86_64 or aarch64 — both must map.
        assert!(asset_arch().is_some());
    }

    #[test]
    fn test_detect_libc_is_stable() {
        let a = detect_libc();
        assert!(a == "musl" || a == "gnu");
        assert_eq!(a, detect_libc());
    }

    #[test]
    fn test_query_owner_absent_tool() {
        // A tool that isn't installed can't own anything — Absent, so
        // managed_by skips it rather than blocking self-update.
        let r = query_owner(
            "definitely-not-a-real-pm-xyz",
            &["-Qo"],
            Path::new("/bin/sh"),
        );
        assert!(matches!(r, Ownership::Absent));
    }

    #[test]
    fn test_query_owner_clean_not_owned() {
        // `false` exits 1 for any args — stands in for a package manager
        // cleanly reporting "no package owns this". Must be NotOwned, not
        // Errored, so a genuinely-unmanaged binary can still self-update.
        if utils::which("false") {
            let r = query_owner("false", &[], Path::new("/tmp/whatever"));
            assert!(matches!(r, Ownership::NotOwned));
        }
    }

    #[test]
    fn test_query_owner_unexpected_exit_is_errored() {
        // An installed tool exiting with neither 0 (owned) nor 1 (cleanly
        // not-owned) must be Errored, so managed_by fails closed.
        if utils::which("sh") {
            let r = query_owner("sh", &["-c", "exit 2 #"], Path::new("/tmp/x"));
            assert!(matches!(r, Ownership::Errored));
        }
    }

    // ── fixtures ────────────────────────────────────
    //
    // Made with the real minisign 0.12 and two throwaway key pairs whose secret
    // halves were thrown away; nothing here is the project's signing key. The
    // recipe, so they can be remade:
    //
    //   minisign -G -W -p k1.pub -s k1.key        (and k2 the same way)
    //   minisign -S -s k1.key -m SHA256SUMS -x ok.minisig -t "oxiclean 9.9.9"
    //
    // plus the variants named below (-s k2.key; -t "oxiclean 1.0.0"; no -t;
    // -l for the legacy format; -t "someotherthing 9.9.9").

    const KEY_1: &str = "RWRJ3l7OuTBzObL1FJNJU+DHlwUL2qvlR9KRuplfrCo3thbGI8KauTW2";
    const KEY_2: &str = "RWRrVhhG9nDJAc1h9tl9EqX1gC4MpsqySajOInrQRN9xD8vmLf0bpcS3";

    /// The bytes the x86_64 entries of `SUMS` stand for.
    const PAYLOAD: &[u8] = b"\x7fELF-oxiclean-fixture-binary-9.9.9";

    /// A signed list for 9.9.9: two aarch64 entries (one digest), two x86_64 (the payload).
    const SUMS: &str = "f8864f1d39b0aef79d4fa8611af4d99f9d7146cfbb7241b90aa9bb9544adc7ef  oxiclean-aarch64-linux-gnu\n\
f8864f1d39b0aef79d4fa8611af4d99f9d7146cfbb7241b90aa9bb9544adc7ef  oxiclean-aarch64-linux-musl\n\
ad29a1323e5b75761ac1779d8d84838bac97d62dca445ebc1fd659c96a28729f  oxiclean-x86_64-linux-gnu\n\
ad29a1323e5b75761ac1779d8d84838bac97d62dca445ebc1fd659c96a28729f  oxiclean-x86_64-linux-musl\n";

    /// Key 1, signed comment `oxiclean 9.9.9`.
    const SIG_OK: &str = "untrusted comment: signature from minisign secret key\n\
RURJ3l7OuTBzOZEJX2dQqL3tOW8dlvj7ABfdS2Rkjip9h8j2RhTiez0AOAS6xh0kgSlLoHs+rCmjPRaewwL4tUYB4RTACo1AoA8=\n\
trusted comment: oxiclean 9.9.9\n\
c3QmPyPpSScn9inp6wzfel+vxD+ohvXF8OlesSe3UOOXJMxHcI1Xp+/xUlnVGyHKJqlTl0iLMUWG+tMtnTNwAA==\n";

    /// Key 1, over the same list, but for the old release `oxiclean 1.0.0`.
    const SIG_OLD: &str = "untrusted comment: signature from minisign secret key\n\
RURJ3l7OuTBzOSIE/2dg99ZoEgdFgsEMLKRMkW17FWaiheyu9DAMXQyV7nmOPXNmJ9EUIFyLjzRRIb/u/m26/gZUb0gWw8gVEww=\n\
trusted comment: oxiclean 1.0.0\n\
ir3yLjP5Suyf3BLBisTfb7s+JO6ONQ8Jq4LRcf9/1qAcbFcscqMurZWw4Aw8H6P19N+nQHd4hu94D3t74P05BA==\n";

    /// Key 2, signed comment `oxiclean 9.9.9`.
    const SIG_WRONG_KEY: &str = "untrusted comment: signature from minisign secret key\n\
RURrVhhG9nDJAdmDaQvvPIDy87rN8i3+wqM5qiw7DkU5FcHc569ub9ySAnS2NsZTnWSqtMRqmySbBR/0C2LMiCZrfTpSkQk3ggQ=\n\
trusted comment: oxiclean 9.9.9\n\
rkWa0BrjEkfyn92bLL8088WOM1JEyxCVwar2PrlL0StPhf64t1ptCjkd4k2hHd/tn63ZWUR+6lO/Wj4Zv1miAQ==\n";

    /// Key 1, minisign's default comment (timestamp and file name), no release named.
    const SIG_NO_VERSION: &str = "untrusted comment: signature from minisign secret key\n\
RURJ3l7OuTBzOXpNTj9W6SfuwwNAUXP+NYwzu8ZTZHUHvNZNV3gR9vhC6lKRjSDvwhB5C0rxGxGeE5qXsedlKzvmJ6OPbVgxdQg=\n\
trusted comment: timestamp:1791325421\tfile:SHA256SUMS\thashed\n\
AoCesbMSiThs4fQu8ZmdeX/aW0gc6U7xKSaXbS4E0vtiswnNw7UzyyMMH52fkbbHbnz/Utj8ndswPvsEAouADA==\n";

    /// Key 1, `minisign -l`, signed comment `oxiclean 9.9.9`.
    const SIG_LEGACY: &str = "untrusted comment: signature from minisign secret key\n\
RWRJ3l7OuTBzOYMYCQkc0gb4l8S92eSRPZNpKkWPpqUe0paEtb2WulvjyGJzDWhhXssNE2D/gaafVjOurQ8f997v/8+rRPIDigs=\n\
trusted comment: oxiclean 9.9.9\n\
vgdgFaE6aTUaD8557FibrNE9ncz5lw3AcafhrC8iWzOgsF8xEMt0DCDo2JJc0w8EMN5cFxMhD4CSEdnPDu6ADQ==\n";

    /// Key 1, signed comment `someotherthing 9.9.9`.
    const SIG_OTHER_PRODUCT: &str = "untrusted comment: signature from minisign secret key\n\
RURJ3l7OuTBzOYe2gU568gs3Z2mbiG3MAYVHos4xoiQ+gCcBk4mlPDTebl11djcAB2/TZTPv400YRQ/bbPkR3DfK3ekODA9MGAU=\n\
trusted comment: someotherthing 9.9.9\n\
QWB3lB28Rlqbw8YxEaH8xtlW2WEE6Z+KYzefvA3vlrrZwVuc1l4hUsI8GtC1krZdGHOIXZFzbIyUgWBV8c3pCQ==\n";

    /// 64 KiB of zeros, gzipped: 96 bytes on the wire.
    const GZIP_BOMB: &[u8] = &[
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xed, 0xc1, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x80, 0x90, 0xfe, 0xaf, 0xee, 0x08, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x6a, 0xeb, 0x8e,
        0x97, 0xd7, 0x00, 0x00, 0x01, 0x00,
    ];

    const ASSET: &str = "oxiclean-x86_64-linux-gnu";
    const PAYLOAD_SHA256: &str = "ad29a1323e5b75761ac1779d8d84838bac97d62dca445ebc1fd659c96a28729f";
    const AARCH64_SHA256: &str = "f8864f1d39b0aef79d4fa8611af4d99f9d7146cfbb7241b90aa9bb9544adc7ef";

    // ── versions and text from the network ──────────

    #[test]
    fn test_strict_version_accepts_only_plain_triples() {
        for ok in ["0.0.0", "1.9.0", "10.20.30", "123456789.0.1"] {
            assert_eq!(strict_version(ok).as_deref(), Some(ok), "{ok}");
        }
        for bad in [
            "",
            "1",
            "1.9",
            "1.9.0.1",
            "v1.9.0",
            "1.9.0-rc1",
            "1.9.0+build",
            "01.9.0",
            "1.09.0",
            "1.9.00",
            "1.9.",
            ".1.9",
            "1..9",
            " 1.9.0",
            "1.9.0 ",
            "1.9.0\n",
            "+1.9.0",
            "-1.9.0",
            "1.9.x",
            "1234567890.0.0",
            "１.９.０",
            "1.9.0\u{1b}[2J",
        ] {
            assert_eq!(strict_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn test_release_version_drops_one_leading_v_and_nothing_more() {
        assert_eq!(release_version("v1.9.0").as_deref(), Some("1.9.0"));
        assert_eq!(release_version("1.9.0").as_deref(), Some("1.9.0"));
        for bad in [
            "vv1.9.0",
            "V1.9.0",
            "v",
            "",
            "latest",
            "v1.9",
            "release-1.9.0",
            "v1.9.0-rc1",
        ] {
            assert_eq!(release_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn test_a_signature_names_a_release_only_as_oxiclean_x_y_z() {
        assert_eq!(signed_version("oxiclean 9.9.9").as_deref(), Some("9.9.9"));
        for bad in [
            "",
            "oxiclean",
            "oxiclean ",
            "oxiclean  9.9.9",
            "oxiclean v9.9.9",
            "oxiclean 9.9.9 ",
            "oxiclean 9.9",
            "Oxiclean 9.9.9",
            "someotherthing 9.9.9",
            "9.9.9",
            "timestamp:1791325421\tfile:SHA256SUMS\thashed",
            "oxiclean 9.9.9\toxiclean 1.0.0",
        ] {
            assert_eq!(signed_version(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn test_release_notes_cannot_drive_the_terminal() {
        // ESC [ 2 J clears the screen; ESC ] 0 ; … BEL retitles the window; a
        // carriage return rewinds the line over the prompt; NUL, BEL and DEL
        // are controls too.
        assert_eq!(sanitize_line("a\u{1b}[2Jb"), "a[2Jb");
        assert_eq!(sanitize_line("x\u{1b}]0;pwned\u{7}y"), "x]0;pwnedy");
        assert_eq!(sanitize_line("safe\rEVIL"), "safeEVIL");
        assert_eq!(sanitize_line("a\u{0}b\u{7}c\u{7f}d"), "abcd");
        // The one-byte CSI of the C1 range does what ESC [ does.
        assert_eq!(sanitize_line("a\u{9b}31mb"), "a31mb");
        // Bidirectional overrides and isolates make text display as other text.
        assert_eq!(sanitize_line("a\u{202e}b\u{2066}c\u{2069}d"), "abcd");
        assert_eq!(
            sanitize_line("a\u{2028}b\u{2029}c\u{feff}d\u{200e}e\u{200f}f\u{61c}g"),
            "abcdefg"
        );
        // Tabs become spaces. Ordinary text survives: accents, CJK, symbols,
        // and an emoji joined with ZWJ.
        assert_eq!(sanitize_line("a\tb"), "a b");
        let fine = "Zürich 日本語 ✔ 👨\u{200d}👩\u{200d}👧 → done";
        assert_eq!(sanitize_line(fine), fine);
    }

    #[test]
    fn test_printable_fits_inside_an_error_message() {
        assert_eq!(printable("v1.9.0"), "v1.9.0");
        assert_eq!(printable("a\nb\u{1b}[31mc"), "ab[31mc");
        assert_eq!(printable(&"y".repeat(60)), "y".repeat(60));
        let shortened = printable(&"x".repeat(200));
        assert_eq!(
            shortened.chars().count(),
            61,
            "60 characters and an ellipsis"
        );
        assert!(shortened.ends_with('…'));
    }

    #[test]
    fn test_digests_round_trip_through_hex_and_nothing_else_parses() {
        let bytes = hex_to_sha256(PAYLOAD_SHA256).unwrap();
        assert_eq!((bytes[0], bytes[31]), (0xad, 0x9f));
        assert_eq!(to_hex(&bytes), PAYLOAD_SHA256);
        assert_eq!(hex_to_sha256(&PAYLOAD_SHA256.to_uppercase()), None);
        assert_eq!(hex_to_sha256(&PAYLOAD_SHA256[..62]), None);
        assert_eq!(hex_to_sha256(&format!("{PAYLOAD_SHA256}0")), None);
        assert_eq!(hex_to_sha256(&format!("{}g", &PAYLOAD_SHA256[..63])), None);
        assert_eq!(hex_to_sha256(&format!(" {}", &PAYLOAD_SHA256[..63])), None);
        assert_eq!(hex_to_sha256(""), None);
    }

    // ── the checksum list ───────────────────────────

    #[test]
    fn test_checksum_lines_are_read_strictly() {
        let h = PAYLOAD_SHA256;
        let text_mode = format!("{h}  {ASSET}");
        assert_eq!(parse_sums_line(&text_mode).map(|(_, n)| n), Some(ASSET));
        let binary_mode = format!("{h} *{ASSET}");
        assert_eq!(parse_sums_line(&binary_mode).map(|(_, n)| n), Some(ASSET));
        // A file name is at most 100 characters.
        let longest = "a".repeat(100);
        let line = format!("{h}  {longest}");
        assert_eq!(
            parse_sums_line(&line).map(|(_, n)| n),
            Some(longest.as_str())
        );
        let line = format!("{h}  {}", "a".repeat(101));
        assert!(parse_sums_line(&line).is_none());
        for bad in [
            format!("{h} oxiclean"),
            format!("{h}\toxiclean"),
            format!("{h}   oxiclean"),
            format!("{h}  "),
            format!("{h}  ../oxiclean"),
            format!("{h}  dir/oxiclean"),
            format!("{h}  oxi clean"),
            format!("{h}  oxiclean "),
            format!("{h}  oxiclean\u{1b}"),
            format!("{h}  oxicläan"),
            format!("{}  oxiclean", h.to_uppercase()),
            format!("{}  oxiclean", &h[..63]),
            String::new(),
            "not a checksum line".to_string(),
        ] {
            assert!(parse_sums_line(&bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn test_the_digest_comes_from_the_entry_with_exactly_that_name() {
        let hex = |name| to_hex(&find_digest(SUMS, name).unwrap());
        assert_eq!(hex("oxiclean-x86_64-linux-gnu"), PAYLOAD_SHA256);
        assert_eq!(hex("oxiclean-x86_64-linux-musl"), PAYLOAD_SHA256);
        assert_eq!(hex("oxiclean-aarch64-linux-gnu"), AARCH64_SHA256);
        // A prefix of an entry, or an entry for another platform, is not a match.
        for missing in [
            "oxiclean-x86_64-linux",
            "oxiclean-x86_64-linux-gnu2",
            "oxiclean-riscv64-linux-gnu",
            "",
        ] {
            assert_eq!(
                find_digest(SUMS, missing),
                Err(Refusal::NoAsset(missing.to_string())),
                "{missing:?}"
            );
        }
        assert_eq!(
            find_digest("", ASSET),
            Err(Refusal::NoAsset(ASSET.to_string()))
        );
    }

    #[test]
    fn test_a_malformed_checksum_list_is_refused_wherever_the_fault_is() {
        let good = format!("{PAYLOAD_SHA256}  {ASSET}");
        let other = format!("{AARCH64_SHA256}  oxiclean-aarch64-linux-gnu");
        // The same name twice is ambiguous, even with the same digest.
        for list in [
            format!("{good}\n{good}\n"),
            format!("{good}\n{AARCH64_SHA256}  {ASSET}\n"),
            format!("{other}\n{other}\n{good}\n"),
        ] {
            assert!(
                matches!(find_digest(&list, ASSET), Err(Refusal::BadManifest(why)) if why.contains("twice")),
                "{list:?}"
            );
        }
        // A line that is not a checksum entry spoils the list, before or after
        // the entry that was asked for, and a blank line counts as one.
        for list in [
            format!("garbage\n{good}\n"),
            format!("{good}\ngarbage\n"),
            format!("{good}\n\n{other}\n"),
            format!("{good}\n{PAYLOAD_SHA256}  ../escape\n"),
        ] {
            assert!(
                matches!(find_digest(&list, ASSET), Err(Refusal::BadManifest(why)) if why.contains("unrecognised")),
                "{list:?}"
            );
        }
        // Line ends and a missing final newline are not faults.
        for list in [
            format!("{good}\r\n{other}\r\n"),
            format!("{good}\n{other}"),
            good.clone(),
        ] {
            assert_eq!(
                to_hex(&find_digest(&list, ASSET).unwrap()),
                PAYLOAD_SHA256,
                "{list:?}"
            );
        }
    }

    // ── keys ────────────────────────────────────────

    #[test]
    fn test_the_fixtures_agree_with_themselves() {
        let digest = digest::digest(&digest::SHA256, PAYLOAD);
        assert_eq!(to_hex(digest.as_ref()), PAYLOAD_SHA256);
        assert!(SUMS.contains(&format!("{PAYLOAD_SHA256}  {ASSET}\n")));
        assert!(is_elf(PAYLOAD));
    }

    #[test]
    fn test_keys_are_read_from_minisign_pub_text() {
        assert!(keys_in("").is_empty());
        assert!(keys_in("untrusted comment: no key yet\n").is_empty());
        let one = format!("untrusted comment: minisign public key 397330B9CE5EDE49\n{KEY_1}\n");
        assert_eq!(keys_in(&one), vec![KEY_1]);
        // A rotation is two key files pasted together; blank lines and CRLF
        // line ends do not matter.
        let two = format!(
            "untrusted comment: old\r\n{KEY_1}\r\n\r\nuntrusted comment: new\r\n{KEY_2}\r\n"
        );
        assert_eq!(keys_in(&two), vec![KEY_1, KEY_2]);
    }

    #[test]
    fn test_the_built_in_keys_are_well_formed() {
        // The day a key goes into minisign.pub, this keeps a typo from shipping
        // a build that refuses every update.
        for (i, key) in keys_in(EMBEDDED_KEYS).iter().enumerate() {
            assert!(
                PublicKey::from_base64(key).is_ok(),
                "key #{} in minisign.pub is not a minisign public key",
                i + 1
            );
        }
    }

    #[test]
    #[ignore = "run by the release workflow: a release has to be able to update itself"]
    fn release_builds_must_ship_an_update_key() {
        assert!(
            !keys_in(EMBEDDED_KEYS).is_empty(),
            "minisign.pub holds no key: a binary built from this tree could never \
             verify an update. Generate the signing key first (see RELEASING.md)."
        );
    }

    // ── verifying a signed release ──────────────────

    fn verify(sig: &str) -> Result<Verified, Refusal> {
        verify_release(
            &[KEY_1],
            "1.8.0",
            "9.9.9",
            ASSET,
            SUMS.as_bytes(),
            sig.as_bytes(),
        )
    }

    #[test]
    fn test_a_genuine_signed_release_is_accepted() {
        let verified = verify(SIG_OK).unwrap();
        assert_eq!(verified.version, "9.9.9");
        assert_eq!(to_hex(&verified.sha256), PAYLOAD_SHA256);
        // Another platform gets its own digest out of the same list.
        let other = verify_release(
            &[KEY_1],
            "1.8.0",
            "9.9.9",
            "oxiclean-aarch64-linux-gnu",
            SUMS.as_bytes(),
            SIG_OK.as_bytes(),
        )
        .unwrap();
        assert_eq!(to_hex(&other.sha256), AARCH64_SHA256);
    }

    #[test]
    fn test_a_signature_from_another_key_is_refused() {
        let r = verify(SIG_WRONG_KEY);
        assert!(
            matches!(&r, Err(Refusal::BadSignature(why)) if why.contains("does not trust")),
            "{r:?}"
        );
    }

    #[test]
    fn test_an_edited_checksum_list_is_refused() {
        let signed = |list: &str| {
            verify_release(
                &[KEY_1],
                "1.8.0",
                "9.9.9",
                ASSET,
                list.as_bytes(),
                SIG_OK.as_bytes(),
            )
        };
        // One digit of the entry we would install, changed.
        let forged = SUMS.replacen("ad29a132", "ad29a133", 1);
        assert_ne!(forged, SUMS);
        // An entry added, an entry removed, nothing at all.
        let longer = format!("{SUMS}{}  oxiclean-extra\n", "0".repeat(64));
        let shorter: String = SUMS.lines().skip(1).map(|l| format!("{l}\n")).collect();
        for list in [forged, longer, shorter, String::new()] {
            let r = signed(&list);
            assert!(
                matches!(&r, Err(Refusal::BadSignature(why)) if why.contains("does not match")),
                "{list:?}: {r:?}"
            );
        }
    }

    #[test]
    fn test_an_edited_signed_comment_is_refused() {
        // The comment is what ties a signature to a release. It carries its
        // own signature, so touching it breaks the verification.
        let edits = [
            SIG_OK.replace("oxiclean 9.9.9", "oxiclean 9.9.10"),
            SIG_OK.replace("oxiclean 9.9.9", "oxiclean 9.9.8"),
            SIG_OLD.replace("oxiclean 1.0.0", "oxiclean 9.9.9"),
        ];
        for edited in edits {
            assert!(edited != SIG_OK && edited != SIG_OLD);
            let r = verify(&edited);
            assert!(
                matches!(&r, Err(Refusal::BadSignature(why)) if why.contains("does not match")),
                "{r:?}"
            );
        }
    }

    #[test]
    fn test_a_signature_that_does_not_name_a_release_is_refused() {
        // A real signature over the real list, but with no release bound to it:
        // the default comment minisign writes when -t is forgotten, and a
        // comment from some other product.
        assert_eq!(
            verify(SIG_NO_VERSION).unwrap_err(),
            Refusal::UnnamedRelease(printable(
                Signature::decode(SIG_NO_VERSION).unwrap().trusted_comment()
            ))
        );
        assert_eq!(
            verify(SIG_OTHER_PRODUCT).unwrap_err(),
            Refusal::UnnamedRelease("someotherthing 9.9.9".to_string())
        );
    }

    #[test]
    fn test_a_validly_signed_old_release_cannot_pass_for_a_new_one() {
        // Replayed under a newer tag: the signature is genuine, and for 1.0.0.
        assert_eq!(
            verify(SIG_OLD).unwrap_err(),
            Refusal::WrongRelease {
                signed: "1.0.0".to_string(),
                tag: "9.9.9".to_string()
            }
        );
        // Offered honestly as 1.0.0 to an installation that is already 1.8.0.
        let rollback = verify_release(
            &[KEY_1],
            "1.8.0",
            "1.0.0",
            ASSET,
            SUMS.as_bytes(),
            SIG_OLD.as_bytes(),
        );
        assert_eq!(
            rollback.unwrap_err(),
            Refusal::NotNewer {
                signed: "1.0.0".to_string(),
                current: "1.8.0".to_string()
            }
        );
        // The release already installed is not an update either.
        let same = verify_release(
            &[KEY_1],
            "9.9.9",
            "9.9.9",
            ASSET,
            SUMS.as_bytes(),
            SIG_OK.as_bytes(),
        );
        assert!(matches!(same, Err(Refusal::NotNewer { .. })), "{same:?}");
        // …and a newer tag over an older signature is the replay again.
        let newer_tag = verify_release(
            &[KEY_1],
            "1.8.0",
            "9.9.10",
            ASSET,
            SUMS.as_bytes(),
            SIG_OK.as_bytes(),
        );
        assert!(
            matches!(newer_tag, Err(Refusal::WrongRelease { .. })),
            "{newer_tag:?}"
        );
    }

    #[test]
    fn test_a_legacy_format_signature_is_refused_with_the_fix() {
        let r = verify(SIG_LEGACY);
        assert!(
            matches!(&r, Err(Refusal::BadSignature(why)) if why.contains("sign without -l")),
            "{r:?}"
        );
    }

    #[test]
    fn test_garbage_is_not_a_signature() {
        let cases: [&[u8]; 6] = [
            b"",
            b"hello",
            b"untrusted comment: x\nnot-base64!!\n",
            &SIG_OK.as_bytes()[..40],
            b"\xff\xfe\x00",
            // the right shape, the wrong content: a comment where a signature goes
            b"untrusted comment: a\nb\ntrusted comment: c\nd\n",
        ];
        for sig in cases {
            let r = verify_release(&[KEY_1], "1.8.0", "9.9.9", ASSET, SUMS.as_bytes(), sig);
            assert_eq!(
                r.unwrap_err(),
                Refusal::UnreadableSignature,
                "{:?}",
                String::from_utf8_lossy(sig)
            );
        }
    }

    #[test]
    fn test_with_no_key_nothing_is_trusted() {
        let r = verify_release(
            &[],
            "1.8.0",
            "9.9.9",
            ASSET,
            SUMS.as_bytes(),
            SIG_OK.as_bytes(),
        );
        assert_eq!(r.unwrap_err(), Refusal::NoKeys);
    }

    #[test]
    fn test_a_malformed_key_fails_closed_even_when_another_key_would_verify() {
        let with = |keys: &[&str]| {
            verify_release(
                keys,
                "1.8.0",
                "9.9.9",
                ASSET,
                SUMS.as_bytes(),
                SIG_OK.as_bytes(),
            )
        };
        assert_eq!(with(&["not a key", KEY_1]).unwrap_err(), Refusal::BadKey(1));
        assert_eq!(with(&[KEY_2, "RWQ"]).unwrap_err(), Refusal::BadKey(2));
        // The key of some other algorithm family is not a minisign key either.
        assert_eq!(
            with(&["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]).unwrap_err(),
            Refusal::BadKey(1)
        );
    }

    #[test]
    fn test_a_release_signed_by_any_one_of_the_keys_is_accepted() {
        // During a rotation both the old and the new key are built in.
        for keys in [[KEY_2, KEY_1], [KEY_1, KEY_2]] {
            assert!(
                verify_release(
                    &keys,
                    "1.8.0",
                    "9.9.9",
                    ASSET,
                    SUMS.as_bytes(),
                    SIG_OK.as_bytes()
                )
                .is_ok(),
                "{keys:?}"
            );
        }
        // …but only keys that are built in count.
        assert_eq!(
            verify_release(
                &[KEY_2],
                "1.8.0",
                "9.9.9",
                ASSET,
                SUMS.as_bytes(),
                SIG_OK.as_bytes()
            )
            .unwrap_err(),
            Refusal::BadSignature("it was signed by a key this build does not trust")
        );
    }

    #[test]
    fn test_a_signed_list_without_this_platform_is_refused() {
        let r = verify_release(
            &[KEY_1],
            "1.8.0",
            "9.9.9",
            "oxiclean-riscv64-linux-gnu",
            SUMS.as_bytes(),
            SIG_OK.as_bytes(),
        );
        assert_eq!(
            r.unwrap_err(),
            Refusal::NoAsset("oxiclean-riscv64-linux-gnu".to_string())
        );
    }

    // ── checking a release without a network ────────

    const API: &str = "https://api.example.test/latest";
    const BASE: &str = "https://downloads.example.test";

    /// Canned answers keyed by URL, remembering what was asked for and in
    /// which order. Anything not canned is a 404.
    struct Canned {
        answers: Vec<(String, Result<Vec<u8>, FetchError>)>,
        asked: std::cell::RefCell<Vec<String>>,
        /// For each request, in order: url, accept, byte limit, time allowed.
        terms: std::cell::RefCell<Vec<(String, String, u64, Duration)>>,
    }

    impl Canned {
        fn new() -> Canned {
            Canned {
                answers: Vec::new(),
                asked: Default::default(),
                terms: Default::default(),
            }
        }

        fn with(mut self, url: &str, body: &[u8]) -> Canned {
            self.answers.push((url.to_string(), Ok(body.to_vec())));
            self
        }

        fn failing(mut self, url: &str, why: FetchError) -> Canned {
            self.answers.push((url.to_string(), Err(why)));
            self
        }

        fn asked(&self) -> Vec<String> {
            self.asked.borrow().clone()
        }

        fn terms(&self) -> Vec<(String, String, u64, Duration)> {
            self.terms.borrow().clone()
        }
    }

    impl Fetch for Canned {
        fn get(
            &self,
            url: &str,
            accept: &str,
            limit: u64,
            within: Duration,
        ) -> Result<Vec<u8>, FetchError> {
            self.asked.borrow_mut().push(url.to_string());
            self.terms
                .borrow_mut()
                .push((url.to_string(), accept.to_string(), limit, within));
            match self.answers.iter().find(|(u, _)| u == url) {
                Some((_, Ok(body))) if body.len() as u64 > limit => {
                    Err(FetchError::Failed("too large".to_string()))
                }
                Some((_, answer)) => answer.clone(),
                None => Err(FetchError::NotFound),
            }
        }
    }

    fn api_answer(tag: &str) -> Vec<u8> {
        serde_json::json!({ "tag_name": tag, "body": "notes" })
            .to_string()
            .into_bytes()
    }

    fn url(tag: &str, name: &str) -> String {
        format!("{BASE}/{tag}/{name}")
    }

    /// A release as GitHub would serve it for `tag`, signed with `sig`.
    fn release(tag: &str, sig: &str) -> Canned {
        Canned::new()
            .with(API, &api_answer(tag))
            .with(&url(tag, "SHA256SUMS"), SUMS.as_bytes())
            .with(&url(tag, "SHA256SUMS.minisig"), sig.as_bytes())
            .with(&url(tag, ASSET), PAYLOAD)
    }

    fn vet(net: &Canned) -> Result<Checked, UpdateError> {
        check(net, &[KEY_1], "1.8.0", ASSET, API, BASE)
    }

    fn plan_of(checked: Result<Checked, UpdateError>) -> Plan {
        match checked {
            Ok(Checked::Available(plan)) => plan,
            other => panic!("expected an available update, got {other:?}"),
        }
    }

    #[test]
    fn test_a_signed_newer_release_is_planned_and_then_downloaded() {
        let net = release("v9.9.9", SIG_OK);
        let plan = plan_of(vet(&net));
        assert_eq!(plan.version, "9.9.9");
        assert_eq!(plan.notes, "notes");
        assert_eq!(plan.asset, ASSET);
        assert_eq!(plan.url, url("v9.9.9", ASSET));
        assert_eq!(to_hex(&plan.sha256), PAYLOAD_SHA256);
        assert_eq!(acquire(&net, &plan).unwrap(), PAYLOAD);
        // Exactly these requests, in this order: the binary is fetched only
        // once the list and signature have passed.
        assert_eq!(
            net.asked(),
            [
                API.to_string(),
                url("v9.9.9", "SHA256SUMS"),
                url("v9.9.9", "SHA256SUMS.minisig"),
                url("v9.9.9", ASSET),
            ]
        );
        assert!(net.asked().iter().all(|u| u.starts_with("https://")));
    }

    #[test]
    fn test_every_request_carries_its_own_size_and_time_limits() {
        let net = release("v9.9.9", SIG_OK);
        let plan = plan_of(vet(&net));
        acquire(&net, &plan).unwrap();
        let terms = net.terms();
        let seen: Vec<(&str, &str, u64, u64)> = terms
            .iter()
            .map(|(url, accept, limit, within)| {
                (
                    url.rsplit('/').next().unwrap(),
                    accept.as_str(),
                    *limit,
                    within.as_secs(),
                )
            })
            .collect();
        // What each download may weigh and how long it may take: the GitHub
        // answer 1 MiB, the checksum list 64 KiB, the signature 4 KiB, all in
        // 30 s; the binary 64 MiB in 5 minutes.
        assert_eq!(
            seen,
            [
                ("latest", "application/vnd.github+json", 1 << 20, 30),
                ("SHA256SUMS", "application/octet-stream", 64 << 10, 30),
                (
                    "SHA256SUMS.minisig",
                    "application/octet-stream",
                    4 << 10,
                    30
                ),
                (ASSET, "application/octet-stream", 64 << 20, 300),
            ]
        );
    }

    #[test]
    fn test_a_tag_without_the_v_works_the_same() {
        let plan = plan_of(vet(&release("9.9.9", SIG_OK)));
        assert_eq!(plan.url, url("9.9.9", ASSET));
    }

    #[test]
    fn test_nothing_is_downloaded_when_already_up_to_date() {
        for tag in ["v1.8.0", "v1.0.0", "v1.7.9"] {
            let net = release(tag, SIG_OK);
            assert!(matches!(vet(&net), Ok(Checked::UpToDate)), "{tag}");
            assert_eq!(net.asked(), [API.to_string()], "{tag}");
        }
    }

    #[test]
    fn test_a_tag_that_is_not_a_plain_version_stops_before_anything_is_fetched() {
        for tag in [
            "nightly",
            "v9.9.9-rc1",
            "v9.9.9/../../x",
            "v9.9.9\u{1b}[2J",
            "v9.9.9 ",
            "",
        ] {
            let net = release(tag, SIG_OK);
            let r = vet(&net);
            let Err(UpdateError::BadTag(shown)) = &r else {
                panic!("{tag:?}: {r:?}")
            };
            assert!(!shown.chars().any(utils::is_terminal_hazard), "{shown:?}");
            assert_eq!(net.asked(), [API.to_string()], "{tag:?}");
        }
    }

    #[test]
    fn test_a_release_without_a_signature_is_not_installed() {
        let tag = "v9.9.9";
        let no_sums = Canned::new()
            .with(API, &api_answer(tag))
            .with(&url(tag, "SHA256SUMS.minisig"), SIG_OK.as_bytes());
        assert_eq!(vet(&no_sums).unwrap_err(), UpdateError::Unsigned);
        let no_sig = Canned::new()
            .with(API, &api_answer(tag))
            .with(&url(tag, "SHA256SUMS"), SUMS.as_bytes());
        assert_eq!(vet(&no_sig).unwrap_err(), UpdateError::Unsigned);
        // Nor is a bare binary with neither.
        let bare = Canned::new()
            .with(API, &api_answer(tag))
            .with(&url(tag, ASSET), PAYLOAD);
        assert_eq!(vet(&bare).unwrap_err(), UpdateError::Unsigned);
    }

    #[test]
    fn test_a_release_signed_by_somebody_else_is_refused() {
        let r = vet(&release("v9.9.9", SIG_WRONG_KEY));
        assert!(
            matches!(r, Err(UpdateError::Refused(Refusal::BadSignature(_)))),
            "{r:?}"
        );
    }

    #[test]
    fn test_the_signature_must_name_the_release_the_api_offers() {
        // Genuine signed material for 1.0.0 served under a 9.9.9 tag…
        let r = vet(&release("v9.9.9", SIG_OLD));
        assert!(
            matches!(r, Err(UpdateError::Refused(Refusal::WrongRelease { .. }))),
            "{r:?}"
        );
        // …and for 9.9.9 served under a still newer tag.
        let r = vet(&release("v9.9.10", SIG_OK));
        assert!(
            matches!(r, Err(UpdateError::Refused(Refusal::WrongRelease { .. }))),
            "{r:?}"
        );
    }

    #[test]
    fn test_a_platform_missing_from_the_signed_list_is_refused() {
        let net = release("v9.9.9", SIG_OK);
        let r = check(
            &net,
            &[KEY_1],
            "1.8.0",
            "oxiclean-riscv64-linux-gnu",
            API,
            BASE,
        );
        assert!(
            matches!(r, Err(UpdateError::Refused(Refusal::NoAsset(_)))),
            "{r:?}"
        );
    }

    #[test]
    fn test_a_corrupted_or_substituted_binary_is_refused() {
        let net = release("v9.9.9", SIG_OK);
        let plan = plan_of(vet(&net));
        let swap = |bytes: &[u8]| {
            let net = Canned::new().with(&plan.url, bytes);
            acquire(&net, &plan)
        };
        // One bit flipped, one byte dropped, one byte added, a different file.
        let mut flipped = PAYLOAD.to_vec();
        flipped[10] ^= 1;
        let mut longer = PAYLOAD.to_vec();
        longer.push(0);
        for bytes in [
            flipped,
            PAYLOAD[1..].to_vec(),
            longer,
            b"\x7fELF-something-else-entirely-0.0.1".to_vec(),
            Vec::new(),
        ] {
            assert_eq!(
                swap(&bytes).unwrap_err(),
                UpdateError::Refused(Refusal::HashMismatch)
            );
        }
        assert_eq!(swap(PAYLOAD).unwrap(), PAYLOAD);
    }

    #[test]
    fn test_signed_bytes_that_are_not_an_executable_are_not_installed() {
        // A maintainer's slip (a script signed in place of the binary) is
        // caught here, not on the user's machine.
        let script = b"#!/bin/sh\necho hi\n";
        let sha256 =
            hex_to_sha256(&to_hex(digest::digest(&digest::SHA256, script).as_ref())).unwrap();
        let plan = Plan {
            version: "9.9.9".to_string(),
            asset: ASSET.to_string(),
            url: url("v9.9.9", ASSET),
            sha256,
            notes: String::new(),
        };
        let net = Canned::new().with(&plan.url, script);
        assert_eq!(acquire(&net, &plan).unwrap_err(), UpdateError::NotABinary);
    }

    #[test]
    fn test_trouble_with_the_network_is_reported_as_such() {
        let boom = || FetchError::Failed("boom".to_string());
        // The API itself.
        let r = vet(&Canned::new().failing(API, boom()));
        assert_eq!(r.unwrap_err(), UpdateError::Fetch("boom".to_string()));
        let r = vet(&Canned::new());
        assert_eq!(
            r.unwrap_err(),
            UpdateError::Fetch("not found (404)".to_string())
        );
        // An answer that is not a release.
        for junk in [&b"<html>rate limited</html>"[..], b"{}", b"[]", b""] {
            let r = vet(&Canned::new().with(API, junk));
            assert!(
                matches!(&r, Err(UpdateError::Fetch(why)) if why.contains("unexpected answer")),
                "{r:?}"
            );
        }
        // The signed files, failing for a reason other than being absent.
        let tag = "v9.9.9";
        let net = Canned::new()
            .with(API, &api_answer(tag))
            .failing(&url(tag, "SHA256SUMS"), boom());
        assert_eq!(
            vet(&net).unwrap_err(),
            UpdateError::Fetch("boom".to_string())
        );
        // The binary: gone, or failing.
        let plan = plan_of(vet(&release(tag, SIG_OK)));
        let gone = Canned::new();
        assert_eq!(
            acquire(&gone, &plan).unwrap_err(),
            UpdateError::Missing(ASSET.to_string())
        );
        let failing = Canned::new().failing(&plan.url, boom());
        assert_eq!(
            acquire(&failing, &plan).unwrap_err(),
            UpdateError::Fetch("boom".to_string())
        );
    }

    #[test]
    fn test_oversized_answers_are_not_accepted() {
        // The caps are real: a canned answer over the cap the caller asked for
        // is refused, which is what the HTTP layer does too (tested below).
        let tag = "v9.9.9";
        let huge_sums = vec![b'a'; MAX_SUMS_BYTES as usize + 1];
        let net = Canned::new()
            .with(API, &api_answer(tag))
            .with(&url(tag, "SHA256SUMS"), &huge_sums)
            .with(&url(tag, "SHA256SUMS.minisig"), SIG_OK.as_bytes());
        assert!(matches!(vet(&net), Err(UpdateError::Fetch(_))));
    }

    #[test]
    fn test_what_the_person_sees_for_each_failure() {
        let fetch = UpdateError::Fetch("connection refused".to_string());
        assert_eq!(
            explain(&fetch, "couldn't check for updates"),
            "couldn't check for updates (connection refused)"
        );
        for refusal in [
            UpdateError::Unsigned,
            UpdateError::NotABinary,
            UpdateError::BadTag("nightly".to_string()),
            UpdateError::Refused(Refusal::HashMismatch),
        ] {
            let said = explain(&refusal, "download failed");
            assert!(said.starts_with("not updating: "), "{said}");
            assert!(!said.contains("download failed"), "{said}");
        }
    }

    // ── the real HTTP layer, against a server on localhost ──

    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread::JoinHandle;

    /// What the test server does with a connection once it has read the request.
    #[derive(Clone)]
    enum Reply {
        /// Send these bytes, then close.
        Raw(Vec<u8>),
        /// Say nothing, until the client gives up.
        Silence,
        /// Send `head`, then one byte every `every`, until the client gives up.
        Trickle { head: Vec<u8>, every: Duration },
    }

    fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
            body.len()
        )
        .into_bytes();
        for (name, value) in headers {
            out.extend(format!("{name}: {value}\r\n").bytes());
        }
        out.extend(b"\r\n");
        out.extend(body);
        out
    }

    /// A throwaway HTTP/1.1 server on 127.0.0.1 with fixed routes. Dropping it
    /// stops it.
    struct Server {
        port: u16,
        hits: Arc<AtomicUsize>,
        stop: Arc<AtomicBool>,
        accept: Option<JoinHandle<()>>,
    }

    impl Server {
        fn start(routes: Vec<(&'static str, Reply)>) -> Server {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let hits = Arc::new(AtomicUsize::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let (h, s) = (hits.clone(), stop.clone());
            let accept = std::thread::spawn(move || {
                while !s.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            h.fetch_add(1, Ordering::SeqCst);
                            let (routes, s) = (routes.clone(), s.clone());
                            std::thread::spawn(move || serve(stream, &routes, &s));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            });
            Server {
                port,
                hits,
                stop,
                accept: Some(accept),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}{path}", self.port)
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(handle) = self.accept.take() {
                let _ = handle.join();
            }
        }
    }

    fn serve(mut stream: TcpStream, routes: &[(&'static str, Reply)], stop: &AtomicBool) {
        stream.set_nonblocking(false).ok();
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut request = Vec::new();
        let mut chunk = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return,
                Ok(n) => request.extend_from_slice(&chunk[..n]),
            }
        }
        let first = String::from_utf8_lossy(&request);
        let path = first.split_whitespace().nth(1).unwrap_or("/").to_string();
        let reply = routes
            .iter()
            .find(|(p, _)| *p == path)
            .map(|(_, r)| r.clone())
            .unwrap_or_else(|| Reply::Raw(response("404 Not Found", &[], b"nope")));
        let started = Instant::now();
        let give_up = || stop.load(Ordering::SeqCst) || started.elapsed() > Duration::from_secs(10);
        match reply {
            Reply::Raw(bytes) => {
                let _ = stream.write_all(&bytes);
            }
            Reply::Silence => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .ok();
                while !give_up() {
                    if let Ok(0) = stream.read(&mut chunk) {
                        return;
                    }
                }
            }
            Reply::Trickle { head, every } => {
                if stream.write_all(&head).is_err() {
                    return;
                }
                while !give_up() {
                    std::thread::sleep(every);
                    if stream.write_all(b"x").is_err() {
                        return;
                    }
                }
            }
        }
    }

    /// The updater's HTTP client, minus the https-only rule and minus the
    /// environment's proxy, so it can reach a server on localhost.
    fn local_client() -> Http {
        Http::build(false, false)
    }

    const SECS_5: Duration = Duration::from_secs(5);

    #[test]
    fn test_http_returns_the_body() {
        let server = Server::start(vec![(
            "/hello",
            Reply::Raw(response("200 OK", &[], b"hello")),
        )]);
        let got = local_client().get(&server.url("/hello"), "*/*", 1024, SECS_5);
        assert_eq!(got, Ok(b"hello".to_vec()));
        assert_eq!(server.hits(), 1);
    }

    #[test]
    fn test_http_404_is_not_found_and_other_statuses_are_failures() {
        let server = Server::start(vec![
            ("/gone", Reply::Raw(response("404 Not Found", &[], b"x"))),
            (
                "/boom",
                Reply::Raw(response("500 Internal Server Error", &[], b"x")),
            ),
            (
                "/denied",
                Reply::Raw(response("403 Forbidden", &[], b"rate limit")),
            ),
        ]);
        let client = local_client();
        assert_eq!(
            client.get(&server.url("/gone"), "*/*", 1024, SECS_5),
            Err(FetchError::NotFound)
        );
        for path in ["/boom", "/denied"] {
            let r = client.get(&server.url(path), "*/*", 1024, SECS_5);
            assert!(matches!(r, Err(FetchError::Failed(_))), "{path}: {r:?}");
        }
    }

    #[test]
    fn test_http_keeps_at_most_the_limit_and_refuses_more() {
        let body = vec![b'z'; 100];
        let server = Server::start(vec![("/b", Reply::Raw(response("200 OK", &[], &body)))]);
        let client = local_client();
        let get = |limit| client.get(&server.url("/b"), "*/*", limit, SECS_5);
        assert_eq!(get(100), Ok(body.clone()), "exactly the limit is fine");
        assert_eq!(get(1000), Ok(body.clone()));
        for limit in [99, 50, 1, 0] {
            let r = get(limit);
            assert!(
                matches!(&r, Err(FetchError::Failed(why)) if why.contains("limit") || why.contains("larger")),
                "limit {limit}: {r:?}"
            );
        }
    }

    #[test]
    fn test_http_never_returns_more_than_the_limit_even_from_a_compressed_body() {
        // 96 bytes on the wire that gunzip to 64 KiB. With a decoder in the
        // client, the cap has to hold on the *decoded* size; without one, the
        // bytes arrive undecoded and small. What must never happen is a
        // result larger than the limit.
        let server = Server::start(vec![(
            "/bomb",
            Reply::Raw(response(
                "200 OK",
                &[("Content-Encoding", "gzip")],
                GZIP_BOMB,
            )),
        )]);
        let limit = 1024;
        let r = local_client().get(&server.url("/bomb"), "*/*", limit, SECS_5);
        match r {
            Ok(body) => assert!(body.len() as u64 <= limit, "{} bytes", body.len()),
            Err(FetchError::Failed(_)) => {}
            Err(other) => panic!("{other:?}"),
        }
    }

    #[test]
    fn test_http_gives_up_on_a_server_that_never_answers() {
        let server = Server::start(vec![("/silent", Reply::Silence)]);
        let started = Instant::now();
        let r = local_client().get(
            &server.url("/silent"),
            "*/*",
            1024,
            Duration::from_millis(300),
        );
        assert!(matches!(r, Err(FetchError::Failed(_))), "{r:?}");
        assert!(started.elapsed() < SECS_5, "took {:?}", started.elapsed());
    }

    #[test]
    fn test_http_gives_up_on_a_server_that_trickles_its_answer() {
        // Headers promise 100 000 bytes; one byte arrives every 50 ms. Without
        // a deadline on the whole transfer this would take most of two hours.
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\nConnection: close\r\n\r\n";
        let server = Server::start(vec![(
            "/drip",
            Reply::Trickle {
                head: head.to_vec(),
                every: Duration::from_millis(50),
            },
        )]);
        let started = Instant::now();
        let r = local_client().get(
            &server.url("/drip"),
            "*/*",
            1 << 20,
            Duration::from_millis(500),
        );
        assert!(matches!(r, Err(FetchError::Failed(_))), "{r:?}");
        assert!(started.elapsed() < SECS_5, "took {:?}", started.elapsed());
    }

    #[test]
    fn test_http_follows_a_redirect_to_the_file() {
        // GitHub serves release assets through a redirect.
        let server = Server::start(vec![
            (
                "/start",
                Reply::Raw(response("302 Found", &[("Location", "/final")], b"")),
            ),
            ("/final", Reply::Raw(response("200 OK", &[], b"arrived"))),
        ]);
        let r = local_client().get(&server.url("/start"), "*/*", 1024, SECS_5);
        assert_eq!(r, Ok(b"arrived".to_vec()));
        assert_eq!(server.hits(), 2);
    }

    #[test]
    fn test_http_stops_following_a_redirect_loop() {
        let server = Server::start(vec![(
            "/loop",
            Reply::Raw(response("302 Found", &[("Location", "/loop")], b"")),
        )]);
        let r = local_client().get(&server.url("/loop"), "*/*", 1024, SECS_5);
        assert!(matches!(r, Err(FetchError::Failed(_))), "{r:?}");
        assert!(server.hits() <= 10, "followed {} redirects", server.hits());
    }

    #[test]
    fn test_the_updater_refuses_plain_http() {
        let server = Server::start(vec![("/x", Reply::Raw(response("200 OK", &[], b"hello")))]);
        let r = Http::build(true, false).get(&server.url("/x"), "*/*", 1024, SECS_5);
        assert!(
            matches!(&r, Err(FetchError::Failed(why)) if why.contains("https")),
            "{r:?}"
        );
        assert_eq!(server.hits(), 0, "it must not even connect");
    }

    // ── staging and installing ──────────────────────

    use std::cell::RefCell;
    use std::os::unix::fs::symlink;

    /// A fresh, empty directory for one test.
    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oxiclean-update-test.{}.{label}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut found: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        found.sort();
        found
    }

    #[test]
    fn test_staging_never_follows_a_link_or_overwrites_anything() {
        let dir = scratch("exclusive");
        let victim = dir.join("victim");
        let link = dir.join("link");
        symlink(&victim, &link).unwrap(); // dangling
        let e = write_new(&link, b"x").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists);
        assert!(!victim.exists(), "a dangling link was followed");

        let existing = dir.join("existing");
        fs::write(&existing, b"keep me").unwrap();
        assert!(write_new(&existing, b"x").is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"keep me");

        let fresh = dir.join("fresh");
        write_new(&fresh, b"hello").unwrap();
        assert_eq!(fs::read(&fresh).unwrap(), b"hello");
        assert_eq!(mode(&fresh), 0o700, "owner only until it is installed");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_staged_file_beside_the_target_is_private_and_cleans_up() {
        let dir = scratch("beside");
        let staged = Staged::beside(&dir, b"payload").unwrap();
        let path = staged.path.clone();
        assert_eq!(
            path.parent().unwrap(),
            dir,
            "same directory, so rename is atomic"
        );
        assert!(path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".oxiclean.new."));
        assert_eq!(fs::read(&path).unwrap(), b"payload");
        assert_eq!(mode(&path), 0o700);
        drop(staged);
        assert!(!path.exists(), "dropped without being installed");
        assert!(names(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_private_stage_lives_in_a_directory_only_we_can_enter() {
        let staged = Staged::private(b"payload").unwrap();
        let path = staged.path.clone();
        let dir = path.parent().unwrap().to_path_buf();
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&path), 0o700);
        assert_eq!(fs::read(&path).unwrap(), b"payload");
        // Two stages never share a directory.
        let other = Staged::private(b"payload").unwrap();
        assert_ne!(other.path.parent().unwrap(), dir);
        drop(staged);
        drop(other);
        assert!(!path.exists());
        assert!(!dir.exists(), "the private directory goes with it");
    }

    #[test]
    fn test_an_install_replaces_the_target_atomically_and_leaves_nothing_behind() {
        let dir = scratch("install");
        let target = dir.join("oxiclean");
        fs::write(&target, b"old binary").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

        let seen = RefCell::new(Vec::new());
        let check = |p: &Path| {
            seen.borrow_mut()
                .push((p.to_path_buf(), fs::read(p).unwrap(), mode(p)));
            Ok(())
        };
        let never = |_: &[u8], _: &Path| -> Result<(), String> { panic!("no privilege needed") };
        install(b"new binary", &target, &check, &never).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new binary");
        assert_eq!(mode(&target), 0o755);
        assert_eq!(names(&dir), ["oxiclean"], "no temp file left behind");
        // What was checked is what was installed, and it was checked where the
        // rename can then be atomic, while still private.
        let seen = seen.borrow();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0.parent().unwrap(), dir);
        assert_eq!(seen[0].1, b"new binary");
        assert_eq!(seen[0].2, 0o700);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_failed_check_installs_nothing() {
        let dir = scratch("checkfail");
        let target = dir.join("oxiclean");
        fs::write(&target, b"old binary").unwrap();
        let check = |_: &Path| Err("it reports 1.2.3".to_string());
        let never = |_: &[u8], _: &Path| -> Result<(), String> { panic!("must not be reached") };
        let r = install(b"new binary", &target, &check, &never);
        assert_eq!(r, Err("it reports 1.2.3".to_string()));
        assert_eq!(fs::read(&target).unwrap(), b"old binary");
        assert_eq!(names(&dir), ["oxiclean"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_directory_we_cannot_write_gets_the_privileged_install() {
        if utils::is_root() {
            return; // root can write anywhere, so this branch is unreachable
        }
        let dir = scratch("readonly");
        let target = dir.join("oxiclean");
        fs::write(&target, b"old binary").unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();

        let checked = RefCell::new(Vec::new());
        let check = |p: &Path| {
            let private = p.parent().unwrap();
            checked.borrow_mut().push((
                p.to_path_buf(),
                fs::read(p).unwrap(),
                mode(p),
                mode(private),
            ));
            Ok(())
        };
        let handed = RefCell::new(None);
        let privileged = |bytes: &[u8], to: &Path| {
            *handed.borrow_mut() = Some((bytes.to_vec(), to.to_path_buf()));
            Ok(())
        };
        let r = install(b"new binary", &target, &check, &privileged);

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(r, Ok(()));
        // The privileged side is handed the in-memory bytes and the real target;
        // nothing was touched here.
        assert_eq!(
            handed.into_inner(),
            Some((b"new binary".to_vec(), target.clone()))
        );
        assert_eq!(fs::read(&target).unwrap(), b"old binary");
        assert_eq!(names(&dir), ["oxiclean"]);
        // The check ran on a private copy that is gone again.
        let checked = checked.into_inner();
        assert_eq!(checked.len(), 1);
        let (staged, content, file_mode, dir_mode) = &checked[0];
        assert_eq!(content, b"new binary");
        assert_eq!((*file_mode, *dir_mode), (0o700, 0o700));
        assert_ne!(staged.parent().unwrap(), dir);
        assert!(!staged.exists() && !staged.parent().unwrap().exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_privileged_install_is_not_attempted_when_the_check_fails_or_it_fails() {
        if utils::is_root() {
            return;
        }
        let dir = scratch("readonly2");
        let target = dir.join("oxiclean");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o555)).unwrap();
        let never = |_: &[u8], _: &Path| -> Result<(), String> { panic!("must not be reached") };
        let bad_check = |_: &Path| Err("wrong version".to_string());
        let r = install(b"x", &target, &bad_check, &never);
        assert_eq!(r, Err("wrong version".to_string()));

        let fails = |_: &[u8], _: &Path| Err("the privileged install failed".to_string());
        let ok_check = |_: &Path| Ok(());
        let r = install(b"x", &target, &ok_check, &fails);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(r, Err("the privileged install failed".to_string()));
        assert!(names(&dir).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_a_missing_directory_is_an_error_not_a_reason_to_escalate() {
        let dir = scratch("missing");
        let target = dir.join("no-such-dir").join("oxiclean");
        let ok = |_: &Path| Ok(());
        let never = |_: &[u8], _: &Path| -> Result<(), String> { panic!("must not be reached") };
        let r = install(b"x", &target, &ok, &never);
        assert!(
            matches!(&r, Err(why) if why.contains("cannot write next to")),
            "{r:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    // ── the script root runs ────────────────────────

    /// Run [`PRIVILEGED_INSTALL`] as the current user, exactly as `sudo` would
    /// run it as root (`Privilege::Root` means "no wrapper").
    fn run_install_script(dst: &Path, dir: &Path, claimed_length: usize, bytes: &[u8]) -> bool {
        let (dst, dir) = (dst.to_str().unwrap(), dir.to_str().unwrap());
        let length = claimed_length.to_string();
        let args = install_script_args(dst, dir, &length);
        utils::elevate_with_input(Privilege::Root, "sh", &args, bytes)
    }

    fn test_bytes(len: usize) -> Vec<u8> {
        // Not all one byte, and bigger than a pipe buffer when asked to be.
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn test_the_install_script_installs_exactly_what_it_is_sent() {
        let dir = scratch("script");
        let target = dir.join("oxiclean");
        fs::write(&target, b"old binary").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        for len in [1usize, 4096, 300_000] {
            let bytes = test_bytes(len);
            assert!(run_install_script(&target, &dir, len, &bytes), "{len}");
            assert_eq!(fs::read(&target).unwrap(), bytes);
            assert_eq!(mode(&target), 0o755);
            assert_eq!(names(&dir), ["oxiclean"], "no temp file left behind");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_the_install_script_refuses_a_short_or_long_transfer() {
        let dir = scratch("script-short");
        let target = dir.join("oxiclean");
        fs::write(&target, b"old binary").unwrap();
        let bytes = test_bytes(10_000);
        // The sender claims more or fewer bytes than arrive: whatever the
        // reason, the half-received file must not become the binary.
        for claimed in [10_001, 9_999, 0, 20_000] {
            assert!(
                !run_install_script(&target, &dir, claimed, &bytes),
                "{claimed}"
            );
            assert_eq!(fs::read(&target).unwrap(), b"old binary");
            assert_eq!(names(&dir), ["oxiclean"], "no temp file left behind");
        }
        // A directory that is not there fails cleanly too.
        let ghost = dir.join("ghost");
        assert!(!run_install_script(
            &ghost.join("oxiclean"),
            &ghost,
            10_000,
            &bytes
        ));
        assert_eq!(names(&dir), ["oxiclean"]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_the_install_script_does_not_write_through_a_planted_link() {
        // The directory is somewhere other people can create names, and the
        // installer must not be steerable by them: the temp file is made by
        // mktemp, exclusively and under a name nobody can guess, rather than
        // under one anyone could plant a link at ahead of time.
        let dir = scratch("script-planted");
        let victim = dir.join("victim");
        fs::write(&victim, b"precious").unwrap();
        for name in [
            ".oxiclean.new",
            ".oxiclean.new.",
            ".oxiclean.new.XXXXXX",
            ".oxiclean.new.0",
            ".oxiclean.new.1",
            ".oxiclean.new.a",
        ] {
            symlink(&victim, dir.join(name)).unwrap();
        }
        let target = dir.join("oxiclean");
        let bytes = test_bytes(4096);
        assert!(run_install_script(&target, &dir, bytes.len(), &bytes));
        assert_eq!(fs::read(&target).unwrap(), bytes);
        assert_eq!(fs::read(&victim).unwrap(), b"precious");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_no_file_name_can_become_code_in_the_install_script() {
        // The old script spliced the paths into `sh -c '…'` between quotes. Here
        // they are positional parameters, so a name stuffed with quotes,
        // substitutions and separators is only ever a name.
        let base = scratch("script-names");
        let nasty_dir = base.join("a b'c\"d $(touch PWNED1) `touch PWNED2` ;touch PWNED3;\n\\ *");
        fs::create_dir(&nasty_dir).unwrap();
        let target = nasty_dir.join("ox'i\n$HOME $(touch PWNED4)");
        let bytes = test_bytes(2048);
        assert!(run_install_script(&target, &nasty_dir, bytes.len(), &bytes));
        assert_eq!(fs::read(&target).unwrap(), bytes);

        // Exactly what we made, and nothing else: the directory holds the
        // binary, and the parent holds only the directory.
        let name_of = |p: &Path| p.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(names(&nasty_dir), [name_of(&target)]);
        assert_eq!(names(&base), [name_of(&nasty_dir)]);
        // `touch PWNEDn` would have run in the script's working directory.
        let cwd = std::env::current_dir().unwrap();
        for marker in ["PWNED1", "PWNED2", "PWNED3", "PWNED4"] {
            let created = cwd.join(marker);
            if created.exists() {
                let _ = fs::remove_file(&created);
                panic!("{marker} was created: a file name was run as code");
            }
        }
        fs::remove_dir_all(&base).unwrap();
    }

    // ── the self-check ──────────────────────────────

    /// A real system tool, by absolute path: never looked up through `PATH`,
    /// and never a file this test wrote and then ran (ETXTBSY under threads).
    fn tool(name: &str) -> PathBuf {
        ["/usr/bin", "/bin"]
            .iter()
            .map(|dir| Path::new(dir).join(name))
            .find(|p| p.is_file())
            .unwrap_or_else(|| panic!("{name} is not in /usr/bin or /bin"))
    }

    fn why(r: &Result<(), String>) -> String {
        r.clone().unwrap_err()
    }

    #[test]
    fn test_self_check_accepts_the_expected_banner() {
        let r = self_check(&tool("echo"), &["oxiclean 1.2.3"], "oxiclean 1.2.3", SECS_5);
        assert_eq!(r, Ok(()));
    }

    #[test]
    fn test_self_check_wants_the_whole_output_to_be_the_banner() {
        for said in [
            "oxiclean 1.2.30",
            "oxiclean 1.2.4",
            "oxiclean 1.2.3 and more",
            "oxiclean 1.2.3\nsecond line",
            "my oxiclean 1.2.3",
            "OXICLEAN 1.2.3",
            "",
        ] {
            let r = self_check(&tool("echo"), &[said], "oxiclean 1.2.3", SECS_5);
            assert!(r.is_err(), "{said:?} was accepted");
            assert!(
                why(&r).ends_with("instead of 'oxiclean 1.2.3'"),
                "{said:?}: {r:?}"
            );
        }
    }

    #[test]
    fn test_self_check_rejects_a_failing_exit_whatever_it_printed() {
        let sh = tool("sh");
        let r = self_check(
            &sh,
            &["-c", "echo 'oxiclean 1.2.3'; exit 3"],
            "oxiclean 1.2.3",
            SECS_5,
        );
        assert!(why(&r).contains("exited with"), "{r:?}");
        let r = self_check(&tool("false"), &[], "", SECS_5);
        assert!(why(&r).contains("exited with"), "{r:?}");
    }

    #[test]
    fn test_self_check_kills_what_does_not_answer() {
        let dir = scratch("selfcheck-kill");
        let pidfile = dir.join("pid");
        let started = Instant::now();
        // `exec` keeps the pid, so the pid on file is the one that must die.
        let r = self_check(
            &tool("sh"),
            &[
                "-c",
                "echo $$ > \"$0\"; exec sleep 30",
                pidfile.to_str().unwrap(),
            ],
            "x",
            Duration::from_secs(1),
        );
        assert!(why(&r).contains("did not answer within"), "{r:?}");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{:?}",
            started.elapsed()
        );
        let pid = fs::read_to_string(&pidfile).expect("the child never started");
        assert!(
            !Path::new(&format!("/proc/{}", pid.trim())).exists(),
            "process {} is still alive",
            pid.trim()
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_self_check_is_not_held_by_a_process_the_binary_left_behind() {
        // The shell answers and exits at once; the background `sleep` keeps the
        // output pipe open for five seconds. That must not hold us for five
        // seconds, and what it left behind is not a clean banner.
        let started = Instant::now();
        let r = self_check(
            &tool("sh"),
            &["-c", "sleep 5 & echo 'oxiclean 1.2.3'"],
            "oxiclean 1.2.3",
            SECS_5,
        );
        assert!(why(&r).contains("did not end"), "{r:?}");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn test_self_check_reads_a_bounded_amount_of_a_chatty_binary() {
        let started = Instant::now();
        let r = self_check(
            &tool("sh"),
            &["-c", "while :; do echo oxiclean; done"],
            "oxiclean",
            SECS_5,
        );
        assert!(r.is_err(), "endless output was accepted");
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    fn test_self_check_explains_a_file_it_may_not_run() {
        let dir = scratch("selfcheck-noexec");
        let file = dir.join("oxiclean");
        fs::write(&file, b"#!/bin/sh\necho hi\n").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
        let r = self_check(&file, &["--version"], "hi", SECS_5);
        let said = why(&r);
        assert!(said.contains("noexec") && said.contains("TMPDIR"), "{said}");
        fs::remove_dir_all(&dir).unwrap();

        let r = self_check(Path::new("/nonexistent/oxiclean"), &[], "x", SECS_5);
        assert!(why(&r).starts_with("it could not be run"), "{r:?}");
    }

    #[test]
    fn test_self_check_gives_the_binary_nothing_but_the_trusted_path() {
        // `env` prints everything it was given: anything we let through shows.
        let expected = format!("PATH={}", utils::trusted_path());
        assert_eq!(self_check(&tool("env"), &[], &expected, SECS_5), Ok(()));
    }

    #[test]
    fn test_self_check_gives_the_binary_no_input() {
        let r = self_check(
            &tool("sh"),
            &["-c", "if read line; then echo got-input; else echo eof; fi"],
            "eof",
            SECS_5,
        );
        assert_eq!(r, Ok(()));
        // Not merely an empty stdin: the null device, whatever ours is.
        let r = self_check(
            &tool("sh"),
            &["-c", "readlink /proc/self/fd/0"],
            "/dev/null",
            SECS_5,
        );
        assert_eq!(r, Ok(()));
    }
}
