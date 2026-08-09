use std::fs;

// ═══════════════════════════════════════════════════
//  Distribution Enum
// ═══════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq)]
pub enum Distro {
    Arch,
    Debian,
    Fedora,
    Suse,
    Nix,
    Void,
    Alpine,
    Gentoo,
    Solus,
    Clear,
    Unknown,
}

impl Distro {
    pub fn name(&self) -> &str {
        match self {
            Self::Arch => "Arch Linux",
            Self::Debian => "Debian/Ubuntu",
            Self::Fedora => "Fedora/RHEL",
            Self::Suse => "openSUSE/SLES",
            Self::Nix => "NixOS",
            Self::Void => "Void Linux",
            Self::Alpine => "Alpine Linux",
            Self::Gentoo => "Gentoo",
            Self::Solus => "Solus",
            Self::Clear => "Clear Linux",
            Self::Unknown => "Unknown",
        }
    }

    pub fn pkg_manager(&self) -> &str {
        match self {
            Self::Arch => "pacman",
            Self::Debian => "apt",
            Self::Fedora => "dnf/yum",
            Self::Suse => "zypper",
            Self::Nix => "nix",
            Self::Void => "xbps",
            Self::Alpine => "apk",
            Self::Gentoo => "portage",
            Self::Solus => "eopkg",
            Self::Clear => "swupd",
            Self::Unknown => "N/A",
        }
    }
}

// ═══════════════════════════════════════════════════
//  Detection Logic
// ═══════════════════════════════════════════════════

/// Parse /etc/os-release content and return matching Distro.
/// Pure function — no file I/O — testable in isolation.
pub fn distro_from_str(content: &str) -> Distro {
    let mut id = String::new();
    let mut id_like = String::new();

    for line in content.lines() {
        if let Some(v) = line.strip_prefix("ID=") {
            id = v.trim_matches('"').to_lowercase();
        } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
            id_like = v.trim_matches('"').to_lowercase();
        }
    }

    // ── Direct ID match ──

    const ARCH: &[&str] = &[
        "arch",
        "manjaro",
        "endeavouros",
        "garuda",
        "artix",
        "cachyos",
        "arcolinux",
        "archcraft",
        "parabola",
        "hyperbola",
        "crystal",
        "bluestar",
        "archbang",
    ];
    const DEBIAN: &[&str] = &[
        "debian",
        "ubuntu",
        "linuxmint",
        "pop",
        "elementary",
        "zorin",
        "kali",
        "parrot",
        "deepin",
        "mx",
        "antix",
        "lmde",
        "devuan",
        "raspbian",
        "neon",
        "pureos",
        "tails",
        "peppermint",
        "bodhi",
        "sparky",
        "bunsen",
    ];
    const FEDORA: &[&str] = &[
        "fedora",
        "rhel",
        "centos",
        "rocky",
        "alma",
        "nobara",
        "ultramarine",
        "oracle",
        "scientific",
        "amazon",
        "eurolinux",
    ];
    const SUSE: &[&str] = &[
        "opensuse",
        "opensuse-leap",
        "opensuse-tumbleweed",
        "opensuse-microos",
        "sles",
        "suse",
    ];

    if ARCH.contains(&id.as_str()) {
        return Distro::Arch;
    }
    if DEBIAN.contains(&id.as_str()) {
        return Distro::Debian;
    }
    if FEDORA.contains(&id.as_str()) {
        return Distro::Fedora;
    }
    if SUSE.contains(&id.as_str()) || id.starts_with("opensuse") {
        return Distro::Suse;
    }

    match id.as_str() {
        "nixos" => return Distro::Nix,
        "void" => return Distro::Void,
        "alpine" | "postmarketos" => return Distro::Alpine,
        "gentoo" | "funtoo" | "calculate" => return Distro::Gentoo,
        "solus" => return Distro::Solus,
        "clear-linux-os" => return Distro::Clear,
        _ => {}
    }

    // ── Fallback: ID_LIKE field ──

    if id_like.contains("arch") {
        return Distro::Arch;
    }
    if id_like.contains("debian") || id_like.contains("ubuntu") {
        return Distro::Debian;
    }
    if id_like.contains("fedora") || id_like.contains("rhel") {
        return Distro::Fedora;
    }
    if id_like.contains("suse") {
        return Distro::Suse;
    }

    Distro::Unknown
}

/// Detect Linux distribution by reading /etc/os-release
pub fn distro() -> Distro {
    match fs::read_to_string("/etc/os-release") {
        Ok(c) => distro_from_str(&c),
        Err(_) => Distro::Unknown,
    }
}

/// Get PRETTY_NAME from /etc/os-release
pub fn pretty_name() -> String {
    fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|c| {
            c.lines().find(|l| l.starts_with("PRETTY_NAME=")).map(|l| {
                l.strip_prefix("PRETTY_NAME=")
                    .unwrap_or("")
                    .trim_matches('"')
                    .to_string()
            })
        })
        .unwrap_or_else(|| "Unknown Linux".into())
}

// ═══════════════════════════════════════════════════
//  Tool Detection
// ═══════════════════════════════════════════════════

/// An AUR helper we know how to clean, with the flags that helper actually
/// wants. The flags differ enough that one shared `-Sc` was wrong for at least
/// one of them (see `trizen` below), so they belong in the table rather than at
/// the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AurHelper {
    /// Binary name, also used as the display label and cache-dir name.
    pub bin: &'static str,
    /// Safe clean: drop cached sources/builds, keep what is still installed.
    /// `None` when the helper has no command that cleans *its own* cache — see
    /// `aura`, which is handled through `prune_dirs` instead.
    pub clean: Option<&'static [&'static str]>,
    /// Aggressive clean, gated behind `--deep`: drop everything cached.
    pub deep_clean: Option<&'static [&'static str]>,
    /// Subdirectories of the helper's cache dir that we clear ourselves, for
    /// helpers whose CLI has no equivalent command. Build leftovers only —
    /// always safe, nothing here re-downloads.
    pub prune_dirs: &'static [&'static str],
    /// Extra subdirectories cleared only under `--deep`, because emptying them
    /// costs a re-download on the next build.
    pub prune_dirs_deep: &'static [&'static str],
}

/// Every AUR helper we support, in display order.
///
/// This used to be a bare name list that `find()` reduced to a single winner,
/// which meant the *array order* silently decided which helper got cleaned:
/// with both paru and yay installed, paru won for no reason other than being
/// written first, and yay's cache was never touched on any machine, ever.
/// Having two helpers installed and using only one is common, and the unused
/// one still accumulates clone/build caches. So we clean every helper present
/// and this order is now presentation only.
const AUR_HELPERS: &[AurHelper] = &[
    AurHelper {
        bin: "paru",
        clean: Some(&["-Sc", "--noconfirm"]),
        deep_clean: Some(&["-Scc", "--noconfirm"]),
        prune_dirs: &[],
        prune_dirs_deep: &[],
    },
    AurHelper {
        bin: "yay",
        clean: Some(&["-Sc", "--noconfirm"]),
        deep_clean: Some(&["-Scc", "--noconfirm"]),
        prune_dirs: &[],
        prune_dirs_deep: &[],
    },
    AurHelper {
        // `-a` restricts the clean to trizen's own AUR cache. Without it,
        // trizen's clean also runs `pacman -Scc` on the shared pacman cache —
        // which removes EVERY cached package, including ones still installed.
        // That is the aggressive behaviour we deliberately keep behind --deep,
        // so a plain run on a trizen system was quietly overreaching. It was
        // also redundant: pkg_cache() already ran `pacman -Sc` moments earlier.
        // https://github.com/trizen/trizen/blob/master/TRIZEN.md
        bin: "trizen",
        clean: Some(&["-Sca", "--noconfirm"]),
        deep_clean: Some(&["-Scca", "--noconfirm"]),
        prune_dirs: &[],
        prune_dirs_deep: &[],
    },
    AurHelper {
        bin: "pikaur",
        clean: Some(&["-Sc", "--noconfirm"]),
        deep_clean: Some(&["-Scc", "--noconfirm"]),
        prune_dirs: &[],
        prune_dirs_deep: &[],
    },
    AurHelper {
        // aura has no command that cleans aura's own cache, so we clear the
        // directories ourselves.
        //
        // Its `-C` family is the *downgrade* namespace, and `-Cc` there means
        // "keep the N most recent versions of each package" — it takes a
        // mandatory count (`clean: Option<usize>` in aura's own flags.rs) and
        // operates on `env.caches()`, i.e. the **pacman** cache. So `-Cc`
        // would (a) fail outright without a number, (b) duplicate the
        // `pacman -Sc` that pkg_cache already ran, and (c) still never touch
        // aura's own cache. `-Sc` is passed straight through to pacman for the
        // same reason — aura is a pacman superset.
        //
        // What actually grows is `~/.cache/aura/builds` (unpacked build trees),
        // `~/.cache/aura/cache` (built tarballs) and `~/.cache/aura/packages`
        // (AUR git clones). The last two cost a rebuild or a re-clone, so they
        // wait for `--deep`, matching how `--dev` gates its own caches.
        //
        // Two sibling dirs are deliberately absent from both lists because they
        // are state, not cache: `snapshots/` holds user-saved restore points
        // that `-B` restores from, and `hashes/` is the bookkeeping that tells
        // aura when each AUR package was last built. Clearing `packages/` is
        // relative to the cache dir, so an `AURDEST` that relocates the clones
        // elsewhere simply finds nothing here rather than deleting the wrong
        // tree.
        // https://github.com/fosskers/aura → rust/aura-pm/src/dirs.rs
        bin: "aura",
        clean: None,
        deep_clean: None,
        prune_dirs: &["builds"],
        prune_dirs_deep: &["cache", "packages"],
    },
];

/// Every AUR helper installed on this system, in [`AUR_HELPERS`] order.
pub fn aur_helpers() -> Vec<AurHelper> {
    AUR_HELPERS
        .iter()
        .copied()
        .filter(|h| crate::utils::which(h.bin))
        .collect()
}

/// Check if Flatpak is installed
pub fn has_flatpak() -> bool {
    crate::utils::which("flatpak")
}

/// Check if Snap is installed
pub fn has_snap() -> bool {
    crate::utils::which("snap")
}

/// Check if Nix is installed (the /nix/store directory is the unambiguous marker)
pub fn has_nix() -> bool {
    std::path::Path::new("/nix/store").exists()
}

/// Detect if the Nix install is multi-user (has a daemon socket)
pub fn nix_is_multiuser() -> bool {
    std::path::Path::new("/nix/var/nix/daemon-socket/socket").exists()
        || std::path::Path::new("/run/nix-daemon.socket").exists()
}

// ══════════════════════════════════════════════════
//  Immutable / atomic system detection
// ══════════════════════════════════════════════════

/// True on an OSTree-based atomic system (Fedora Silverblue, Kinoite, Bazzite,
/// and other rpm-ostree variants). The kernel/initramfs drops `/run/ostree-booted`
/// only when booted into an OSTree deployment, so it's the unambiguous marker —
/// same spirit as the `/nix/store` check for Nix. These systems report as their
/// base distro (Fedora) by ID, but their storage is reclaimed with
/// `rpm-ostree cleanup`, not `dnf clean`.
pub fn is_ostree() -> bool {
    std::path::Path::new("/run/ostree-booted").exists()
}

/// True when the root filesystem is mounted read-only — the hallmark of an
/// image-based immutable system (SteamOS, openSUSE MicroOS, …). We check `/usr`
/// specifically because that's the tree these systems lock down; on a normal
/// system `/usr` has no separate mount and this resolves to `/` (read-write).
/// Returns false if `/proc/mounts` can't be read, so a normal system is never
/// mistaken for an immutable one.
pub fn is_readonly_rootfs() -> bool {
    match fs::read_to_string("/proc/mounts") {
        Ok(m) => path_is_readonly_in(&m, "/usr").unwrap_or(false),
        Err(_) => false,
    }
}

// ══════════════════════════════════════════════════
//  Privilege Escalation
// ══════════════════════════════════════════════════

/// Available privilege-escalation helpers. `Root` means we are already uid 0
/// and no escalation is needed. `None` means the system has *no* escalation
/// tool at all (no sudo, no doas, and we aren't root) — callers must surface a
/// clear "install sudo or doas" message rather than trying and failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    Doas,
    Sudo,
    Root,
    None,
}

impl Privilege {
    /// Binary name used to invoke this helper. `Root` and `None` return an
    /// empty string — `Root` runs the command directly with no wrapper, and
    /// `None` has no wrapper to run at all.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Doas => "doas",
            Self::Sudo => "sudo",
            Self::Root => "",
            Self::None => "",
        }
    }
}

/// Pick the best available privilege-escalation method.
/// Order: already-root → doas → sudo → none.
/// `doas` is preferred over `sudo` because on minimal systems (Alpine, Void)
/// it is often the only one installed. `None` is returned when the system has
/// no escalation tool — we deliberately do NOT std::process::exit here so that
/// --dry-run and user-only operations (cache, trash, dev) still work without
/// privileges; the caller decides how to handle the missing helper.
pub fn find_privilege() -> Privilege {
    if crate::utils::is_root() {
        return Privilege::Root;
    }
    if crate::utils::which("doas") {
        return Privilege::Doas;
    }
    if crate::utils::which("sudo") {
        return Privilege::Sudo;
    }
    Privilege::None
}

// ══════════════════════════════════════════════════
//  Disk Detection
// ══════════════════════════════════════════════════

// SSD/HDD/NVMe are universally recognised industry acronyms; the
// idiomatic Rust spellings (Ssd, Hdd, Nv_me) are harder to read.
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiskType {
    NVMe,
    SSD,
    HDD,
    Unknown,
}

/// Pure helper: given the contents of
/// `/sys/block/<name>/queue/rotational` and the block-device name,
/// classify the disk.
///
/// NVMe is detected by name prefix because some NVMe drives report
/// `rotational=1` due to kernel quirks. Anything else falls back to the
/// rotational flag.
pub fn disk_type_from_rotational(rotational: &str, block_name: &str) -> DiskType {
    if block_name.starts_with("nvme") {
        return DiskType::NVMe;
    }
    match rotational.trim() {
        "0" => DiskType::SSD,
        "1" => DiskType::HDD,
        _ => DiskType::Unknown,
    }
}

/// Pure helper: extract the parent block-device name from a device path.
///
/// Examples:
/// * `/dev/sda3`       → `sda`
/// * `/dev/sdb`        → `sdb`
/// * `/dev/nvme0n1p2`  → `nvme0n1`
/// * `/dev/nvme0n1`    → `nvme0n1`
/// * `/dev/mmcblk0p1`  → `mmcblk0`
pub fn extract_block_name(device: &str) -> String {
    let name = device.trim_start_matches("/dev/");

    if name.starts_with("nvme") || name.starts_with("mmcblk") {
        // Strip a trailing `p<digits>` partition suffix if present.
        if let Some(pos) = name.rfind('p') {
            if !name[pos + 1..].is_empty() && name[pos + 1..].chars().all(|c| c.is_ascii_digit()) {
                return name[..pos].to_string();
            }
        }
        return name.to_string();
    }

    // sd*, vd*, hd*: strip trailing digits.
    name.trim_end_matches(|c: char| c.is_ascii_digit())
        .to_string()
}

/// Pure helper: parse `/proc/mounts` content and return the device backing
/// the requested mount point, if any.
pub fn find_mount_device_in(mounts: &str, mount_point: &str) -> Option<String> {
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1] == mount_point {
            return Some(parts[0].to_string());
        }
    }
    None
}

/// Pure helper: given `/proc/mounts` content and a path, decide whether the
/// filesystem backing that path is mounted read-only.
///
/// Uses longest-prefix matching so `/usr` resolves to its own mount if one
/// exists, otherwise to `/`. The `ro`/`rw` flag is the *first* comma-separated
/// mount option (field 4) — we match it as an exact token so `errors=remount-ro`
/// or `relatime` are never mistaken for a read-only flag. Returns `None` when no
/// mount covers the path (caller decides the default).
pub fn path_is_readonly_in(mounts: &str, path: &str) -> Option<bool> {
    let mut best_len = 0usize;
    let mut best_ro: Option<bool> = None;
    for line in mounts.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let mount_point = parts[1];
        let covers = mount_point == "/"
            || mount_point == path
            || path.starts_with(&format!("{mount_point}/"));
        // Keep the longest (most specific) mount that covers the path; on a
        // length tie the later line wins, matching kernel overmount semantics.
        if !covers || mount_point.len() < best_len {
            continue;
        }
        best_len = mount_point.len();
        best_ro = Some(parts[3].split(',').any(|opt| opt == "ro"));
    }
    best_ro
}

/// Detect the type of the disk that hosts `/home` (falling back to `/`).
/// Returns `DiskType::Unknown` if anything can't be read — never panics.
pub fn detect_root_disk_type() -> DiskType {
    let mounts = match fs::read_to_string("/proc/mounts") {
        Ok(c) => c,
        Err(_) => return DiskType::Unknown,
    };

    let device = find_mount_device_in(&mounts, "/home")
        .or_else(|| find_mount_device_in(&mounts, "/"))
        .unwrap_or_default();

    let block_name = extract_block_name(&device);
    if block_name.is_empty() {
        return DiskType::Unknown;
    }

    let rotational = fs::read_to_string(format!("/sys/block/{}/queue/rotational", block_name))
        .unwrap_or_default();

    disk_type_from_rotational(&rotational, &block_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AUR helper table ──

    #[test]
    fn test_trizen_clean_is_aur_scoped() {
        // Regression guard for a real overreach: without `-a`, trizen's clean
        // also runs `pacman -Scc` on the shared pacman cache, wiping every
        // cached package including installed ones. That is --deep behaviour,
        // so a plain run must never trigger it. Both flag sets stay scoped.
        let trizen = AUR_HELPERS.iter().find(|h| h.bin == "trizen").unwrap();
        assert!(trizen.clean.unwrap().contains(&"-Sca"));
        assert!(trizen.deep_clean.unwrap().contains(&"-Scca"));
    }

    #[test]
    fn test_aura_never_uses_a_clean_command() {
        // aura has no command that cleans aura's own cache: `-Sc` passes
        // through to pacman, and `-Cc` needs a mandatory count and also targets
        // the pacman cache. Either would duplicate pkg_cache's `pacman -Sc`
        // while leaving aura's cache untouched, so aura must stay on the
        // prune-by-directory path.
        let aura = AUR_HELPERS.iter().find(|h| h.bin == "aura").unwrap();
        assert!(aura.clean.is_none());
        assert!(aura.deep_clean.is_none());
        assert!(!aura.prune_dirs.is_empty());
    }

    #[test]
    fn test_pruned_dirs_never_include_user_state() {
        // `snapshots/` holds user-saved package restore points that aura's `-B`
        // restores from, and `hashes/` is build bookkeeping — both are state, not
        // cache. Nothing we prune may name either, in the safe or the deep list.
        for h in AUR_HELPERS {
            for dir in h.prune_dirs.iter().chain(h.prune_dirs_deep.iter()) {
                assert_ne!(*dir, "snapshots", "{} would delete restore points", h.bin);
                assert_ne!(*dir, "hashes", "{} would delete build bookkeeping", h.bin);
                assert!(
                    !dir.is_empty() && !dir.contains('/') && !dir.contains(".."),
                    "{} has a prune dir that is not a plain child name: {:?}",
                    h.bin,
                    dir
                );
            }
        }
    }

    #[test]
    fn test_hand_pruned_helpers_never_share_a_dir_between_modes() {
        // A dir listed in both lists would be cleared twice in a --deep run.
        for h in AUR_HELPERS {
            for d in h.prune_dirs_deep {
                assert!(
                    !h.prune_dirs.contains(d),
                    "{} lists {:?} in both prune lists",
                    h.bin,
                    d
                );
            }
        }
    }

    #[test]
    fn test_every_helper_is_cleanable_exactly_one_way() {
        // A helper must either drive its own clean command or be pruned by
        // directory — never both (double work) and never neither (silently
        // reports "already clean" forever).
        for h in AUR_HELPERS {
            let by_command = h.clean.is_some();
            let by_prune = !h.prune_dirs.is_empty();
            assert!(
                by_command != by_prune,
                "{} must be cleaned by exactly one mechanism",
                h.bin
            );
            // Deep flags only make sense alongside a safe counterpart.
            if h.clean.is_none() {
                assert!(h.deep_clean.is_none(), "{} has orphaned deep flags", h.bin);
            }
        }
    }

    #[test]
    fn test_command_helpers_are_noninteractive_and_distinct() {
        // A missing --noconfirm would hang a --yes/cron run waiting on stdin,
        // and a helper whose deep flags equal its safe flags would silently
        // apply deep behaviour to every plain run.
        for h in AUR_HELPERS {
            let (Some(clean), Some(deep)) = (h.clean, h.deep_clean) else {
                continue;
            };
            assert!(
                clean.contains(&"--noconfirm"),
                "{} safe clean would block on stdin",
                h.bin
            );
            assert!(
                deep.contains(&"--noconfirm"),
                "{} deep clean would block on stdin",
                h.bin
            );
            assert_ne!(
                clean, deep,
                "{} would apply deep behaviour on a plain run",
                h.bin
            );
        }
    }

    #[test]
    fn test_aur_helpers_returns_only_installed_in_table_order() {
        // aur_helpers() filters the table by which(); the result must stay a
        // subsequence of the table so output order is deterministic and no
        // unknown binary can appear.
        let found = aur_helpers();
        let table: Vec<&str> = AUR_HELPERS.iter().map(|h| h.bin).collect();
        let mut idx = 0usize;
        for h in &found {
            let pos = table[idx..]
                .iter()
                .position(|b| *b == h.bin)
                .unwrap_or_else(|| panic!("{} is out of table order or unknown", h.bin));
            idx += pos + 1;
        }
    }

    // ── detection logic tests (pure, no I/O) ──

    #[test]
    fn test_detect_arch_direct() {
        let content = "ID=arch\nPRETTY_NAME=\"Arch Linux\"\n";
        assert_eq!(distro_from_str(content), Distro::Arch);
    }

    #[test]
    fn test_detect_cachyos_via_id() {
        // CachyOS sets ID=cachyos directly (not just ID_LIKE)
        let content = "ID=cachyos\nID_LIKE=arch\n";
        assert_eq!(distro_from_str(content), Distro::Arch);
    }

    #[test]
    fn test_detect_derivative_via_id_like() {
        // Distros not in the direct list should fall back to ID_LIKE
        let content = "ID=linuxmint\nID_LIKE=ubuntu debian\n";
        assert_eq!(distro_from_str(content), Distro::Debian);
    }

    #[test]
    fn test_detect_opensuse_variants() {
        // IDs starting with "opensuse" (not exact match) should still map to Suse
        let content = "ID=opensuse-tumbleweed\n";
        assert_eq!(distro_from_str(content), Distro::Suse);
    }

    #[test]
    fn test_detect_unknown_no_panic() {
        let content = "ID=somethingweird\nID_LIKE=alsounknown\n";
        assert_eq!(distro_from_str(content), Distro::Unknown);
    }

    #[test]
    fn test_detect_empty_os_release() {
        let content = "";
        assert_eq!(distro_from_str(content), Distro::Unknown);
    }

    // ── smoke tests for live detection (no panic) ──

    #[test]
    fn test_detection_doesnt_panic() {
        let d = distro();
        assert!(!d.name().is_empty());
    }

    #[test]
    fn test_pretty_name_not_empty() {
        assert!(!pretty_name().is_empty());
    }

    // ── Privilege enum ──

    #[test]
    fn test_privilege_name() {
        assert_eq!(Privilege::Sudo.name(), "sudo");
        assert_eq!(Privilege::Doas.name(), "doas");
        // Root means "no escalation wrapper" — name() must return an empty string
        // so that callers never accidentally exec a binary called "".
        assert_eq!(Privilege::Root.name(), "");
        // None means "no escalation tool exists" — also an empty name so it is
        // never spawned; callers gate on the variant, not the name.
        assert_eq!(Privilege::None.name(), "");
    }

    #[test]
    fn test_privilege_equality() {
        // Privilege is Copy + PartialEq so call sites can compare cheaply.
        let p = Privilege::Doas;
        assert_eq!(p, Privilege::Doas);
        assert_ne!(p, Privilege::Sudo);
        assert_ne!(p, Privilege::Root);
        assert_ne!(p, Privilege::None);
    }

    #[test]
    fn test_find_privilege_doesnt_panic() {
        // Live detection must always return *some* variant — never panic.
        let _ = find_privilege();
    }

    // ── DiskType: rotational parsing (pure) ──

    #[test]
    fn test_disk_type_from_rotational_0() {
        assert_eq!(disk_type_from_rotational("0", "sda"), DiskType::SSD);
    }

    #[test]
    fn test_disk_type_from_rotational_1() {
        assert_eq!(disk_type_from_rotational("1", "sda"), DiskType::HDD);
    }

    #[test]
    fn test_disk_type_rotational_with_trailing_newline() {
        // /sys/block/*/queue/rotational always ends with '\n' — must be trimmed.
        assert_eq!(disk_type_from_rotational("0\n", "sda"), DiskType::SSD);
        assert_eq!(disk_type_from_rotational("1\n", "sda"), DiskType::HDD);
    }

    #[test]
    fn test_disk_type_nvme_by_name() {
        // NVMe is identified by the block-name prefix, regardless of the
        // rotational flag (some buggy NVMe report rotational=1).
        assert_eq!(disk_type_from_rotational("0", "nvme0n1"), DiskType::NVMe);
        assert_eq!(disk_type_from_rotational("1", "nvme0n1"), DiskType::NVMe);
    }

    #[test]
    fn test_disk_type_unknown_on_garbage() {
        assert_eq!(
            disk_type_from_rotational("garbage", "sda"),
            DiskType::Unknown
        );
        assert_eq!(disk_type_from_rotational("", "sda"), DiskType::Unknown);
    }

    // ── block_name extraction (pure) ──

    #[test]
    fn test_extract_block_name_sata() {
        assert_eq!(extract_block_name("/dev/sda3"), "sda");
        assert_eq!(extract_block_name("/dev/sdb"), "sdb");
        assert_eq!(extract_block_name("/dev/sda12"), "sda");
    }

    #[test]
    fn test_extract_block_name_nvme() {
        assert_eq!(extract_block_name("/dev/nvme0n1p2"), "nvme0n1");
        assert_eq!(extract_block_name("/dev/nvme0n1"), "nvme0n1");
        assert_eq!(extract_block_name("/dev/nvme1n1p15"), "nvme1n1");
    }

    #[test]
    fn test_extract_block_name_mmcblk() {
        // SD cards, eMMC.
        assert_eq!(extract_block_name("/dev/mmcblk0p1"), "mmcblk0");
        assert_eq!(extract_block_name("/dev/mmcblk0"), "mmcblk0");
    }

    #[test]
    fn test_extract_block_name_empty() {
        // Empty / unparseable input must not panic and must round-trip cleanly.
        assert_eq!(extract_block_name(""), "");
    }

    // ── find_mount_device_in: pure parsing of /proc/mounts ──

    #[test]
    fn test_find_mount_device_root() {
        let mounts = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/sda2 / ext4 rw,relatime 0 0
/dev/sda3 /home ext4 rw,relatime 0 0
";
        assert_eq!(
            find_mount_device_in(mounts, "/"),
            Some("/dev/sda2".to_string())
        );
        assert_eq!(
            find_mount_device_in(mounts, "/home"),
            Some("/dev/sda3".to_string())
        );
    }

    #[test]
    fn test_find_mount_device_missing() {
        let mounts = "/dev/sda1 / ext4 rw 0 0\n";
        assert_eq!(find_mount_device_in(mounts, "/home"), None);
        assert_eq!(find_mount_device_in("", "/"), None);
    }

    // ── path_is_readonly_in: immutable-system detection (pure) ──

    #[test]
    fn test_readonly_normal_system_is_rw() {
        // Ordinary system: root is rw, /usr has no separate mount → resolves to /.
        let mounts = "\
/dev/sda2 / ext4 rw,relatime 0 0
/dev/sda3 /home ext4 rw,relatime 0 0
";
        assert_eq!(path_is_readonly_in(mounts, "/usr"), Some(false));
    }

    #[test]
    fn test_readonly_dedicated_usr_mount_wins() {
        // Immutable-style layout: /usr is its own read-only mount. Longest-prefix
        // match must pick /usr (ro), not the rw root.
        let mounts = "\
/dev/sda2 / ext4 rw,relatime 0 0
/dev/sda4 /usr ext4 ro,relatime 0 0
";
        assert_eq!(path_is_readonly_in(mounts, "/usr"), Some(true));
    }

    #[test]
    fn test_readonly_root_ro_propagates() {
        // SteamOS-style: the whole rootfs is ro and /usr has no separate mount.
        let mounts = "/dev/sda2 / btrfs ro,relatime 0 0\n";
        assert_eq!(path_is_readonly_in(mounts, "/usr"), Some(true));
    }

    #[test]
    fn test_readonly_ro_token_is_exact() {
        // `errors=remount-ro` and `relatime` must NOT be read as a read-only
        // flag — only the standalone `ro` token counts.
        let mounts = "/dev/sda2 / ext4 rw,errors=remount-ro,relatime 0 0\n";
        assert_eq!(path_is_readonly_in(mounts, "/usr"), Some(false));
    }

    #[test]
    fn test_readonly_no_covering_mount_is_none() {
        // Nothing covers the path (no root, no /usr) → None, so the live
        // detector defaults to "not read-only" and never false-positives.
        let mounts = "proc /proc proc rw 0 0\n";
        assert_eq!(path_is_readonly_in(mounts, "/usr"), None);
        assert_eq!(path_is_readonly_in("", "/usr"), None);
    }

    #[test]
    fn test_readonly_no_false_prefix_match() {
        // A mount at /usrlocal must not be treated as covering /usr.
        let mounts = "\
/dev/sda2 / ext4 rw 0 0
/dev/sda5 /usrlocal ext4 ro 0 0
";
        assert_eq!(path_is_readonly_in(mounts, "/usr"), Some(false));
    }
}
