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

/// Detect available AUR helper (Arch-based only)
pub fn aur_helper() -> Option<&'static str> {
    ["paru", "yay", "trizen", "pikaur", "aura"]
        .iter()
        .copied()
        .find(|h| crate::utils::which(h))
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
