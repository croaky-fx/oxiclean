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
        let content = "ID=someubuntubased\nID_LIKE=ubuntu\n";
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
}
