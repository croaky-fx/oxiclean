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
            Self::Arch    => "Arch Linux",
            Self::Debian  => "Debian/Ubuntu",
            Self::Fedora  => "Fedora/RHEL",
            Self::Suse    => "openSUSE/SLES",
            Self::Nix     => "NixOS",
            Self::Void    => "Void Linux",
            Self::Alpine  => "Alpine Linux",
            Self::Gentoo  => "Gentoo",
            Self::Solus   => "Solus",
            Self::Clear   => "Clear Linux",
            Self::Unknown => "Unknown",
        }
    }

    pub fn pkg_manager(&self) -> &str {
        match self {
            Self::Arch    => "pacman",
            Self::Debian  => "apt",
            Self::Fedora  => "dnf/yum",
            Self::Suse    => "zypper",
            Self::Nix     => "nix",
            Self::Void    => "xbps",
            Self::Alpine  => "apk",
            Self::Gentoo  => "portage",
            Self::Solus   => "eopkg",
            Self::Clear   => "swupd",
            Self::Unknown => "N/A",
        }
    }
}

// ═══════════════════════════════════════════════════
//  Detection Logic
// ═══════════════════════════════════════════════════

/// Detect Linux distribution by reading /etc/os-release
pub fn distro() -> Distro {
    let content = match fs::read_to_string("/etc/os-release") {
        Ok(c) => c,
        Err(_) => return Distro::Unknown,
    };

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
        "arch", "manjaro", "endeavouros", "garuda", "artix", "cachyos",
        "arcolinux", "archcraft", "parabola", "hyperbola", "crystal",
        "bluestar", "archbang",
    ];
    const DEBIAN: &[&str] = &[
        "debian", "ubuntu", "linuxmint", "pop", "elementary", "zorin",
        "kali", "parrot", "deepin", "mx", "antix", "lmde", "devuan",
        "raspbian", "neon", "pureos", "tails", "peppermint", "bodhi",
        "sparky", "bunsen",
    ];
    const FEDORA: &[&str] = &[
        "fedora", "rhel", "centos", "rocky", "alma", "nobara",
        "ultramarine", "oracle", "scientific", "amazon", "eurolinux",
    ];
    const SUSE: &[&str] = &[
        "opensuse", "opensuse-leap", "opensuse-tumbleweed",
        "opensuse-microos", "sles", "suse",
    ];

    if ARCH.contains(&id.as_str())   { return Distro::Arch; }
    if DEBIAN.contains(&id.as_str()) { return Distro::Debian; }
    if FEDORA.contains(&id.as_str()) { return Distro::Fedora; }
    if SUSE.contains(&id.as_str()) || id.starts_with("opensuse") {
        return Distro::Suse;
    }

    match id.as_str() {
        "nixos"                      => return Distro::Nix,
        "void"                       => return Distro::Void,
        "alpine" | "postmarketos"    => return Distro::Alpine,
        "gentoo" | "funtoo" | "calculate" => return Distro::Gentoo,
        "solus"                      => return Distro::Solus,
        "clear-linux-os"             => return Distro::Clear,
        _ => {}
    }

    // ── Fallback: ID_LIKE field ──

    if id_like.contains("arch")                            { return Distro::Arch; }
    if id_like.contains("debian") || id_like.contains("ubuntu") { return Distro::Debian; }
    if id_like.contains("fedora") || id_like.contains("rhel")   { return Distro::Fedora; }
    if id_like.contains("suse")                            { return Distro::Suse; }

    Distro::Unknown
}

/// Get PRETTY_NAME from /etc/os-release
pub fn pretty_name() -> String {
    fs::read_to_string("/etc/os-release")
    .ok()
    .and_then(|c| {
        c.lines()
        .find(|l| l.starts_with("PRETTY_NAME="))
        .map(|l| {
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

    #[test]
    fn test_distro_names() {
        assert_eq!(Distro::Arch.name(), "Arch Linux");
        assert_eq!(Distro::Debian.name(), "Debian/Ubuntu");
        assert_eq!(Distro::Fedora.name(), "Fedora/RHEL");
        assert_eq!(Distro::Unknown.name(), "Unknown");
    }

    #[test]
    fn test_pkg_managers() {
        assert_eq!(Distro::Arch.pkg_manager(), "pacman");
        assert_eq!(Distro::Debian.pkg_manager(), "apt");
        assert_eq!(Distro::Unknown.pkg_manager(), "N/A");
    }

    #[test]
    fn test_detection_doesnt_panic() {
        let d = distro();
        assert!(!d.name().is_empty());
    }

    #[test]
    fn test_pretty_name_not_empty() {
        assert!(!pretty_name().is_empty());
    }

    #[test]
    fn test_distro_equality() {
        assert_eq!(Distro::Arch, Distro::Arch);
        assert_ne!(Distro::Arch, Distro::Debian);
    }

    #[test]
    fn test_distro_clone() {
        let d = Distro::Arch;
        assert_eq!(d, d.clone());
    }
}
