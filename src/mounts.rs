//! The file systems mounted inside a directory that is about to be emptied.
//!
//! `fs::remove_dir_all`, like `rm -r`, does not stop at a mount point: it goes
//! in and removes what is mounted there, and fails only at the end, when the
//! mount point itself cannot be removed. A cache with something mounted inside
//! it (a bind mount of a project, a network share, a container's volume) lost
//! that something on a run that was only meant to empty a cache.
//!
//! The kernel's own list is the one place that shows every such mount.
//! Comparing device numbers, as `rm --one-file-system` does, misses a bind
//! mount, which is the same file system on both sides of it. The list is read
//! from `/proc/self/mountinfo`, so it is the mounts of the namespace oxiclean
//! itself runs in, which is the one its paths mean.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

const MOUNTINFO: &str = "/proc/self/mountinfo";

/// The mount points of one moment, with their paths as the kernel writes them:
/// real paths, with no symlink in them. A path to ask about has to come from
/// [`fs::canonicalize`], or be built from one, and not merely look right:
/// `/home` is a link to `/var/home` on Fedora Silverblue, and a mount at
/// `/var/home/x/.cache/y` is not found by asking about `/home/x/.cache/y`.
#[derive(Debug, Default)]
pub struct Mounts {
    points: BTreeSet<PathBuf>,
}

impl Mounts {
    /// The mounts there are now. `Err` when the list cannot be read, which is
    /// not the same as there being none.
    pub fn read() -> io::Result<Mounts> {
        Mounts::read_from(Path::new(MOUNTINFO))
    }

    fn read_from(table: &Path) -> io::Result<Mounts> {
        Ok(Mounts::parse(&fs::read(table)?))
    }

    /// One mount to a line: `id parent major:minor root mount-point options
    /// [optional fields] - type source options`. The mount point is the fifth
    /// field, whatever the rest looks like.
    fn parse(table: &[u8]) -> Mounts {
        let mut points = BTreeSet::new();
        for line in table.split(|&byte| byte == b'\n') {
            if let Some(field) = line.split(|&byte| byte == b' ').nth(4) {
                if field.first() == Some(&b'/') {
                    points.insert(PathBuf::from(OsString::from_vec(unescape(field))));
                }
            }
        }
        Mounts { points }
    }

    /// Whether `path` is itself a mount point.
    pub fn is_mount_point(&self, path: &Path) -> bool {
        self.points.contains(path)
    }

    /// The mount points anywhere below `dir`, not counting `dir` itself, in path
    /// order. Everything below a directory sorts right after it, which is what
    /// makes this a lookup and not a pass over the whole list.
    pub fn below<'a>(&'a self, dir: &Path) -> impl Iterator<Item = &'a Path> + 'a {
        let dir = dir.to_path_buf();
        let itself = usize::from(self.points.contains(dir.as_path()));
        self.points
            .range(dir.clone()..)
            .skip(itself)
            .map(PathBuf::as_path)
            .take_while(move |mount| mount.starts_with(&dir))
    }
}

/// The kernel writes a space, a tab, a newline and a backslash in a path as
/// `\040`, `\011`, `\012` and `\134`: a backslash and three octal digits. Anything
/// else is the byte it is, a backslash that starts no such escape included.
fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&byte, tail)) = rest.split_first() {
        match (byte, tail) {
            (b'\\', [a @ b'0'..=b'3', b @ b'0'..=b'7', c @ b'0'..=b'7', ..]) => {
                out.push((a - b'0') * 64 + (b - b'0') * 8 + (c - b'0'));
                rest = &tail[3..];
            }
            _ => {
                out.push(byte);
                rest = tail;
            }
        }
    }
    out
}

#[cfg(test)]
impl Mounts {
    /// A list that says what a test needs it to, without mounting anything.
    pub fn of(points: &[&Path]) -> Mounts {
        Mounts {
            points: points.iter().map(|p| p.to_path_buf()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mounts(points: &[&str]) -> Mounts {
        Mounts::of(&points.iter().map(Path::new).collect::<Vec<_>>())
    }

    fn below(mounts: &Mounts, dir: &str) -> Vec<String> {
        mounts
            .below(Path::new(dir))
            .map(|p| p.display().to_string())
            .collect()
    }

    // Lines as the kernel writes them (Documentation/filesystems/proc.rst has the
    // first two): the mount point is the fifth field, and a root that is not `/`
    // marks a bind mount of a directory.
    const TABLE: &str = "\
22 28 0:21 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
60 1 8:2 / /home/user/.cache/my\\040dir rw,relatime - ext4 /dev/sda2 rw
61 1 8:2 /data /var/home/u/.cache/a\\134b rw,relatime shared:1 master:2 propagate_from:3 - ext4 /dev/sda2 rw
";

    #[test]
    fn test_the_mount_point_is_the_fifth_field_of_a_line() {
        let table = Mounts::parse(TABLE.as_bytes());
        for point in [
            "/sys",
            "/mnt2",
            "/home/user/.cache/my dir",
            "/var/home/u/.cache/a\\b",
        ] {
            assert!(table.is_mount_point(Path::new(point)), "{point}: {table:?}");
        }
        // The root of a bind mount, the device and the file system are not mount points.
        for other in ["/mnt1", "/dev/root", "/dev/sda2", "/data", "/"] {
            assert!(!table.is_mount_point(Path::new(other)), "{other}");
        }
        assert_eq!(table.points.len(), 4);
    }

    #[test]
    fn test_escapes_are_undone_and_nothing_else_is_touched() {
        assert_eq!(unescape(b"/a\\040b"), b"/a b");
        assert_eq!(unescape(b"/a\\011b\\012c"), b"/a\tb\nc");
        assert_eq!(unescape(b"/a\\134b"), b"/a\\b");
        assert_eq!(unescape(b"/a\\134040"), b"/a\\040", "one step, not two");
        // Any byte, so a name that is not UTF-8 comes back as it was.
        assert_eq!(unescape(b"/\\377x"), b"/\xffx");
        // Not an escape: too short, not octal, too big for a byte.
        for plain in [&b"/a\\"[..], b"/a\\04", b"/a\\0x4", b"/a\\400", b"/a\\8"] {
            assert_eq!(unescape(plain), plain);
        }
        assert_eq!(unescape(b""), b"");
    }

    #[test]
    fn test_a_table_that_makes_no_sense_makes_no_mounts() {
        for table in [
            &b""[..],
            b"\n\n",
            b"1 2 3:4 /\n",
            b"1 2 3:4 / relative rw - x y z\n",
            b"garbage",
            b"   \n",
        ] {
            assert!(
                Mounts::parse(table).points.is_empty(),
                "{}",
                String::from_utf8_lossy(table)
            );
        }
        // The last line needs no newline, and a line that is no good costs the others nothing.
        let table = Mounts::parse(b"nonsense\n1 2 3:4 / /a rw - x y z\n5 6 7:8 / /b rw - x y z");
        assert_eq!(table.points.len(), 2);
    }

    #[test]
    fn test_what_is_below_a_directory_is_exactly_what_is_inside_it() {
        let m = mounts(&["/", "/a/b", "/a/b/c", "/a/b/c/d", "/a/b.c", "/a/bb", "/x"]);
        // Inside, however deep, and not the directory itself.
        assert_eq!(below(&m, "/a/b"), ["/a/b/c", "/a/b/c/d"]);
        // A name that only begins the same is a different directory.
        assert_eq!(below(&m, "/a/b/c"), ["/a/b/c/d"]);
        assert_eq!(
            below(&m, "/a"),
            ["/a/b", "/a/b/c", "/a/b/c/d", "/a/b.c", "/a/bb"]
        );
        assert!(below(&m, "/a/b/c/d").is_empty());
        assert!(below(&m, "/a/bbb").is_empty());
        assert!(below(&m, "/nothing/here").is_empty());
        // The root file system is under nothing, and everything else is under it.
        assert!(below(&m, "/home/user/.cache").is_empty());
        assert_eq!(below(&m, "/").len(), 6);
    }

    #[test]
    fn test_a_trailing_slash_is_the_same_directory() {
        let m = mounts(&["/a/b"]);
        assert!(m.is_mount_point(Path::new("/a/b/")));
        assert_eq!(below(&m, "/a/"), ["/a/b"]);
        assert!(below(&m, "/a/b/").is_empty());
    }

    #[test]
    fn test_this_machines_list_can_be_read() {
        let now = Mounts::read().unwrap();
        assert!(!now.points.is_empty());
        assert!(Mounts::read_from(Path::new("/nonexistent/mountinfo")).is_err());
    }
}
