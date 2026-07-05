#!/bin/sh
set -eu

REPO="croaky-fx/oxiclean"
BIN="oxiclean"
DEST="/usr/local/bin"

RED=''
GRN=''
YLW=''
BLD=''
RST=''
if [ -t 1 ]; then
	RED="$(printf '\033[31m')"
	GRN="$(printf '\033[32m')"
	YLW="$(printf '\033[33m')"
	BLD="$(printf '\033[1m')"
	RST="$(printf '\033[0m')"
fi

info() { printf '%s==>%s %s\n' "$BLD" "$RST" "$1"; }
ok() { printf '  %s✔%s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '  %s!%s %s\n' "$YLW" "$RST" "$1" >&2; }
die() {
	printf '  %serror:%s %s\n' "$RED" "$RST" "$1" >&2
	exit 1
}

need() {
	command -v "$1" >/dev/null 2>&1
}

detect_arch() {
	arch="$(uname -m)"
	case "$arch" in
	x86_64 | amd64) echo "x86_64" ;;
	aarch64 | arm64) echo "aarch64" ;;
	*) die "unsupported architecture: $arch (prebuilt binaries are x86_64 and aarch64 only — build from source with: cargo install --git https://github.com/${REPO})" ;;
	esac
}

detect_libc() {
	if [ -n "${OXICLEAN_LIBC:-}" ]; then
		echo "$OXICLEAN_LIBC"
		return
	fi
	for f in /lib/libc.musl-*.so.1 /lib/ld-musl-*.so.1; do
		if [ -e "$f" ]; then
			echo "musl"
			return
		fi
	done
	if need ldd && ldd /usr/bin/env 2>&1 | grep -qi musl; then
		echo "musl"
		return
	fi
	if need getconf && getconf GNU_LIBC_VERSION >/dev/null 2>&1; then
		echo "gnu"
		return
	fi
	if need ldd && ldd --version 2>&1 | grep -qi 'gnu\|glibc'; then
		echo "gnu"
		return
	fi
	echo "gnu"
}

fetch() {
	url="$1"
	out="$2"
	if need curl; then
		curl -fsSL "$url" -o "$out"
	elif need wget; then
		wget -qO "$out" "$url"
	else
		die "need curl or wget to download"
	fi
}

is_elf() {
	head -c 4 "$1" 2>/dev/null | grep -q "$(printf '\177ELF')"
}

main() {
	[ "$(uname -s)" = "Linux" ] || die "OxiClean only runs on Linux"
	need install || die "'install' command not found (coreutils)"
	need uname || die "'uname' not found"

	arch="$(detect_arch)"
	libc="$(detect_libc)"
	info "Detected: ${BLD}${arch}${RST} / ${BLD}${libc}${RST}"

	asset="${BIN}-${arch}-linux-${libc}"
	url="https://github.com/${REPO}/releases/latest/download/${asset}"

	tmp="$(mktemp -d "${TMPDIR:-/tmp}/oxiclean.XXXXXX")"
	trap 'rm -rf "$tmp"' EXIT INT TERM
	bin="$tmp/$BIN"

	info "Downloading latest release ($asset)..."
	fetch "$url" "$bin" || die "download failed — check your connection or the release exists at github.com/${REPO}/releases/latest"
	[ -s "$bin" ] || die "downloaded file is empty"
	is_elf "$bin" || die "downloaded file is not a valid Linux binary (got HTML or a partial download?)"
	chmod +x "$bin"
	ok "Downloaded $(wc -c <"$bin" | tr -d ' ') bytes"

	got_ver="$("$bin" --version 2>/dev/null || true)"
	[ -n "$got_ver" ] || die "downloaded binary did not run — libc mismatch? try: OXICLEAN_LIBC=musl sh install.sh"

	info "Installing to ${BLD}${DEST}/${BIN}${RST}..."
	if [ -w "$DEST" ]; then
		install -Dm755 "$bin" "$DEST/$BIN"
	else
		warn "$DEST needs root — you'll be prompted for your password"
		if need sudo; then
			sudo install -Dm755 "$bin" "$DEST/$BIN"
		elif need doas; then
			doas install -Dm755 "$bin" "$DEST/$BIN"
		else
			die "no sudo or doas found, and $DEST is not writable"
		fi
	fi

	if [ -x "$DEST/$BIN" ]; then
		ok "Installed ${BLD}${got_ver}${RST}"
		case ":$PATH:" in
		*":$DEST:"*) : ;;
		*) warn "$DEST is not in your PATH — add it to your shell profile" ;;
		esac
		printf '\n  Run %soxiclean --help%s to get started.\n\n' "$BLD" "$RST"
	else
		die "installation failed — $DEST/$BIN not found after install"
	fi
}

main "$@"
