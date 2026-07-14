#!/usr/bin/env python3
"""
Refresh src/basic_tor/tor_checksums.py for a Tor Expert Bundle version.

Fetches the Tor Project's signed sha256sums file for a Tor Browser release,
GPG-verifies it against the pinned Tor Browser Developers signing key, extracts
the tor-expert-bundle hashes for the supported platforms, and rewrites the
CHECKSUMS table.

Unlike Kubo (which basic_ipfs cross-checks between two origins), Tor publishes a
single sums file per release — but it ships a detached OpenPGP signature, which
is a *stronger* second factor than a second download mirror. GPG verification
here is the trust gate; runtime verification in basic_tor stays checksum-only
and needs no GPG.

Usage:
    python scripts/refresh_checksums.py 15.0.17

Requires `gpg` on PATH with the Tor Browser Developers key imported:
    gpg --auto-key-locate nodefault,wkd --locate-keys torbrowser@torproject.org
    # or:
    gpg --keyserver keys.openpgp.org --recv-keys \
        EF6E286DDA85EA2A4BA7DE684E2C6E8793298290

Run this before bumping basic_tor.TOR_BUNDLE_VERSION. Verify the diff, then commit.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

DIST = "https://dist.torproject.org/torbrowser"
ARCHIVE = "https://archive.torproject.org/tor-package-archive/torbrowser"

# Tor Browser Developers signing key. Matches what the Tor Project documents at
# https://support.torproject.org/tbb/how-to-verify-signature/
TOR_SIGNING_FPR = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"

# Platforms basic_tor auto-downloads. Order preserved in the generated table.
PLATFORMS = ("linux-x86_64", "macos-x86_64", "macos-aarch64", "windows-x86_64")

SUMS_NAME = "sha256sums-signed-build.txt"


def _get(url: str) -> bytes:
    r = requests.get(url, timeout=60, allow_redirects=True)
    r.raise_for_status()
    return r.content


def _fetch_with_fallback(version: str, name: str) -> bytes:
    last: Exception | None = None
    for base in (DIST, ARCHIVE):
        try:
            return _get(f"{base}/{version}/{name}")
        except requests.RequestException as exc:
            last = exc
    raise SystemExit(f"could not fetch {name} for {version} from dist or archive: {last}")


def gpg_verify(sums: bytes, sig: bytes) -> None:
    if not _have_gpg():
        raise SystemExit(
            "gpg not found on PATH. Install GnuPG and import the Tor Browser "
            "Developers key, or rerun with --no-gpg (NOT recommended)."
        )
    if not _key_present():
        raise SystemExit(
            f"Tor Browser Developers key {TOR_SIGNING_FPR} is not in your GPG keyring.\n"
            f"Import it, then retry:\n"
            f"  gpg --keyserver keys.openpgp.org --recv-keys {TOR_SIGNING_FPR}"
        )
    with tempfile.TemporaryDirectory() as td:
        sums_path = Path(td) / SUMS_NAME
        sig_path = Path(td) / (SUMS_NAME + ".asc")
        sums_path.write_bytes(sums)
        sig_path.write_bytes(sig)
        proc = subprocess.run(
            ["gpg", "--status-fd", "1", "--verify", str(sig_path), str(sums_path)],
            capture_output=True, text=True,
        )
    out = proc.stdout + proc.stderr
    # Require a GOODSIG/VALIDSIG from the expected fingerprint. Checking the
    # return code alone is not enough — a valid signature from the *wrong* key
    # would also exit 0.
    if f"VALIDSIG {TOR_SIGNING_FPR}" not in out and TOR_SIGNING_FPR not in out:
        raise SystemExit(f"GPG verification failed or wrong signer:\n{out}")
    if "Good signature" not in out and "GOODSIG" not in out:
        raise SystemExit(f"GPG did not report a good signature:\n{out}")
    print(f"GPG signature OK (signed by {TOR_SIGNING_FPR}).")


def _have_gpg() -> bool:
    try:
        subprocess.run(["gpg", "--version"], capture_output=True, check=True)
        return True
    except (OSError, subprocess.CalledProcessError):
        return False


def _key_present() -> bool:
    proc = subprocess.run(
        ["gpg", "--list-keys", TOR_SIGNING_FPR], capture_output=True, text=True
    )
    return proc.returncode == 0


def parse_sums(sums_text: str, version: str) -> dict[str, str]:
    """Pull the tor-expert-bundle sha256 for each supported platform."""
    wanted = {
        plat: f"tor-expert-bundle-{plat}-{version}.tar.gz" for plat in PLATFORMS
    }
    found: dict[str, str] = {}
    by_name = {}
    for line in sums_text.splitlines():
        parts = line.split()
        if len(parts) == 2 and len(parts[0]) == 64:
            by_name[parts[1]] = parts[0].lower()
    for plat, fname in wanted.items():
        sha = by_name.get(fname)
        if not sha or not re.fullmatch(r"[0-9a-f]{64}", sha):
            raise SystemExit(f"no valid sha256 for {fname} in {SUMS_NAME}")
        found[plat] = sha
    return found


def update_table(version: str, shas: dict[str, str]) -> None:
    path = Path(__file__).resolve().parent.parent / "src" / "basic_tor" / "tor_checksums.py"
    text = path.read_text()

    block = f'    "{version}": {{\n'
    for plat in PLATFORMS:
        block += f'        "{plat}": "{shas[plat]}",\n'
    block += "    },"

    pattern = re.compile(rf'    "{re.escape(version)}":\s*\{{[^}}]*\}},?', re.DOTALL)
    if pattern.search(text):
        text = pattern.sub(block.rstrip(","), text)
    else:
        text = re.sub(
            r"(CHECKSUMS:\s*dict\[str,\s*dict\[str,\s*str\]\]\s*=\s*\{)",
            r"\1\n" + block,
            text,
            count=1,
        )
    path.write_text(text)
    print(f"Updated {path} with {version}:")
    for plat in PLATFORMS:
        print(f"  {plat:<14} {shas[plat][:16]}…")


def main() -> int:
    p = argparse.ArgumentParser(description="Refresh tor_checksums.py for a Tor bundle version")
    p.add_argument("version", help="Tor Browser release, e.g. 15.0.17")
    p.add_argument("--no-gpg", action="store_true",
                   help="skip GPG signature verification (NOT recommended)")
    args = p.parse_args()
    version = args.version.lstrip("v")

    print(f"Fetching {SUMS_NAME} for {version}…")
    sums = _fetch_with_fallback(version, SUMS_NAME)

    if args.no_gpg:
        print("WARNING: skipping GPG verification (--no-gpg). The recorded hashes "
              "are only as trustworthy as your TLS connection to the mirror.")
    else:
        sig = _fetch_with_fallback(version, SUMS_NAME + ".asc")
        gpg_verify(sums, sig)

    shas = parse_sums(sums.decode("utf-8", errors="replace"), version)
    update_table(version, shas)
    print("\nDone. Review the diff, then bump TOR_BUNDLE_VERSION in "
          "src/basic_tor/__init__.py and commit.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
