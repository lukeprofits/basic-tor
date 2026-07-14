"""
Pure unit tests — no network, no tor process. Fast.

Covers everything testable without downloading the bundle or bootstrapping:
platform detection, version gating, checksum lookup + mismatch, host
allowlist, safe archive extraction, control-protocol parsing, sums parsing.
"""

from __future__ import annotations

import io
import tarfile
from unittest import mock

import pytest

import basic_tor
from basic_tor import (
    TorBinaryNotFound,
    _archive_name,
    _candidate_urls,
    _check_redirect_origin,
    _expected_sha256,
    _platform_key,
    _safe_member_name,
    tor_checksums,
)

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "system,machine,expected",
    [
        ("Linux", "x86_64", "linux-x86_64"),
        ("Linux", "amd64", "linux-x86_64"),
        ("Darwin", "arm64", "macos-aarch64"),
        ("Darwin", "aarch64", "macos-aarch64"),
        ("Darwin", "x86_64", "macos-x86_64"),
        ("Windows", "AMD64", "windows-x86_64"),
    ],
)
def test_platform_key_supported(system, machine, expected):
    with mock.patch("platform.system", return_value=system), \
         mock.patch("platform.machine", return_value=machine):
        assert _platform_key() == expected


def test_platform_key_linux_aarch64_points_at_system_tor():
    # Tor ships no linux-aarch64 Expert Bundle; the error must steer users to a
    # system tor rather than dead-ending.
    with mock.patch("platform.system", return_value="Linux"), \
         mock.patch("platform.machine", return_value="aarch64"):
        with pytest.raises(TorBinaryNotFound) as exc:
            _platform_key()
    assert "apt install tor" in str(exc.value) or "PATH" in str(exc.value)


def test_platform_key_unsupported_os():
    with mock.patch("platform.system", return_value="Plan9"), \
         mock.patch("platform.machine", return_value="mips"):
        with pytest.raises(TorBinaryNotFound):
            _platform_key()


# ---------------------------------------------------------------------------
# Version gating + URL construction
# ---------------------------------------------------------------------------


def test_candidate_urls_rejects_malformed_version():
    with mock.patch.object(basic_tor, "TOR_BUNDLE_VERSION", "../../etc/passwd"):
        with pytest.raises(TorBinaryNotFound):
            _candidate_urls()


def test_candidate_urls_accepts_stable_and_alpha():
    for ver in ("15.0.17", "16.0a8", "14.5"):
        with mock.patch.object(basic_tor, "TOR_BUNDLE_VERSION", ver):
            urls = _candidate_urls()
        assert len(urls) == 2
        assert urls[0].startswith("https://dist.torproject.org")
        assert urls[1].startswith("https://archive.torproject.org")
        assert ver in urls[0]


def test_archive_name_matches_tor_naming():
    with mock.patch("platform.system", return_value="Linux"), \
         mock.patch("platform.machine", return_value="x86_64"), \
         mock.patch.object(basic_tor, "TOR_BUNDLE_VERSION", "15.0.17"):
        assert _archive_name() == "tor-expert-bundle-linux-x86_64-15.0.17.tar.gz"


# ---------------------------------------------------------------------------
# Checksums
# ---------------------------------------------------------------------------


def test_known_checksum_present():
    sha = tor_checksums.known_checksum("15.0.17", "linux-x86_64")
    assert sha == "4621e1573dbd6d5d6f4bb4121b37652a8b7204ae5abea600fb6b9e05e5695696"


def test_known_checksum_absent():
    assert tor_checksums.known_checksum("0.0.0", "linux-x86_64") is None
    assert tor_checksums.known_checksum("15.0.17", "solaris-sparc") is None


def test_expected_sha256_refuses_unknown_version():
    # An unknown version must NOT silently fetch a hash from the mirror.
    with mock.patch("platform.system", return_value="Linux"), \
         mock.patch("platform.machine", return_value="x86_64"), \
         mock.patch.object(basic_tor, "TOR_BUNDLE_VERSION", "99.0.0"):
        with pytest.raises(TorBinaryNotFound) as exc:
            _expected_sha256()
    assert "refresh_checksums" in str(exc.value)


# ---------------------------------------------------------------------------
# Host allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "https://dist.torproject.org/torbrowser/15.0.17/x.tar.gz",
    "https://archive.torproject.org/tor-package-archive/torbrowser/15.0.17/x.tar.gz",
    "https://cdn.dist.torproject.org/x",  # subdomain of an allowed host
])
def test_redirect_origin_allowed(url):
    _check_redirect_origin(url)  # must not raise


@pytest.mark.parametrize("url", [
    "https://attacker.example/evil.tar.gz",
    "https://dist.torproject.org.evil.com/x",
    "http://evil/",
    # Plaintext downgrade to an *allowed* host must also be refused.
    "http://dist.torproject.org/torbrowser/15.0.17/x.tar.gz",
])
def test_redirect_origin_rejected(url):
    with pytest.raises(TorBinaryNotFound):
        _check_redirect_origin(url)


# ---------------------------------------------------------------------------
# Safe extraction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["tor/tor", "data/geoip", "a/b/c/d"])
def test_safe_member_name_ok(name):
    assert _safe_member_name(name) is True


@pytest.mark.parametrize("name", [
    "/etc/passwd", "../escape", "tor/../../x", "\\windows", "",
    "a/b/c/d/e/f/g",  # exceeds depth cap
])
def test_safe_member_name_rejected(name):
    assert _safe_member_name(name) is False


def test_extract_bundle_rejects_traversal(tmp_path):
    # A tar with a "../evil" member must be refused before any write.
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="../evil")
        payload = b"x"
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    buf.seek(0)
    archive = tmp_path / "bad.tar.gz"
    archive.write_bytes(buf.getvalue())
    with pytest.raises(TorBinaryNotFound):
        basic_tor._extract_bundle(archive, tmp_path / "out")


def test_extract_bundle_rejects_symlink(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name="tor/link")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        tf.addfile(info)
    buf.seek(0)
    archive = tmp_path / "link.tar.gz"
    archive.write_bytes(buf.getvalue())
    with pytest.raises(TorBinaryNotFound):
        basic_tor._extract_bundle(archive, tmp_path / "out")


def test_extract_bundle_happy_path(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data, mode in [
            ("tor/tor", b"#!binary", 0o755),
            ("data/geoip", b"geoip-data", 0o644),
        ]:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = mode
            tf.addfile(info, io.BytesIO(data))
    buf.seek(0)
    archive = tmp_path / "ok.tar.gz"
    archive.write_bytes(buf.getvalue())
    out = tmp_path / "out"
    basic_tor._extract_bundle(archive, out)
    assert (out / "tor" / "tor").read_bytes() == b"#!binary"
    assert (out / "data" / "geoip").read_bytes() == b"geoip-data"


# ---------------------------------------------------------------------------
# Auto-download rejects a hash mismatch (no real network)
# ---------------------------------------------------------------------------


def test_auto_download_rejects_checksum_mismatch(tmp_path, monkeypatch):
    monkeypatch.setattr(basic_tor, "TOR_BUNDLE_VERSION", "15.0.17")
    monkeypatch.setattr(basic_tor, "_platform_key", lambda: "linux-x86_64")
    monkeypatch.setattr(basic_tor, "_check_disk_space", lambda p: None)

    # Pretend the download succeeded but produced the wrong bytes → wrong hash.
    def fake_download(url, dest, timeout=600):
        dest.write_bytes(b"not the real bundle")
        return "deadbeef" * 8  # 64 hex chars, not the pinned value
    monkeypatch.setattr(basic_tor, "_download", fake_download)

    with pytest.raises(TorBinaryNotFound) as exc:
        basic_tor._auto_download_tor(tmp_path / "install")
    assert "mismatch" in str(exc.value).lower()
    # Nothing left installed.
    assert not (tmp_path / "install" / "tor" / "tor").exists()
