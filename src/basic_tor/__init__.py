"""
basic_tor — stupid-simple, trustworthy Tor for Python.

Runs the *official* Tor binary (the Tor Expert Bundle that Tor Browser and
OnionShare ship) under the hood. Auto-downloads and verifies it on first use,
launches it with its own data directory and a dedicated local SOCKS port, and
hands you back a proxy URL any SOCKS-aware client can use.

This package does **not** reimplement Tor. It manages the real thing — same
trust as Tor Browser — so you get the actual Tor network, not a pure-Python
approximation.

Quick start::

    import basic_tor
    import requests

    proxy = basic_tor.ensure_running()        # "socks5h://127.0.0.1:<port>"
    r = requests.get("https://check.torproject.org/api/ip",
                     proxies={"http": proxy, "https": proxy})
    print(r.json())                           # {"IsTor": true, ...}

    basic_tor.new_identity()                  # request a fresh circuit
    basic_tor.stop()                          # or just let atexit handle it

The tor process starts lazily on the first call and stops cleanly on process
exit. First run needs internet to fetch the bundle (~30 MB) and takes 10-60 s
to bootstrap; later runs reuse the cached consensus and start in a few seconds.
"""

from __future__ import annotations

import atexit
import datetime
import hashlib
import hmac
import json
import logging
import os
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
from pathlib import Path
from typing import Any, NoReturn
from urllib.parse import urljoin, urlparse

import requests
from platformdirs import user_data_dir

from . import tor_checksums
from ._control import TorControlClient, TorControlError

try:
    from importlib.metadata import PackageNotFoundError
    from importlib.metadata import version as _pkg_version

    __version__ = _pkg_version("basic-tor")
except PackageNotFoundError:
    __version__ = "0+unknown"

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration — assign before the first API call to override
# ---------------------------------------------------------------------------

APP_NAME = "basic_tor"

# Pinned Tor Browser release that names the Expert Bundle archive. The tor
# *daemon* inside has its own version (0.4.x); read that at runtime via
# tor_version(). To bump: change this, run scripts/refresh_checksums.py, commit.
TOR_BUNDLE_VERSION = "15.0.17"

# Official Tor distribution. dist prunes old releases within weeks of a new
# stable; archive keeps everything. We try dist first, then fall back to
# archive so a pinned version keeps installing after it rotates off dist.
_DIST_BASE = "https://dist.torproject.org/torbrowser"
_ARCHIVE_BASE = "https://archive.torproject.org/tor-package-archive/torbrowser"

# Hostnames a download is permitted to touch or redirect to. TLS already
# catches a MitM, but pinning the origin means a 30x to attacker.example fails
# instead of relying on the SHA-256 check alone.
_ALLOWED_DOWNLOAD_HOSTS = ("dist.torproject.org", "archive.torproject.org")

# Dedicated local SOCKS port. None → let tor pick a free port ("auto") and we
# discover it via the control port; the returned socks_url() always reflects
# the real port, so callers never hardcode it. Set to a fixed int (e.g. 9052)
# if you need a stable port. 9052 avoids system Tor (9050) and Tor Browser
# (9150). We always bind to 127.0.0.1 only.
SOCKS_PORT: int | None = None

# Where tor keeps its DataDirectory (state, cached consensus, control cookie).
# None → platformdirs.user_data_dir(APP_NAME)/tor_data. Persistent by default
# so warm starts are fast.
DATA_DIR: Path | None = None

# Seconds to wait for tor to bootstrap to 100% (separate from the download
# timeout below). Cold first-run bootstrap can take 10-60 s.
BOOTSTRAP_TIMEOUT = 120.0

# Seconds allowed for the one-time bundle download.
_DOWNLOAD_TIMEOUT = 600

# Free-space buffer required before auto-download (~30 MB archive, ~100 MB
# extracted tree, plus consensus cache headroom).
_INSTALL_FREE_BYTES = 300 * 1024 * 1024

# tor's notice log, kept inside the data dir for easy bug reports.
_TOR_LOG_NAME = "tor.log"

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class TorError(RuntimeError):
    """Base class for everything this package raises."""


class TorBinaryNotFound(TorError):
    """Tor binary missing and auto-download failed (or platform unsupported)."""


class TorBootstrapTimeout(TorError):
    """tor did not reach 'Bootstrapped 100%' in time."""


class TorDataDirLocked(TorError):
    """The DataDirectory is locked by another running tor process."""


# Re-export so callers can catch control failures without importing the private
# module. (TorControlError is defined in _control to keep that module standalone.)
__all__ = [
    "ensure_running", "start", "is_running", "socks_url", "new_identity", "stop",
    "tor_version",
    "TorError", "TorBinaryNotFound", "TorBootstrapTimeout", "TorDataDirLocked",
    "TorControlError",
    "TOR_BUNDLE_VERSION", "SOCKS_PORT", "DATA_DIR", "BOOTSTRAP_TIMEOUT",
]

# ---------------------------------------------------------------------------
# Platform detection
# ---------------------------------------------------------------------------


def _base_dir() -> Path:
    """Package directory — respects PyInstaller one-file bundles."""
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


# Platform keys match the Tor Expert Bundle archive naming exactly
# (tor-expert-bundle-<key>-<version>.tar.gz), so there is no amd64/x86_64
# translation layer to get wrong.
_SUPPORTED_PLATFORMS = ("linux-x86_64", "macos-x86_64", "macos-aarch64", "windows-x86_64")


def _platform_key() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        if machine in ("x86_64", "amd64"):
            return "linux-x86_64"
        if machine in ("aarch64", "arm64"):
            # The Tor Project does not publish a linux-aarch64 Expert Bundle.
            _raise_use_system_tor(system, machine, "linux ARM64")
        _raise_use_system_tor(system, machine, f"linux/{machine}")
    if system == "darwin":
        if machine in ("arm64", "aarch64"):
            return "macos-aarch64"
        if machine in ("x86_64", "amd64"):
            return "macos-x86_64"
    if system == "windows":
        if machine in ("amd64", "x86_64"):
            return "windows-x86_64"

    _raise_use_system_tor(system, machine, f"{system}/{machine}")


def _raise_use_system_tor(system: str, machine: str, label: str) -> NoReturn:
    """Raise a helpful error for a platform with no Expert Bundle.

    We can still run if the user has a system tor on PATH — that path is tried
    before download in _find_or_install_tor — so point them at it rather than
    dead-ending.
    """
    hint = "sudo apt install tor" if system == "linux" else "install tor via your package manager"
    manual = Path(user_data_dir(APP_NAME)) / "bin" / f"{system}-{machine}" / _binary_name()
    raise TorBinaryNotFound(
        f"No official Tor Expert Bundle for {label}.\n"
        f"  Supported for auto-download: {', '.join(_SUPPORTED_PLATFORMS)}.\n"
        f"  basic_tor will use a `tor` binary already on your PATH if present —\n"
        f"    {hint}\n"
        f"  or place a tor binary manually at:\n"
        f"    {manual}"
    )


def _binary_name() -> str:
    return "tor.exe" if sys.platform == "win32" else "tor"


# ---------------------------------------------------------------------------
# Install paths
# ---------------------------------------------------------------------------


def _install_root() -> Path:
    """Where this version's extracted bundle tree lives.

    Versioned so bumping TOR_BUNDLE_VERSION installs alongside the old tree
    rather than mutating it in place. Written under user_data_dir, never into
    site-packages (a trust boundary owned by the package manager).
    """
    return Path(user_data_dir(APP_NAME)) / "tor" / TOR_BUNDLE_VERSION / _platform_key()


def _user_binary_path() -> Path:
    return _install_root() / "tor" / _binary_name()


def _bundled_binary_path() -> Path:
    """Path inside the installed wheel — for pre-placed binaries
    (PyInstaller / Briefcase / air-gapped deploys)."""
    return _base_dir() / "bin" / _platform_key() / "tor" / _binary_name()


def _geoip_paths(root: Path) -> tuple[Path, Path]:
    return root / "data" / "geoip", root / "data" / "geoip6"


def _get_data_dir() -> Path:
    if DATA_DIR is not None:
        return Path(DATA_DIR)
    return Path(user_data_dir(APP_NAME)) / "tor_data"


# ---------------------------------------------------------------------------
# Download + verify + extract
# ---------------------------------------------------------------------------


# Tor Browser versions look like "15.0.17" or "16.0a8". We interpolate this
# into a URL, so anything outside this shape (traversal, query injection,
# whitespace) is rejected before it reaches the network.
_VERSION_RE = re.compile(r"^\d+\.\d+(\.\d+)?([ab]\d+)?$")

# Hardening caps for extraction. The real bundle is ~100 MB extracted across a
# shallow tree; anything materially larger or deeper is suspect.
_MAX_MEMBER_BYTES = 256 * 1024 * 1024
_MAX_PATH_DEPTH = 6
# Ceiling on the streamed download itself, independent of the per-member cap.
_MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024


def _archive_name() -> str:
    return f"tor-expert-bundle-{_platform_key()}-{TOR_BUNDLE_VERSION}.tar.gz"


def _candidate_urls() -> list[str]:
    if not _VERSION_RE.match(TOR_BUNDLE_VERSION):
        raise TorBinaryNotFound(
            f"Refusing to download with malformed TOR_BUNDLE_VERSION "
            f"{TOR_BUNDLE_VERSION!r}. Expected something like '15.0.17' or '16.0a8'."
        )
    name = _archive_name()
    return [
        f"{_DIST_BASE}/{TOR_BUNDLE_VERSION}/{name}",
        f"{_ARCHIVE_BASE}/{TOR_BUNDLE_VERSION}/{name}",
    ]


def _check_redirect_origin(final_url: str) -> None:
    parsed = urlparse(final_url)
    # Scheme pin as well as host pin: a 30x downgrade to plain http on an
    # *allowed* host would otherwise hand the transfer to any on-path MitM.
    # The SHA-256 gate still rejects bad bytes, but there is no reason to
    # ever fetch over plaintext.
    if parsed.scheme != "https":
        raise TorBinaryNotFound(
            f"Refusing non-HTTPS download URL {final_url!r}."
        )
    host = (parsed.hostname or "").lower()
    for allowed in _ALLOWED_DOWNLOAD_HOSTS:
        if host == allowed or host.endswith("." + allowed):
            return
    raise TorBinaryNotFound(
        f"Refusing to follow redirect to unexpected host {host!r}. "
        f"Allowed: {', '.join(_ALLOWED_DOWNLOAD_HOSTS)}."
    )


class _PinnedRedirectAdapter(requests.adapters.HTTPAdapter):
    """HTTP adapter that re-checks the host pin at every redirect hop.

    Plain ``allow_redirects=True`` only lets us inspect the *final* URL — a 30x
    chain through attacker.example (with valid TLS) would still leak request
    headers before landing back on a trusted host. Walk the chain manually and
    enforce the origin pin on each hop.
    """

    def send(self, request, **kwargs):  # type: ignore[override]
        # HTTPAdapter.send performs a single request (it never follows
        # redirects itself — that is normally the Session's job). We walk the
        # chain here instead so the host pin is enforced on every hop, then
        # return the final response; the Session sees a non-redirect and stops.
        kwargs.pop("allow_redirects", None)
        resp = super().send(request, **kwargs)
        seen = 0
        while resp.is_redirect and seen < 30:
            seen += 1
            next_url = resp.headers.get("Location", "")
            if not next_url:
                break
            next_url = urljoin(resp.url, next_url)
            _check_redirect_origin(next_url)
            try:
                resp.close()
            except Exception:
                pass
            new_req = request.copy()
            new_req.url = next_url
            resp = super().send(new_req, **kwargs)
        return resp


def _download_session() -> requests.Session:
    try:
        from urllib3.util.retry import Retry
    except ImportError:  # very old urllib3
        from requests.packages.urllib3.util.retry import Retry  # type: ignore

    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=(502, 503, 504, 520, 522, 524),
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = _PinnedRedirectAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _download(url: str, dest: Path, timeout: int = _DOWNLOAD_TIMEOUT) -> str:
    """Stream ``url`` into ``dest``, returning the SHA-256 hex digest.

    Streams to disk and hashes incrementally, aborting early if the byte count
    exceeds _MAX_DOWNLOAD_BYTES — the hash check is still the fail-closed gate,
    this just bounds the resource cost of a hostile or misconfigured origin.
    """
    logger.info("Downloading %s", url)
    hasher = hashlib.sha256()
    received = 0
    last_pct = -1
    dest.parent.mkdir(parents=True, exist_ok=True)
    with _download_session() as session, session.get(url, stream=True, timeout=timeout) as r:
        _check_redirect_origin(r.url)
        r.raise_for_status()
        total = int(r.headers.get("Content-Length", 0))
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(chunk_size=1 << 16):
                if not chunk:
                    continue
                received += len(chunk)
                if received > _MAX_DOWNLOAD_BYTES:
                    raise TorBinaryNotFound(
                        f"Refusing to download more than {_MAX_DOWNLOAD_BYTES} bytes "
                        f"from {url}. Origin misbehaving or version points at something "
                        f"unexpected."
                    )
                hasher.update(chunk)
                fh.write(chunk)
                if total:
                    pct = received * 100 // total
                    if pct >= last_pct + 10:
                        logger.info("  %3d%%  (%d / %d bytes)", pct, received, total)
                        last_pct = pct
    return hasher.hexdigest().lower()


def _expected_sha256() -> str:
    """The SHA-256 we require for this version+platform.

    Only the baked-in table is trusted. Fetching the companion sums file from
    the same origin is refused: whoever controls the mirror controls both. New
    versions must have their hash committed to tor_checksums.py first.
    """
    baked = tor_checksums.known_checksum(TOR_BUNDLE_VERSION, _platform_key())
    if baked is not None:
        return baked.lower()
    raise TorBinaryNotFound(
        f"No baked-in SHA-256 for Tor bundle {TOR_BUNDLE_VERSION}/{_platform_key()}. "
        f"Refusing to fetch a digest from the same origin as the archive — that "
        f"defeats verification. Run scripts/refresh_checksums.py {TOR_BUNDLE_VERSION} "
        f"and reinstall, or pin basic_tor.TOR_BUNDLE_VERSION to a version already "
        f"in the table."
    )


def _safe_member_name(name: str) -> bool:
    if not name or name.startswith(("/", "\\")):
        return False
    p = Path(name)
    if p.is_absolute():
        return False
    parts = p.parts
    if not 0 < len(parts) <= _MAX_PATH_DEPTH:
        return False
    return all(part != ".." for part in parts)


def _extract_bundle(archive_path: Path, dest_root: Path) -> None:
    """Extract the whole Expert Bundle tree under ``dest_root``.

    The bundle is a *tree*, not a lone binary: tor/tor ships alongside its
    bundled libcrypto/libssl/libevent (found at runtime via $ORIGIN rpath),
    data/geoip{,6}, and the pluggable transports. Plucking out just the binary
    would break dynamic linking, so extract everything — but validate every
    member (no absolute paths, no traversal, regular files/dirs only, size
    capped) before writing.
    """
    dest_root.mkdir(parents=True, exist_ok=True)
    with tarfile.open(str(archive_path), mode="r:gz") as tf:
        members = tf.getmembers()
        for m in members:
            if not (m.isfile() or m.isdir()):
                raise TorBinaryNotFound(
                    f"Refusing archive member of unexpected type "
                    f"({'symlink' if m.issym() or m.islnk() else 'special'}): {m.name!r}"
                )
            if not _safe_member_name(m.name):
                raise TorBinaryNotFound(f"Refusing archive member with unsafe path: {m.name!r}")
            if m.isfile() and m.size > _MAX_MEMBER_BYTES:
                raise TorBinaryNotFound(
                    f"Archive member {m.name!r} is {m.size} bytes — exceeds the "
                    f"{_MAX_MEMBER_BYTES}-byte cap."
                )
        for m in members:
            target = dest_root / m.name
            if m.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            src = tf.extractfile(m)
            if src is None:
                continue
            with src, open(target, "wb") as out:
                shutil.copyfileobj(src, out, length=1 << 16)
            # Preserve the executable bit from the archive so tor and the
            # pluggable-transport binaries stay runnable.
            if m.mode & 0o111:
                target.chmod(target.stat().st_mode | stat.S_IXUSR)


def _check_disk_space(target: Path) -> None:
    probe = target
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    try:
        free = shutil.disk_usage(probe).free
    except OSError:
        return  # best-effort
    if free < _INSTALL_FREE_BYTES:
        raise TorBinaryNotFound(
            f"Not enough disk space to install Tor: {free // (1024 * 1024)} MB free at "
            f"{probe}, need at least {_INSTALL_FREE_BYTES // (1024 * 1024)} MB."
        )


def _write_provenance(root: Path, url: str, sha256_hex: str) -> None:
    prov = root / ".provenance.json"
    data = {
        "bundle_version": TOR_BUNDLE_VERSION,
        "url": url,
        "sha256": sha256_hex,
        "verification": "baked-in",
        "installed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": _platform_key(),
    }
    try:
        prov.write_text(json.dumps(data, indent=2))
    except OSError:
        pass


def _auto_download_tor(root: Path) -> None:
    urls = _candidate_urls()
    expected = _expected_sha256()
    _check_disk_space(root.parent)

    root.mkdir(parents=True, exist_ok=True)
    archive_tmp = root / (_archive_name() + ".partial")
    archive_tmp.unlink(missing_ok=True)

    used_url = ""
    last_exc: Exception | None = None
    for url in urls:
        try:
            actual = _download(url, archive_tmp)
        except (requests.RequestException, OSError) as exc:
            last_exc = exc
            logger.info("download from %s failed (%s) — trying next mirror", url, exc)
            archive_tmp.unlink(missing_ok=True)
            continue
        if not hmac.compare_digest(actual, expected):
            archive_tmp.unlink(missing_ok=True)
            raise TorBinaryNotFound(
                f"SHA-256 mismatch for Tor bundle {TOR_BUNDLE_VERSION} ({_platform_key()}): "
                f"expected {expected}, got {actual}. Refusing to install an unverified binary."
            )
        used_url = url
        break
    else:
        raise TorBinaryNotFound(
            f"Failed to download Tor bundle {TOR_BUNDLE_VERSION} for {_platform_key()} "
            f"from any mirror ({', '.join(_ALLOWED_DOWNLOAD_HOSTS)}): {last_exc}"
        ) from last_exc

    # Extract into a sibling staging dir, then atomic-rename the tree into place
    # so an interrupted extract never leaves a half-populated install.
    staging = root.parent / (root.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    try:
        _extract_bundle(archive_tmp, staging)
        binary = staging / "tor" / _binary_name()
        if not binary.exists():
            raise TorBinaryNotFound(
                f"tor binary not found inside bundle for {_platform_key()} "
                f"(expected tor/{_binary_name()})."
            )
        if root.exists():
            shutil.rmtree(root, ignore_errors=True)
        os.replace(staging, root)
    finally:
        archive_tmp.unlink(missing_ok=True)
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)

    _write_provenance(root, used_url, expected)
    logger.info("Tor bundle %s installed at %s (verified via baked-in SHA-256)",
                TOR_BUNDLE_VERSION, root)


def _find_or_install_tor() -> Path:
    """user_data_dir install → bundled wheel → system PATH → auto-download.

    A pre-placed binary in user_data_dir wins so air-gapped/pre-vetted installs
    are honoured; a wheel-bundled tree wins next (PyInstaller/Briefcase); then a
    system ``tor`` on PATH (the only route on unsupported platforms like
    linux-aarch64); finally auto-download.
    """
    user = _user_binary_path()
    if user.exists():
        _ensure_exec(user)
        return user

    bundled = _bundled_binary_path()
    if bundled.exists():
        _ensure_exec(bundled)
        return bundled

    on_path = shutil.which("tor")
    if on_path:
        logger.info("Using system-installed tor at %s", on_path)
        return Path(on_path)

    logger.info("Tor binary not found locally — downloading bundle %s…", TOR_BUNDLE_VERSION)
    _auto_download_tor(_install_root())
    return _user_binary_path()


def _ensure_exec(path: Path) -> None:
    try:
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
    except OSError as exc:
        logger.warning("could not chmod %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _secure_mkdir(path: Path, mode: int = 0o700) -> None:
    """Create ``path`` (and parents) with restrictive ``mode`` on POSIX.

    tor refuses to use a DataDirectory that is group/world accessible, and the
    control auth cookie inside it must stay private, so 0700 is both a security
    property and a correctness requirement.
    """
    path = Path(path)
    if path.exists():
        if os.name == "posix":
            try:
                os.chmod(path, mode)
            except OSError:
                pass
        return
    parent = path.parent
    if parent != path and not parent.exists():
        _secure_mkdir(parent, mode=mode)
    if os.name == "posix":
        try:
            os.mkdir(str(path), mode)
        except FileExistsError:
            return
        try:
            os.chmod(str(path), mode)
        except OSError:
            pass
    else:
        path.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# TorManager — process-singleton daemon lifecycle
# ---------------------------------------------------------------------------


class TorManager:
    """Manages the tor subprocess for the lifetime of the process."""

    def __init__(self) -> None:
        self._binary: Path | None = None
        self._data_dir: Path | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._log_path: Path | None = None
        self._log_file: Any = None
        self._control_port: int | None = None
        self._cookie_path: Path | None = None
        self._socks_port: int | None = None
        self._initialised = False

    # ---------------- startup ----------------

    def start(self, timeout: float) -> None:
        # Guard on liveness, not just the flag: if a previously-started tor
        # crashed, _initialised is still True but the process is dead, so a
        # re-entry here must relaunch rather than return a stale dead port.
        if self.is_running():
            return
        self._initialised = False

        self._binary = _find_or_install_tor()
        self._data_dir = _get_data_dir()
        _secure_mkdir(self._data_dir, mode=0o700)

        self._launch()
        try:
            self._await_bootstrap(timeout)
        except BaseException:
            self._kill_process()
            raise

        _ensure_atexit_registered()
        self._initialised = True
        logger.info("Tor ready — SOCKS on 127.0.0.1:%s, data dir %s",
                    self._socks_port, self._data_dir)

    def _geoip_args(self) -> list[str]:
        # tor won't find geoip at a nonstandard install path unless told; it
        # runs without them but with degraded path selection, so pass them when
        # present (a system tor on PATH ships its own, so absence is fine).
        binary = self._binary
        assert binary is not None
        # For the bundle install, geoip lives at <install_root>/data/geoip.
        root = binary.parent.parent  # <root>/tor/tor -> <root>
        geoip, geoip6 = _geoip_paths(root)
        args: list[str] = []
        if geoip.exists():
            args += ["--GeoIPFile", str(geoip)]
        if geoip6.exists():
            args += ["--GeoIPv6File", str(geoip6)]
        return args

    def _launch(self) -> None:
        assert self._binary is not None and self._data_dir is not None
        control_file = self._data_dir / "control_port"
        cookie_file = self._data_dir / "control_auth_cookie"
        self._cookie_path = cookie_file
        self._log_path = self._data_dir / _TOR_LOG_NAME
        # Stale control-port file from a previous run would be read as this
        # run's port before tor rewrites it — remove it first.
        control_file.unlink(missing_ok=True)

        socks_spec = f"127.0.0.1:{SOCKS_PORT}" if SOCKS_PORT is not None else "127.0.0.1:auto"

        cmd = [
            str(self._binary),
            "--DataDirectory", str(self._data_dir),
            "--SocksPort", socks_spec,
            "--ControlPort", "auto",
            "--ControlPortWriteToFile", str(control_file),
            "--CookieAuthentication", "1",
            "--CookieAuthFile", str(cookie_file),
            "--Log", f"notice file {self._log_path}",
            "--ClientOnly", "1",
            # If we die (even SIGKILL), tor polls this PID and exits — no orphan.
            "--__OwningControllerProcess", str(os.getpid()),
        ]
        cmd += self._geoip_args()

        # notice log goes to the file above; discard stdout/stderr so a full OS
        # pipe buffer can never block the long-lived process.
        popen_kwargs: dict[str, Any] = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
        }
        if sys.platform == "win32":
            popen_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        self._process = subprocess.Popen(cmd, **popen_kwargs)
        logger.info("tor started (pid %d)", self._process.pid)

    def _await_bootstrap(self, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        assert self._data_dir is not None
        control_file = self._data_dir / "control_port"

        # 1) Wait for tor to publish its control port + write the auth cookie.
        while time.monotonic() < deadline:
            self._check_alive()
            if control_file.exists() and self._cookie_path and self._cookie_path.exists():
                port = self._read_control_port(control_file)
                if port is not None:
                    self._control_port = port
                    break
            time.sleep(0.2)
        else:
            raise TorBootstrapTimeout(
                f"tor did not open its control port within {timeout:.0f}s. "
                f"See log: {self._log_path}"
            )

        # 2) Poll bootstrap progress over the control port until 100%.
        while time.monotonic() < deadline:
            self._check_alive()
            phase = self._bootstrap_phase()
            if phase >= 100:
                self._socks_port = self._discover_socks_port()
                return
            time.sleep(0.5)
        raise TorBootstrapTimeout(
            f"tor did not finish bootstrapping within {timeout:.0f}s "
            f"(last progress {self._bootstrap_phase()}%). See log: {self._log_path}"
        )

    def _check_alive(self) -> None:
        if self._process and self._process.poll() is not None:
            tail = self._read_log_tail()
            lower = tail.lower()
            if "another tor process" in lower or "already an active tor process" in lower:
                raise TorDataDirLocked(
                    f"The Tor DataDirectory at {self._data_dir} is locked by another "
                    f"tor process. Only one tor can use a data dir at a time. Stop the "
                    f"other process or set basic_tor.DATA_DIR to a different path.\n"
                    f"--- tor log tail ---\n{tail}"
                )
            raise TorError(
                f"tor exited unexpectedly (code {self._process.returncode}):\n{tail}"
            )

    @staticmethod
    def _read_control_port(control_file: Path) -> int | None:
        # File content: "PORT=127.0.0.1:NNNNN\n"
        try:
            text = control_file.read_text().strip()
        except OSError:
            return None
        m = re.search(r"PORT=(?:\d+\.\d+\.\d+\.\d+):(\d+)", text)
        return int(m.group(1)) if m else None

    def _control(self) -> TorControlClient:
        assert self._control_port is not None and self._cookie_path is not None
        return TorControlClient(self._control_port, str(self._cookie_path))

    def _bootstrap_phase(self) -> int:
        try:
            with self._control() as ctl:
                line = ctl.getinfo("status/bootstrap-phase")
        except (TorControlError, OSError):
            return 0
        m = re.search(r"PROGRESS=(\d+)", line)
        return int(m.group(1)) if m else 0

    def _discover_socks_port(self) -> int:
        # Prefer the authoritative value from tor; fall back to the configured
        # fixed port if the control query is unexpectedly empty.
        try:
            with self._control() as ctl:
                listeners = ctl.getinfo("net/listeners/socks")
        except (TorControlError, OSError):
            listeners = ""
        m = re.search(r"(?:\d+\.\d+\.\d+\.\d+):(\d+)", listeners)
        if m:
            return int(m.group(1))
        if SOCKS_PORT is not None:
            return SOCKS_PORT
        raise TorError("could not determine tor SOCKS port from control connection")

    def _read_log_tail(self, n_bytes: int = 4096) -> str:
        if not self._log_path or not self._log_path.exists():
            return "(no tor log yet)"
        try:
            with open(self._log_path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                fh.seek(max(0, size - n_bytes))
                return fh.read().decode(errors="replace")
        except OSError:
            return "(log unreadable)"

    # ---------------- runtime ops ----------------

    def new_identity(self) -> None:
        with self._control() as ctl:
            ctl.signal("NEWNYM")

    def tor_version(self) -> str:
        with self._control() as ctl:
            return ctl.getinfo("version")

    def socks_port(self) -> int:
        assert self._socks_port is not None
        return self._socks_port

    def is_running(self) -> bool:
        return (
            self._initialised
            and self._process is not None
            and self._process.poll() is None
        )

    # ---------------- shutdown ----------------

    def stop(self) -> None:
        if not self._initialised:
            return
        logger.info("Shutting down tor…")
        try:
            with self._control() as ctl:
                ctl.signal("SHUTDOWN")
        except Exception:
            pass
        self._terminate_process()
        self._initialised = False

    def _terminate_process(self) -> None:
        proc = self._process
        if proc is None:
            return
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            if sys.platform == "win32":
                proc.terminate()
            else:
                proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        self._process = None

    def _kill_process(self) -> None:
        """Hard stop used on a failed start — no clean SHUTDOWN attempt."""
        proc = self._process
        if proc is None:
            return
        try:
            proc.kill()
            proc.wait(timeout=5)
        except Exception:
            pass
        self._process = None
        self._initialised = False


# ---------------------------------------------------------------------------
# Module-level singleton + public API
# ---------------------------------------------------------------------------

_manager: TorManager | None = None
_lock = threading.RLock()
_atexit_registered = False


def _ensure_atexit_registered() -> None:
    global _atexit_registered
    if not _atexit_registered:
        atexit.register(stop)
        _atexit_registered = True


def _get_manager() -> TorManager:
    global _manager
    if _manager is None:
        _manager = TorManager()
    return _manager


def ensure_running(timeout: float | None = None) -> str:
    """Start tor if it isn't already running; return the SOCKS proxy URL.

    Idempotent: repeated calls return the same URL. On first call this may
    download and verify the Tor Expert Bundle (~30 MB) and wait for the network
    to bootstrap (10-60 s). ``timeout`` bounds the bootstrap wait only (default
    ``BOOTSTRAP_TIMEOUT``); the one-time download has its own longer timeout.

    Returns a ``socks5h://`` URL — the ``h`` routes DNS through Tor, which is
    what you want for both anonymity and ``.onion`` addresses.
    """
    if timeout is None:
        timeout = BOOTSTRAP_TIMEOUT
    with _lock:
        mgr = _get_manager()
        if not mgr.is_running():
            mgr.start(timeout)
        return socks_url()


def start(timeout: float | None = None) -> str:
    """Alias for :func:`ensure_running` — symmetry with :func:`stop`."""
    return ensure_running(timeout)


def is_running() -> bool:
    """True if tor is running and bootstrapped in this process."""
    with _lock:
        return _manager is not None and _manager.is_running()


def socks_url(scheme: str = "socks5h") -> str:
    """Return the current SOCKS proxy URL. Raises if tor isn't running.

    Default scheme ``socks5h`` resolves hostnames through Tor (no DNS leak, and
    ``.onion`` works). Pass ``scheme="socks5"`` only if you specifically want
    local DNS resolution.
    """
    with _lock:
        if _manager is None or not _manager.is_running():
            raise TorError("tor is not running — call basic_tor.ensure_running() first")
        return f"{scheme}://127.0.0.1:{_manager.socks_port()}"


def new_identity() -> None:
    """Request a fresh circuit (control SIGNAL NEWNYM). Raises if not running.

    tor rate-limits NEWNYM to roughly one every 10 seconds; calling faster is
    accepted but coalesced by tor.
    """
    with _lock:
        if _manager is None or not _manager.is_running():
            raise TorError("tor is not running — call basic_tor.ensure_running() first")
        _manager.new_identity()


def tor_version() -> str:
    """Return the version of the tor *daemon* currently running (e.g. 0.4.9.11).

    This is distinct from ``TOR_BUNDLE_VERSION`` (the Tor Browser release that
    named the downloaded bundle). Raises if tor isn't running.
    """
    with _lock:
        if _manager is None or not _manager.is_running():
            raise TorError("tor is not running — call basic_tor.ensure_running() first")
        return _manager.tor_version()


def stop() -> None:
    """Stop the tor process if running. Safe to call repeatedly and at exit."""
    global _manager
    with _lock:
        if _manager is not None:
            _manager.stop()
