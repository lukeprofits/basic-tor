# Security model

basic_tor runs the **official Tor binary**. It does not implement any part of the
Tor protocol itself. Your anonymity properties are exactly those of the tor
daemon shipped in the Tor Project's Expert Bundle — the same binary inside Tor
Browser and OnionShare.

## Supply-chain / binary trust

The threat we defend against: an attacker who can tamper with the binary you run.

1. **Pinned version.** `TOR_BUNDLE_VERSION` names an exact Tor Browser release.
   We never "latest".

2. **Origin allowlist.** Downloads are restricted to `dist.torproject.org` and
   `archive.torproject.org` over TLS. A custom HTTP adapter re-checks the host on
   **every redirect hop**, so a 30x chain through a hostile host is refused
   before any request headers are sent — not just checked on the final URL.

3. **Baked-in SHA-256, fail-closed.** Every download is verified against a hash
   committed inside this package (and installed via signed PyPI metadata). We
   **never** fetch the checksum from the same origin as the archive — an attacker
   who controls the mirror controls both files, so that would be no check at all.
   An unknown version refuses to install rather than fetching a digest online.

4. **GPG-verified at author time.** `scripts/refresh_checksums.py` fetches the Tor
   Project's signed `sha256sums-signed-build.txt` and **verifies its OpenPGP
   signature against the Tor Browser Developers key**
   (`EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`) before recording any hash. So a
   value in `tor_checksums.py` has already passed a signature check. End users
   need no GPG — the fail-closed SHA-256 check inherits that trust.

5. **Hardened extraction.** The bundle is a tree (binary + libs + geoip +
   transports). Extraction validates every member: no absolute paths, no `..`
   traversal, regular files/directories only (symlinks/hardlinks/devices
   refused), per-member and total-size caps. Extraction stages to a sibling
   directory and atomically renames into place, so an interrupted install never
   leaves a half-populated tree.

6. **No pure-Python Tor.** We deliberately do not use `torpy` or any
   reimplementation. Those lag the real protocol's security fixes and are not
   audited to the standard the C tor is.

7. **Never writes to site-packages.** The binary is cached under the per-user
   data dir, never inside the installed package (a trust boundary owned by your
   package manager, world-writable-adjacent on some multi-user hosts).

## Runtime isolation

- tor runs with its **own `DataDirectory`** and `ClientOnly 1`.
- SOCKS binds to **`127.0.0.1` only**, on a dedicated port (default: a free port
  chosen by tor, discovered via the control port; never the system 9050/9150).
- The **control port** uses `SAFECOOKIE` authentication: the 32-byte cookie
  (readable only by your user, in the 0700 data dir) is never sent over the
  wire — only an HMAC — and the client **verifies the server's identity back**,
  closing a local-race window where another process grabs the control port.
- We do **not** reuse a pre-existing local SOCKS listener. A bare SOCKS port
  can't be authenticated, so blindly trusting one would let a port-squatting
  process MITM all traffic. basic_tor only ever uses a tor it launched itself.
- tor is launched with `__OwningControllerProcess <pid>`, so it exits if our
  process dies — even on `SIGKILL`, where `atexit` never runs. No orphans.

## DNS

`socks_url()` returns `socks5h://` by default, routing DNS resolution through
Tor. Using plain `socks5://` leaks visited hostnames to your local resolver and
cannot reach `.onion` services. Prefer the default.

## Reporting

Open an issue (or contact the maintainer privately for anything sensitive). This
wrapper's security depends on the tor daemon itself — Tor protocol issues should
go to the Tor Project.
