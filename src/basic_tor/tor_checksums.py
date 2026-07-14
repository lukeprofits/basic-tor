"""
Built-in SHA-256 checksums for the official Tor Expert Bundle archives.

Why baked in: if dist.torproject.org (or a mirror) is compromised, an attacker
could swap both the archive and its ``sha256sums-signed-build.txt`` companion.
Verifying against a hash that shipped inside the wheel — installed via signed
PyPI metadata — closes that gap. Unknown versions are refused outright rather
than fetching a digest from the same origin as the archive; that would defeat
the verification.

The refresh script (``scripts/refresh_checksums.py``) GPG-verifies the Tor
Project's signed sums file against the pinned Tor Browser Developers signing
key before writing any hash here, so a value in this table has already passed
a signature check at author time. Runtime stays checksum-table-only and
fail-closed — no GPG dependency for end users.

To populate a new version: ``python scripts/refresh_checksums.py <version>``
"""

# The checksums are keyed by the *Tor Browser release* version (e.g. "15.0.17"),
# which names the Expert Bundle archive. The tor daemon *inside* the bundle has
# its own version (0.4.x.y) — surface that at runtime via the control port, not
# from this table. See TOR_BUNDLE_VERSION in basic_tor/__init__.py.
#
# {bundle_version: {platform_key: sha256_hex}}
CHECKSUMS: dict[str, dict[str, str]] = {
    "15.0.17": {
        "linux-x86_64":  "4621e1573dbd6d5d6f4bb4121b37652a8b7204ae5abea600fb6b9e05e5695696",
        "macos-x86_64":  "95243f76bcf05d6179d017c3f3e4ece7b53cc58dff1ba617b03a2fe2c8298b5b",
        "macos-aarch64": "c99cf6f69740a443c7fffaf598ceb0952b3914041507c8afe11bed84a3333eb1",
        "windows-x86_64": "5f91e9426bf641dfe539dc28029088c72bed0b1d8f1c79104a0f89273cb3ebe1",
    },
}


def known_checksum(version: str, platform_key: str) -> "str | None":
    """Return the baked-in SHA-256 hex, or None if not in the table."""
    return CHECKSUMS.get(version, {}).get(platform_key)
