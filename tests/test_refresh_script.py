"""
Unit test for the checksum-refresh parser (offline). Verifies it pulls the
right expert-bundle hashes out of a real-shaped sums file.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "refresh_checksums.py"
_spec = importlib.util.spec_from_file_location("refresh_checksums", _SCRIPT)
refresh = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(refresh)  # type: ignore[union-attr]


SAMPLE_SUMS = """\
2592f79bd726d978a2253815e3d0dcbd45e767a473c28aeebe49754e9626dc35  tor-expert-bundle-linux-i686-15.0.17.tar.gz
4621e1573dbd6d5d6f4bb4121b37652a8b7204ae5abea600fb6b9e05e5695696  tor-expert-bundle-linux-x86_64-15.0.17.tar.gz
c99cf6f69740a443c7fffaf598ceb0952b3914041507c8afe11bed84a3333eb1  tor-expert-bundle-macos-aarch64-15.0.17.tar.gz
95243f76bcf05d6179d017c3f3e4ece7b53cc58dff1ba617b03a2fe2c8298b5b  tor-expert-bundle-macos-x86_64-15.0.17.tar.gz
5f91e9426bf641dfe539dc28029088c72bed0b1d8f1c79104a0f89273cb3ebe1  tor-expert-bundle-windows-x86_64-15.0.17.tar.gz
deadbeef  some-other-file.txt
"""


def test_parse_sums_picks_supported_platforms():
    shas = refresh.parse_sums(SAMPLE_SUMS, "15.0.17")
    assert set(shas) == set(refresh.PLATFORMS)
    assert shas["linux-x86_64"] == \
        "4621e1573dbd6d5d6f4bb4121b37652a8b7204ae5abea600fb6b9e05e5695696"
    assert shas["macos-aarch64"] == \
        "c99cf6f69740a443c7fffaf598ceb0952b3914041507c8afe11bed84a3333eb1"


def test_parse_sums_missing_platform_raises():
    partial = "\n".join(
        ln for ln in SAMPLE_SUMS.splitlines() if "macos-aarch64" not in ln
    )
    with pytest.raises(SystemExit):
        refresh.parse_sums(partial, "15.0.17")


def test_parse_sums_reproduces_committed_table():
    # The parser over the committed 15.0.17 sums must reproduce exactly what is
    # already baked into tor_checksums.py — the "no manual updates" guarantee.
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from basic_tor import tor_checksums

    shas = refresh.parse_sums(SAMPLE_SUMS, "15.0.17")
    assert shas == tor_checksums.CHECKSUMS["15.0.17"]
