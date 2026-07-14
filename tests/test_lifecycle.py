"""
End-to-end lifecycle tests. Marked ``network`` — they download the bundle on
first run and bootstrap the real Tor network, so they are slow and require
internet. Skip offline with:  pytest -m "not network"
"""

from __future__ import annotations

import pytest

import basic_tor

pytestmark = pytest.mark.network


@pytest.fixture(autouse=True)
def _clean_stop():
    yield
    basic_tor.stop()


def test_ensure_running_returns_socks5h_url():
    url = basic_tor.ensure_running(timeout=120)
    assert url.startswith("socks5h://127.0.0.1:")
    assert basic_tor.is_running()
    # Idempotent — second call returns the same URL, no restart.
    assert basic_tor.ensure_running() == url
    # start() is an alias for ensure_running().
    assert basic_tor.start() == url


def test_socks_url_raises_when_stopped():
    assert not basic_tor.is_running()
    with pytest.raises(basic_tor.TorError):
        basic_tor.socks_url()


def test_traffic_actually_exits_via_tor():
    requests = pytest.importorskip("requests")
    pytest.importorskip("socks")  # requests[socks] / PySocks
    url = basic_tor.ensure_running(timeout=120)
    r = requests.get(
        "https://check.torproject.org/api/ip",
        proxies={"http": url, "https": url},
        timeout=60,
    )
    assert r.json().get("IsTor") is True


def test_new_identity_and_tor_version():
    basic_tor.ensure_running(timeout=120)
    ver = basic_tor.tor_version()
    assert ver.count(".") >= 2  # e.g. 0.4.9.11
    basic_tor.new_identity()  # must not raise


def test_stop_is_idempotent():
    basic_tor.ensure_running(timeout=120)
    basic_tor.stop()
    basic_tor.stop()  # safe to call again
    assert not basic_tor.is_running()
