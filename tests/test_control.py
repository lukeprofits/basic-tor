"""
Unit tests for the control-port client — no real tor, a fake socket feeds
canned protocol bytes.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from basic_tor import _control
from basic_tor._control import TorControlClient, TorControlError


class FakeSocket:
    """Feeds queued server replies; records what the client sends."""

    def __init__(self, replies: list[bytes]) -> None:
        self._replies = list(replies)
        self.sent: list[bytes] = []
        self._inbox = b""

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)
        # Serve the next queued reply for each command sent.
        if self._replies:
            self._inbox += self._replies.pop(0)

    def recv(self, n: int) -> bytes:
        if not self._inbox:
            return b""
        chunk, self._inbox = self._inbox[:n], self._inbox[n:]
        return chunk

    def settimeout(self, t):  # noqa: D401
        pass

    def close(self):
        pass


def _client_with(replies: list[bytes]) -> TorControlClient:
    c = TorControlClient(9999, "/nonexistent")
    c._sock = FakeSocket(replies)
    return c


def test_getinfo_inline_value():
    c = _client_with([b"250-version=0.4.9.11\r\n250 OK\r\n"])
    assert c.getinfo("version") == "0.4.9.11"


def test_getinfo_bootstrap_phase():
    reply = (b'250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 '
             b'TAG=done SUMMARY="Done"\r\n250 OK\r\n')
    c = _client_with([reply])
    line = c.getinfo("status/bootstrap-phase")
    assert "PROGRESS=100" in line


def test_getinfo_missing_key_raises():
    c = _client_with([b"250-other=x\r\n250 OK\r\n"])
    with pytest.raises(TorControlError):
        c.getinfo("version")


def test_signal_ok():
    c = _client_with([b"250 OK\r\n"])
    c.signal("NEWNYM")  # must not raise
    assert c._sock.sent[-1] == b"SIGNAL NEWNYM\r\n"


def test_signal_rejected():
    c = _client_with([b"552 Unrecognized signal\r\n"])
    with pytest.raises(TorControlError):
        c.signal("BOGUS")


def test_data_reply_multiline():
    # 250+ data form terminated by a lone dot.
    reply = b"250+conf=\r\nLine1\r\nLine2\r\n.\r\n250 OK\r\n"
    c = _client_with([reply])
    assert c.getinfo("conf") == "Line1\nLine2"


def test_safecookie_handshake_verifies_server():
    cookie = b"\x11" * 32
    client_nonce_holder = {}

    # Build a server that answers AUTHCHALLENGE with a correct SERVERHASH.
    class Handshake(FakeSocket):
        def sendall(self, data: bytes) -> None:
            self.sent.append(data)
            text = data.decode()
            if text.startswith("AUTHCHALLENGE"):
                client_nonce = bytes.fromhex(text.split()[2].strip())
                client_nonce_holder["n"] = client_nonce
                server_nonce = b"\x22" * 32
                server_hash = hmac.new(
                    _control._SERVER_KEY, cookie + client_nonce + server_nonce,
                    hashlib.sha256,
                ).hexdigest()
                self._inbox += (
                    f"250 AUTHCHALLENGE SERVERHASH={server_hash} "
                    f"SERVERNONCE={server_nonce.hex()}\r\n"
                ).encode()
            elif text.startswith("AUTHENTICATE"):
                self._inbox += b"250 OK\r\n"

    c = TorControlClient(9999, "/nonexistent")
    c._sock = Handshake([])
    c._authenticate(cookie)  # must complete without raising
    # Client must have sent an AUTHENTICATE after the challenge.
    assert any(s.startswith(b"AUTHENTICATE") for s in c._sock.sent)


def test_safecookie_rejects_bad_server_hash():
    cookie = b"\x11" * 32

    class BadServer(FakeSocket):
        def sendall(self, data: bytes) -> None:
            self.sent.append(data)
            if data.decode().startswith("AUTHCHALLENGE"):
                self._inbox += (
                    b"250 AUTHCHALLENGE SERVERHASH=" + b"00" * 32 +
                    b" SERVERNONCE=" + b"22" * 32 + b"\r\n"
                )

    c = TorControlClient(9999, "/nonexistent")
    c._sock = BadServer([])
    with pytest.raises(TorControlError):
        c._authenticate(cookie)
