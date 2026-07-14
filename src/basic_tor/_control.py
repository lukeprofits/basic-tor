"""
A minimal Tor control-port client.

Just enough of the control protocol (tor-spec ``control-spec.txt``) to:

  * authenticate over a loopback control port using SAFECOOKIE,
  * ``GETINFO`` bootstrap progress / socks listener / tor version,
  * send ``SIGNAL NEWNYM`` (new identity) and ``SIGNAL SHUTDOWN`` (clean stop).

We deliberately do **not** depend on ``stem``: it is a large, effectively
unmaintained dependency for what amounts to a line protocol over a socket.
SAFECOOKIE (rather than plain COOKIE) means the 32-byte auth cookie is never
sent over the wire — only an HMAC of it — and we authenticate the server's
identity back, closing a local-race window on multi-user hosts.

This module is intentionally free of any dependency on the rest of the package
so it can be unit-tested in isolation.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import socket

# Fixed HMAC keys from control-spec.txt (SAFECOOKIE section). These are
# protocol constants, not secrets.
_SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
_CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"


class TorControlError(RuntimeError):
    """A control-port command failed or the handshake was rejected."""


class TorControlClient:
    """Synchronous client for a single tor control connection.

    Usage::

        with TorControlClient(port, cookie_path) as ctl:
            phase = ctl.getinfo("status/bootstrap-phase")
            ctl.signal("NEWNYM")

    Not thread-safe: one connection serves one caller at a time. The manager
    opens a fresh connection per operation rather than holding one open, which
    keeps the control socket idle (and closed) for the common case.
    """

    def __init__(self, port: int, cookie_path: str, host: str = "127.0.0.1",
                 timeout: float = 10.0) -> None:
        self._host = host
        self._port = port
        self._cookie_path = cookie_path
        self._timeout = timeout
        self._sock: socket.socket | None = None
        self._buf = b""

    # ---------------- connection lifecycle ----------------

    def __enter__(self) -> TorControlClient:
        self.connect()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def connect(self) -> None:
        cookie = self._read_cookie()
        sock = socket.create_connection((self._host, self._port), timeout=self._timeout)
        sock.settimeout(self._timeout)
        self._sock = sock
        try:
            self._authenticate(cookie)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None
        self._buf = b""

    def _read_cookie(self) -> bytes:
        with open(self._cookie_path, "rb") as fh:
            cookie = fh.read()
        # tor's control auth cookie is exactly 32 bytes. A wrong length means
        # we're reading the wrong file (or a truncated write) — fail loud
        # rather than send a malformed AUTHCHALLENGE.
        if len(cookie) != 32:
            raise TorControlError(
                f"control auth cookie at {self._cookie_path} is {len(cookie)} bytes, "
                f"expected 32 — refusing to authenticate."
            )
        return cookie

    # ---------------- SAFECOOKIE handshake ----------------

    def _authenticate(self, cookie: bytes) -> None:
        client_nonce = os.urandom(32)
        code, lines = self._command(f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}")
        if code != 250 or not lines:
            raise TorControlError(f"AUTHCHALLENGE rejected: {code} {lines}")

        server_hash_hex, server_nonce_hex = self._parse_authchallenge(lines[0])
        server_nonce = bytes.fromhex(server_nonce_hex)

        # Authenticate the *server* to us before trusting it: recompute the
        # SERVERHASH ourselves. A process that grabbed the control port but
        # cannot read the cookie cannot forge this.
        expected_server_hash = hmac.new(
            _SERVER_KEY, cookie + client_nonce + server_nonce, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected_server_hash, server_hash_hex.lower()):
            raise TorControlError(
                "control-port SERVERHASH mismatch — the process on the control "
                "port could not prove it holds the auth cookie. Refusing to "
                "authenticate (possible local port hijack)."
            )

        client_hash = hmac.new(
            _CLIENT_KEY, cookie + client_nonce + server_nonce, hashlib.sha256
        ).hexdigest()
        code, lines = self._command(f"AUTHENTICATE {client_hash}")
        if code != 250:
            raise TorControlError(f"AUTHENTICATE rejected: {code} {lines}")

    @staticmethod
    def _parse_authchallenge(line: str) -> tuple[str, str]:
        # e.g. "AUTHCHALLENGE SERVERHASH=<hex> SERVERNONCE=<hex>"
        server_hash = server_nonce = None
        for tok in line.split():
            if tok.startswith("SERVERHASH="):
                server_hash = tok[len("SERVERHASH="):]
            elif tok.startswith("SERVERNONCE="):
                server_nonce = tok[len("SERVERNONCE="):]
        if not server_hash or not server_nonce:
            raise TorControlError(f"malformed AUTHCHALLENGE reply: {line!r}")
        return server_hash, server_nonce

    # ---------------- high-level commands ----------------

    def getinfo(self, key: str) -> str:
        """Return the value of a single ``GETINFO`` key.

        Handles both the inline ``250-key=value`` form and the multi-line
        ``250+key=`` data form (value terminated by a lone ``.``).
        """
        code, lines = self._command(f"GETINFO {key}")
        if code != 250:
            raise TorControlError(f"GETINFO {key} failed: {code} {lines}")
        prefix = key + "="
        for ln in lines:
            if ln.startswith(prefix):
                val = ln[len(prefix):]
                # Data form ("250+key=\r\n" then data lines) leaves an empty
                # first line, so the joined value carries a leading newline —
                # strip that one separator, keep any real embedded newlines.
                return val[1:] if val.startswith("\n") else val
        raise TorControlError(f"GETINFO {key}: key not present in reply {lines!r}")

    def signal(self, name: str) -> None:
        code, lines = self._command(f"SIGNAL {name}")
        if code != 250:
            raise TorControlError(f"SIGNAL {name} failed: {code} {lines}")

    # ---------------- wire protocol ----------------

    def _command(self, command: str) -> tuple[int, list[str]]:
        """Send one command line, return (final status code, reply lines).

        Reply lines exclude the ``NNN-`` / ``NNN+`` / ``NNN `` status prefix.
        Data payloads (``250+key=`` … ``.``) are flattened into the line list
        as their raw content lines.
        """
        if self._sock is None:
            raise TorControlError("control connection is not open")
        self._sock.sendall(command.encode("utf-8") + b"\r\n")
        return self._read_reply()

    def _read_reply(self) -> tuple[int, list[str]]:
        lines: list[str] = []
        code = 0
        while True:
            raw = self._read_line()
            if len(raw) < 4:
                raise TorControlError(f"short control reply line: {raw!r}")
            code = int(raw[:3])
            sep = raw[3:4]
            content = raw[4:]
            if sep == "-":            # mid-reply line
                lines.append(content)
            elif sep == " ":          # final line
                lines.append(content)
                return code, lines
            elif sep == "+":          # data reply: read until lone "."
                data = [content]
                while True:
                    dl = self._read_line()
                    if dl == ".":
                        break
                    # tor dot-stuffs leading dots; undo it.
                    data.append(dl[1:] if dl.startswith("..") else dl)
                lines.append("\n".join(data))
            else:
                raise TorControlError(f"unexpected control reply separator: {raw!r}")

    def _read_line(self) -> str:
        while b"\r\n" not in self._buf:
            assert self._sock is not None
            chunk = self._sock.recv(4096)
            if not chunk:
                raise TorControlError("control connection closed mid-reply")
            self._buf += chunk
            if len(self._buf) > (1 << 20):
                raise TorControlError("control reply exceeded 1 MiB — refusing to buffer more")
        line, _, self._buf = self._buf.partition(b"\r\n")
        return line.decode("utf-8", errors="replace")
