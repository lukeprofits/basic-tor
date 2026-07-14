# basic-tor

An intentionally tiny Tor library for Python. Zero setup, the real official Tor under the hood.

### Description

`basic-tor` does exactly four things:

- Start [Tor](https://www.torproject.org/) and hand you a SOCKS proxy URL (`socks5h://127.0.0.1:<port>`)
- Tell you whether Tor is running
- Request a new identity (fresh circuit)
- Stop Tor cleanly

It does **not** reimplement Tor. It downloads, verifies, and runs the **official Tor binary** — the [Tor Expert Bundle](https://www.torproject.org/download/tor/), the exact same `tor` that Tor Browser and OnionShare ship. Auto-downloaded on first use, auto-shutdown on exit. No daemon to install, no torrc to edit, no accounts.

I made `basic-tor` because no other Python packages make it this simple. Everything else either assumes you already have Tor installed and configured, or reimplements Tor in pure Python (don't use those — they lag years behind on protocol security).

If it does exactly what you need → great, use it. If it doesn't → don't use it. Simple as that.

### Install

```
pip install basic-tor
```

First call downloads the Tor Expert Bundle (~30 MB, SHA-256 verified) into your per-user data directory (`~/.local/share/basic_tor/` on Linux; `platformdirs` picks the right path per OS) and starts `tor` as a background subprocess. It stops automatically when your program exits.

### Usage

```python
import basic_tor
import requests

# Start Tor (if not already running) and get the proxy URL
proxy = basic_tor.ensure_running()   # → "socks5h://127.0.0.1:<port>"

# Hand it to any SOCKS-aware client
r = requests.get("https://check.torproject.org/api/ip",
                 proxies={"http": proxy, "https": proxy})
print(r.json())                      # {"IsTor": true, ...}

basic_tor.is_running()               # → True
basic_tor.socks_url()                # → the same proxy URL (raises if not running)
basic_tor.new_identity()             # fresh circuit (Tor rate-limits to ~1 per 10 s)
basic_tor.tor_version()              # → "0.4.9.11" (the actual tor daemon version)
basic_tor.stop()                     # or just let your program exit
```

That's the whole API. `start()` also exists as an alias for `ensure_running()` if you prefer the symmetry with `stop()`.

First bootstrap takes 10–60 s (building a route through the Tor network). Later runs reuse the cached network consensus and start in a few seconds. `ensure_running()` is idempotent — call it as often as you like.

**Why `socks5h://` and not `socks5://`?** The `h` makes your client resolve DNS *through Tor*. Plain `socks5://` leaks every hostname you visit to your local DNS resolver and can't reach `.onion` addresses. Keep the default.

All failures raise `basic_tor.TorError`. Subclasses, all with actionable messages:

- `TorBinaryNotFound` — no Tor binary and auto-download failed (no network, disk full, unsupported platform).
- `TorBootstrapTimeout` — Tor didn't reach `Bootstrapped 100%` in time (default 120 s). Slow or blocked network.
- `TorDataDirLocked` — another Tor process owns the data directory. One process per data dir.
- `TorControlError` — a control-port command failed.

### Config

Override module variables **before** the first call if you want non-defaults:

```python
import basic_tor

basic_tor.SOCKS_PORT = 9052            # default None = Tor picks a free port
basic_tor.DATA_DIR = "/mnt/data/tor"   # default: platformdirs user data dir
basic_tor.BOOTSTRAP_TIMEOUT = 180.0    # seconds to wait for bootstrap
basic_tor.TOR_BUNDLE_VERSION = "15.0.17"  # must be in tor_checksums.py
```

By default `SOCKS_PORT` is `None`: Tor binds a free port and the returned URL tells you which. That means it can **never** clash with a system Tor (9050) or Tor Browser (9150). Pin it (e.g. `9052`) only if you need a stable port across runs.

### Updating the pinned Tor version

The version is pinned in `basic_tor/__init__.py` (`TOR_BUNDLE_VERSION` — a Tor Browser release number, which is how the Tor Project names Expert Bundles; the tor daemon inside has its own version, see `tor_version()`).

```bash
python scripts/refresh_checksums.py 15.0.18   # fetches + GPG-verifies + records new hashes
# review the diff, bump TOR_BUNDLE_VERSION, commit
```

The script fetches the Tor Project's signed `sha256sums-signed-build.txt` and verifies its signature against the Tor Browser Developers key before recording anything. Runtime verification stays checksum-only — users never need GPG.

### Troubleshooting

**Slow first run.** Auto-download is ~30 MB plus 10–60 s of bootstrap. Subsequent starts are fast (~3 s). The binary lives in `platformdirs.user_data_dir("basic_tor")` so it survives reinstalls. To wipe it, delete that directory.

**`TorDataDirLocked` on startup.** Another `basic-tor`-using process owns the data directory. Run one process per data dir — or set `basic_tor.DATA_DIR` to a different path before starting.

**Auto-download fails (corporate proxy / firewall).** The downloader honors the standard environment variables:

```bash
HTTPS_PROXY=http://corp-proxy:3128 \
REQUESTS_CA_BUNDLE=/etc/ssl/corp-ca.pem \
python your_script.py
```

**Unsupported platform (e.g. Linux ARM64 / Raspberry Pi).** The Tor Project publishes Expert Bundles for `linux-x86_64`, `macos-x86_64`, `macos-aarch64`, and `windows-x86_64` only. On anything else, install a system Tor (`sudo apt install tor`) — `basic-tor` automatically uses a `tor` binary found on your `PATH` when no bundle is available.

**Bootstrap stuck below 100%.** Your network may block Tor (some countries and corporate firewalls do). Check the log at `<data_dir>/tor.log`. Bridge/pluggable-transport configuration is not built in yet — the transport binaries ship in the bundle, so a PR wiring them up is welcome.

**Want to inspect the Tor log.** It's at `<data_dir>/tor.log` (default `~/.local/share/basic_tor/tor_data/tor.log`).

### Security

- **Verified downloads, fail-closed.** Every download is checked against a SHA-256 baked into the wheel (`basic_tor/tor_checksums.py`) using a constant-time compare. Unknown versions are refused — fetching a digest from the same origin as the archive adds no real protection. Downloads are pinned to `dist.torproject.org` / `archive.torproject.org` at **every redirect hop** — not just the final URL — and require HTTPS on every hop.
- **Checksums are GPG-verified at authoring time** against the Tor Browser Developers signing key (`EF6E286DDA85EA2A4BA7DE684E2C6E8793298290`), so the baked-in table inherits the Tor Project's own signature.
- **Same trust as Tor Browser.** You run the official binary, launched with its own data directory, SOCKS bound to `127.0.0.1` only, control port secured with SAFECOOKIE authentication.
- **No orphan processes.** Tor watches your process ID and exits if your program dies — even on `SIGKILL`, where normal cleanup never runs.

See [`SECURITY.md`](SECURITY.md) for the full threat model.

One thing worth knowing: `basic-tor` gives you Tor's *transport* anonymity. Your application traffic (cookies, headers, browser fingerprint, what you log in to) can still identify you — that part is on you.

### How it works

`basic-tor` runs the Tor Expert Bundle's `tor` as a subprocess and talks to it over Tor's control port (a tiny built-in client — no heavyweight dependencies). Bootstrap progress is polled over the control port rather than scraped from logs; `new_identity()` is a control-port `SIGNAL NEWNYM`; shutdown is a clean `SIGNAL SHUTDOWN`.

- **Auto-download:** the bundle fetches from the Tor Project on first use, checksum-verified, and cached per-user. The Python wheel itself stays tiny because it ships no binaries.
- **The whole bundle is kept** — tor's bundled libraries, GeoIP databases (passed to tor explicitly), and pluggable-transport binaries.
- **PyInstaller / Briefcase friendly:** respects `sys._MEIPASS`; a pre-placed binary at `<user_data_dir>/basic_tor/tor/<version>/<platform>/tor/tor` skips the download entirely (air-gapped deploys).
- **Dependencies:** just `requests` and `platformdirs`.

### Contributing

If you want to add functionality, open a PR. I'll merge it if it keeps the library simple and matches the existing patterns.

### License

MIT for this library. See [LICENSE](LICENSE).

The Tor binary is **not** part of this package — it is downloaded from the Tor Project on first use and covered by its own terms (Tor is 3-clause BSD; the Expert Bundle builds enable GPLv3-licensed components, and the binary reports itself as GPLv3). `basic-tor` never bundles or redistributes it.
