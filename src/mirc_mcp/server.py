"""MCP server (stdio only) that drives a local mIRC through mcp-bridge.mrc."""

from __future__ import annotations

import base64
import logging
import os
import re
import ssl
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import certpin, dialogs
from .bridge import MircBridge, MircError
from .policy import Policy, PolicyError

BRIDGE_SCRIPT_VERSION = "1"
log = logging.getLogger("mirc_mcp")


def b64(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


@dataclass
class Mirc:
    """The checked operations, independent of MCP so the smoke test can call them."""

    bridge: MircBridge
    policy: Policy
    # Extra arguments when pin_certificate restarts mIRC (the smoke test passes its -r/-noreg).
    start_args: tuple[str, ...] = ()
    servers_ini_fallback: Path = field(
        default_factory=lambda: Path(os.environ.get("APPDATA", "."), "mIRC", "servers.ini")
    )

    def _eval(self, expr: str) -> str:
        return self.bridge.evaluate(expr)

    def bridge_version(self) -> str:
        v = self._eval("$mcp.version")
        if v == "$mcp.version" or v == "":
            raise MircError("mcp-bridge.mrc is not loaded in mIRC (see README)")
        return v

    def connections(self) -> list[dict[str, object]]:
        self.bridge_version()
        out = []
        for n in range(1, int(self._eval("$mcp.conn(0)") or 0) + 1):
            cid, status, server, network, me = (self._eval(f"$mcp.conn({n})").split("\t") + [""] * 5)[:5]
            allowed = True
            try:
                self.policy.check_server(server)
            except PolicyError:
                allowed = False
            out.append(
                {"cid": int(cid), "status": status, "server": server, "network": network, "nick": me, "allowed": allowed}
            )
        return out

    def _connection(self, cid: int) -> dict[str, object]:
        for c in self.connections():
            if c["cid"] == cid:
                self.policy.check_server(str(c["server"]))
                return c
        raise PolicyError(f"no connection with cid {cid}")

    def windows(self, cid: int) -> dict[str, list]:
        self._connection(cid)
        chans = []
        for n in range(1, int(self._eval(f"$mcp.chan({cid},0)") or 0) + 1):
            name, users, topic = (self._eval(f"$mcp.chan({cid},{n})").split("\t", 2) + ["", ""])[:3]
            chans.append({"channel": name, "users": int(users or 0), "topic": topic})
        queries = [
            self._eval(f"$mcp.query({cid},{n})")
            for n in range(1, int(self._eval(f"$mcp.query({cid},0)") or 0) + 1)
        ]
        return {"channels": chans, "queries": queries}

    def messages(self, cid: int | None, window: str | None, after_seq: int, limit: int) -> dict[str, object]:
        self.bridge_version()
        limit = max(1, min(limit, self.policy.read_limit))
        last = int(self._eval("$mcp.seq") or 0)
        allowed_cids = {c["cid"] for c in self.connections() if c["allowed"]}
        out: list[dict[str, object]] = []
        seq = last
        # Walk backwards so `limit` keeps the newest, then return oldest first.
        while seq > after_seq and len(out) < limit:
            raw = self._eval(f"$mcp.msg({seq})")
            seq -= 1
            if not raw:
                break  # rolled out of the ring buffer
            c, t, kind, win, nick, text = (raw.split("\t", 5) + [""] * 6)[:6]
            if int(c) not in allowed_cids:
                continue
            if cid is not None and int(c) != cid:
                continue
            if window is not None and win.lower() != window.lower():
                continue
            out.append({"seq": seq + 1, "cid": int(c), "time": int(t), "type": kind, "window": win, "nick": nick, "text": text})
        out.reverse()
        return {"last_seq": last, "messages": out}

    def _require_joined(self, cid: int, target: str, is_chan: bool) -> None:
        if is_chan and self.policy.require_joined:
            joined = {c["channel"].lower() for c in self.windows(cid)["channels"]}
            if target.lower() not in joined:
                raise PolicyError(f"not joined to {target} (require_joined is on)")

    def _do(self, cid: int, verb: str, target: str, text: str | None = None) -> None:
        line = f"/mcp.do {cid} {verb} {b64(target)}"
        if text:
            line += f" {b64(text)}"
        log.info("mcp.do cid=%s verb=%s target=%s bytes=%s", cid, verb, target, len((text or "").encode()))
        self.bridge.command(line)

    def send(self, cid: int, target: str, text: str, kind: str) -> str:
        self.policy.check_send_kind(kind)
        is_chan = self.policy.check_target(target)
        self.policy.check_text(text)
        self._connection(cid)
        self._require_joined(cid, target, is_chan)
        self._do(cid, kind, target, text)
        return f"sent {kind} to {target}"

    def command(self, cid: int, command: str, target: str, text: str) -> str:
        self.policy.check_command(command)
        is_chan = self.policy.check_target(target)
        if command in {"join", "part", "names", "topic"} and not is_chan:
            raise PolicyError(f"/{command} needs a channel")
        if command == "whois" and is_chan:
            raise PolicyError("/whois needs a nick")
        if text and command not in {"part", "topic"}:
            raise PolicyError(f"/{command} takes no text")
        self.policy.check_text(text, required=False)
        self._connection(cid)
        if command == "topic" and text:
            self._require_joined(cid, target, is_chan)
        self._do(cid, command, target, text or None)
        return f"/{command} {target} sent; replies arrive in mIRC's windows"

    def identifier(self, cid: int, name: str, args: list[str], prop: str | None) -> str:
        expr = self.policy.build_identifier(name, args, prop)
        self._connection(cid)
        return self._eval(f"$mcp.ev({cid},{b64(expr)})")

    # ---- settings ------------------------------------------------------------
    # Fixed mirc.ini keys only. The SOCKS password key is never read.
    AUDIT_KEYS = (
        ("socks", "enabled"), ("socks", "method"), ("socks", "hostname"), ("socks", "port"),
        ("socks", "dccs"), ("socks", "userid"), ("ident", "active"), ("dde", "ServerStatus"),
        ("update", "check"),
    )

    def audit(self) -> dict[str, object]:
        """Read leak-relevant settings (after /saveini, so the file matches what mIRC holds)."""
        self.bridge.command("/saveini", flood_protection=False)
        v = {f"{s}.{k}": self._eval(f"$readini($mircini,n,{s},{k})") for s, k in self.AUDIT_KEYS}
        findings = []
        proxy_ok = (
            v["socks.enabled"] == "yes"
            and v["socks.method"] == "5"
            and v["socks.hostname"] in ("127.0.0.1", "localhost")
            and v["socks.port"].isdigit()
            and int(v["socks.port"]) in self.policy.tor_socks_ports
        )
        if not proxy_ok:
            findings.append(
                "Server connections do not go through a local Tor SOCKS5 proxy: hostnames are resolved by "
                "Windows DNS and connections go out directly (a .onion name then fails with 'Unable to resolve "
                "server' and is leaked to the DNS resolver)."
            )
        if v["socks.dccs"] != "yes":
            findings.append("DCC is not routed through the proxy (matters only if DCC is ever allowed).")
        if v["socks.userid"]:
            findings.append("A SOCKS user ID is stored; Tor does not need one (harden clears it and the password).")
        if v["ident.active"] != "no":
            findings.append("The identd server is on: it listens on TCP 113 while connecting.")
        if v["dde.ServerStatus"] != "off":
            findings.append("The DDE server is on: any local program can drive mIRC through it (mirc-mcp does not need it).")
        if v["update.check"] not in ("0", ""):
            findings.append("Automatic update checks are on: mIRC contacts its website directly.")
        return {"settings": v, "findings": findings, "ok": not findings}

    def harden(self, tor_port: int) -> dict[str, object]:
        """Apply fixed, tightening-only changes, then re-audit. Nothing here can loosen a setting."""
        self.policy.check_socks_port(tor_port)
        for line in (
            f"/proxy -cm5+d 127.0.0.1 {tor_port}",  # SOCKS5, DCC via proxy too, clear user/password
            "/proxy on",
            "/identd off",
            "/ddeserver off",
        ):
            log.info("harden: %s", line)
            self.bridge.command(line, flood_protection=False)
        result = self.audit()
        result["note"] = (
            "With the proxy on, mIRC sends every server connection through it, 127.0.0.1 included, so a local "
            "relay is no longer reachable; connect to the .onion name directly instead (mIRC hands the name to the "
            "proxy unresolved, verified on 7.86). Update checks are not changed here, and mIRC can still contact "
            "www.mirc.com outside the proxy: block mirc.exe outbound in Windows Firewall to stop that."
        )
        return result

    # ---- status, dialogs, scripts --------------------------------------------

    def status(self, lines: int) -> dict[str, object]:
        """Read-only: connections, the last `lines` status-window lines, open dialogs, scripts.
        Uses built-in identifiers only, so it works without mcp-bridge.mrc."""
        lines = max(0, min(lines, 200))
        ev = self._eval
        conns = []
        for n in range(1, int(ev("$scon(0)") or 0) + 1):
            conns.append(
                {
                    "cid": int(ev(f"$scon({n}).cid") or 0),
                    "status": ev(f"$scon({n}).status"),
                    "server": ev(f"$scon({n}).server"),
                    "port": ev(f"$scon({n}).port"),
                    "ssl": ev(f"$scon({n}).ssl"),
                }
            )
        total = int(ev("$line(Status Window,0)") or 0)
        tail = [ev(f"$line(Status Window,{i})") for i in range(max(1, total - lines + 1), total + 1)]
        return {
            "pid": self.bridge.pid(),
            "version": ev("$version"),
            "active_status": ev("$status"),
            "active_server": ev("$server"),
            "connections": conns,
            "status_lines": [t for t in tail if t.strip(" -")],
            "dialogs": dialogs.list_dialogs(self.bridge.pid()),
            "scripts": self.scripts(),
            "bridge_script_loaded": ev("$isalias(mcp.version)") == "$true",
        }

    def open_dialogs(self) -> list[dict[str, str]]:
        return dialogs.list_dialogs(self.bridge.pid())

    def close_dialog(self, title: str) -> str:
        try:
            closed = dialogs.close(self.bridge.pid(), title)
        except ValueError as e:
            raise PolicyError(str(e)) from e
        if not closed:
            return f"no open dialog titled {title!r} (or, for About, its OK button is not enabled yet)"
        time.sleep(0.5)
        still = [d for d in dialogs.list_dialogs(self.bridge.pid()) if d["title"] == title]
        return f"cancelled {title!r}" + (" but it is still open" if still else "")

    def scripts(self) -> list[str]:
        return [self._eval(f"$script({i})") for i in range(1, int(self._eval("$script(0)") or 0) + 1)]

    def reload_script(self, name: str) -> dict[str, object]:
        if not self.policy.allow_reload:
            raise PolicyError("reload_script is disabled (allow_reload = false)")
        matches = [p for p in self.scripts() if PureWindowsPath(p).name.lower() == name.lower()]
        if not matches:
            raise PolicyError(f"{name!r} is not a loaded script (loaded: {[PureWindowsPath(p).name for p in self.scripts()]})")
        path = matches[0]
        if re.search(r'[|$%"\x00-\x1f]', path) or not path.lower().endswith((".mrc", ".ini")):
            raise PolicyError("refusing to reload a script whose path has characters mIRC would parse")
        log.info("reload_script %s", path)
        self.bridge.command(f'/reload -rs "{path}"', flood_protection=False)
        time.sleep(0.5)
        return {"reloaded": path, "scripts": self.scripts()}

    # ---- connect through the guard -------------------------------------------

    OUTCOMES = (
        ("cert_failure", re.compile(r"certificate verify failed|invalid certificate", re.I)),
        ("resolve_failure", re.compile(r"unable to resolve", re.I)),
        ("proxy_failure", re.compile(r"^\* proxy:", re.I)),
        ("guard_blocked", re.compile(r"blocked", re.I)),
        ("refused", re.compile(r"connection refused|unable to connect", re.I)),
    )

    def guard_connect(self, wait_seconds: int) -> dict[str, object]:
        alias = self.policy.connect_alias
        if not alias:
            raise PolicyError("guard_connect is disabled (connect_alias is empty)")
        if self._eval(f"$isalias({alias})") != "$true":
            raise PolicyError(f"alias {alias!r} is not loaded; load your guard script first")
        before = int(self._eval("$line(Status Window,0)") or 0)
        log.info("guard_connect /%s", alias)
        self.bridge.command(f"/{alias}", flood_protection=False)
        deadline = time.monotonic() + max(5, min(wait_seconds, 180))
        outcome, new = "pending", []
        while time.monotonic() < deadline:
            time.sleep(1)
            total = int(self._eval("$line(Status Window,0)") or 0)
            new = [self._eval(f"$line(Status Window,{i})") for i in range(before + 1, total + 1)]
            new = [t for t in new if t.strip(" -")]
            if self._eval("$status") == "connected":
                outcome = "connected"
                break
            hit = next((name for name, rx in self.OUTCOMES for t in new if rx.search(t)), None)
            if hit:
                outcome = hit
                if any("retry" in t.lower() for t in new):
                    outcome += " (mIRC is retrying)"
                break
        return {
            "outcome": outcome,
            "status": self._eval("$status"),
            "server": self._eval("$server"),
            "new_status_lines": new[-40:],
            "dialogs": self.open_dialogs(),
        }

    # ---- certificate pinning ---------------------------------------------------

    def _servers_ini(self) -> Path:
        mdir = self._eval("$mircdir")
        name = self._eval("$readini($mircini,n,files,servers)") or "servers.ini"
        p = Path(name)
        return p if p.is_absolute() else Path(mdir) / p

    def pin_certificate(self, sha256: str, host: str, port: int, restart: bool) -> dict[str, object]:
        if not self.policy.allow_pin:
            raise PolicyError("pin_certificate is disabled (allow_pin = false)")
        want = certpin.normalise_fp(sha256)
        if not 1 <= port <= 65535:
            raise PolicyError("port must be 1-65535")
        host = host.lower()
        running = self.bridge.running()
        if running:
            servers_ini = self._servers_ini()
        else:
            servers_ini = self.servers_ini_fallback
        if running and not restart:
            raise PolicyError(
                "mIRC is running and rewrites servers.ini from memory, so the pin would be lost. "
                "Pass restart=true to have mIRC closed (/exit -n), the pin written, and mIRC started "
                "again with -noconnect."
            )
        try:
            presented = certpin.fetch(host, port, self.policy.tor_socks_ports[0])
        except (OSError, ssl.SSLError) as e:
            raise PolicyError(f"could not fetch the certificate from {host}:{port}: {e}") from e
        if presented.sha256 != want:
            raise PolicyError(
                f"fingerprint mismatch: {host}:{port} presents SHA-256 {presented.sha256}, not {want}. Nothing written."
            )
        exe = None
        if running:
            exe = self.bridge.exe_path()
            pid = self.bridge.pid()
            log.info("pin_certificate: closing mIRC pid %s", pid)
            self.bridge.command("/exit -n", flood_protection=False)
            end = time.monotonic() + 20
            while self.bridge.running() and time.monotonic() < end:
                time.sleep(0.3)
            if self.bridge.running():
                raise PolicyError("mIRC did not exit within 20 s (a modal dialog may be open); nothing written")
            time.sleep(1)  # let mIRC finish writing its ini files
        action = certpin.write_entry(servers_ini, presented, host)
        result: dict[str, object] = {
            "pinned": True,
            "action": action,
            "servers_ini": str(servers_ini),
            "host": host,
            "port": port,
            "sha256": presented.sha256,
            "sha1": presented.sha1,
            "cn": presented.cn,
        }
        if exe:
            args = [exe, *self.start_args, "-noconnect"]
            proc = subprocess.Popen(args)
            self.bridge.retarget(proc.pid)
            end = time.monotonic() + 20
            while not self.bridge.running() and time.monotonic() < end:
                time.sleep(0.3)
            result["restarted_pid"] = proc.pid
            result["start_args"] = args[1:]
        return result


def build(m: Mirc) -> MCPServer:
    server = MCPServer(
        name="mirc",
        instructions=(
            "Reads and writes a local mIRC client through a restricted bridge. Only allowlisted "
            "connections, targets, verbs and identifiers are accepted; there is no raw command or "
            "raw evaluation tool. Messages come from the bridge's in-memory buffer of recent "
            "events (since the bridge script was loaded), newest last."
        ),
    )

    def guarded(fn, *a):
        try:
            return fn(*a)
        except (PolicyError, MircError, certpin.PinError) as e:
            raise ToolError(str(e)) from e

    @server.tool()
    def list_connections() -> list[dict[str, object]]:
        """List mIRC server connections (cid, status, server, network, nick, allowed by policy)."""
        return guarded(m.connections)

    @server.tool()
    def list_windows(cid: int) -> dict[str, list]:
        """List joined channels (with user count and topic) and open query windows of a connection."""
        return guarded(m.windows, cid)

    @server.tool()
    def read_messages(cid: int | None = None, window: str | None = None, after_seq: int = 0, limit: int = 50) -> dict[str, object]:
        """Recent TEXT/ACTION/NOTICE/own messages, oldest first. Pass the returned last_seq as after_seq to poll for new ones."""
        return guarded(m.messages, cid, window, after_seq, limit)

    @server.tool()
    def send_message(cid: int, target: str, text: str, kind: str = "msg") -> str:
        """Send a message (kind: msg, notice or action) to an allowlisted channel or nick. No CTCP."""
        return guarded(m.send, cid, target, text, kind)

    @server.tool()
    def irc_command(cid: int, command: str, target: str, text: str = "") -> str:
        """Run one allowlisted IRC command: join/part/names/topic take a channel, whois a nick; part reason or new topic go in text."""
        return guarded(m.command, cid, command, target, text)

    @server.tool()
    def evaluate_identifier(cid: int, name: str, args: list[str] | None = None, prop: str | None = None) -> str:
        """Evaluate one allowlisted mIRC identifier in a connection, e.g. name='chan', args=['#x'], prop='topic' -> $chan(#x).topic."""
        return guarded(m.identifier, cid, name, args or [], prop)

    @server.tool()
    def audit_settings() -> dict[str, object]:
        """Read mIRC's leak-relevant settings (proxy, identd, DDE, update check) and list problems. Read-only apart from /saveini."""
        return guarded(m.audit)

    if m.policy.allow_harden:

        @server.tool()
        def harden_settings(tor_port: int = 9050) -> dict[str, object]:
            """Route mIRC through the local Tor SOCKS5 proxy (127.0.0.1:tor_port, DCC included) and turn off identd and the DDE server. Tightening only."""
            return guarded(m.harden, tor_port)

    @server.tool()
    def mirc_status(lines: int = 20) -> dict[str, object]:
        """Read-only: pid, version, $status/$server, each connection (status, server, port, ssl), the last N status-window lines, open modal dialogs and loaded scripts."""
        return guarded(m.status, lines)

    @server.tool()
    def list_dialogs() -> list[dict[str, str]]:
        """List mIRC's open modal dialogs. While one is open, mIRC runs no script events (guards, buffer, cert prompt)."""
        return guarded(m.open_dialogs)

    @server.tool()
    def close_dialog(title: str) -> str:
        """Cancel one named mIRC dialog (mIRC Options, mIRC Favorites, mIRC Connection Help, About mIRC, mIRC SSL Certificate Warning). Cancel never applies changes; a certificate warning is refused, not accepted."""
        return guarded(m.close_dialog, title)

    @server.tool()
    def list_scripts() -> list[str]:
        """Full paths of the loaded remote scripts."""
        return guarded(m.scripts)

    if m.policy.allow_reload:

        @server.tool()
        def reload_script(name: str) -> dict[str, object]:
            """Re-read an already loaded remote script by file name (e.g. 'guard.mrc') with /reload -rs. Cannot load new scripts."""
            return guarded(m.reload_script, name)

    if m.policy.connect_alias:

        @server.tool()
        def guard_connect(wait_seconds: int = 30) -> dict[str, object]:
            """Run the configured connect-guard alias (policy connect_alias) and nothing else, then report: connected, cert_failure, resolve_failure, proxy_failure, guard_blocked, refused or pending, with the new status lines."""
            return guarded(m.guard_connect, wait_seconds)

    if m.policy.allow_pin:

        @server.tool()
        def pin_certificate(sha256: str, host: str, port: int, restart: bool = False) -> dict[str, object]:
            """Trust a server certificate by SHA-256 fingerprint. Fetches the certificate the server presents (loopback directly, .onion via the local Tor SOCKS port) and refuses unless it matches; then writes mIRC's [sslcache] entry ('accept in future'). host must be as you connect to it (127.0.0.1 or the .onion name). mIRC must be closed, or pass restart=true to close it (/exit -n) and start it again with -noconnect."""
            return guarded(m.pin_certificate, sha256, host, port, restart)

    return server


def main() -> None:
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    policy = Policy.load()
    bridge = MircBridge()
    try:
        build(Mirc(bridge, policy)).run("stdio")
    finally:
        bridge.close()


if __name__ == "__main__":
    main()
