"""MCP server (stdio only) that drives a local mIRC through mcp-bridge.mrc."""

from __future__ import annotations

import base64
import logging
import sys
from dataclasses import dataclass

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

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
        except (PolicyError, MircError) as e:
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
