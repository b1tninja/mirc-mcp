"""End-to-end smoke test against a real mIRC, with no network beyond 127.0.0.1.

It starts a throwaway mIRC with its own settings folder (-r, -noreg, -noconnect,
update check and identd off), loads mcp-bridge.mrc there, and points it at a tiny
fake IRC server on 127.0.0.1. Your own mIRC profile is not read or changed, and it
may stay open: the test addresses its own mIRC by process id and never sends a
message to any other mIRC window.

    .venv\\Scripts\\python tools\\smoke.py [--mirc "C:\\Program Files (x86)\\mIRC\\mirc.exe"]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import socket
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from mirc_mcp.bridge import MircBridge, MircError  # noqa: E402
from mirc_mcp.policy import Policy, PolicyError  # noqa: E402
from mirc_mcp.server import Mirc  # noqa: E402

CHAN = "#smoke"
TOPIC = "smoke topic | $me %x"


class FakeIrc:
    """Just enough of an IRC server for registration, JOIN, PRIVMSG and WHOIS."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received: list[str] = []
        self.conn: socket.socket | None = None
        self.nick = "?"
        threading.Thread(target=self._run, daemon=True).start()

    def send(self, line: str) -> None:
        assert self.conn
        self.conn.sendall((line + "\r\n").encode("utf-8"))

    def _run(self) -> None:
        self.conn, _ = self.sock.accept()
        buf = b""
        while True:
            try:
                data = self.conn.recv(4096)
            except OSError:
                return  # mIRC went away at the end of the test
            if not data:
                return
            buf += data
            while b"\r\n" in buf:
                raw, buf = buf.split(b"\r\n", 1)
                self._line(raw.decode("utf-8", "replace"))

    def _line(self, line: str) -> None:
        self.received.append(line)
        cmd, _, rest = line.partition(" ")
        cmd = cmd.upper()
        if cmd == "CAP" and rest.startswith("LS"):
            self.send(":fake.local CAP * LS :")
        elif cmd == "NICK":
            self.nick = rest.split()[0].lstrip(":")
        elif cmd == "USER":
            self.send(f":fake.local 001 {self.nick} :Welcome")
            self.send(f":fake.local 005 {self.nick} CHANTYPES=# PREFIX=(ov)@+ :are supported")
            self.send(f":fake.local 376 {self.nick} :End of MOTD")
        elif cmd == "PING":
            self.send(f":fake.local PONG fake.local {rest}")
        elif cmd == "JOIN":
            ch = rest.split()[0]
            self.send(f":{self.nick}!u@h JOIN {ch}")
            self.send(f":fake.local 332 {self.nick} {ch} :{TOPIC}")
            self.send(f":fake.local 353 {self.nick} = {ch} :{self.nick} alice")
            self.send(f":fake.local 366 {self.nick} {ch} :End")
        elif cmd == "WHOIS":
            self.send(f":fake.local 318 {self.nick} {rest} :End of WHOIS")


class DialogCloser(threading.Thread):
    """Close first-run dialogs of *our* throwaway mIRC only (About nag, Favorites, Options).

    While any modal dialog is open, mIRC still displays incoming lines but runs no script
    events, so the bridge's buffer stays empty. About is closed with its own OK button once
    the evaluation countdown has enabled it; other dialogs get IDCANCEL."""

    def __init__(self, pid: int) -> None:
        super().__init__(daemon=True)
        self.pid = pid
        self.closed: list[str] = []
        self.stop = threading.Event()

    def run(self) -> None:
        import ctypes
        from ctypes import wintypes

        u = ctypes.windll.user32
        u.FindWindowExW.restype = wintypes.HWND
        u.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
        u.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        while not self.stop.wait(0.5):
            h = None
            while h := u.FindWindowExW(None, h, "#32770", None):
                owner = wintypes.DWORD()
                u.GetWindowThreadProcessId(h, ctypes.byref(owner))
                if owner.value != self.pid or not u.IsWindowVisible(h):
                    continue
                title = ctypes.create_unicode_buffer(128)
                u.GetWindowTextW(h, title, 128)
                if title.value == "About mIRC":
                    ok = u.FindWindowExW(h, None, "Button", "OK")
                    if ok and u.IsWindowEnabled(ok):
                        u.SendMessageW(ok, 0x00F5, 0, 0)  # BM_CLICK
                        self.closed.append(title.value)
                else:
                    u.PostMessageW(h, 0x0111, 2, 0)  # WM_COMMAND IDCANCEL
                    self.closed.append(title.value)

    def no_dialogs(self) -> bool:
        return not [c for c, _ in windows_of(self.pid) if c == "#32770"]


def windows_of(pid: int) -> list[tuple[str, str]]:
    import ctypes
    from ctypes import wintypes

    u = ctypes.windll.user32
    out: list[tuple[str, str]] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(h, _):
        owner = wintypes.DWORD()
        u.GetWindowThreadProcessId(h, ctypes.byref(owner))
        if owner.value == pid and u.IsWindowVisible(h):
            cls, title = ctypes.create_unicode_buffer(128), ctypes.create_unicode_buffer(256)
            u.GetClassNameW(h, cls, 128)
            u.GetWindowTextW(h, title, 256)
            out.append((cls.value, title.value))
        return True

    u.EnumWindows(cb, 0)
    return out


def diagnose(bridge: MircBridge, pid: int) -> None:
    print("--- diagnostics")
    print("windows:", windows_of(pid))
    try:
        print("state:", bridge.evaluate("$remote $script(0) $hget(0) $mcp.seq"))
        for win in ("Status Window", CHAN):
            n = int(bridge.evaluate(f"$line({win},0)") or 0)
            for i in range(1, n + 1):
                line = bridge.evaluate(f"$line({win},{i})")
                if line.strip(" -"):
                    print(f"  {win}: {line}")
    except MircError as e:
        print("bridge:", e)


def wait(what: str, fn, timeout: float = 20.0):
    end = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < end:
        try:
            last = fn()
            if last:
                return last
        except (MircError, PolicyError) as e:
            last = e
        time.sleep(0.25)
    raise SystemExit(f"FAIL: timed out waiting for {what} (last: {last!r})")


def check(name: str, ok: bool, detail: object = "") -> None:
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail and not ok else ""))
    if not ok:
        check.failed += 1  # type: ignore[attr-defined]


check.failed = 0  # type: ignore[attr-defined]


def refused(fn, *a) -> bool:
    try:
        fn(*a)
    except PolicyError:
        return True
    return False


async def mcp_client_roundtrip(policy_path: Path, pid: int) -> list[str]:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    env = dict(os.environ, MIRC_MCP_POLICY=str(policy_path), MIRC_MCP_PID=str(pid))
    params = StdioServerParameters(command=sys.executable, args=["-m", "mirc_mcp"], env=env, cwd=str(ROOT))
    async with stdio_client(params) as (r, w), ClientSession(r, w) as s:
        await s.initialize()
        tools = sorted(t.name for t in (await s.list_tools()).tools)
        res = await s.call_tool("list_connections", {})
        return tools + [json.dumps(res.structured_content or {}) + " " + " ".join(getattr(c, "text", "") for c in res.content)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mirc", default=r"C:\Program Files (x86)\mIRC\mirc.exe")
    ap.add_argument("--keep", action="store_true", help="leave the throwaway mIRC running")
    opts = ap.parse_args()

    irc = FakeIrc()
    profile = Path(tempfile.mkdtemp(prefix="mirc-mcp-smoke-"))
    script = (ROOT / "mirc" / "mcp-bridge.mrc").resolve()
    (profile / "mirc.ini").write_text(
        "[update]\ncheck=0\n[mirc]\nnick=mcpsmoke\nanick=mcpsmoke_\nuser=smoke\nhost=\n"
        "[ident]\nactive=no\n",
        encoding="utf-8",
    )
    policy_path = profile / "policy.toml"
    policy_path.write_text('allowed_servers = ["fake.local", "127.0.0.1"]\n', encoding="utf-8")
    proc = subprocess.Popen([opts.mirc, f"-r{profile}", "-noreg", "-noconnect"])
    print(f"mIRC pid {proc.pid}, profile {profile}, fake IRC on 127.0.0.1:{irc.port}")

    def own_window():
        b = MircBridge(pid=proc.pid)
        try:
            b._hwnd()
        except MircError:
            b.close()
            raise
        return b

    bridge = wait("mIRC window", own_window)
    open_policy = Policy.from_dict({"allowed_servers": ["fake.local", "127.0.0.1"], "commands": ["join", "part", "whois", "names", "topic"]})
    m = Mirc(bridge, open_policy)
    try:
        wait("mIRC ready", lambda: bridge.evaluate("$version"))
        closer = DialogCloser(proc.pid)
        closer.start()
        time.sleep(1.5)  # let the startup dialogs appear before waiting for them to go
        wait("startup dialogs to close", closer.no_dialogs, 60)
        print(f"     closed dialogs: {sorted(set(closer.closed))}")
        bridge.command(f'/load -rs "{script}"')
        check("bridge script loaded", wait("bridge", m.bridge_version) == "1")
        check("evaluate $version", bridge.evaluate("$version").startswith("7."), bridge.evaluate("$version"))

        # Test harness only: the MCP server itself has no way to issue /server.
        bridge.command(f"/server 127.0.0.1:{irc.port}")
        conn = wait("connected", lambda: next((c for c in m.connections() if c["status"] == "connected"), None))
        cid = int(conn["cid"])
        print(f"     connection: {conn}")
        check("default policy refuses a non-onion server", refused(Mirc(bridge, Policy()).windows, cid))

        m.command(cid, "join", CHAN, "")
        w = wait("joined", lambda: m.windows(cid)["channels"])
        check("list_windows shows channel + topic", w[0]["channel"] == CHAN and w[0]["topic"] == TOPIC, w)
        check("evaluate_identifier $chan(#smoke).topic", m.identifier(cid, "chan", [CHAN], "topic") == TOPIC)
        check("evaluate_identifier $me", m.identifier(cid, "me", [], None) == irc.nick)

        start = int(bridge.evaluate("$mcp.seq") or 0)
        irc.send(f":alice!a@h PRIVMSG {CHAN} :hello from alice | $me")
        irc.send(f":alice!a@h PRIVMSG {irc.nick} :private hi")
        msgs = wait("incoming", lambda: [x for x in m.messages(cid, None, start, 50)["messages"] if x["nick"] == "alice"] if len(m.messages(cid, None, start, 50)["messages"]) >= 2 else None)
        check("read_messages channel text verbatim", msgs[0]["text"] == "hello from alice | $me" and msgs[0]["window"] == CHAN, msgs)
        check("read_messages query", msgs[1]["window"] == "alice", msgs)

        text = "pipes | dollars $me %vars {braces} [brackets] ünïcode"
        m.send(cid, CHAN, text, "msg")
        sent = wait("PRIVMSG at server", lambda: [l for l in irc.received if l.startswith(f"PRIVMSG {CHAN} ")])
        check("send_message arrives literally", sent[-1] == f"PRIVMSG {CHAN} :{text}", sent[-1])
        own = [x for x in m.messages(cid, CHAN, start, 50)["messages"] if x["type"] == "SELF"]
        check("own message recorded verbatim (UTF-8)", bool(own) and own[-1]["text"] == text, own)
        m.send(cid, CHAN, "waves", "action")
        act = wait("ACTION", lambda: [l for l in irc.received if "\x01ACTION waves\x01" in l])
        check("action sent as CTCP ACTION", bool(act))

        check("refuses CTCP payload", refused(m.send, cid, CHAN, "\x01DCC SEND x 1 2 3\x01", "msg"))
        check("refuses =nick (DCC chat) target", refused(m.send, cid, "=alice", "x", "msg"))
        check("refuses private msg not allowlisted", refused(m.send, cid, "alice", "x", "msg"))
        check("refuses channel not joined", refused(m.send, cid, "#other", "x", "msg"))
        check("refuses unknown command", refused(m.command, cid, "server", "#x", ""))
        check("refuses $read identifier", refused(m.identifier, cid, "read", ["x"], None))
        check("refuses nested $ in args", refused(m.identifier, cid, "chan", ["$dll(x)"], None))
        before = len(irc.received)
        bridge.command("/mcp.do %d ctcp %s" % (cid, "YWxpY2U="))  # script-side verb check
        time.sleep(0.5)
        check("script refuses verb outside its list", not any("PRIVMSG alice" in l for l in irc.received[before:]))

        check("refuses whois of a nick not in allowed_targets", refused(m.command, cid, "whois", "alice", ""))
        m2 = Mirc(bridge, Policy.from_dict({"allowed_servers": ["fake.local"], "allowed_targets": ["#*", "alice"]}))
        m2.command(cid, "whois", "alice", "")
        check("whois reaches server", bool(wait("WHOIS", lambda: [l for l in irc.received if l.upper().startswith("WHOIS")])))

        tools = asyncio.run(mcp_client_roundtrip(policy_path, proc.pid))
        expected = {"evaluate_identifier", "irc_command", "list_connections", "list_windows", "read_messages", "send_message", "audit_settings", "harden_settings"}
        check("MCP stdio: tools listed", expected <= set(tools[:-1]), tools)
        check("MCP stdio: list_connections over the protocol", "fake.local" in tools[-1] or "127.0.0.1" in tools[-1], tools[-1])

        # Settings last: turning the proxy on changes how this instance would connect.
        before = m.audit()
        check("audit flags proxy off, identd/DDE on", len(before["findings"]) >= 2 and not before["ok"], before)
        check("audit never returns the SOCKS password key", not any("pw" in k for k in before["settings"]))
        check("harden refuses a port outside tor_socks_ports", refused(m.harden, 1080))
        check("harden refused when allow_harden is false", refused(Mirc(bridge, Policy.from_dict({"allow_harden": False})).harden, 9050))
        after = m.harden(9050)
        st = after["settings"]
        check(
            "harden: SOCKS5 127.0.0.1:9050 on, DCC via proxy, identd and DDE off",
            st["socks.enabled"] == "yes" and st["socks.method"] == "5" and st["socks.port"] == "9050"
            and st["socks.dccs"] == "yes" and st["ident.active"] == "no" and st["dde.ServerStatus"] == "off",
            after,
        )
        rest = [f for f in after["findings"] if "update" not in f.lower()]
        check("harden leaves no finding except possibly update checks", not rest, after["findings"])
    except BaseException:
        diagnose(bridge, proc.pid)
        raise
    else:
        if check.failed:  # type: ignore[attr-defined]
            diagnose(bridge, proc.pid)
    finally:
        if not opts.keep:
            try:
                bridge.command("/exit")
            except MircError:
                pass
            try:
                proc.wait(3)
            except subprocess.TimeoutExpired:
                proc.kill()  # /exit is ignored while a modal dialog is up
            shutil.rmtree(profile, ignore_errors=True)
        bridge.close()
    print("received by fake server:", *irc.received, sep="\n  ")
    print("OK" if not check.failed else f"{check.failed} FAILED")  # type: ignore[attr-defined]
    return 1 if check.failed else 0  # type: ignore[attr-defined]


if __name__ == "__main__":
    raise SystemExit(main())
