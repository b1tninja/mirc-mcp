# mirc-mcp

A local MCP server (stdio only) that lets an MCP client read from and write to a
running mIRC on the same Windows PC, through a restricted bridge.

**It adds no network exposure.** The server talks to mIRC with mIRC's documented
SendMessage interface: a window message plus a 4 KiB named shared-memory mapping
inside your Windows session. There is no socket, no port and no DDE, and the mIRC
side (`mirc/mcp-bridge.mrc`) opens no socket and starts no DCC. The MCP client
starts the server as a child process and talks to it over stdin/stdout.

## Why this design

No MCP server for mIRC existed when this was written (2026-11-07). The IRC MCP
servers that do exist (`tbarron-xyz/mcp-irc-ts`, `matheusfillipe/ircv3-mcp`,
`jbanier/irc-mcp`, ...) are IRC clients in their own right. They would open their own
connection, bypassing any proxy or connect guard you have set up in mIRC, so they are the wrong tool for driving an existing client.

| Way to drive mIRC | Network? | Verdict |
|---|---|---|
| **SendMessage `WM_MCOMMAND`/`WM_MEVALUATE` + `mIRCN` mapping** | none | **used**: documented, synchronous, returns results, ctypes only |
| DDE (`mIRC` service, `COMMAND`/`EVALUATE`) | none | works, but legacy, and any local program can use it. Consider turning it off (Options > Other > DDE) since nothing here needs it |
| Script socket bridge (`socklisten 127.0.0.1`) | a listening TCP port | rejected: a port that any local process (or a browser via DNS rebinding) can reach |
| Reading log files | none | read-only, needs logging to disk, and has no send |

## What it exposes

| Tool | Does |
|---|---|
| `list_connections` | cid, status, server, network, nick, and whether policy allows it |
| `list_windows(cid)` | joined channels (users, topic) and open queries |
| `read_messages(cid?, window?, after_seq, limit)` | recent TEXT/ACTION/NOTICE/own lines from the bridge's in-memory ring buffer (500 entries, never written to disk) |
| `send_message(cid, target, text, kind)` | `msg` / `notice` / `action` to an allowlisted target |
| `irc_command(cid, command, target, text)` | one of `join part whois names topic` (default allows `whois names topic`) |
| `evaluate_identifier(cid, name, args, prop)` | one allowlisted identifier, e.g. `$chan(#x).topic` |
| `audit_settings()` | reads fixed leak-relevant `mirc.ini` keys (proxy, identd, DDE, update check, Favorites on connect, Local Info lookup method) after `/saveini` and lists problems; the SOCKS password key is never read. The lookup method is `[options] n2` field 4 on 7.86 (0 Normal, 1 Server, 2 Website); "Website" is flagged because it fetches your IP from a web site, possibly outside the proxy |
| `harden_settings(tor_port)` | tightening only: `/proxy -cm5+d 127.0.0.1 <port>` and `/proxy on` (SOCKS5, DCC included, user/password cleared), `/identd off`, `/ddeserver off`. The port must be in `tor_socks_ports` (default 9050, 9150); `allow_harden = false` removes the tool |
| `mirc_status(lines)` | read-only: pid, version, `$status`/`$server`, each connection (status, server, port, ssl), the last N status-window lines, open dialogs, loaded scripts. Works without `mcp-bridge.mrc` |
| `list_dialogs()` / `close_dialog(title)` | list mIRC's open modal dialogs; cancel one of `mIRC Options`, `mIRC Favorites`, `mIRC Connection Help`, `About mIRC` (closed with its OK once mIRC enables it), `mIRC SSL Certificate Warning` (Cancel = refuse the cert). Cancel never applies a change |
| `list_scripts()` / `reload_script(name)` | list loaded remote scripts; `/reload -rs` one that is already loaded, by file name. It cannot load a new script. `allow_reload = false` removes it |
| `guard_connect(wait_seconds)` | runs exactly one alias, `connect_alias` (empty by default, so the tool is off until you name your guard's alias in `policy.toml`), which must already be loaded, then reports `connected`, `cert_failure`, `resolve_failure`, `proxy_failure`, `guard_blocked`, `refused` or `pending`, with the new status lines. It never runs `/server`, and by default (`require_proxy_for_connect`) it refuses unless mIRC's SOCKS5 proxy is on 127.0.0.1 with a Tor port, so a `.onion` name can never go to Windows DNS. `connect_alias = ""` removes it |
| `pin_certificate(sha256, host, port, restart)` | trusts a server certificate by SHA-256 (see below). `allow_pin = false` removes it |
| `apply_mts_theme(path, scheme, dry_run)` / `restore_appearance(backup)` | applies only the appearance of a local `.mts` theme (MTS 1.x): the 26 `Colors` items, the 16-colour `RGBColors` palette and `FontDefault`, as `/color` and `/font` commands built from validated numbers. Theme code (`Script`, `!Script` event lines, `Load`/`Unload`), images, sounds and engines/DLLs are never used and are listed as ignored. `dry_run` (default) changes nothing; applying first saves the current appearance to `%LOCALAPPDATA%\mirc-mcp\appearance-*.json`, which `restore_appearance` puts back. `allow_theme = false` removes both |
| `disable_favorites_on_connect(restart)` | turns off "Show favorites on connect" (`[options] n4`, field 19 on 7.86), whose modal dialog blocks script events on every connect. Unticks it in the open Favorites dialog, or with `restart=true` closes mIRC, changes only that field in `mirc.ini` (one-time backup), and starts mIRC again. `audit_settings` reports it |

Settings are changed with mIRC's own commands rather than by editing `mirc.ini`, because
mIRC rewrites that file from memory on exit and would undo an edit made while it runs.

### Nick leak through a bouncer (verified on 7.86)

mIRC registers with its configured nick (`$mnick`). When a bouncer welcomes it under that nick
and then renames it, mIRC sends `USERHOST <configured nick>` to the network straight after the
welcome. Unticking Options > Connect > Local Info does not stop this. The fix is to set mIRC's
configured nick to the bouncer's nick. `mirc_status` warns while the two differ.

### Included theme

`themes/phosphor.mts` is an original appearance-only MTS theme: green phosphor on black in
Consolas 14 pt (a negative MTS font size is a point size), like an old terminal. Notices and CTCP are amber, highlights yellow, kicks red, and colours 2 and 12 (the blues
bots and servers use for links) are a bright cyan-blue. Every palette colour has at least 7:1
contrast on the black background (WCAG AAA). Scheme 1
is an amber CRT. It contains no script, event, image or sound lines, so it is safe with any MTS
engine. Try it with `apply_mts_theme("themes/phosphor.mts")` (dry run), then `dry_run=false`.

### CRT scanlines

`themes/phosphor-scanlines.bmp` (made by `tools/make_scanlines.py`) is an 8x3 tile of faint green
scanlines for Phosphor: two black rows and one green line, as bright as it can be while every palette
colour keeps at least 4.5:1 contrast on the line (main text 10:1).
Copy it into mIRC's folder and tile it with mIRC's own command (verified on 7.86: `-s` is the
status window, `-e` with `#` or `=` sets the default for every channel or query window):

```
/background -st "phosphor-scanlines.bmp"
/background -et # "phosphor-scanlines.bmp"
/background -et = "phosphor-scanlines.bmp"
```

`/background -sx`, `-ex #`, `-ex =` remove them. Glow and screen curvature need a shader overlay
such as ShaderGlass; mIRC has no way to draw them.

### Certificate pinning

mIRC 7.86 remembers certificates in `servers.ini` under `[sslcache]` as
`nN=<SHA-1>,<subject CN>,<IP connected to>,<flag>`. Through a SOCKS proxy mIRC never learns the IP, so for a `.onion` reached via Tor the third field is empty; `pin_certificate` therefore writes that empty-host form too when you pin a `.onion` host (verified on 7.86: without it the pinned certificate was still rejected through the proxy). Ticking "Automatically accept this
certificate in future" writes flag `1`. Tested on 7.86: an entry with flag `1` is honoured
even when Options > Connect > SSL rejects invalid certificates (`[ssl] warn=0`), so pinning
needs no weaker setting. Hostname checks don't apply, which suits a bouncer with a
self-signed certificate.

`pin_certificate` makes one TLS handshake to fetch the certificate the server presents. For
a loopback host it connects directly; for a `.onion` host it goes through the first
`tor_socks_ports` entry on 127.0.0.1. Either way the only socket opened is to 127.0.0.1. If
the presented SHA-256 differs from the one you passed, nothing is written. On a match it
adds or updates the `[sslcache]` line and keeps a one-time `servers.ini.mirc-mcp.bak`.
Because mIRC rewrites `servers.ini` from memory, mIRC must be closed. With `restart=true`
the tool closes it (`/exit -n`), writes the entry, and starts the same executable again with
`-noconnect`. Use the host exactly as you connect to it: `127.0.0.1` for a local relay, or
the `.onion` name.

### mIRC and Tor: what was verified (mIRC 7.86, 2026-11-07)

- **With the SOCKS5 proxy on, mIRC hands a `.onion` name to the proxy unresolved.** A fake
  SOCKS5 server received `CONNECT ATYP=3 <name>.onion:6697`, and the Windows DNS cache had no
  entry for the name. So pointing mIRC at Tor's SOCKS port is enough to reach an onion
  service; no relay or torsocks-style wrapper is needed.
- **With the proxy off, mIRC asks Windows DNS for the name** and fails with "Unable to resolve
  server". That leaks the onion name to your DNS resolver. [RFC 7686 §2](https://www.rfc-editor.org/rfc/rfc7686.html#section-2)
  says applications that don't implement Tor "SHOULD NOT perform a DNS lookup" for `.onion`.
- **With the proxy on, `127.0.0.1` targets go through the proxy too** (`ATYP=1 127.0.0.1`), so
  a local relay stops being reachable once the proxy is on.
- **mIRC can contact `www.mirc.com` (port 443) at startup outside any proxy**, even with
  `[update] check=0`. A fresh unregistered instance did so in every run. The proxy settings
  don't cover this, so block `mirc.exe` outbound in Windows Firewall if mIRC must never touch
  the network itself.

Earlier reports of the same `.onion` problem in other clients: the [mIRC forum on SOCKS5 and
DNS](https://forums.mirc.com/ubbthreads.php/topics/216565), an [AdiIRC thread](https://dev.adiirc.com/boards/1/topics/882)
where a DNS check before proxying broke `.onion`, and the [TripSit Tor proxy guide](https://wiki.tripsit.me/wiki/Proxy_Configuration_for_Tor).

There is deliberately **no raw command and no raw evaluate tool**. Evaluating an
arbitrary mIRC expression is code execution (`$dll`, `$com`, custom aliases), and a raw
command could start a `/server`, `/dcc` or `/run`.

### Layers of the guard

1. **Python policy** (`policy.py`): the address mIRC *dialled* (`$server(-1)`, not the name the
   server announces, which through a bouncer is e.g. `irc.znc.in`) must match `allowed_servers` (default
   `*.onion`), and targets must match `allowed_targets` (default `#*`, so no private
   messages until you list nicks). Channels must already be joined. Text may not contain
   `\x01` (no CTCP, so no DCC offer), CR/LF or NUL, and is capped at 400 bytes. Identifier
   arguments may not contain `$ % ( ) , [ ] |` or whitespace, so they cannot nest an
   evaluation. The policy file can only narrow the built-in lists; naming an unsupported
   verb or identifier is an error.
2. **Transport**: all user text and targets reach mIRC base64-encoded in a single
   `/mcp.do <cid> <verb> <b64> <b64>` line, so mIRC never parses them for `|`, `$` or `%`.
3. **mIRC script** (`mcp-bridge.mrc`): re-checks the verb list, rejects `\x01`, `=nick`
   (DCC chat) targets, comma lists and `join 0`.
4. **Anything else you already run** (a connect-guard script in mIRC, CTCP/DCC filtering on a bouncer) stays in force; the bridge adds no way around it.

What this does **not** protect against: any program running as you can already send
these window messages (or DDE) to mIRC directly. The bridge limits what *the MCP client*
can do; it does not sandbox your user account. As a mIRC-side backstop, consider
Options > Other > Lock to disable `/run`, `/dll`, `/com` and DCC.

## Install

```bash
cd mirc-mcp
uv venv -p 3.14 .venv
uv pip install -p .venv\Scripts\python.exe -e ".[dev]"
```

Copy `mirc/mcp-bridge.mrc` to `%APPDATA%\mIRC\` and load it once in mIRC:

```
/load -rs "%APPDATA%\mIRC\mcp-bridge.mrc"
```

Optional: copy `policy.example.toml` to `%APPDATA%\mirc-mcp\policy.toml` and edit it
(or point `MIRC_MCP_POLICY` at another file). If several mIRC instances are open,
`MIRC_MCP_PID` selects one.

Register with Claude Code (stdio):

```bash
claude mcp add mirc -- <path-to>\mirc-mcp\.venv\Scripts\python.exe -m mirc_mcp
```

**Caveat: modal dialogs pause the buffer.** While any modal dialog is open in mIRC
(Options, About, Favorites), mIRC still displays incoming lines but runs no script
events, so `read_messages` sees nothing new until the dialog closes. Sending and
evaluating still work.

## Tests

- `pytest`: policy unit tests, which need no mIRC.
- `python tools\smoke.py`: an end-to-end test (61 checks, all passing on mIRC 7.86 on
  2026-11-07). It starts a throwaway mIRC with its own settings folder
  (`-r <temp> -noreg -noconnect`, no update check, identd off) and drives it by process id
  against a fake IRC server on 127.0.0.1. A background thread closes that instance's own
  first-run dialogs (the evaluation nag only once its OK button is enabled), because they
  would block script events. At the end the test kills the instance and deletes its
  profile. Your own mIRC and profile are never addressed.
- `python tools\sandbox.py`: runs the same smoke test inside Windows Sandbox with
  networking disabled. It maps mIRC, Python and this folder read-only and has one writable
  output folder. Written but **not yet run**: the sandbox was in use.
