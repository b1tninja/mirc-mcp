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

There is deliberately **no raw command and no raw evaluate tool**. Evaluating an
arbitrary mIRC expression is code execution (`$dll`, `$com`, custom aliases), and a raw
command could start a `/server`, `/dcc` or `/run`.

### Layers of the guard

1. **Python policy** (`policy.py`): connections must match `allowed_servers` (default
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
- `python tools\smoke.py`: an end-to-end test (23 checks, all passing on mIRC 7.86 on
  2026-11-07). It starts a throwaway mIRC with its own settings folder
  (`-r <temp> -noreg -noconnect`, no update check, identd off) and drives it by process id
  against a fake IRC server on 127.0.0.1. A background thread closes that instance's own
  first-run dialogs (the evaluation nag only once its OK button is enabled), because they
  would block script events. At the end the test kills the instance and deletes its
  profile. Your own mIRC and profile are never addressed.
- `python tools\sandbox.py`: runs the same smoke test inside Windows Sandbox with
  networking disabled. It maps mIRC, Python and this folder read-only and has one writable
  output folder. Written but **not yet run**: the sandbox was in use.
