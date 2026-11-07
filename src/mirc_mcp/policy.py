"""What the MCP server is allowed to ask mIRC to do.

The server never forwards a free-form command or expression to mIRC. Every request
is one of a fixed set of verbs or identifiers, checked here first; the policy file
can only narrow that set, never widen it.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path

# Verbs mcp-bridge.mrc knows. A policy may allow fewer, never more.
SEND_KINDS = frozenset({"msg", "notice", "action"})
COMMANDS = frozenset({"join", "part", "whois", "names", "topic"})

# Identifiers safe to evaluate: they read state and cannot run commands, read files
# or load code. ($read, $findfile, $dll, $com, $sock*, $dcc* and custom aliases are
# absent on purpose.)
IDENTIFIERS = frozenset(
    {
        "me", "server", "network", "port", "status", "cid", "version", "usermode",
        "chan", "nick", "query", "comchan", "ial", "away", "awaymsg", "idle",
        "ctime", "time", "date", "fulldate", "chantypes", "chanmodes", "prefix",
    }
)

CHANNEL_RE = re.compile(r"[#&][^\x00-\x20,\x07]{1,49}")
NICK_RE = re.compile(r"\*?[A-Za-z\[\]\\`_^{|}][A-Za-z0-9\[\]\\`_^{|}-]{0,31}")
# Arguments that reach $eval: no $ % ( ) , [ ] | or whitespace, so they cannot
# nest an identifier, a variable or an evaluation bracket.
EVAL_ARG_RE = re.compile(r"[^\s$%(),\[\]|\x00-\x1f]{1,64}")
PROP_RE = re.compile(r"[a-z]{1,16}")
FORBIDDEN_TEXT = re.compile(r"[\x00\x01\r\n]")


class PolicyError(ValueError):
    pass


def _lower(items: list[str]) -> tuple[str, ...]:
    return tuple(i.lower() for i in items)


@dataclass(frozen=True)
class Policy:
    # Connections the server may act on, matched against $server (case-insensitive
    # glob). The default fits a bouncer reached only as an onion service.
    allowed_servers: tuple[str, ...] = ("*.onion",)
    # Message/command targets (glob, case-insensitive). Channels by default, no
    # private messages until a nick or pattern is listed.
    allowed_targets: tuple[str, ...] = ("#*",)
    # Sending to a channel needs it to be joined already.
    require_joined: bool = True
    send_kinds: frozenset[str] = SEND_KINDS
    commands: frozenset[str] = frozenset({"whois", "names", "topic"})
    identifiers: frozenset[str] = IDENTIFIERS
    max_text_bytes: int = 400
    read_limit: int = 200

    @classmethod
    def load(cls, path: Path | None = None) -> Policy:
        if path is None:
            env = os.environ.get("MIRC_MCP_POLICY")
            path = Path(env) if env else Path(os.environ.get("APPDATA", "."), "mirc-mcp", "policy.toml")
        if not path.exists():
            return cls()
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> Policy:
        d = cls()
        def narrow(key: str, allowed: frozenset[str], default: frozenset[str]) -> frozenset[str]:
            if key not in data:
                return default
            wanted = frozenset(str(x).lower() for x in data[key])  # type: ignore[union-attr]
            unknown = wanted - allowed
            if unknown:
                raise PolicyError(f"{key}: not supported, cannot be enabled: {sorted(unknown)}")
            return wanted

        return cls(
            allowed_servers=_lower(data.get("allowed_servers", list(d.allowed_servers))),  # type: ignore[arg-type]
            allowed_targets=_lower(data.get("allowed_targets", list(d.allowed_targets))),  # type: ignore[arg-type]
            require_joined=bool(data.get("require_joined", d.require_joined)),
            send_kinds=narrow("send_kinds", SEND_KINDS, d.send_kinds),
            commands=narrow("commands", COMMANDS, d.commands),
            identifiers=narrow("identifiers", IDENTIFIERS, d.identifiers),
            max_text_bytes=min(int(data.get("max_text_bytes", d.max_text_bytes)), 450),  # type: ignore[arg-type]
            read_limit=int(data.get("read_limit", d.read_limit)),  # type: ignore[arg-type]
        )

    # ---- checks -----------------------------------------------------------

    def check_server(self, server: str) -> None:
        if not any(fnmatchcase(server.lower(), p) for p in self.allowed_servers):
            raise PolicyError(f"connection to {server!r} is not in allowed_servers")

    def check_target(self, target: str) -> bool:
        """Validate a target; return True when it is a channel."""
        is_chan = bool(CHANNEL_RE.fullmatch(target))
        if not is_chan and not NICK_RE.fullmatch(target):
            raise PolicyError(f"{target!r} is not a valid channel or nick")
        if not any(fnmatchcase(target.lower(), p) for p in self.allowed_targets):
            raise PolicyError(f"{target!r} is not in allowed_targets")
        return is_chan

    def check_text(self, text: str, *, required: bool = True) -> None:
        if required and not text.strip():
            raise PolicyError("empty text")
        if FORBIDDEN_TEXT.search(text):
            raise PolicyError("text may not contain NUL, CR, LF or the CTCP byte \\x01")
        if len(text.encode("utf-8")) > self.max_text_bytes:
            raise PolicyError(f"text longer than {self.max_text_bytes} bytes")

    def check_send_kind(self, kind: str) -> None:
        if kind not in self.send_kinds:
            raise PolicyError(f"send kind {kind!r} not allowed (allowed: {sorted(self.send_kinds)})")

    def check_command(self, command: str) -> None:
        if command not in self.commands:
            raise PolicyError(f"command {command!r} not allowed (allowed: {sorted(self.commands)})")

    def build_identifier(self, name: str, args: list[str], prop: str | None) -> str:
        if name not in self.identifiers:
            raise PolicyError(f"identifier ${name} not allowed (allowed: {sorted(self.identifiers)})")
        for a in args:
            if not EVAL_ARG_RE.fullmatch(a):
                raise PolicyError(f"argument {a!r} has characters that could nest evaluation")
        if prop is not None and not PROP_RE.fullmatch(prop):
            raise PolicyError(f"property {prop!r} must be lowercase letters")
        expr = f"${name}"
        if args:
            expr += "(" + ",".join(args) + ")"
        if prop:
            expr += "." + prop
        return expr
