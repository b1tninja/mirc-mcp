"""Offline edits of mirc.ini, for settings mIRC has no command for.

mIRC keeps its options in memory and rewrites mirc.ini from them, so these edits are made
only while mIRC is closed. Only one comma-separated field of one [options] key changes;
every other byte of the file is kept, and a one-time backup is written next to it.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path


class SettingsError(ValueError):
    pass


def set_options_field(ini: Path, key: str, index: int, value: str) -> str:
    """Set field `index` (0-based) of `key=` in [options]. Returns the previous value."""
    if not re.fullmatch(r"n\d+", key) or not re.fullmatch(r"[0-9]+", value):
        raise SettingsError("only numeric fields of [options] nN keys can be set")
    raw = ini.read_bytes()
    text = raw.decode("utf-8", errors="surrogateescape")
    sec = re.search(r"(?ms)^\[options\][ \t]*\r?$(.*?)(?=^\[|\Z)", text)
    if not sec:
        raise SettingsError("mirc.ini has no [options] section")
    m = re.compile(rf"(?m)^{key}=([^\r\n]*)").search(text, sec.start(1), sec.end(1))
    if not m:
        raise SettingsError(f"[options] has no {key}=")
    fields = m.group(1).split(",")
    if index >= len(fields):
        raise SettingsError(f"[options] {key} has only {len(fields)} fields")
    old = fields[index]
    fields[index] = value
    backup = ini.with_name(ini.name + ".mirc-mcp.bak")
    if not backup.exists():
        shutil.copy2(ini, backup)
    ini.write_bytes((text[: m.start(1)] + ",".join(fields) + text[m.end(1) :]).encode("utf-8", errors="surrogateescape"))
    return old
