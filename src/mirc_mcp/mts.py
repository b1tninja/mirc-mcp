"""Read the appearance part of an MTS (mIRC Theme Standard) theme, and nothing else.

MTS 1.x themes are plain text: an `[mts]` section, optional `[schemeN]` sections, settings
and event lines. Themes can also run code (a `Script` file, `!Script` event lines, `Load` /
`Unload` events) and load images and sounds. This module never acts on any of those: it
extracts only `Colors`, `RGBColors` and `FontDefault`, validates every value, and turns them
into fixed-form `/color` and `/font` commands. Everything else is reported as ignored.

Format reference: the MTS 1.1 themer reference (Peace and Protection wiki, MTSREF).
Item names and value encodings were verified against mIRC 7.86.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_BYTES = 256 * 1024

# Order of the 26 numbers in an MTS `Colors` line, mapped to the names mIRC 7.86's /color
# accepts (each verified to set its own item). "Grayed text" is mIRC's "gray".
COLOR_ITEMS = (
    "background", "action", "ctcp", "highlight", "info", "info2", "invite", "join", "kick", "mode",
    "nick", "normal", "notice", "notify", "other", "own", "part", "quit", "topic", "wallops", "whois",
    "editbox", "editbox text", "listbox", "listbox text", "gray",
)
FONT_NAME_RE = re.compile(r"[A-Za-z0-9 ._&+()-]{1,40}")
# Keys and events that would run code or load files; listed so the caller sees what was skipped.
CODE_KEYS = {"script", "load", "unload"}
FILE_KEYS_PREFIX = ("image", "snd")


class ThemeError(ValueError):
    pass


@dataclass
class Font:
    name: str
    size: int
    bold: bool


@dataclass
class Theme:
    name: str = ""
    mts_version: str = ""
    scheme: str | None = None
    colors: list[int] | None = None
    rgb: list[tuple[int, int, int]] | None = None
    font: Font | None = None
    ignored_code: list[str] = field(default_factory=list)
    ignored_files: list[str] = field(default_factory=list)
    ignored_other: list[str] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)

    def commands(self) -> list[str]:
        out = []
        if self.colors is not None:
            out += [f"/color {item} {n}" for item, n in zip(COLOR_ITEMS, self.colors, strict=True)]
        if self.rgb is not None:
            out += [f"/color {i} {r + g * 256 + b * 65536}" for i, (r, g, b) in enumerate(self.rgb)]
        if self.font is not None:
            out.append(f"/font -z{'b' if self.font.bold else ''} {self.font.size} {self.font.name}")
        return out


def _sections(text: str) -> dict[str, dict[str, str]]:
    text = text.lstrip("﻿")  # many themes start with a UTF-8 byte-order mark
    sections: dict[str, dict[str, str]] = {}
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        m = re.fullmatch(r"\[([^\]]+)\]", line)
        if m:
            current = m.group(1).strip().lower()
            sections.setdefault(current, {})
            continue
        if current is None:
            continue
        key, _, value = line.partition(" ")
        sections[current].setdefault(key.lower(), value.strip())
    return sections


def parse_colors(value: str) -> list[int]:
    parts = [p.strip() for p in value.split(",")]
    if len(parts) != len(COLOR_ITEMS) or not all(re.fullmatch(r"\d{1,2}", p) for p in parts):
        raise ThemeError(f"Colors must be {len(COLOR_ITEMS)} comma-separated numbers 0-98")
    nums = [int(p) for p in parts]
    if any(n > 98 for n in nums):
        raise ThemeError("Colors values must be 0-98")
    return nums


def parse_rgb(value: str) -> list[tuple[int, int, int]]:
    sets = value.split()
    if len(sets) != 16:
        raise ThemeError("RGBColors must be 16 space-separated R,G,B sets")
    out = []
    for s in sets:
        parts = s.split(",")
        if len(parts) != 3 or not all(re.fullmatch(r"\d{1,3}", p) and int(p) <= 255 for p in parts):
            raise ThemeError(f"RGBColors entry {s!r} is not R,G,B with values 0-255")
        out.append((int(parts[0]), int(parts[1]), int(parts[2])))
    return out


def parse_font(value: str) -> Font:
    parts = [p.strip() for p in value.split(",")]
    if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2].upper() != "B"):
        raise ThemeError("FontDefault must be 'name,size' or 'name,size,B'")
    name, size = parts[0], parts[1]
    if not FONT_NAME_RE.fullmatch(name):
        raise ThemeError(f"font name {name!r} has characters that are not allowed")
    if not re.fullmatch(r"-?\d{1,2}", size) or int(size) == 0:
        raise ThemeError("font size must be a non-zero number between -99 and 99")
    return Font(name, int(size), len(parts) == 3)


def parse(text: str, scheme: str | None = None) -> Theme:
    sec = _sections(text)
    if "mts" not in sec:
        raise ThemeError("not an MTS theme: no [mts] section")
    main = sec["mts"]
    theme = Theme(name=main.get("name", ""), mts_version=main.get("mtsversion", ""))
    theme.schemes = sorted(k[len("scheme"):] for k in main if re.fullmatch(r"scheme\d+", k))
    values = dict(main)
    if scheme is not None:
        key = f"scheme{scheme}"
        if key not in sec:
            raise ThemeError(f"theme has no [{key}] section (schemes: {theme.schemes or 'none'})")
        values.update(sec[key])
        theme.scheme = scheme
    for key, value in values.items():
        if key == "colors":
            theme.colors = parse_colors(value)
        elif key == "rgbcolors":
            theme.rgb = parse_rgb(value)
        elif key == "fontdefault":
            theme.font = parse_font(value)
        elif key in CODE_KEYS or value.lower().startswith("!script"):
            theme.ignored_code.append(key)
        elif key.startswith(FILE_KEYS_PREFIX):
            theme.ignored_files.append(key)
        elif key not in ("name", "mtsversion") and not re.fullmatch(r"scheme\d+", key):
            theme.ignored_other.append(key)
    return theme


def load(path: Path, scheme: str | None = None) -> Theme:
    if path.suffix.lower() != ".mts":
        raise ThemeError("only .mts files are read")
    if not path.is_file():
        raise ThemeError(f"{path} is not a file")
    if path.stat().st_size > MAX_BYTES:
        raise ThemeError(f"theme file is larger than {MAX_BYTES} bytes")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("cp1252", errors="replace")
    return parse(text, scheme)
