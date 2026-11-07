from __future__ import annotations

import pytest

from mirc_mcp.mts import COLOR_ITEMS, ThemeError, load, parse

DEFAULT_COLORS = "0,6,4,5,2,3,3,3,3,3,3,1,5,7,6,1,3,2,3,5,1,0,1,0,1,15"
DEFAULT_RGB = (
    "255,255,255 0,0,0 0,0,128 0,144,0 255,0,0 128,0,0 160,0,160 255,128,0 "
    "255,255,0 0,255,0 0,144,144 0,255,255 0,0,255 255,0,255 128,128,128 208,208,208"
)

THEME = f"""; synthetic test theme
[mts]
Name Test Theme
MTSVersion 1.1
Author someone
Colors {DEFAULT_COLORS}
RGBColors {DEFAULT_RGB}
FontDefault Lucida Console,9,B
FontChan Tahoma,10
Script test.mrc
TextChan !Script theme.textchan
Load !Script theme.load
ImageStatus tile bg.png
SndJoin join.wav
JoinSelf * Now talking in <chan>
Scheme1 Dark

[scheme1]
Colors 1,6,4,5,2,3,3,3,3,3,3,0,5,7,6,0,3,2,3,5,0,1,0,1,0,14
"""


def test_reads_only_appearance_and_lists_the_rest():
    t = parse(THEME)
    assert t.name == "Test Theme" and t.mts_version == "1.1"
    assert t.colors == [int(x) for x in DEFAULT_COLORS.split(",")]
    assert t.rgb[0] == (255, 255, 255) and t.rgb[15] == (208, 208, 208)
    assert (t.font.name, t.font.size, t.font.bold) == ("Lucida Console", 9, True)
    assert set(t.ignored_code) == {"script", "textchan", "load"}
    assert set(t.ignored_files) == {"imagestatus", "sndjoin"}
    assert t.schemes == ["1"]


def test_commands_are_fixed_form():
    cmds = parse(THEME).commands()
    assert len(cmds) == len(COLOR_ITEMS) + 16 + 1
    assert cmds[0] == "/color background 0" and cmds[25] == "/color gray 15"
    assert cmds[26] == "/color 0 16777215"  # white = 255 + 255*256 + 255*65536
    assert cmds[28] == f"/color 2 {128 * 65536}"  # navy 0,0,128
    assert cmds[-1] == "/font -zb 9 Lucida Console"
    for c in cmds:
        assert not any(ch in c for ch in "|$%;{}"), c


def test_scheme_overrides_main():
    t = parse(THEME, "1")
    assert t.scheme == "1" and t.colors[0] == 1 and t.colors[25] == 14
    assert t.rgb is not None  # inherited from the main section
    with pytest.raises(ThemeError):
        parse(THEME, "2")


@pytest.mark.parametrize(
    "line",
    [
        "Colors 1,2,3",  # wrong count
        "Colors " + ",".join(["99"] * 26),  # out of range
        "Colors " + ",".join(["1"] * 25) + ",$me",  # not a number
        "RGBColors 1,2,3",  # wrong count
        "RGBColors " + " ".join(["256,0,0"] * 16),  # out of range
        "FontDefault Arial|run calc,9",  # characters mIRC would parse
        "FontDefault Arial,$size",
        "FontDefault Arial,0",
        "FontDefault Arial,9,X",
    ],
)
def test_rejects_bad_values(line):
    with pytest.raises(ThemeError):
        parse(f"[mts]\nName x\nMTSVersion 1.1\n{line}\n")


def test_requires_mts_section_and_mts_file(tmp_path):
    with pytest.raises(ThemeError):
        parse("[other]\nName x\n")
    f = tmp_path / "theme.txt"
    f.write_text(THEME)
    with pytest.raises(ThemeError):
        load(f)
    g = tmp_path / "theme.mts"
    g.write_bytes(THEME.replace("someone", "s\xf8me").encode("cp1252"))  # legacy encoding
    assert load(g).name == "Test Theme"
