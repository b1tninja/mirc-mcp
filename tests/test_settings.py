from __future__ import annotations

import pytest

from mirc_mcp.settings import SettingsError, set_options_field

INI = (
    b"[rfiles]\r\nn4=scripts/x.ini\r\n\r\n[options]\r\n"
    b"n1=5,100,1\r\nn4=1,1,1,0,0,3,9999,0,0,1,0,0,1024,1,1,99,60,0,0,1,1\r\n\r\n[text]\r\nx=1\r\n"
)


def test_sets_only_that_field_in_options(tmp_path):
    ini = tmp_path / "mirc.ini"
    ini.write_bytes(INI)
    assert set_options_field(ini, "n4", 19, "0") == "1"
    out = ini.read_bytes()
    assert out == INI.replace(b"0,0,1,1\r\n\r\n[text]", b"0,0,0,1\r\n\r\n[text]")
    assert b"n4=scripts/x.ini" in out  # same key in another section untouched
    assert (tmp_path / "mirc.ini.mirc-mcp.bak").read_bytes() == INI


def test_refuses_bad_input(tmp_path):
    ini = tmp_path / "mirc.ini"
    ini.write_bytes(INI)
    for args in (("n4", 99, "0"), ("host", 0, "0"), ("n4", 1, "x"), ("n9", 0, "0")):
        with pytest.raises(SettingsError):
            set_options_field(ini, *args)
