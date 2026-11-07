from __future__ import annotations

import pytest

from mirc_mcp.certpin import PinError, Presented, normalise_fp, write_entry

FP = "A6:21:BD:79:D6:26:11:77:52:AE:B4:D0:6C:31:8C:A5:F1:63:D3:C9:88:36:69:A3:AD:50:66:15:02:F5:6C:5A"
P = Presented(sha256=normalise_fp(FP), sha1="c50d2ba6991d86d63fcc956d6f9806718864c931", cn="host.unknown")


def test_normalise_fp():
    assert normalise_fp(FP) == FP.replace(":", "").lower()
    for bad in ("", "abc", FP[:-3], "C5:0D:2B:A6:99:1D:86:D6:3F:CC:95:6D:6F:98:06:71:88:64:C9:31"):
        with pytest.raises(PinError):
            normalise_fp(bad)


def test_adds_section_when_missing(tmp_path):
    ini = tmp_path / "servers.ini"
    ini.write_bytes(b"[servers]\r\nn0=xSERVER:x:6667\r\n")
    assert write_entry(ini, P, "127.0.0.1") == "added"
    text = ini.read_text()
    assert "[sslcache]\nn0=C50D2BA6991D86D63FCC956D6F9806718864C931,host.unknown,127.0.0.1,1" in text.replace("\r\n", "\n")
    assert (tmp_path / "servers.ini.mirc-mcp.bak").read_bytes() == b"[servers]\r\nn0=xSERVER:x:6667\r\n"
    assert b"\r\n" in ini.read_bytes() and b"\n\n" not in ini.read_bytes().replace(b"\r\n", b"")


def test_updates_rejected_entry_and_keeps_others(tmp_path):
    ini = tmp_path / "servers.ini"
    ini.write_bytes(
        b"[sslcache]\r\nn0=AAAA,other,example.onion,1\r\n"
        b"n1=C50D2BA6991D86D63FCC956D6F9806718864C931,host.unknown,127.0.0.1,0\r\n\r\n[recent]\r\nn0=x\r\n"
    )
    assert write_entry(ini, P, "127.0.0.1") == "updated"
    lines = ini.read_text().replace("\r\n", "\n").splitlines()
    assert "n0=AAAA,other,example.onion,1" in lines
    assert "n1=C50D2BA6991D86D63FCC956D6F9806718864C931,host.unknown,127.0.0.1,1" in lines
    assert lines[-1] == "n0=x" or "[recent]" in lines


def test_adds_with_next_index(tmp_path):
    ini = tmp_path / "servers.ini"
    ini.write_bytes(b"[sslcache]\r\nn0=AAAA,other,a,1\r\nn3=BBBB,other,b,0\r\n\r\n[recent]\r\nn0=x\r\n")
    assert write_entry(ini, P, "127.0.0.1") == "added"
    text = ini.read_text().replace("\r\n", "\n")
    assert "n4=C50D2BA6991D86D63FCC956D6F9806718864C931,host.unknown,127.0.0.1,1\n\n[recent]" in text


def test_rejects_cn_with_comma(tmp_path):
    with pytest.raises(PinError):
        write_entry(tmp_path / "servers.ini", Presented(P.sha256, P.sha1, "a,b"), "127.0.0.1")
