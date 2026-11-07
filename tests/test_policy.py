from __future__ import annotations

import pytest

from mirc_mcp.policy import Policy, PolicyError
from mirc_mcp.server import b64


def test_defaults_allow_onion_only():
    p = Policy()
    p.check_server("abc.onion")
    with pytest.raises(PolicyError):
        p.check_server("irc.libera.chat")


def test_targets():
    p = Policy()
    assert p.check_target("#mirc") is True
    for bad in ("someone", "=dccnick", "#a,#b", "0", "#a b", ""):
        with pytest.raises(PolicyError):
            p.check_target(bad)
    assert Policy.from_dict({"allowed_targets": ["*status"]}).check_target("*status") is False


def test_text_rejects_ctcp_and_newlines():
    p = Policy()
    p.check_text("hello | $me %var")  # transported as base64, so these are inert
    for bad in ("\x01DCC SEND x 1 2 3\x01", "a\r\nPRIVMSG x :y", "", "x" * 401):
        with pytest.raises(PolicyError):
            p.check_text(bad)


def test_policy_cannot_widen():
    with pytest.raises(PolicyError):
        Policy.from_dict({"commands": ["server"]})
    with pytest.raises(PolicyError):
        Policy.from_dict({"identifiers": ["read"]})
    with pytest.raises(PolicyError):
        Policy.from_dict({"send_kinds": ["ctcp"]})
    assert Policy().commands == {"whois", "names", "topic"}


def test_identifier_args_cannot_nest():
    p = Policy()
    assert p.build_identifier("chan", ["#x"], "topic") == "$chan(#x).topic"
    assert p.build_identifier("me", [], None) == "$me"
    for args in (["$dll(x)"], ["%pass"], ["#x)", "y"], ["[ $me ]"], ["a b"], ["a|b"]):
        with pytest.raises(PolicyError):
            p.build_identifier("chan", args, None)
    with pytest.raises(PolicyError):
        p.build_identifier("read", ["x"], None)
    with pytest.raises(PolicyError):
        p.build_identifier("chan", ["1"], "Topic()")


def test_b64_is_editbox_safe():
    import re

    assert re.fullmatch(r"[A-Za-z0-9+/=]+", b64("héllo | $me %x {}"))
