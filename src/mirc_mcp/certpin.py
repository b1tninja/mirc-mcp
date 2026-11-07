"""Pin a server certificate for mIRC by SHA-256 fingerprint.

Verified on mIRC 7.86: mIRC remembers certificates in servers.ini under [sslcache] as
`nN=<SHA-1 hex>,<subject CN>,<host as typed>,<flag>`, where flag 1 means "automatically
accept this certificate in future". An entry with flag 1 is honoured even when
Options > Connect > SSL is set to reject invalid certificates ([ssl] warn=0), so pinning
needs no change to that setting. mIRC rewrites servers.ini from memory, so the entry has
to be written while mIRC is not running.

Before writing, the certificate is fetched from the server itself and its SHA-256 must
equal the fingerprint given. Fetching opens a socket to 127.0.0.1 only: directly for a
loopback host, or through the local Tor SOCKS5 port for a .onion host.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import socket
import ssl
import struct
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

LOOPBACK = {"127.0.0.1", "localhost", "::1"}
ONION_RE = re.compile(r"[a-z2-7]{56}\.onion")


class PinError(ValueError):
    pass


def normalise_fp(fp: str) -> str:
    h = re.sub(r"[\s:]", "", fp).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", h):
        raise PinError("fingerprint must be a SHA-256 hash: 64 hex digits, colons allowed")
    return h


@dataclass(frozen=True)
class Presented:
    sha256: str
    sha1: str
    cn: str


def _socks5(tor_port: int, host: str, port: int, timeout: float) -> socket.socket:
    s = socket.create_connection(("127.0.0.1", tor_port), timeout=timeout)
    s.sendall(b"\x05\x01\x00")
    if s.recv(2) != b"\x05\x00":
        s.close()
        raise PinError(f"127.0.0.1:{tor_port} did not answer as a SOCKS5 proxy without authentication")
    name = host.encode("ascii")
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack(">H", port))
    reply = s.recv(10)
    if len(reply) < 2 or reply[1] != 0:
        s.close()
        raise PinError(f"Tor could not reach {host}:{port} (SOCKS5 reply {reply[1] if len(reply) > 1 else '?'})")
    return s


def fetch(host: str, port: int, tor_port: int, timeout: float = 90.0) -> Presented:
    """TLS handshake without verification, to read the certificate the server presents."""
    if host in LOOPBACK:
        raw = socket.create_connection((host, port), timeout=timeout)
    elif ONION_RE.fullmatch(host):
        raw = _socks5(tor_port, host, port, timeout)
    else:
        raise PinError("only a loopback host or a v3 .onion host can be pinned")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with raw, ctx.wrap_socket(raw, server_hostname=None if host in LOOPBACK else host) as tls:
        der = tls.getpeercert(binary_form=True)
    if not der:
        raise PinError("the server presented no certificate")
    cert = x509.load_der_x509_certificate(der)
    cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return Presented(hashlib.sha256(der).hexdigest(), hashlib.sha1(der).hexdigest(), str(cns[0].value) if cns else "")


def write_entry(servers_ini: Path, presented: Presented, host: str) -> str:
    """Add or update the [sslcache] entry. Keeps a one-time backup next to the file."""
    if any(c in presented.cn for c in ",\r\n"):
        raise PinError("certificate CN contains characters mIRC's cache line cannot hold")
    raw = servers_ini.read_bytes() if servers_ini.exists() else b""
    text = raw.decode("utf-8", errors="surrogateescape")
    nl = "\r\n" if "\r\n" in text or not text else "\n"
    lines = text.split(nl)
    sha1 = presented.sha1.upper()
    entry_value = f"{sha1},{presented.cn},{host},1"

    try:
        start = next(i for i, l in enumerate(lines) if l.strip().lower() == "[sslcache]")
    except StopIteration:
        while lines and lines[-1] == "":
            lines.pop()
        lines += ["", "[sslcache]", f"n0={entry_value}", ""]
        action = "added"
    else:
        end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("[")), len(lines))
        used = []
        action = "added"
        for i in range(start + 1, end):
            k, _, v = lines[i].partition("=")
            if re.fullmatch(r"n\d+", k):
                used.append(int(k[1:]))
                fields = v.split(",")
                if fields and fields[0].upper() == sha1 and len(fields) >= 3 and fields[2].lower() == host.lower():
                    lines[i] = f"{k}={entry_value}"
                    action = "updated"
        if action == "added":
            pos = end
            while pos > start + 1 and lines[pos - 1] == "":
                pos -= 1
            lines.insert(pos, f"n{max(used, default=-1) + 1}={entry_value}")
    backup = servers_ini.with_name(servers_ini.name + ".mirc-mcp.bak")
    if servers_ini.exists() and not backup.exists():
        shutil.copy2(servers_ini, backup)
    servers_ini.write_bytes(nl.join(lines).encode("utf-8", errors="surrogateescape"))
    return action
