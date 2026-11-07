"""mIRC's modal dialogs, seen and closed through plain Win32 window messages.

Only dialogs owned by the mIRC process the bridge talks to are touched. Closing means
Cancel (WM_COMMAND IDCANCEL): it discards whatever the dialog would have changed. The
one exception is the evaluation-copy "About mIRC" nag, which has no Cancel and no
settings, and is closed with its own OK button once mIRC has enabled it.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes

WM_COMMAND = 0x0111
WM_GETTEXT = 0x000D
WM_GETTEXTLENGTH = 0x000E
BM_CLICK = 0x00F5
IDCANCEL = 2

# Dialogs close_dialog may cancel. Cancel never applies a change in any of these.
CLOSABLE = frozenset(
    {
        "mIRC Options",
        "mIRC Favorites",
        "mIRC Connection Help",
        "About mIRC",
        "mIRC SSL Certificate Warning",  # Cancel = refuse the certificate
    }
)

_u = ctypes.WinDLL("user32", use_last_error=True)
_u.FindWindowExW.restype = wintypes.HWND
_u.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
_u.SendMessageW.restype = ctypes.c_ssize_t
_u.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_u.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
_u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
_u.GetDlgItem.restype = wintypes.HWND
_u.GetDlgItem.argtypes = [wintypes.HWND, ctypes.c_int]


def owner_pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    _u.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def _title(hwnd: int) -> str:
    buf = ctypes.create_unicode_buffer(256)
    _u.GetWindowTextW(hwnd, buf, 256)
    return buf.value


def control_text(hwnd: int) -> str:
    """Text of a control in another process (WM_GETTEXT works across processes)."""
    n = _u.SendMessageW(hwnd, WM_GETTEXTLENGTH, 0, 0)
    buf = ctypes.create_unicode_buffer(n + 1)
    _u.SendMessageW(hwnd, WM_GETTEXT, n + 1, ctypes.cast(buf, ctypes.c_void_p).value)
    return buf.value


def find(pid: int, title: str | None = None) -> list[tuple[int, str]]:
    """Visible dialogs (#32770) of process `pid`, optionally with an exact title."""
    out = []
    h = None
    while h := _u.FindWindowExW(None, h, "#32770", title):
        if owner_pid(h) == pid and _u.IsWindowVisible(h):
            out.append((h, _title(h)))
    return out


def list_dialogs(pid: int) -> list[dict[str, str]]:
    return [{"title": t, "class": "#32770"} for _, t in find(pid)]


def close(pid: int, title: str) -> bool:
    """Cancel the named dialog. Returns False if it is not open (or About's OK is not ready)."""
    if title not in CLOSABLE:
        raise ValueError(f"{title!r} is not a dialog close_dialog may close (allowed: {sorted(CLOSABLE)})")
    done = False
    for h, _ in find(pid, title):
        if title == "About mIRC":
            ok = _u.FindWindowExW(h, None, "Button", "OK")
            if ok and _u.IsWindowEnabled(ok):
                _u.SendMessageW(ok, BM_CLICK, 0, 0)
                done = True
        else:
            _u.PostMessageW(h, WM_COMMAND, IDCANCEL, 0)
            done = True
    return done
