"""Talk to a running mIRC through its documented SendMessage interface.

mIRC reads a line from a named shared-memory mapping ("mIRC" or "mIRCN") when it
receives WM_MCOMMAND (run it as if typed in an editbox) or WM_MEVALUATE (evaluate
it and write the result back into the mapping). Nothing here opens a socket: the
whole channel is a window message plus 4 KiB of shared memory inside this Windows
session.

Reference: https://github.com/mIRC-Scripters/mirckb/blob/master/docs/source/advanced/sendmessage.rst
"""

from __future__ import annotations

import ctypes
import os
import threading
from ctypes import wintypes

WM_USER = 0x0400
WM_MCOMMAND = WM_USER + 200
WM_MEVALUATE = WM_USER + 201

# cMethod bits (see reference above)
M_EDITBOX = 1
M_FLOOD = 4
M_UNICODE = 8
M_EXTENDED_ERRORS = 16

MAP_SIZE = 4096  # documented minimum; in UTF-16 that is 2047 characters plus NUL
MAX_CHARS = MAP_SIZE // 2 - 1

PAGE_READWRITE = 0x04
FILE_MAP_ALL_ACCESS = 0x000F001F
ERROR_ALREADY_EXISTS = 183
INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value
SMTO_BLOCK = 0x0001
SMTO_ABORTIFHUNG = 0x0002

_ERRORS = {
    2: "bad mapped filename",
    4: "bad mapped file size",
    8: "bad eventid",
    16: "bad server",
    32: "bad script",
    64: "disabled in mIRC's lock dialog",
}


class MircError(RuntimeError):
    pass


def _api() -> tuple[ctypes.WinDLL, ctypes.WinDLL]:
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowW.restype = wintypes.HWND
    user32.IsWindow.argtypes = [wintypes.HWND]
    user32.IsWindow.restype = wintypes.BOOL
    user32.FindWindowExW.argtypes = [wintypes.HWND, wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR]
    user32.FindWindowExW.restype = wintypes.HWND
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD
    user32.SendMessageTimeoutW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
        wintypes.UINT,
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    user32.SendMessageTimeoutW.restype = ctypes.c_size_t

    kernel32.CreateFileMappingW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
    ]
    kernel32.CreateFileMappingW.restype = wintypes.HANDLE
    kernel32.MapViewOfFile.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_size_t,
    ]
    kernel32.MapViewOfFile.restype = wintypes.LPVOID
    kernel32.UnmapViewOfFile.argtypes = [wintypes.LPCVOID]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    return user32, kernel32


class MircBridge:
    """One shared mapping, reused for every call, guarded by a lock."""

    def __init__(self, window_class: str = "mIRC", timeout_ms: int = 5000, pid: int | None = None) -> None:
        if os.name != "nt":
            raise MircError("mIRC's SendMessage interface exists only on Windows")
        self._user32, self._kernel32 = _api()
        self._window_class = window_class
        # With several mIRC instances open, MIRC_MCP_PID picks one; otherwise the first.
        env_pid = os.environ.get("MIRC_MCP_PID")
        self._pid = pid if pid is not None else (int(env_pid) if env_pid else None)
        self._timeout_ms = timeout_ms
        self._lock = threading.Lock()
        self._index, self._handle = self._create_mapping()
        self._view = self._kernel32.MapViewOfFile(self._handle, FILE_MAP_ALL_ACCESS, 0, 0, 0)
        if not self._view:
            self._kernel32.CloseHandle(self._handle)
            raise MircError(f"MapViewOfFile failed: {ctypes.get_last_error()}")

    def _create_mapping(self) -> tuple[int, int]:
        # The reference asks callers to skip a name that already exists: another
        # program is using it. Start away from 0 ("mIRC"), which DLLs commonly take.
        base = 7000 + os.getpid() % 1000
        for offset in range(200):
            index = base + offset
            handle = self._kernel32.CreateFileMappingW(
                INVALID_HANDLE_VALUE, None, PAGE_READWRITE, 0, MAP_SIZE, f"mIRC{index}"
            )
            err = ctypes.get_last_error()
            if not handle:
                raise MircError(f"CreateFileMapping failed: {err}")
            if err == ERROR_ALREADY_EXISTS:
                self._kernel32.CloseHandle(handle)
                continue
            return index, handle
        raise MircError("no free mIRCN mapping name")

    def close(self) -> None:
        if self._view:
            self._kernel32.UnmapViewOfFile(self._view)
            self._view = None
        if self._handle:
            self._kernel32.CloseHandle(self._handle)
            self._handle = None

    def _hwnd(self) -> int:
        hwnd = None
        while True:
            hwnd = self._user32.FindWindowExW(None, hwnd, self._window_class, None)
            if not hwnd:
                who = f" with pid {self._pid}" if self._pid is not None else ""
                raise MircError(f"mIRC is not running (no window of class 'mIRC'{who})")
            if self._pid is None:
                return hwnd
            owner = wintypes.DWORD(0)
            self._user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
            if owner.value == self._pid:
                return hwnd

    def _write(self, text: str) -> None:
        if len(text) > MAX_CHARS:
            raise MircError(f"line too long for the mapping ({len(text)} > {MAX_CHARS})")
        data = text.encode("utf-16-le") + b"\0\0"
        ctypes.memmove(self._view, data, len(data))

    def _send(self, msg: int, method: int) -> None:
        result = ctypes.c_size_t(0)
        ok = self._user32.SendMessageTimeoutW(
            self._hwnd(),
            msg,
            method | M_UNICODE | M_EXTENDED_ERRORS,
            self._index,
            SMTO_BLOCK | SMTO_ABORTIFHUNG,
            self._timeout_ms,
            ctypes.byref(result),
        )
        if not ok:
            raise MircError(f"mIRC did not answer within {self._timeout_ms} ms")
        code = result.value
        if code:
            why = [text for bit, text in _ERRORS.items() if code & bit] or ["script error"]
            raise MircError(f"mIRC refused the request ({code}: {', '.join(why)})")

    def command(self, line: str, *, flood_protection: bool = True) -> None:
        """Run `line` as if typed into the status window's editbox."""
        with self._lock:
            self._write(line)
            self._send(WM_MCOMMAND, M_EDITBOX | (M_FLOOD if flood_protection else 0))

    def evaluate(self, expression: str) -> str:
        """Evaluate `expression` (identifiers and variables) and return the text."""
        with self._lock:
            self._write(expression)
            self._send(WM_MEVALUATE, 0)
            return ctypes.wstring_at(self._view, MAX_CHARS).split("\0", 1)[0]
