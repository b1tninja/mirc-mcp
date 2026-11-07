"""Run tools/smoke.py inside Windows Sandbox with networking disabled.

The sandbox gets read-only views of the mIRC install, this Python, and this project
(with its .venv), plus one writable output folder. Nothing in it can reach a network,
your mIRC profile or your registry, and it is discarded when the window closes.

    .venv\\Scripts\\python tools\\sandbox.py [--out DIR] [--timeout 300]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parents[1]
MIRC = Path(r"C:\Program Files (x86)\mIRC")
SB = r"C:\sb"


def wsb(out: Path) -> str:
    py = Path(sys.base_prefix)  # the real interpreter behind the venv

    def mapped(host: Path, guest: str, ro: bool = True) -> str:
        return (
            "<MappedFolder>"
            f"<HostFolder>{escape(str(host))}</HostFolder>"
            f"<SandboxFolder>{escape(guest)}</SandboxFolder>"
            f"<ReadOnly>{'true' if ro else 'false'}</ReadOnly>"
            "</MappedFolder>"
        )

    run = (
        rf"set PYTHONPATH={SB}\mirc-mcp\src;{SB}\mirc-mcp\.venv\Lib\site-packages"
        rf"&& set PYTHONDONTWRITEBYTECODE=1"
        rf"&& {SB}\python\python.exe {SB}\mirc-mcp\tools\smoke.py --mirc {SB}\mIRC\mirc.exe"
        rf" > {SB}\out\smoke.txt 2>&1"
        rf"& echo %errorlevel% > {SB}\out\done.txt"
    )
    return (
        "<Configuration>"
        "<Networking>Disable</Networking>"
        "<ClipboardRedirection>Disable</ClipboardRedirection>"
        "<PrinterRedirection>Disable</PrinterRedirection>"
        "<AudioInput>Disable</AudioInput><VideoInput>Disable</VideoInput>"
        "<MappedFolders>"
        + mapped(MIRC, rf"{SB}\mIRC")
        + mapped(py, rf"{SB}\python")
        + mapped(ROOT, rf"{SB}\mirc-mcp")
        + mapped(out, rf"{SB}\out", ro=False)
        + "</MappedFolders>"
        f"<LogonCommand><Command>cmd.exe /c \"{escape(run)}\"</Command></LogonCommand>"
        "</Configuration>"
    )


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=Path(tempfile.gettempdir()) / "mirc-mcp-sandbox")
    ap.add_argument("--timeout", type=int, default=300)
    opts = ap.parse_args()
    out: Path = opts.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    for f in ("smoke.txt", "done.txt"):
        (out / f).unlink(missing_ok=True)
    cfg = out / "smoke.wsb"
    cfg.write_text(wsb(out), encoding="utf-8")
    subprocess.Popen(["WindowsSandbox.exe", str(cfg)])
    print(f"sandbox starting; output in {out}")
    end = time.monotonic() + opts.timeout
    while not (out / "done.txt").exists():
        if time.monotonic() > end:
            print("timed out; the sandbox window is still open")
            return 2
        time.sleep(2)
    time.sleep(1)
    print((out / "smoke.txt").read_text(encoding="utf-8", errors="replace"))
    code = (out / "done.txt").read_text().strip()
    print(f"exit code in sandbox: {code}. Close the sandbox window to discard it.")
    return 0 if code == "0" else 1


if __name__ == "__main__":
    raise SystemExit(main())
