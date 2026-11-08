"""Write themes/phosphor-scanlines.bmp: a small tile of CRT scanlines (24-bit BMP, stdlib only).

Rows repeat every 3 pixels: two near-black rows with a faint green cast, one slightly
brighter green row. Kept very dark so text contrast stays high."""

import struct
import sys
from pathlib import Path

W, H = 8, 3
ROWS = [(0, 6, 2), (0, 6, 2), (0, 22, 8)]  # R, G, B per row (top to bottom)


def bmp(width, height, rows):
    row_bytes = (width * 3 + 3) & ~3
    pixels = b""
    for y in range(height - 1, -1, -1):  # BMP rows are stored bottom-up
        r, g, b = rows[y]
        line = bytes([b, g, r]) * width
        pixels += line + b"\0" * (row_bytes - len(line))
    header = struct.pack("<2sIHHI", b"BM", 54 + len(pixels), 0, 0, 54)
    info = struct.pack("<IiiHHIIiiII", 40, width, height, 1, 24, 0, len(pixels), 2835, 2835, 0, 0)
    return header + info + pixels


out = Path(sys.argv[1])
out.write_bytes(bmp(W, H, ROWS))
print(out, out.stat().st_size, "bytes")
