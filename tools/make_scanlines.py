"""Write themes/phosphor-scanlines.bmp: a small tile of CRT scanlines (24-bit BMP, stdlib only).

Rows repeat every 3 pixels: two black rows and one green scanline row, as bright as it can be
while every Phosphor palette colour keeps at least 4.5:1 contrast on it."""

import struct
import sys
from pathlib import Path

W, H = 8, 3
ROWS = [(0, 0, 0), (0, 0, 0), (0, 54, 19)]  # black, black, scanline (brightest that keeps 4.5:1 for every Phosphor colour)


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
