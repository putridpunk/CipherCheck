"""Draws the CipherCheck icon (a green "C_" on a dark Matrix tile) with pure Python.

    python tools/make_icon.py

Writes assets/: ciphercheck.png (256), ciphercheck.ico, ciphercheck.icns.
No third-party packages are needed (own PNG/ICO/ICNS writers).
"""

from __future__ import annotations

import math
import struct
import zlib
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "assets"

BG = (3, 22, 12)
GREEN = (0, 255, 65)
HEAD = (214, 255, 224)


def smooth(edge0: float, edge1: float, x: float) -> float:
    t = min(max((x - edge0) / (edge1 - edge0), 0.0), 1.0)
    return t * t * (3 - 2 * t)


def sd_round_box(x: float, y: float, hx: float, hy: float, r: float) -> float:
    qx, qy = abs(x) - hx + r, abs(y) - hy + r
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r


def over(dst: tuple, rgb: tuple, a: float) -> tuple:
    """Composite colour `rgb` with coverage `a` over premultiplied RGBA `dst`."""
    r, g, b, da = dst
    return (rgb[0] * a + r * (1 - a), rgb[1] * a + g * (1 - a),
            rgb[2] * a + b * (1 - a), a + da * (1 - a))


def sample(u: float, v: float, px: float) -> tuple:
    """Premultiplied RGBA of the icon at (u, v) in [-1, 1]; px = pixel size in those units."""
    aa = px * 1.2
    px_ = (0.0, 0.0, 0.0, 0.0)

    # tile
    d = sd_round_box(u, v, 0.94, 0.94, 0.30)
    tile = 1 - smooth(-aa, aa, d)
    if tile <= 0:
        return px_
    px_ = over(px_, BG, tile)

    # faint falling-glyph columns
    col, row = math.floor((u + 1) / 0.19), math.floor((v + 1) / 0.17)
    h = (col * 73856093 ^ row * 19349663) & 0xFFFF
    if h % 3 == 0 and abs(((u + 1) % 0.19) - 0.095) < 0.035 and abs(((v + 1) % 0.17) - 0.085) < 0.045:
        px_ = over(px_, GREEN, 0.20 * (1 - (v + 1) / 2.4) * tile)

    # tile border
    border = (1 - smooth(-aa, aa, abs(d + 0.035) - 0.018)) * 0.65
    px_ = over(px_, GREEN, border * tile)

    # the letter C: annulus with an opening on the right, soft glow behind it
    cx, cy = u + 0.06, v
    rad = math.hypot(cx, cy)
    ang = math.degrees(math.atan2(cy, cx))
    ring = max(rad - 0.56, 0.37 - rad)             # < 0 inside the ring
    gap = (38 - abs(ang)) * math.pi / 180 * rad    # > 0 inside the opening
    c_sd = max(ring, gap)
    glow = 0.30 * math.exp(-(max(c_sd, 0) / 0.09) ** 2)
    px_ = over(px_, GREEN, glow * tile)
    px_ = over(px_, GREEN, (1 - smooth(-aa, aa, c_sd)) * tile)

    # the blinking cursor "_"
    cur = max(abs(u - 0.38) - 0.27, abs(v - 0.60) - 0.065)
    px_ = over(px_, HEAD, (1 - smooth(-aa, aa, cur)) * tile)
    return px_


def render(size: int) -> bytes:
    """RGBA bytes (straight alpha), row-major, supersampled."""
    ss = 3 if size <= 128 else 2
    px = 2.0 / size
    out = bytearray()
    for j in range(size):
        for i in range(size):
            r = g = b = a = 0.0
            for sj in range(ss):
                for si in range(ss):
                    u = (i + (si + 0.5) / ss) * px - 1
                    v = (j + (sj + 0.5) / ss) * px - 1
                    sr, sg, sb, sa = sample(u, v, px / ss)
                    r += sr; g += sg; b += sb; a += sa
            n = ss * ss
            a /= n
            if a > 0:
                out += bytes((min(255, round(r / n / a)), min(255, round(g / n / a)),
                              min(255, round(b / n / a)), min(255, round(a * 255))))
            else:
                out += b"\x00\x00\x00\x00"
    return bytes(out)


def png(size: int, rgba: bytes) -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + rgba[y * size * 4:(y + 1) * size * 4] for y in range(size))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def dib(size: int, rgba: bytes) -> bytes:
    """Classic BMP-in-ICO entry (bottom-up BGRA + empty AND mask)."""
    header = struct.pack("<IiiHHIIiiII", 40, size, size * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    rows = []
    for y in range(size - 1, -1, -1):
        row = rgba[y * size * 4:(y + 1) * size * 4]
        rows.append(b"".join(bytes((row[k + 2], row[k + 1], row[k], row[k + 3]))
                             for k in range(0, len(row), 4)))
    mask_row = b"\x00" * (((size + 31) // 32) * 4)
    return header + b"".join(rows) + mask_row * size


def ico(images: dict[int, bytes]) -> bytes:
    entries, blobs, offset = b"", b"", 6 + 16 * len(images)
    for size, rgba in sorted(images.items()):
        blob = png(size, rgba) if size >= 256 else dib(size, rgba)
        entries += struct.pack("<BBBBHHII", size % 256, size % 256, 0, 0, 1, 32, len(blob), offset)
        blobs += blob
        offset += len(blob)
    return struct.pack("<HHH", 0, 1, len(images)) + entries + blobs


def icns(images: dict[int, bytes]) -> bytes:
    types = {128: b"ic07", 256: b"ic08", 512: b"ic09"}
    body = b""
    for size, tag in types.items():
        data = png(size, images[size])
        body += tag + struct.pack(">I", len(data) + 8) + data
    return b"icns" + struct.pack(">I", len(body) + 8) + body


def main() -> None:
    ASSETS.mkdir(exist_ok=True)
    sizes = [16, 32, 48, 64, 128, 256, 512]
    images = {s: render(s) for s in sizes}
    (ASSETS / "ciphercheck.png").write_bytes(png(256, images[256]))
    (ASSETS / "ciphercheck.ico").write_bytes(ico({s: images[s] for s in (16, 32, 48, 64, 128, 256)}))
    (ASSETS / "ciphercheck.icns").write_bytes(icns(images))
    for f in sorted(ASSETS.iterdir()):
        print(f"{f.name}  {f.stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
