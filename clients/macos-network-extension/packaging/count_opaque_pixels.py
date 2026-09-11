"""Count the opaque pixels in an 8-bit RGBA PNG, and print the number.

★ WHY THIS IS NOT A `sips` PIPELINE. The first attempt read every fourth byte of a sips-produced TIFF as an
alpha channel and answered "667 visible" for a fully transparent image — the header is not a fixed eight
bytes. A check that is wrong in the direction of PASSING is worse than no check, so this decodes the PNG
itself: the format is fully specified, and the answer can be verified against images whose answer is known.

Exits non-zero, with the reason on stderr, for anything it cannot read — never a number it is unsure of.
"""

import sys
import zlib


def opaque_pixels(path):
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    pos, idat, width, height, depth, colour, interlace = 8, b"", None, None, None, None, 0
    while pos + 8 <= len(data):
        length = int.from_bytes(data[pos:pos + 4], "big")
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        if kind == b"IHDR":
            width = int.from_bytes(body[0:4], "big")
            height = int.from_bytes(body[4:8], "big")
            depth, colour, interlace = body[8], body[9], body[12]
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
        pos += 12 + length
    if (width, height) == (None, None):
        raise ValueError("no IHDR")
    if colour != 6 or depth != 8 or interlace != 0:
        raise ValueError("expected a non-interlaced 8-bit RGBA PNG, got colour type %s depth %s interlace %s"
                         % (colour, depth, interlace))
    raw, bpp = zlib.decompress(idat), 4
    stride, previous, at, count = width * bpp, bytearray(width * bpp), 0, 0
    for _ in range(height):
        filt, line, at = raw[at], bytearray(raw[at + 1:at + 1 + stride]), at + 1 + stride
        for x in range(stride):
            left = line[x - bpp] if x >= bpp else 0
            up = previous[x]
            upleft = previous[x - bpp] if x >= bpp else 0
            if filt == 1:
                line[x] = (line[x] + left) & 255
            elif filt == 2:
                line[x] = (line[x] + up) & 255
            elif filt == 3:
                line[x] = (line[x] + (left + up) // 2) & 255
            elif filt == 4:
                p = left + up - upleft
                pa, pb, pc = abs(p - left), abs(p - up), abs(p - upleft)
                line[x] = (line[x] + (left if pa <= pb and pa <= pc else up if pb <= pc else upleft)) & 255
        count += sum(1 for x in range(3, stride, 4) if line[x] > 8)
        previous = line
    return count


if __name__ == "__main__":
    try:
        print(opaque_pixels(sys.argv[1]))
    except Exception as err:  # noqa: BLE001 — the caller wants a reason, not a traceback
        sys.stderr.write("count_opaque_pixels: %s: %s\n" % (sys.argv[1], err))
        sys.exit(1)
