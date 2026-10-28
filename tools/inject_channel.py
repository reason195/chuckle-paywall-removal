"""Inject the Umeng channel ID-value pair back into an APK Signing Block.

apksigner rewrites the whole APK Signing Block, so the original
0x71777777 {"channel":"app"} pair (and Play's 0x504b4453 block) disappear on any
re-sign. The app reads that pair (on2.oO0OO00 -> fh0) and degrades without it.

APK Signature Scheme v2/v3 digest the APK as three chunks:
  1. the ZIP entry contents,
  2. the central directory bytes,
  3. the EOCD with its central-directory-offset field replaced by the signing
     block start offset.
The block's own size and its unknown ID-value pairs are *not* covered, and the
block start offset does not move when a pair is inserted, so an extra pair can be
added without touching the signature. Only the EOCD's cd offset (a field that is
substituted during hashing) has to follow the shifted central directory.
"""
import struct
import sys
from pathlib import Path

MAGIC = b"APK Sig Block 42"
CHANNEL_ID = 0x71777777
CHANNEL_VAL = b'{"channel":"app"}'


def inject(src: Path, dst: Path) -> None:
    data = bytearray(src.read_bytes())

    magic = data.rfind(MAGIC)
    if magic < 0:
        raise SystemExit("no APK Signing Block found")
    magic_end = magic + 16
    size2 = struct.unpack_from("<Q", data, magic - 8)[0]
    block_start = magic_end - 8 - size2
    size1 = struct.unpack_from("<Q", data, block_start)[0]
    assert size1 == size2, (size1, size2)
    print(f"block start=0x{block_start:x} size={size1}")

    pair = struct.pack("<Q", 4 + len(CHANNEL_VAL)) + struct.pack("<I", CHANNEL_ID) + CHANNEL_VAL
    new_size = size1 + len(pair)
    print(f"inserting channel pair ({len(pair)} bytes) -> block size {new_size}")

    out = bytearray()
    out += data[:block_start]
    out += struct.pack("<Q", new_size)
    out += data[block_start + 8:magic - 8]      # existing pairs
    out += pair
    out += struct.pack("<Q", new_size)
    out += MAGIC
    out += data[magic_end:]                      # central directory + EOCD

    delta = len(pair)

    eocd = out.rfind(b"PK\x05\x06")
    if eocd < 0:
        raise SystemExit("no EOCD")
    cd_off = struct.unpack_from("<I", out, eocd + 16)[0]
    struct.pack_into("<I", out, eocd + 16, cd_off + delta)
    print(f"EOCD cd offset 0x{cd_off:x} -> 0x{cd_off + delta:x}")

    dst.write_bytes(bytes(out))
    print(f"wrote {dst} ({len(out)} bytes)")


if __name__ == "__main__":
    inject(Path(sys.argv[1]), Path(sys.argv[2]))
