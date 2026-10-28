"""Bisect which paywall patch makes AppSettingActivity crash.

Builds one APK per single-patch variant into out/bisect/, all signed with the
same local key so they install over each other.
"""
import hashlib
import os
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APK_IN = ROOT / "chuckle-1.1.1-154.apk"
BT = Path(r"C:\Users\Daniel\AppData\Local\Android\Sdk\build-tools\37.0.0")
JDK = Path(r"C:\Users\Daniel\tools\jdk\jdk-21.0.12.1+1")
KS = ROOT / "out" / "nopaywall.keystore"

PATCHES = {
    "q6free":  ("classes.dex", 0x1E12BC, "62001f5d",     "12000f00"),
    "q6force": ("classes.dex", 0x1E149C, "71004cbe0000", "12000f00"),
    "dvjpaid": ("classes2.dex", 0x3A5DD8, "71002f660000", "12100f00"),
}


def adler(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def fix_header(dex: bytes) -> bytes:
    size = struct.unpack_from("<I", dex, 0x20)[0]
    out = bytearray(dex[:size])
    out[12:32] = b"\x00" * 20
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    out[8:12] = b"\x00" * 4
    struct.pack_into("<I", out, 8, adler(bytes(out[12:])))
    return bytes(out)


def build(names: list[str], out_apk: Path) -> None:
    src = zipfile.ZipFile(APK_IN)
    touched: dict[str, bytes] = {}
    for name in names:
        dex_name, off, expect, repl = PATCHES[name]
        dex = bytearray(touched.get(dex_name) or src.read(dex_name))
        have = bytes(dex[off:off + len(expect) // 2]).hex()
        assert have == expect, f"{name}: {have} != {expect}"
        dex[off:off + len(repl) // 2] = bytes.fromhex(repl)
        touched[dex_name] = fix_header(bytes(dex))

    tmp = out_apk.with_suffix(".unsigned.apk")
    with zipfile.ZipFile(tmp, "w") as out:
        for info in src.infolist():
            n = info.filename
            if n.startswith("META-INF/") and n.endswith((".RSA", ".SF", ".MF", ".EC")):
                continue
            new = zipfile.ZipInfo(n, date_time=info.date_time)
            new.compress_type = info.compress_type
            new.external_attr = info.external_attr
            new.internal_attr = info.internal_attr
            new.create_system = info.create_system
            out.writestr(new, touched.get(n) or src.read(n))

    env = dict(os.environ, JAVA_HOME=str(JDK))
    subprocess.run([str(BT / "zipalign.exe"), "-f", "-p", "4", str(tmp), str(tmp.with_suffix(".aligned.apk"))],
                   check=True, capture_output=True)
    subprocess.run([str(BT / "apksigner.bat"), "sign", "--ks", str(KS), "--ks-pass", "pass:chuckle",
                    "--key-pass", "pass:chuckle", "--ks-key-alias", "chuckle",
                    "--out", str(out_apk), str(tmp.with_suffix(".aligned.apk"))],
                   check=True, capture_output=True, env=env)
    print("built", out_apk.name, "with", ",".join(names))


if __name__ == "__main__":
    dest = ROOT / "out" / "bisect"
    dest.mkdir(parents=True, exist_ok=True)
    for key in PATCHES:
        build([key], dest / f"variant-{key}.apk")
