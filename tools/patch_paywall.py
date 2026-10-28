"""Chuckle 1.1.1 (154) — strip the activation / subscription paywall.

Three decision predicates carry the whole premium surface, so the paywall is
removed by forcing them instead of touching Billing, RemoteConfig or the network
stack:

  classes.dex  q6.oO0OO00()Z   "freemium_enable"      -> false
                               every ad path and every upgrade surface is inert.
  classes.dex  q6.oO0OOO0()Z   "must buy now"         -> false
                               the first-run forced purchase dialog never shows.
  classes2.dex dvj.oO0OOo()Z   "has active sub"       -> true
                               trial prompts skip, premium features pass their
                               entitlement check.

Second step, after signing: restore the APK Signing Block channel pair
0x71777777 = {"channel":"app"} that apksigner wipes. The app reads it via
on2.oO0OO00 -> fh0 and its theme manager leaves ColorStateList fields null
without it, which crashes list rows and the search bar with
"RippleDrawable requires a non-null color". See inject_channel.py for why an
extra ID-value pair does not invalidate the v2/v3 signature.

All dex edits are equal-length overwrites padded with nops, so no code_off /
try / debug_info offset moves; header checksum and SHA-1 are recomputed.
"""
import hashlib
import os
import struct
import subprocess
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APK_IN = Path(os.environ.get("CHUCKLE_APK", ROOT / "chuckle-1.1.1-154.apk"))
OUT_APK = Path(os.environ.get("CHUCKLE_OUT", ROOT / "chuckle-1.1.1-154-nopaywall.apk"))
BT = Path(os.environ.get("ANDROID_BUILD_TOOLS",
                       r"C:\Users\Daniel\AppData\Local\Android\Sdk\build-tools\37.0.0"))
JDK = Path(os.environ.get("JAVA_HOME", r"C:\Users\Daniel\tools\jdk\jdk-21.0.12.1+1"))
KS = Path(os.environ.get("CHUCKLE_KEYSTORE", ROOT / "out" / "nopaywall.keystore"))
KS_PASS = os.environ.get("CHUCKLE_KS_PASS", "chuckle")
KS_ALIAS = os.environ.get("CHUCKLE_KS_ALIAS", "chuckle")

PATCHES = [
    ("classes.dex", 0x1E12BC, "62001f5d", "12000f00",
     "q6.oO0OO00()Z -> false   freemium/paywall off"),
    ("classes.dex", 0x1E149C, "71004cbe0000", "12000f00",
     "q6.oO0OOO0()Z -> false   no forced purchase dialog"),
    ("classes2.dex", 0x3A5DD8, "71002f660000", "12100f00",
     "dvj.oO0OOo()Z -> true    subscription considered active"),
    # igl.oO0OO00() verifies the APK signer hash against a value decrypted out of
    # res/raw; any re-sign fails it. pk0 (a Koin initializer) then swaps
    # xfn.oO0Ooo, the theme provider, for the empty ok0 stub, which is why every
    # ColorStateList turns null and RippleDrawable construction crashes.
    ("classes4.dex", 0x3503A4, "62001a52", "12100f00",
     "igl.oO0OO00()Z -> true   own-signature integrity check passes"),
    ("classes2.dex", 0x3A5D98, "0100", "0200",
     "dvj.oO0OOo0 registers 1 -> 2 (fake record needs v1)"),
    # the Premium page reads the persisted record directly, so give the empty
    # branch the activated label as well.
    ("classes2.dex", 0x3A5CBA, "0406147f", "0106147f",
     "cvj prime_status_unactivated -> prime_status_activated"),
]

# Programs that overwrite only the head of a region: the untouched tail stays as
# unreachable but still valid instructions. dex, insns offset, expected prefix,
# program, label.
PROGRAMS = [
    ("classes2.dex", 0x3A5DA8, "6200422f",
     "2200 1226"        # new-instance v0, Llvm;
     "7010 008b 0000"   # invoke-direct {v0}, Object.<init>  (lvm has no own ctor)
     "1a01 c98f"        # const-string v1, "active"
     "5b01 6a58"        # iput-object v1, v0, Llvm;->oO0OO0O
     "1201"             # const/4 v1, #0
     "5c01 7058"        # iput-boolean v1, v0, Llvm;->oO0OOOo  (expired=false)
     "1100",            # return-object v0
     "dvj.oO0OOo0() -> synthesized active subscription record"),
]


def adler(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def fix_header(dex: bytes) -> bytes:
    """signature first (sha1 over 32..end), then checksum (adler32 over 12..end,
    which includes the signature)."""
    size = struct.unpack_from("<I", dex, 0x20)[0]
    out = bytearray(dex[:size])
    out[12:32] = b"\x00" * 20
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    out[8:12] = b"\x00" * 4
    struct.pack_into("<I", out, 8, adler(bytes(out[12:])))
    return bytes(out)


def main() -> None:
    src = zipfile.ZipFile(APK_IN)
    touched: dict[str, bytes] = {}

    for dex_name in ("classes.dex", "classes2.dex", "classes4.dex"):
        dex = bytearray(touched.get(dex_name) or src.read(dex_name))
        changed = False
        for name, off, expect, repl, label in PATCHES:
            if name != dex_name:
                continue
            have = bytes(dex[off:off + len(expect) // 2]).hex()
            assert have == expect, f"{label}: {have} != {expect}"
            repl = repl.replace(" ", "")
            repl += "0000" * ((len(expect) - len(repl)) // 4)          # nop padding
            assert len(repl) == len(expect), f"{label}: length mismatch"
            dex[off:off + len(repl) // 2] = bytes.fromhex(repl)
            changed = True
            print(f"  {label}")
        for name, off, prefix, prog, label in PROGRAMS:
            if name != dex_name:
                continue
            have = bytes(dex[off:off + len(prefix) // 2]).hex()
            assert have == prefix, f"{label}: {have} != {prefix}"
            body = bytes.fromhex(prog.replace(" ", ""))
            dex[off:off + len(body)] = body
            changed = True
            print(f"  {label}")
        if changed:
            data = fix_header(bytes(dex))
            body = bytearray(data)
            body[8:12] = b"\x00" * 4
            assert struct.unpack_from("<I", data, 8)[0] == adler(bytes(body[12:]))
            touched[dex_name] = data

    tmp = ROOT / "out" / "unsigned-nopaywall.apk"
    with zipfile.ZipFile(tmp, "w") as out:
        for info in src.infolist():
            n = info.filename
            if n.startswith("META-INF/") and n.endswith((".RSA", ".SF", ".MF", ".EC")):
                continue  # stale v1 signature
            new = zipfile.ZipInfo(n, date_time=info.date_time)
            new.compress_type = info.compress_type
            new.external_attr = info.external_attr
            new.internal_attr = info.internal_attr
            new.create_system = info.create_system
            out.writestr(new, touched.get(n) or src.read(n))

    aligned = ROOT / "out" / "aligned-nopaywall.apk"
    subprocess.run([str(BT / "zipalign.exe"), "-f", "-p", "4", str(tmp), str(aligned)],
                   check=True, capture_output=True)
    signed = ROOT / "out" / "signed-nopaywall.apk"
    subprocess.run([str(BT / "apksigner.bat"), "sign", "--ks", str(KS),
                    "--ks-pass", f"pass:{KS_PASS}", "--key-pass", f"pass:{KS_PASS}",
                    "--ks-key-alias", KS_ALIAS, "--out", str(signed), str(aligned)],
                   check=True, capture_output=True, env=dict(os.environ, JAVA_HOME=str(JDK)))

    # restore the channel ID-value pair the app depends on
    subprocess.run(["python", str(ROOT / "tools" / "inject_channel.py"),
                    str(signed), str(OUT_APK)], check=True)
    print("final ->", OUT_APK.name, OUT_APK.stat().st_size, "bytes")


if __name__ == "__main__":
    main()
