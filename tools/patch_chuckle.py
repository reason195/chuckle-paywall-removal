"""Chuckle 1.1.1 (154) — remove in-app paywall / activation logic.

Two surgical dex patches; no manifest or resource changes needed.

PATCH A  Lads_mobile_sdk/ab0;->get()Ljava/lang/Object;
    robolectric-free SafeIterableMap / dagger provider factory used ONLY by
    ek m.oO0OO00 to build the ad-SDK `se0` initializer. Returning null there is
    already an accepted value. Replaces the two-branch switch with
    `const/4 v0, #0` + `return-object v0`.

PATCH B  Lekm;->oO0OO00()V  (insns 0x48..0x4f)
    The ad-SDK bootstrap always appends `new Lse0;` to its initializer list
    right before handing it to Koin. `se0.run()` performs the whole app-level
    `ecm.oO0OO0O = new re0();` + `jqa` Koin start. Skipping that inner call
    (goto -> 0x0011, the shared move-exception/continue block) removes exactly
    that one initializer. Every other initializer still runs in order, so Koin
    never starts from the ad path.

Net effect: `ecm.oO0OO0O` (and the `qfj`/`gsl`/`dtg` config stack hanging off
it) stays null, the RemoteConfig `freemium_enable` key can no longer be read as
true, the `settings_iap` "advanced_user_buy" record never appears, and
`q6.oO0OOOO0()` falls back to FREE/TRIAL instead of PAID. `PremiumActivity`
itself still opens from Settings, it just cannot grant anything.

Both patches stay the same length or shorter and only overwrite plain
instructions, so every code_off / try range / debug_info offset keeps its
original address. The dex header checksum + SHA-1 signature are recomputed.
"""
import hashlib
import struct
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
APK_IN = ROOT / "chuckle-1.1.1-154.apk"
APK_OUT = ROOT / "chuckle-1.1.1-154-nopaywall.apk"
UNSIGNED = ROOT / "out" / "unsigned-nopaywall.apk"


def adler(data: bytes) -> int:
    return zlib.adler32(data) & 0xFFFFFFFF


def fix_header(dex: bytearray) -> bytearray:
    """Recompute the signature (sha1 over bytes 32..end) and then the checksum
    (adler32 over bytes 12..end). Order matters: the signature sits inside the
    checksum's range, so it must be written first."""
    size = struct.unpack_from("<I", dex, 0x20)[0]
    out = bytearray(bytes(dex[:size]))
    out[12:32] = b"\x00" * 20
    sig = hashlib.sha1(bytes(out[32:])).digest()
    out[12:32] = sig
    out[8:12] = b"\x00" * 4
    csum = adler(bytes(out[12:]))
    struct.pack_into("<I", out, 8, csum)
    return out


def main() -> None:
    src = zipfile.ZipFile(APK_IN)
    dex = bytearray(src.read("classes.dex"))
    original = bytes(dex)

    # ---- PATCH A: ab0.get() -> null ---------------------------------------
    a_off = 0x11002
    a_old = bytes(dex[a_off:a_off + 8])
    assert a_old == bytes.fromhex("8b00f16c8b00f86c"), a_old.hex()
    dex[a_off:a_off + 8] = bytes.fromhex("1200"   # const/4 v0, #0
                                          "1100"  # return-object v0
                                          "0000"
                                          "0000")
    print(f"patch A @0x{a_off:x}: {a_old.hex()} -> {bytes(dex[a_off:a_off+8]).hex()}")

    # ---- PATCH B: drop the se0 initializer --------------------------------
    b_code = 0x55BCC8          # ekm.oO0OO00 code_off
    b_at = b_code + 2 * 0x4F   # instruction 0x4F: invoke-virtual {v1, v5}, Ldoe;.add
    b_old = bytes(dex[b_at:b_at + 16])
    assert b_old == bytes.fromhex("0c0122059738701021cd05006e20185e"), b_old.hex()
    dex[b_at:b_at + 16] = bytes.fromhex(
        "1205"    # const/4 v5, #0
        "0000"
        "0000"
        "0000"
        "0000"
        "28c4"    # goto -0x3c  -> 0x0011 (move-exception / loop continue)
        "0000"
        "0000")
    print(f"patch B @0x{b_at:x}: dropped `new Lse0;` registration")

    dex = fix_header(bytearray(dex))
    changed = [i for i in range(len(original)) if original[i] != dex[i]]
    print(f"bytes changed: {len(changed)} (header 24 + patches 16)")

    # ---- rebuild the archive, keeping everything else byte-identical ------
    UNSIGNED.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(UNSIGNED, "w") as out:
        for info in src.infolist():
            data = src.read(info.filename)
            if info.filename == "classes.dex":
                data = bytes(dex)
            if info.filename.startswith("META-INF/") and info.filename.endswith(
                (".RSA", ".SF", ".MF", ".EC")
            ):
                continue  # old v1 signature no longer valid
            new = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            new.compress_type = info.compress_type
            new.external_attr = info.external_attr
            new.internal_attr = info.internal_attr
            new.create_system = info.create_system
            new.comment = info.comment
            out.writestr(new, data)
    print(f"unsigned apk -> {UNSIGNED}  ({UNSIGNED.stat().st_size} bytes)")
    print(f"next: zipalign + apksigner -> {APK_OUT}")


if __name__ == "__main__":
    main()
