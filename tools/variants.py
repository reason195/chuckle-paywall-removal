"""Build patch-subset variants of any Chuckle APK to isolate which patch causes a
regression (e.g. an X API 403). All variants share one signing key, so they can be
installed with `adb install -r` over each other **without wiping the X login**.

    python tools/variants.py <apk> <plan.json> [out_dir]

Produces:
    A_base.apk       integrity + status label only (control: re-sign fix only)
    B_no_record.apk  + three boolean predicates, no synthetic subscription record
    C_full.apk       all patches (identical to the delivered build)

A/B recipe:
    adb install -r A_base.apk ; adb logcat -c ; pull-to-refresh ; adb logcat -d | grep g3f
    ... repeat for B and C, compare RESPONSE codes ...
    adb install -r C_full.apk   # ALWAYS restore the full build afterwards
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import zipfile
import zlib
from pathlib import Path

BT = Path(os.environ.get("ANDROID_BUILD_TOOLS",
                         r"C:\Users\Daniel\AppData\Local\Android\Sdk\build-tools\37.0.0"))
JDK = Path(os.environ.get("JAVA_HOME", r"C:\Users\Daniel\tools\jdk\jdk-21.0.12.1+1"))
KS = Path(os.environ.get("CHUCKLE_KEYSTORE", Path(__file__).resolve().parent.parent / "out" / "nopaywall.keystore"))
INJECTOR = Path(__file__).with_name("inject_channel.py")

VARIANTS = {
    "A_base": {"integrity", "status"},
    "B_no_record": {"freemium", "forced", "entitlement", "integrity", "status"},
    "C_full": {"freemium", "forced", "entitlement", "integrity", "status", "record"},
}


def adler(b):
    return zlib.adler32(b) & 0xFFFFFFFF


def fix_header(dex: bytes) -> bytes:
    size = struct.unpack_from("<I", dex, 0x20)[0]
    out = bytearray(dex[:size])
    out[12:32] = b"\x00" * 20
    out[12:32] = hashlib.sha1(bytes(out[32:])).digest()
    out[8:12] = b"\x00" * 4
    struct.pack_into("<I", out, 8, adler(bytes(out[12:])))
    return bytes(out)


def make(apk: Path, plan: dict, vname: str, keys: set, out_dir: Path):
    T = plan["targets"]
    src = zipfile.ZipFile(apk)
    dexes = {n: bytearray(src.read(n)) for n in src.namelist()
             if n.startswith("classes") and n.endswith(".dex")}

    for key, repl in (("freemium", "12000f00"), ("forced", "12000f00"),
                      ("entitlement", "12100f00"), ("integrity", "12100f00")):
        if key not in keys or not T.get(key):
            continue
        t = T[key]
        d = dexes[t["dex"]]
        want = bytes.fromhex(t["expect"])
        assert bytes(d[t["insns"]:t["insns"] + len(want)]) == want, key
        r = bytes.fromhex(repl)
        d[t["insns"]:t["insns"] + len(want)] = r + b"\x00" * (len(want) - len(r))

    if "status" in keys and T.get("status"):
        un, ac = T["status"]["unactivated"], T["status"]["activated"]
        done = False
        for n, d in dexes.items():
            p = struct.pack("<I", un)
            i = d.find(p)
            while i != -1:
                if i >= 2 and d[i - 2] == 0x14:
                    struct.pack_into("<I", d, i, ac)
                    done = True
                    break
                i = d.find(p, i + 1)
            if done:
                break
        assert done, "status label constant not found"

    if "record" in keys and T.get("record"):
        r = T["record"]
        d = dexes[r["dex"]]
        struct.pack_into("<H", d, r["code_off"], 2)
        idx = r["indices"]

        def u16(v):
            return struct.pack("<H", v).hex()

        prog = ("2200" + u16(idx["type"]) +
                "7010" + u16(idx["obj_init"]) + "0000" +
                "1a01" + u16(idx["literal"]) +
                "5b01" + u16(idx["code_field"]) +
                "1201" + "5c01" + u16(idx["expired_field"]) + "1100")
        want = bytes.fromhex(r["expect"])
        assert bytes(d[r["insns"]:r["insns"] + len(want)]) == want
        body = bytes.fromhex(prog)
        d[r["insns"]:r["insns"] + len(want)] = body + b"\x00" * (len(want) - len(body))

    for n in dexes:
        dexes[n] = fix_header(bytes(dexes[n]))

    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{vname}.apk"
    tmp = out.with_suffix(".u.apk")
    with zipfile.ZipFile(tmp, "w") as z:
        for info in src.infolist():
            n = info.filename
            if n.startswith("META-INF/") and n.endswith((".RSA", ".SF", ".MF", ".EC")):
                continue
            ni = zipfile.ZipInfo(n, date_time=info.date_time)
            ni.compress_type = info.compress_type
            ni.external_attr = info.external_attr
            ni.internal_attr = info.internal_attr
            ni.create_system = info.create_system
            z.writestr(ni, dexes.get(n) or src.read(n))
    al, sg = out.with_suffix(".a.apk"), out.with_suffix(".s.apk")
    subprocess.run([str(BT / "zipalign.exe"), "-f", "-p", "4", str(tmp), str(al)],
                   check=True, capture_output=True)
    subprocess.run([str(BT / "apksigner.bat"), "sign", "--ks", str(KS),
                    "--ks-pass", "pass:chuckle", "--key-pass", "pass:chuckle",
                    "--ks-key-alias", "chuckle", "--out", str(sg), str(al)],
                   check=True, capture_output=True, env=dict(os.environ, JAVA_HOME=str(JDK)))
    subprocess.run([sys.executable, str(INJECTOR), str(sg), str(out)],
                   check=True, capture_output=True)
    print(f"built {vname}: {out.stat().st_size} bytes  keys={sorted(keys)}")


if __name__ == "__main__":
    apk = Path(sys.argv[1])
    plan = json.loads(Path(sys.argv[2]).read_text())
    out_dir = Path(sys.argv[3]) if len(sys.argv) > 3 else apk.parent / "out" / "variants"
    for name, keys in VARIANTS.items():
        make(apk, plan, name, keys, out_dir)
