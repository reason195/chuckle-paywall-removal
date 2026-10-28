"""Apply the paywall patches at smali level (apktool tree) instead of raw dex bytes.

Idempotent: each method body is replaced wholesale, so re-running is safe and a
new app version only needs the same few methods located again (locate.py gives
class/method names for the obfuscated build).

    python smali_patch.py <decoded_dir> [--unactivated 0x7f140604 --activated 0x7f140601]
"""
import argparse
import re
import sys
from pathlib import Path

BODIES = {
    # file, class, method signature, new body lines
    ("smali/q6.smali", "oO0OO00", "()Z"): "    const/4 v0, 0x0\n    return v0\n",
    ("smali/q6.smali", "oO0OOO0", "()Z"): "    const/4 v0, 0x0\n    return v0\n",
    ("smali_classes2/dvj.smali", "oO0OOo", "()Z"): "    const/4 v0, 0x1\n    return v0\n",
    ("smali_classes4/igl.smali", "oO0OO00", "()Z"): "    const/4 v0, 0x1\n    return v0\n",
    ("smali_classes2/dvj.smali", "oO0OOo0", "()Llvm;"): (
        "    new-instance v0, Llvm;\n"
        "    invoke-direct {v0}, Ljava/lang/Object;-><init>()V\n"
        "    const-string v1, \"active\"\n"
        "    iput-object v1, v0, Llvm;->oO0OO0O:Ljava/lang/String;\n"
        "    const/4 v1, 0x0\n"
        "    iput-boolean v1, v0, Llvm;->oO0OOOo:Z\n"
        "    return-object v0\n"
    ),
}


def replace_method(path: Path, name: str, desc: str, body: str) -> bool:
    text = path.read_text(encoding="utf-8")
    # header line, e.g. ".method public static oO0OO00()Z"
    pat = re.compile(
        r"^\.method[^\n]*\b" + re.escape(name) + re.escape(desc) + r"\n(?:.*?)^\.end method",
        re.M | re.S)
    m = pat.search(text)
    if not m:
        return False
    header = text[m.start():text.find("\n", m.start())]
    locals_n = max(1, len(set(re.findall(r"\bv(\d+)\b", body)))) + 1
    new = f"{header}\n    .locals {locals_n}\n\n{body}.end method"
    text = text[:m.start()] + new + text[m.end():]
    path.write_text(text, encoding="utf-8")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--unactivated", default="0x7f140604")
    ap.add_argument("--activated", default="0x7f140601")
    a = ap.parse_args()
    root = Path(a.dir)
    ok = 0
    for (rel, name, desc), body in BODIES.items():
        p = root / rel
        if not p.exists():
            print(f"  !! missing {rel}")
            continue
        if replace_method(p, name, desc, body):
            print(f"  ok  {rel}: {name}{desc}")
            ok += 1
        else:
            print(f"  !! method not found {rel}: {name}{desc}")

    cvj = root / "smali_classes2/cvj.smali"
    if cvj.exists():
        t = cvj.read_text(encoding="utf-8")
        if a.unactivated in t:
            cvj.write_text(t.replace(a.unactivated, a.activated), encoding="utf-8")
            print(f"  ok  cvj status label {a.unactivated} -> {a.activated}")
    print(f"{ok} method bodies rewritten")


if __name__ == "__main__":
    sys.exit(main())
