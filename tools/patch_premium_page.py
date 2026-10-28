"""Two extra patches that make the Premium page present an active subscription.

1) dvj.oO0OOo0()  null -> synthesized lvm
   Builds a SubscriptionsBean in place: code "active", expired = false.
   Verified indices from classes2.dex:
     type   Llvm;                       = 9746  (0x2612)
     method Llvm;-><init>()V            = 41493 (0xA1D5)
     field  Llvm;->oO0OO0O:Ljava/lang/String; = 22634 (0x586A)
     field  Llvm;->oO0OOOo:Z                  = 22640 (0x5870)
     string "active"                    = 36809 (0x8FC9)

2) cvj.<clinit> prime_status_unactivated -> prime_status_activated
   0x7f140604 -> 0x7f140601, so the branch that renders the "not activated"
   label prints the activated one instead. The page reads the persisted record
   directly (si0), not through dvj, so the label needs its own patch.
"""
import struct
import sys
import zipfile

DEX = sys.argv[1] if len(sys.argv) > 1 else "classes2.dex"


def load(path):
    return bytearray(zipfile.ZipFile("chuckle-1.1.1-154.apk").read(path))


def write_program(dex, off, prefix_hex, program_hex, label):
    prefix = bytes.fromhex(prefix_hex)
    have = bytes(dex[off:off + len(prefix)]).hex()
    assert have == prefix_hex, f"{label}: prefix {have} != {prefix_hex}"
    prog = bytes.fromhex(program_hex)
    dex[off:off + len(prog)] = prog
    print(f"  {label}  @0x{off:x}  ({len(prog)//2} bytes)")


def main():
    dex = load(DEX)

    fake_record = (
        "2200 1226"        # new-instance v0, Llvm;
        "7010 d5a1 0000"   # invoke-direct {v0}, Llvm;-><init>()V
        "1a01 c98f"        # const-string v1, "active"
        "5b01 6a58"        # iput-object v1, v0, Llvm;->oO0OO0O
        "1201"             # const/4 v1, #0
        "5a01 7058"        # iput-boolean v1, v0, Llvm;->oO0OOOo   (expired=false)
        "1100"             # return-object v0
    ).replace(" ", "")
    write_program(dex, 0x3A5DA8, "6200422f", fake_record,
                  "dvj.oO0OOo0() -> fake active record")

    # cvj.<clinit>: const v1, #int 0x7f140604  (imm32 at +2)
    off = 0x3A5CBA
    have = bytes(dex[off:off + 4]).hex()
    assert have == "0406147f", have
    dex[off:off + 4] = bytes.fromhex("0106147f")
    print("  cvj status label: unactivated -> activated")

    open("out/classes2.patched.dex", "wb").write(bytes(dex))


if __name__ == "__main__":
    main()
