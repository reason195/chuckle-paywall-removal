"""Dump pseudo-smali for selected classes from the APK's dex files.

Usage: python tools/dexsmali.py CLASS1 [CLASS2 ...]
Class names may be given as 'Lyh5;' or 'yh5'. Searches all dex files.
"""
import sys
import zipfile
from loguru import logger

logger.remove()
from androguard.core.dex import DEX

APK = 'chuckle-1.1.1-154.apk'


def fmt_operand(op):
    # op is (type, value) or (type, idx, str)
    if len(op) == 3:
        return op[2]
    v = op[1]
    if isinstance(v, str):
        return v
    return str(v)


def dump_class(d, cls):
    out = []
    out.append(f"class {cls.get_name()}  super={cls.get_superclassname()}")
    ifaces = cls.get_interfaces()
    if ifaces:
        out.append(f"  implements: {ifaces}")
    for f in cls.get_fields():
        try:
            fv = f.get_init_value()
        except Exception:
            fv = None
        out.append(f"  field: {f.get_name()} : {f.get_descriptor()}" + (f"  = {fv}" if fv is not None else ""))
    for m in cls.get_methods():
        out.append(f"  method: {m.get_name()}{m.get_descriptor()}"
                   + (" (abstract/native)" if not m.get_code() else ""))
        code = m.get_code()
        if not code:
            continue
        out.append(f"    registers: {code.get_registers_size()}")
        for inst in code.get_bc().get_instructions():
            line = f"      {inst.get_name()}"
            try:
                ops = inst.get_operands(0)
                parts = [fmt_operand(o) for o in ops]
                line += ' ' + ', '.join(parts)
            except Exception as e:
                line += f"  <err {e}>"
            out.append(line)
    return '\n'.join(out)


def main():
    wanted = sys.argv[1:]
    wanted = {w if w.startswith('L') else 'L' + w for w in wanted}
    wanted = {w if w.endswith(';') else w + ';' for w in wanted}
    z = zipfile.ZipFile(APK)
    for dexname in ['classes.dex', 'classes2.dex', 'classes3.dex', 'classes4.dex']:
        d = DEX(z.read(dexname))
        names = {c.get_name(): c for c in d.get_classes()}
        for w in list(wanted):
            if w in names:
                print(f"########## {dexname} :: {w} ##########")
                print(dump_class(d, names[w]))
                wanted.discard(w)
    if wanted:
        print("NOT FOUND:", sorted(wanted))


if __name__ == '__main__':
    main()
