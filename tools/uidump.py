import sys
import xml.etree.ElementTree as ET

src, dst = sys.argv[1], sys.argv[2]
root = ET.parse(src).getroot()
rows = []
for n in root.iter("node"):
    txt = (n.get("text") or "") + " | " + (n.get("content-desc") or "")
    if txt.strip(" |"):
        rows.append("%-32s %-28s click=%s class=%s" % (
            txt[:30], n.get("bounds"), n.get("clickable"), (n.get("class") or "").split(".")[-1]))
with open(dst, "w", encoding="utf-8") as f:
    f.write("\n".join(rows))
print("rows", len(rows))
