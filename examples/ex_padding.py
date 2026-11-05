"""Пример: паддинг сообщения по битам и нарезка на блоки."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

msg = "1101001"
print(f"Исходное сообщение: {msg} ({len(msg)} бит)\n")

for name, fn, bs in (("pad32", crypt.pad32, 32), ("pad64", crypt.pad64, 64)):
    data, n = fn(msg, with_len=True)
    print(f"{name}: длина {n} бит, блоки:")
    for i, b in enumerate(crypt.blocks(data, bs)):
        print(f"   блок {i}: {crypt.group(b)}")
    print()

print("Битовые схемы, блок 32 бита:")
for s in ("zero", "iso7816_4", "iso9797_m1", "iso9797_m3", "tbc"):
    p = crypt.pad32(msg, s)
    print(f"  {s:11} {crypt.group(p):<72} -> {crypt.unpad32(p, s)}")

text = b"HELLO WORLD"
print(f"\nВсе схемы на тексте {text!r} (блок — типичный для схемы):")
for s in crypt.SCHEMES:
    bs = 64 if s == "pkcs5" else crypt.INFO[s][2]
    p = crypt.pad(text, bs, s)
    h = p.hex(" ")
    h = h if len(h) <= 60 else h[:27] + " ... " + h[-27:]
    print(f"  {s:11} {bs:5} бит  {h:<60} -> {crypt.unpad(p, bs, s)!r}")

print("\nСправка и другие имена:")
for name in ("gost_p2", "sha256", "streebog", "pkcs1_t2"):
    print(" ", name, "=", crypt.info(name))
