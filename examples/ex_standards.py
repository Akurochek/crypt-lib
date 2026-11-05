"""Пример: стандартные S- и P-блоки по имени + сборка из них настоящих DES и PRESENT
со сверкой по эталонным векторам из стандартов."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

print("Стандартные S-блоки:")
for name, desc in crypt.SBOXES.items():
    print(f"  {name:11} {desc}")
print("\nСтандартные P-блоки:")
for name, (table, n_in) in crypt.PBOXES.items():
    print(f"  {name:12} {n_in} -> {len(table)} бит")

d = b"HELLOxyz"
print(f"\nВход {d.hex(' ')}")
for name in ("aes", "kuznyechik", "present", "gift", "magma"):
    out = crypt.sbox(d, name)
    print(f"  sbox {name:11} {out.hex(' ')}  -> обратно {crypt.sbox_inv(out, name)!r}")
print(f"  sbox des         {crypt.sbox(d[:6], 'des').hex(' ')}  (48 бит -> 32 бита, первые 6 байт)")
for name in ("des_ip", "present"):
    out = crypt.pbox(d, name)
    print(f"  pbox {name:11} {out.hex(' ')}  -> обратно {crypt.pbox_inv(out, name)!r}")


# ---------- DES целиком: IP, E, S, P, FP, PC1, PC2 из библиотеки ----------
def des_encrypt(block: bytes, key: bytes) -> bytes:
    cd = crypt.pbox(key, "des_pc1")                  # 56 бит
    c, d = int.from_bytes(cd, "big") >> 28, int.from_bytes(cd, "big") & 0xFFFFFFF
    keys = []
    for s in (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1):
        c = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF
        d = ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
        keys.append(crypt.pbox(((c << 28) | d).to_bytes(7, "big"), "des_pc2"))
    x = crypt.pbox(block, "des_ip")
    l, r = x[:4], x[4:]
    for k in keys:
        f = crypt.pbox(crypt.sbox(crypt.xor(crypt.pbox(r, "des_e"), k), "des"), "des_p")
        l, r = r, crypt.xor(l, f)
    return crypt.pbox(r + l, "des_fp")


# ---------- PRESENT-80 целиком: S-блок и P-блок из библиотеки ----------
def present_encrypt(block: bytes, key: bytes) -> bytes:
    k = int.from_bytes(key, "big")                   # 80 бит
    s = block
    for rnd in range(1, 32):
        s = crypt.xor(s, (k >> 16).to_bytes(8, "big"))
        s = crypt.pbox(crypt.sbox(s, "present"), "present")
        k = ((k << 61) | (k >> 19)) & ((1 << 80) - 1)
        top = crypt.sbox(bytes([k >> 76]), "present")[0] & 0xF
        k = (top << 76) | (k & ((1 << 76) - 1))
        k ^= rnd << 15
    return crypt.xor(s, (k >> 16).to_bytes(8, "big"))


print("\nСборка шифров из стандартных блоков библиотеки:")
c = des_encrypt(bytes.fromhex("0123456789ABCDEF"), bytes.fromhex("133457799BBCDFF1"))
print(f"  DES     {c.hex().upper()}  эталон 85E813540F0AB405  {'OK' if c.hex().upper() == '85E813540F0AB405' else 'ОШИБКА'}")
c = present_encrypt(bytes(8), bytes(10))
print(f"  PRESENT {c.hex().upper()}  эталон 5579C1387B228445  {'OK' if c.hex().upper() == '5579C1387B228445' else 'ОШИБКА'}")
