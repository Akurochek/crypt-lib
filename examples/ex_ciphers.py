"""Пример: блочные шифры и режимы. Видно, почему ECB плох: одинаковые блоки -> одинаковый шифртекст."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

msg = b"ATTACK AT DAWN!!" * 3 + b"ok"          # три одинаковых блока по 16 байт
key = bytes(range(32))

print("Шифры, один блок:")
for name, kl in (("des", 8), ("3des", 24), ("aes", 16), ("aes", 32), ("magma", 32), ("kuznyechik", 32), ("present", 10)):
    c = crypt.cipher(name, key[:kl])
    blk = msg[:c.block_size]
    e = c.encrypt_block(blk)
    print(f"  {c.name:10} {e.hex():34} -> {c.decrypt_block(e)!r}")

print("\nРежимы на AES-128 (одинаковые блоки текста):")
for mode in crypt.MODES:
    ct = crypt.encrypt(msg, key[:16], "aes", mode, iv=bytes(12 if mode == "gcm" else 8 if mode == "ctr" else 16))
    body = ct[0 if mode == "ecb" else 12 if mode == "gcm" else 8 if mode == "ctr" else 16:]
    blocks = [body[i:i + 16].hex()[:8] for i in range(0, 48, 16)]
    print(f"  {mode:5} первые 3 блока: {' '.join(blocks)}  {'<- повтор!' if len(set(blocks)) < 3 else ''}")
    assert crypt.decrypt(ct, key[:16], "aes", mode) == msg

c = crypt.Kuznyechik(key)
print("\nИмитовставка ГОСТ (CMAC) «Кузнечик»:", crypt.cmac(c, msg, 8).hex())
ct, tag = crypt.gcm_encrypt(crypt.AES(key[:16]), b"secret", os.urandom(12), aad=b"header")
print("AES-GCM: шифртекст", ct.hex(), "тег", tag.hex())

f = lambda half, k: crypt.sbox(crypt.xor(half, k), "aes")
toy = crypt.Feistel(f, [b"k1k1", b"k2k2", b"k3k3", b"k4k4"], block_size=8)
e = toy.encrypt_block(b"12345678")
print("\nСвой Фейстель (S-блок AES):", e.hex(), "->", toy.decrypt_block(e))
