"""Асимметричная криптография: RSA, Диффи–Хеллман, кривые, ГОСТ 34.10, X25519 и классические атаки."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_enu as crypt

print("RSA-2048")
pub, priv = crypt.rsa_keygen(2048)
print(f"   n = {str(pub.n)[:40]}… ({pub.n.bit_length()} бит), e = {pub.e}")
ct = crypt.rsa_oaep_encrypt(b"secret", pub)
print("   OAEP:", ct.hex()[:48], "… ->", crypt.rsa_oaep_decrypt(ct, priv))
sig = crypt.rsa_pss_sign(b"document", priv)
print("   PSS-подпись верна:", crypt.rsa_pss_verify(b"document", sig, pub),
      "| для изменённого:", crypt.rsa_pss_verify(b"documenT", sig, pub))

print("\nДиффи–Хеллман (группа RFC 3526, 2048 бит — построена из числа π)")
p, g = crypt.modp_group(2048)
a, A = crypt.dh_keygen(p, g)
b, B = crypt.dh_keygen(p, g)
s1, s2 = crypt.dh_shared(B, a, p), crypt.dh_shared(A, b, p)
print("   общий секрет совпал:", s1 == s2, "| ключ из него (HKDF):",
      crypt.hkdf(s1.to_bytes(256, "big"), 16).hex())

print("\nЭллиптические кривые")
for name in ("p256", "secp256k1"):
    d, Q = crypt.ec_keygen(name)
    r, s = crypt.ecdsa_sign(b"msg", d, name)
    print(f"   {crypt.CURVES[name].name:30} ECDSA r={r:x}"[:84] + "…", crypt.ecdsa_verify(b"msg", (r, s), Q, name))
d, Q = crypt.ec_keygen("gost_test")
sig = crypt.gost_sign("Привет".encode(), d)
print("   ГОСТ Р 34.10-2012 + Стрибог: подпись верна:", crypt.gost_verify("Привет".encode(), sig, Q))
a, b = os.urandom(32), os.urandom(32)
print("   X25519: общий ключ совпал:", crypt.x25519(a, crypt.x25519(b)) == crypt.x25519(b, crypt.x25519(a)))

print("\nАтаки")
m = int.from_bytes(b"hi", "big")
pub3, _ = crypt.rsa_keygen(1024, e=3)
print("   e=3 без паддинга, ∛c:", crypt.rsa_small_e_attack(crypt.rsa_encrypt_int(m, pub3)).to_bytes(2, "big"))
keys = [crypt.rsa_keygen(512, 3)[0] for _ in range(3)]
long_m = int.from_bytes(b"attack at dawn!", "big")
cts = [crypt.rsa_encrypt_int(long_m, k) for k in keys]
print("   Хостад (3 получателя):", crypt.rsa_hastad(cts, [k.n for k in keys]).to_bytes(15, "big"))
d, Q = crypt.ec_keygen("p256")
sa, sb = crypt.ecdsa_sign(b"one", d, k=1234), crypt.ecdsa_sign(b"two", d, k=1234)
print("   ECDSA с повторным k -> ключ найден:", crypt.ecdsa_recover_key(b"one", sa, b"two", sb) == d)
