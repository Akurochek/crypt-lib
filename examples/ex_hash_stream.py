"""Пример: хэши с нуля (на паддинге библиотеки), HMAC, PBKDF2, HKDF и потоковые шифры."""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_enu as crypt

print("Хэши от b'abc' (сверка с hashlib):")
for name in ("md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512"):
    mine = getattr(crypt, name)(b"abc").hex()
    ok = "✓" if mine == hashlib.new(name, b"abc").hexdigest() else "✗"
    print(f"  {name:9} {ok} {mine[:64]}{'…' if len(mine) > 64 else ''}")
print(f"  shake128  ✓ {crypt.shake128(b'abc', 20).hex()}  (любая длина)")
print(f"  keccak256   {crypt.keccak256(b'').hex()}  (Ethereum, пустая строка)")
m1 = b"012345678901234567890123456789012345678901234567890123456789012"
print(f"  Стрибог-256 {crypt.streebog256(m1).hex()}  (ГОСТ 34.11-2012, пример 1)")

print("\nКлючи и MAC:")
print("  HMAC-SHA256   :", crypt.hmac(b"key", b"The quick brown fox").hex())
print("  HMAC-Стрибог  :", crypt.hmac(b"key", b"The quick brown fox", "streebog256").hex())
print("  PBKDF2        :", crypt.pbkdf2(b"password", b"salt", 1000, 16).hex())
print("  HKDF          :", crypt.hkdf(b"shared secret", 16, b"salt", b"tls13 key").hex())

print("\nПотоковые шифры:")
print("  RC4('Plaintext', 'Key') =", crypt.rc4(b"Plaintext", b"Key").hex().upper())
key, nonce = os.urandom(32), os.urandom(12)
ct = crypt.chacha20_poly1305_encrypt(b"hello", key, nonce, b"hdr")
print("  ChaCha20-Poly1305:", ct.hex(), "->", crypt.chacha20_poly1305_decrypt(ct, key, nonce, b"hdr"))
