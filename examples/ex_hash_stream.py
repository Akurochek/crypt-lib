"""Пример: хэши с нуля (на паддинге библиотеки), HMAC, PBKDF2 и потоковые шифры."""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

for name in ("sha256", "sha1", "md5"):
    mine = getattr(crypt, name)(b"abc").hex()
    print(f"{name:6}('abc') = {mine}  {'== hashlib' if mine == hashlib.new(name, b'abc').hexdigest() else '!!'}")
print("HMAC-SHA256:", crypt.hmac(b"key", b"The quick brown fox").hex())
print("PBKDF2     :", crypt.pbkdf2(b"password", b"salt", 1000, 16).hex())

print("\nRC4('Plaintext', 'Key') =", crypt.rc4(b"Plaintext", b"Key").hex().upper())
key, nonce = os.urandom(32), os.urandom(12)
ct = crypt.chacha20_poly1305_encrypt(b"hello", key, nonce, b"hdr")
print("ChaCha20-Poly1305:", ct.hex(), "->", crypt.chacha20_poly1305_decrypt(ct, key, nonce, b"hdr"))
