"""Почему у потокового шифра нельзя повторять nonce и почему нужен MAC."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_enu as crypt

key, nonce = os.urandom(32), os.urandom(12)
xor = lambda a, b: bytes(x ^ y for x, y in zip(a, b))

print("1. Повтор nonce: два сообщения на одной гамме")
p1 = b"Meet me at the old bridge at 9 pm"
p2 = b"Transfer 100 USD to account 4242!"
c1, c2 = crypt.chacha20(p1, key, nonce), crypt.chacha20(p2, key, nonce)
print("   C1 xor C2 =", xor(c1, c2).hex()[:48], "…  (гамма сократилась: это P1 xor P2)")
guess = b"Transfer"                         # угадали начало одного сообщения…
print("   угадали начало P2 'Transfer' -> начало P1:", xor(xor(c1, c2), guess))

print("\n2. Подмена без MAC: переворот бит в шифртексте")
pay = b"pay=0100;to=alice"
ct = bytearray(crypt.chacha20(pay, key, nonce))
delta = xor(b"0100", b"9900")              # знаем формат, но не ключ
ct[4:8] = xor(ct[4:8], delta)
print("   было:", pay, "-> стало:", crypt.chacha20(bytes(ct), key, nonce))

print("\n3. С ChaCha20-Poly1305 подмена ловится")
sealed = bytearray(crypt.chacha20_poly1305_encrypt(pay, key, nonce))
sealed[4] ^= 0x09
try:
    crypt.chacha20_poly1305_decrypt(bytes(sealed), key, nonce)
except ValueError as e:
    print("   расшифровка отклонена:", e)

print("\n4. RC4: смещение второго байта гаммы (атака Мантина–Шамира)")
n = 20000
zeros = sum(crypt.rc4_keystream(os.urandom(16), 2)[1] == 0 for _ in range(n))
print(f"   байт 2 == 0 в {zeros / n:.4f} случаев, ожидалось бы {1 / 256:.4f} (в ~2 раза чаще)")
