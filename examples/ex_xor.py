"""Пример: XOR с ключом по битам."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

msg, key = "110100111010", "1010"
enc = crypt.xor(msg, key)
rep = (key * len(msg))[:len(msg)]
print(f"сообщение  {crypt.group(msg, 4)}")
print(f"ключ       {crypt.group(rep, 4)}   (ключ {key} повторяется)")
print(f"XOR        {crypt.group(enc, 4)}")
print(f"обратно    {crypt.group(crypt.xor(enc, key), 4)}   (тот же XOR с тем же ключом)")

enc = crypt.xor(b"SECRET", b"key")
print(f"\nС байтами тоже работает: b'SECRET' ^ b'key' = {enc.hex(' ')} -> {crypt.xor(enc, b'key')!r}")
