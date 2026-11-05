"""Пример: S-блок (подстановка) и обратный S-блок по битам."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

print("Таблица S-блока PRESENT (вход -> выход):")
for i, v in enumerate(crypt.PRESENT_SBOX):
    print(f"  {i:04b} -> {v:04b}", end="\n" if i % 4 == 3 else "")

data = "0100100001001001"
out = crypt.sbox(data, "present")
print(f"\nВход:     {crypt.group(data, 4)}")
print(f"Выход:    {crypt.group(out, 4)}   (каждые 4 бита по таблице)")
print(f"Обратно:  {crypt.group(crypt.sbox_inv(out, 'present'), 4)}")

data = "0101001100000000"
out = crypt.sbox(data, "aes")
print(f"\nAES (по 8 бит): {crypt.group(data)} -> {crypt.group(out)} -> обратно {crypt.group(crypt.sbox_inv(out, 'aes'))}")

my = [(i + 3) % 16 for i in range(16)]
out = crypt.sbox("00010010", my)
print(f"Свой S-блок (x+3 по 4 бита): 0001 0010 -> {crypt.group(out, 4)} -> обратно {crypt.group(crypt.sbox_inv(out, my), 4)}")
