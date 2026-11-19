"""Пример: P-блок (перестановка битов) и обратный P-блок."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_enu as crypt

perm = [3, 2, 1, 0]
d = "1100"
out = crypt.pbox(d, perm)
print("Разворот 4 бит, perm =", perm)
print(f"  вход {d} -> выход {out} -> назад {crypt.pbox_inv(out, perm)}\n")

perm = [1, 3, 0, 4, 2]
d = "10110"
out = crypt.pbox(d, perm)
print("Произвольная перестановка 5 бит, perm =", perm, "(i-й бит выхода = бит perm[i] входа)")
print(f"  вход {d} -> выход {out} -> назад {crypt.pbox_inv(out, perm)}\n")

d = crypt.to_bits(b"ABCDEFGH")
out = crypt.pbox(d, "present")
print("Перестановка PRESENT (64 бита):")
print(f"  вход   {crypt.group(d)}")
print(f"  выход  {crypt.group(out)}")
print(f"  назад  {crypt.group(crypt.pbox_inv(out, 'present'))}")

print(f"\nDES E (расширение 32 -> 48): {crypt.group(crypt.pbox('1' + '0' * 31, 'des_e'))}")
