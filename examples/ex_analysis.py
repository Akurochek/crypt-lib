"""Пример: сравнение S-блоков и лавинный эффект шифров."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

print(f"{'S-блок':11} {'бит':>3} {'дифф.равн.':>10} {'нелин.':>6} {'степень':>7}  неподвижные точки")
for name in ("aes", "kuznyechik", "present", "gift"):
    r = crypt.sbox_report(name)
    print(f"{name:11} {r['n']:>3} {r['differential_uniformity']:>10} {r['nonlinearity']:>6} "
          f"{r['algebraic_degree']:>7}  {r['fixed_points']}")
weak = list(range(16))[::-1]                 # x -> 15-x — линейный, плохой S-блок
r = crypt.sbox_report(weak)
print(f"{'x->15-x':11} {r['n']:>3} {r['differential_uniformity']:>10} {r['nonlinearity']:>6} {r['algebraic_degree']:>7}")

print("\nDDT S-блока PRESENT (строки — входная разность):")
for row in crypt.ddt("present")[:5]:
    print("  ", " ".join(f"{v:2}" for v in row))

print("\nЛавинный эффект (идеал 0.5):")
for name, kl in (("aes", 16), ("des", 8), ("magma", 32), ("kuznyechik", 32), ("present", 10)):
    c = crypt.cipher(name, os.urandom(kl))
    print(f"  {c.name:10} {crypt.avalanche(c.encrypt_block, c.block_size, 10):.3f}")
toy = crypt.SPN([os.urandom(8) for _ in range(2)])         # 1 раунд — лавины почти нет
print(f"  SPN 1 раунд {crypt.avalanche(toy.encrypt_block, 8, 10):.3f}")
print(f"\nЭнтропия: текст {crypt.entropy('Привет, мир! ' * 20):.2f} бит/байт, "
      f"шифртекст {crypt.entropy(crypt.encrypt(b'a' * 4000, b'k' * 16, mode='ctr')):.2f}")
