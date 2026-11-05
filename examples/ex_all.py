"""Пример: всё вместе — один раунд игрушечного SP-шифра.
padding -> XOR с ключом -> S-блок -> P-блок, и обратно в обратном порядке."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypt

m = "1101"
r = crypt.pad(m, 40, "pkcs7");
print(r)
