"""Пример: классические шифры и их взлом частотным анализом."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import crypto_enu as crypt
from test_crypt import RU_TEXT

print("Цезарь:     ", crypt.caesar("Привет, мир!", 3))
print("Атбаш:      ", crypt.atbash("Привет, мир!"))
print("Аффинный:   ", crypt.affine("Привет, мир!", 5, 7))
print("Виженер:    ", crypt.vigenere("Привет, мир!", "ключ"))
print("Хилл:       ", crypt.hill("helloworld", [[3, 3], [2, 5]]))
print("Изгородь:   ", crypt.rail_fence("WEAREDISCOVERED", 3))
print("Столбцовая: ", crypt.columnar("WEAREDISCOVERED", "ZEBRAS"))

ct = crypt.vigenere(RU_TEXT, "тайна")
print("\nШифртекст Виженера:", ct[:70], "...")
print("Индекс совпадений: текст", round(crypt.index_of_coincidence(RU_TEXT), 4),
      "шифртекст", round(crypt.index_of_coincidence(ct), 4))
print("Касиски, вероятные длины ключа:", crypt.kasiski(ct)[:4])
key, pt = crypt.crack_vigenere(ct)
print(f"Взлом: ключ {key!r} ->", pt[:70], "...")
print("Цезарь взломан, сдвиг:", crypt.crack_caesar(crypt.caesar(RU_TEXT, 17))[0])
print("Топ-5 частот:", {k: round(v, 3) for k, v in list(crypt.frequencies(RU_TEXT).items())[:5]})
