# crypt-lib

Учебная криптобиблиотека на чистом Python: всё написано с нуля и сверено с эталонными
векторами стандартов (FIPS, NIST SP 800-38, ГОСТ Р 34.12/34.13-2015, RFC). Для учёбы и лаб,
не для защиты реальных данных (нет защиты от атак по времени).

Данные — `bytes`, обычный текст (берётся UTF-8) или строка битов `"1101"` (ответ тоже строкой битов).

```bash
pip install git+https://github.com/Akurochek/crypt-lib.git   # поставить как библиотеку
python test_crypt.py          # все тесты
python examples/ex_ciphers.py # и другие примеры в examples/
```

## Модули

| Модуль | Что есть |
|---|---|
| `bits` | `to_bits`, `from_bits`, `group` |
| `padding` | 22 схемы: PKCS#7/5, ANSI X9.23, ISO 10126, ISO 7816-4, ISO 9797-1 м1/м3, ГОСТ 34.13 процедуры 1–3, TBC, TLS, SSL3, ESP, PKCS#1 v1.5, SHA-2/MD5 (MD-усиление), Keccak pad10*1, SHA-3/SHAKE, Стрибог. `crypt.info("gost_p2")` |
| `sbox`, `pbox`, `xor` | S-блоки AES, Кузнечик, Магма, PRESENT, GIFT, DES; P-блоки DES, PRESENT |
| `ciphers` | `DES`, `TDES`, `AES` (128/192/256), `Magma`, `Kuznyechik`, `Present` (80/128), свои `Feistel` и `SPN`; `crypt.cipher("aes", key)` |
| `modes` | ECB, CBC, PCBC, CFB (в т.ч. CFB-8), OFB, CTR (NIST и ГОСТ), CMAC = имитовставка ГОСТ, CBC-MAC, GCM; `encrypt` / `decrypt` |
| `stream` | RC4, ChaCha20, Poly1305, ChaCha20-Poly1305 |
| `hashes` | SHA-256, SHA-1, MD5 (поверх `padding`), HMAC, PBKDF2 |
| `classic` | Цезарь, ROT13, Атбаш, аффинный, простая замена, Виженер, Бофор, самоключ, Хилл, «изгородь», столбцовая перестановка |
| `classic` (анализ) | частоты, индекс совпадений, χ², Касиски, взлом Цезаря / аффинного / Виженера |
| `analysis` | DDT, LAT, дифференциальная равномерность, нелинейность, алгебраическая степень, `sbox_report`, лавинный эффект, SAC, энтропия, расстояние Хэмминга |

## Быстрый старт

```python
import crypt

key = bytes(32)
ct = crypt.encrypt(b"secret", key, "kuznyechik", "cbc")      # IV в начале, PKCS#7
crypt.decrypt(ct, key, "kuznyechik", "cbc")                   # b'secret'
crypt.encrypt(b"secret", key[:16], "aes", "gcm", aad=b"hdr")  # nonce + шифртекст + тег

c = crypt.Magma(key)
crypt.ctr(c, b"data", b"\x12\x34\x56\x78")                    # гаммирование ГОСТ, IV на полблока
crypt.cmac(c, b"data", 4)                                     # имитовставка ГОСТ, 32 бита

crypt.crack_vigenere(crypt.vigenere(long_text, "ключ"))       # ('ключ', long_text)
crypt.sbox_report("aes")                                      # нелинейность 112, дифф. равн. 4, ...
```

## Эталоны в тестах

DES (FIPS 46), AES-128/192/256 (FIPS-197), «Кузнечик», «Магма» (ГОСТ Р 34.12-2015),
PRESENT-80/128, режимы AES (NIST SP 800-38A), CMAC (RFC 4493), GCM (тест-кейсы McGrew–Viega),
CTR и имитовставка для «Кузнечика» и «Магмы» (ГОСТ Р 34.13-2015, прил. А), RC4, ChaCha20 и Poly1305
(RFC 8439), SHA-256/SHA-1/MD5/HMAC/PBKDF2 (сверка с `hashlib`).

## Лицензия

MIT — см. [LICENSE](LICENSE).
