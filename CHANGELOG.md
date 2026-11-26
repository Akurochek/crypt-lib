# Журнал изменений

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версии — [Semantic Versioning](https://semver.org/lang/ru/).

## [0.2.1] — 2026-11-26

### Добавлено
- Файлы `AUTHORS.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `CITATION.cff`.
- Метаданные пакета: `__version__`, `__author__`, `__license__` в `crypto_enu`.
- В `pyproject.toml`: список авторов, классификаторы PyPI, ссылки, extras `test` и `images`.
- Раздел «Авторы» и «Как цитировать» в README.

### Изменено
- В LICENSE указаны правообладатели — авторы библиотеки.
- Docstring-и модулей ссылаются на `crypto_enu/…` вместо старого `crypt/…`.

## [0.2.0] — 2026-11-19

### Добавлено
- Хэши SHA-224/384/512, SHA-512/t, SHA-3, SHAKE, Keccak, Стрибог (ГОСТ Р 34.11-2012), HKDF.
- Модуль `pubkey`: RSA (OAEP, PSS, PKCS#1 v1.5), Диффи–Хеллман (RFC 3526), Эль-Гамаль,
  ECDH/ECDSA (P-256, secp256k1), ГОСТ Р 34.10-2012, X25519, учебные атаки на RSA и ECDSA.
- README с иллюстрациями (`tools/make_images.py`).

### Изменено
- Пакет переименован из `crypt` в `crypto_enu` (конфликт со встроенным модулем `crypt`).

## [0.1.0] — 2026-11-05

### Добавлено
- Первая версия: 22 схемы дополнения, S/P-блоки, XOR, DES/3DES/AES/Магма/Кузнечик/PRESENT,
  сети Фейстеля и SPN, режимы ECB…GCM и CMAC, RC4, ChaCha20-Poly1305, SHA-1/SHA-256/MD5,
  HMAC, PBKDF2, классические шифры с взломом, анализ S-блоков и лавинного эффекта.

[0.2.1]: https://github.com/Akurochek/crypt-lib/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/Akurochek/crypt-lib/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Akurochek/crypt-lib/releases/tag/v0.1.0
