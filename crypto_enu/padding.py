"""Схемы дополнения (padding) сообщения до кратности размеру блока.

Всё считается в БИТАХ: pad(data, 64) — блок 64 бита; pad32/64/128/256 — то же.
data — строка битов "1101", текст или bytes (см. crypto_enu/bits.py).
По умолчанию схема iso7816_4 (дописать 1, потом нули) — работает с любой длиной в битах.

Байтовые схемы (pkcs7, ansi_x923, tls, esp, sha3, md5, pkcs1_*, ...) требуют, чтобы и блок,
и данные были кратны 8 битам. Список схем — SCHEMES, справка — info("pkcs7"),
другие имена тех же схем (gost_p2, sha256, x923, ...) — ALIASES.
"""
import os

from .bits import to_bits, _out

DEFAULT = "iso7816_4"

# имя: (стандарт, что делает, типичный блок в битах)
INFO = {
    # --- блочные шифры ---
    "zero":       ("ГОСТ Р 34.13-2015 процедура 1, ISO/IEC 9797-1 метод 1",
                   "нули; если уже кратно — не дополняем (неоднозначно, если данные кончаются нулями)", 64),
    "pkcs7":      ("RFC 5652 (CMS), RFC 2315",
                   "N байт со значением N", 128),
    "pkcs5":      ("RFC 8018 (PKCS#5)",
                   "то же, что PKCS#7, но только для блока 64 бита (DES)", 64),
    "ansi_x923":  ("ANSI X9.23",
                   "нулевые байты + последний байт = N", 64),
    "iso10126":   ("ISO 10126 (отозван), W3C XML Encryption",
                   "случайные байты + последний байт = N", 128),
    "iso7816_4":  ("ISO/IEC 7816-4, ISO/IEC 9797-1 метод 2, ГОСТ Р 34.13-2015 процедура 2, NIST SP 800-38A",
                   "бит 1, затем нули; всегда добавляет хотя бы 1 бит", 128),
    "gost_p3":    ("ГОСТ Р 34.13-2015 процедура 3",
                   "бит 1, затем нули — но только если длина не кратна блоку (для CTR/MAC, где длина известна)", 128),
    "iso9797_m1": ("ISO/IEC 9797-1 метод 1",
                   "нули, пустое сообщение — один нулевой блок", 64),
    "iso9797_m3": ("ISO/IEC 9797-1 метод 3",
                   "в начало блок с длиной сообщения в битах + нули в конце", 64),
    "tbc":        ("Trailing Bit Complement",
                   "заполнение инверсией последнего бита данных", 64),
    "space":      ("—",
                   "пробелы (0x20), для текстов", 64),
    # --- протоколы ---
    "tls":        ("RFC 5246 (TLS 1.2, CBC), RFC 4346",
                   "N байт со значением N-1 (последний байт = длина паддинга без себя)", 128),
    "ssl3":       ("RFC 6101 (SSL 3.0)",
                   "случайные байты + последний байт = N-1", 64),
    "esp":        ("RFC 4303 (IPsec ESP)",
                   "байты 1, 2, 3, ..., N-1 + последний байт = N-1 (без поля Next Header)", 128),
    # --- RSA: дополняет сообщение до ОДНОГО блока размером с модуль ---
    "pkcs1_t1":   ("RFC 8017 PKCS#1 v1.5, тип 1 (подпись)",
                   "00 01 FF..FF 00 M, минимум 8 байт FF; сообщение ≤ k-11 байт", 1024),
    "pkcs1_t2":   ("RFC 8017 PKCS#1 v1.5, тип 2 (шифрование)",
                   "00 02 <случайные ненулевые> 00 M, минимум 8 случайных; сообщение ≤ k-11 байт", 1024),
    # --- хэш-функции ---
    "sha2":       ("FIPS 180-4 (SHA-1/224/256/384/512), GB/T 32905 (SM3) — MD-усиление",
                   "бит 1, нули, длина сообщения в битах (big-endian): 64 бита, при блоке ≥1024 — 128 бит", 512),
    "md5":        ("RFC 1321 (MD5), RFC 1320 (MD4), RIPEMD-160",
                   "бит 1, нули, 64-битная длина в битах little-endian", 512),
    "pad10_1":    ("FIPS 202 (Keccak pad10*1), в битовой нотации стандарта",
                   "бит 1, нули, бит 1; минимум 2 бита", 1088),
    "sha3":       ("FIPS 202 (SHA3-224/256/384/512), байтами",
                   "0x06 00..00 0x80 (один байт — 0x86)", 1088),
    "shake":      ("FIPS 202 (SHAKE128/256), байтами",
                   "0x1F 00..00 0x80 (один байт — 0x9F)", 1344),
    "keccak":     ("оригинальный Keccak (Ethereum keccak256), байтами",
                   "0x01 00..00 0x80 (один байт — 0x81)", 1088),
    "streebog":   ("ГОСТ Р 34.11-2012 «Стрибог»",
                   "СЛЕВА дописывается 0..01: 0^(n-1) || 1 || M — Стрибог обрабатывает сообщение с конца", 512),
}
SCHEMES = tuple(INFO)

ALIASES = {
    "null": "zero", "zeros": "zero", "gost_p1": "zero",
    "rfc5652": "pkcs7", "cms": "pkcs7", "rfc2040": "pkcs7",
    "x923": "ansi_x923",
    "w3c": "iso10126", "xmlenc": "iso10126", "random": "iso10126",
    "bit": "iso7816_4", "one_and_zeros": "iso7816_4", "iso9797_m2": "iso7816_4",
    "gost_p2": "iso7816_4", "nist": "iso7816_4", "sp800_38a": "iso7816_4",
    "rfc5246": "tls", "rfc4303": "esp", "ipsec": "esp", "rfc6101": "ssl3",
    "rsa_sign": "pkcs1_t1", "rsa_encrypt": "pkcs1_t2",
    "sha1": "sha2", "sha224": "sha2", "sha256": "sha2", "sha384": "sha2", "sha512": "sha2",
    "sm3": "sha2", "md_strengthening": "sha2",
    "md4": "md5", "ripemd160": "md5",
    "keccak_pad": "pad10_1", "sha3_256": "sha3", "shake128": "shake", "shake256": "shake",
    "keccak256": "keccak", "ethereum": "keccak",
    "gost3411": "streebog", "gost_34_11": "streebog",
}

_BYTE_SCHEMES = {"pkcs7", "pkcs5", "ansi_x923", "iso10126", "space", "tls", "ssl3", "esp",
                 "pkcs1_t1", "pkcs1_t2", "md5", "sha3", "shake", "keccak"}
_LEN_BYTE = {"pkcs7", "pkcs5", "ansi_x923", "iso10126", "tls", "ssl3", "esp"}   # длина в 1 байте
_KECCAK = {"sha3": 0x06, "shake": 0x1F, "keccak": 0x01}


def info(scheme: str) -> str:
    """Справка по схеме: info("gost_p2") -> 'iso7816_4: ...'."""
    s = _name(scheme)
    std, what, blk = INFO[s]
    return f"{s}: {what}. Стандарт: {std}. Типичный блок {blk} бит."


def _name(scheme: str) -> str:
    s = scheme.lower().replace("-", "_").replace(" ", "_")
    s = ALIASES.get(s, s)
    if s not in INFO:
        raise ValueError(f"неизвестная схема {scheme!r}, есть: {', '.join(SCHEMES)}")
    return s


def _len_field(block: int) -> int:
    return 128 if block >= 1024 else 64


def _check(bits: str, block: int, scheme: str):
    if block < 1:
        raise ValueError("размер блока должен быть > 0 бит")
    if scheme in _BYTE_SCHEMES:
        if block % 8 or len(bits) % 8:
            raise ValueError(f"{scheme} — байтовая схема: блок и данные должны быть кратны 8 битам "
                             f"(данных {len(bits)} бит); для произвольных битов есть iso7816_4, zero, tbc")
    if scheme in _LEN_BYTE and block > 255 * 8:
        raise ValueError(f"{scheme}: блок не больше 255 байт (длина пишется в один байт)")
    if scheme == "pkcs5" and block != 64:
        raise ValueError("PKCS#5 определён только для блока 64 бита")
    if scheme == "sha2" and block <= _len_field(block):
        raise ValueError(f"sha2: блок должен быть больше поля длины ({_len_field(block)} бит), обычно 512 или 1024")
    if scheme == "md5" and block <= 64:
        raise ValueError("md5: блок должен быть больше 64 бит, обычно 512")
    if scheme in ("pkcs1_t1", "pkcs1_t2") and block < 12 * 8:
        raise ValueError("PKCS#1 v1.5: блок (размер модуля RSA) минимум 12 байт")


def _byte(n: int) -> str:
    return f"{n:08b}"


def _pad_bits(bits: str, block: int, scheme: str) -> str:
    _check(bits, block, scheme)
    n = block - len(bits) % block       # сколько бит добавить, 1..block
    nb = n // 8                         # то же в байтах (для байтовых схем)

    if scheme in ("zero", "iso9797_m1"):
        return bits if bits and n == block else bits + "0" * n
    if scheme in ("pkcs7", "pkcs5"):
        return bits + _byte(nb) * nb
    if scheme == "ansi_x923":
        return bits + "0" * (n - 8) + _byte(nb)
    if scheme == "iso10126":
        return bits + to_bits(os.urandom(nb - 1)) + _byte(nb)
    if scheme == "iso7816_4":
        return bits + "1" + "0" * (n - 1)
    if scheme == "gost_p3":
        return bits if bits and n == block else bits + "1" + "0" * (n - 1)
    if scheme == "iso9797_m3":
        if len(bits) >= 1 << block:
            raise ValueError("сообщение слишком длинное, чтобы записать длину в один блок")
        header = format(len(bits), f"0{block}b")
        return header + (_pad_bits(bits, block, "iso9797_m1") if bits else "")
    if scheme == "tbc":
        fill = "0" if bits and bits[-1] == "1" else "1"
        return bits + fill * n
    if scheme == "space":
        return bits + _byte(0x20) * nb
    if scheme == "tls":
        return bits + _byte(nb - 1) * nb
    if scheme == "ssl3":
        return bits + to_bits(os.urandom(nb - 1)) + _byte(nb - 1)
    if scheme == "esp":
        return bits + "".join(_byte(i) for i in range(1, nb)) + _byte(nb - 1)
    if scheme in ("pkcs1_t1", "pkcs1_t2"):
        k, m = block // 8, len(bits) // 8
        if m > k - 11:
            raise ValueError(f"PKCS#1 v1.5: сообщение {m} байт, а в блок {k} байт влезает максимум {k - 11}")
        ps = b"\xff" * (k - 3 - m) if scheme == "pkcs1_t1" else _nonzero_random(k - 3 - m)
        bt = b"\x01" if scheme == "pkcs1_t1" else b"\x02"
        return to_bits(b"\x00" + bt + ps + b"\x00") + bits
    if scheme in ("sha2", "md5"):
        lf = _len_field(block) if scheme == "sha2" else 64
        if len(bits) >= 1 << lf:
            raise ValueError(f"сообщение длиннее 2^{lf} бит")
        k = (-len(bits) - 1 - lf) % block
        if scheme == "sha2":
            length = format(len(bits), f"0{lf}b")
        else:
            length = to_bits(len(bits).to_bytes(8, "little"))
        return bits + "1" + "0" * k + length
    if scheme == "pad10_1":
        k = (-len(bits) - 2) % block
        return bits + "1" + "0" * k + "1"
    if scheme in _KECCAK:
        d = _KECCAK[scheme]
        if nb == 1:
            return bits + _byte(d | 0x80)
        return bits + _byte(d) + "0" * (8 * (nb - 2)) + _byte(0x80)
    if scheme == "streebog":
        return "0" * (n - 1) + "1" + bits


def _nonzero_random(n: int) -> bytes:
    out = b""
    while len(out) < n:
        out += os.urandom(n - len(out)).replace(b"\x00", b"")
    return out


def _bad(scheme: str):
    return ValueError(f"неверный {scheme} padding")


def _unpad_bits(bits: str, block: int, scheme: str, whole_bytes: bool = False) -> str:
    """whole_bytes — данные пришли байтами: нули/заполнитель срезаем целыми байтами."""
    _check(bits, block, scheme)
    if scheme == "gost_p3" and not bits:
        return bits
    if not bits or len(bits) % block:
        raise ValueError(f"длина {len(bits)} бит не кратна блоку {block} бит")

    if scheme in ("zero", "iso9797_m1"):
        return _strip(bits, "0", whole_bytes)
    if scheme in ("pkcs7", "pkcs5", "ansi_x923", "iso10126"):
        nb = int(bits[-8:], 2)
        if not 1 <= nb <= block // 8:
            raise _bad(scheme)
        tail = bits[-8 * nb:-8]
        if scheme in ("pkcs7", "pkcs5") and tail != _byte(nb) * (nb - 1) \
                or scheme == "ansi_x923" and tail != "0" * len(tail):
            raise _bad(scheme)
        return bits[:-8 * nb]
    if scheme == "iso7816_4":
        body = bits.rstrip("0")
        if not body.endswith("1"):
            raise ValueError("неверный ISO 7816-4 padding")
        return body[:-1]
    if scheme == "gost_p3":
        # Процедура 3 неоднозначна: если маркера 1 0..0 в последнем блоке нет — дополнения не было.
        last = bits[-block:]
        body = _strip(last, "0", whole_bytes)
        if whole_bytes:
            ok = body.endswith(_byte(0x80))
            return bits[:-block] + body[:-8] if ok else bits
        return bits[:-block] + body[:-1] if body.endswith("1") else bits
    if scheme == "iso9797_m3":
        return bits[block:block + int(bits[:block], 2)]
    if scheme == "tbc":
        return _strip(bits, bits[-1], whole_bytes)
    if scheme == "space":
        sp = _byte(0x20)
        while bits.endswith(sp):
            bits = bits[:-8]
        return bits
    if scheme in ("tls", "ssl3", "esp"):
        p = int(bits[-8:], 2)
        nb = p + 1
        if nb > block // 8:
            raise _bad(scheme)
        pad = bits[-8 * nb:-8]
        if scheme == "tls" and pad != _byte(p) * p \
                or scheme == "esp" and pad != "".join(_byte(i) for i in range(1, nb)):
            raise _bad(scheme)
        return bits[:-8 * nb]
    if scheme in ("pkcs1_t1", "pkcs1_t2"):
        if len(bits) != block:
            raise ValueError("PKCS#1 v1.5: ожидается ровно один блок")
        eb = bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8))
        bt = 1 if scheme == "pkcs1_t1" else 2
        sep = eb.find(b"\x00", 2)
        if eb[0] != 0 or eb[1] != bt or sep < 10 \
                or bt == 1 and eb[2:sep] != b"\xff" * (sep - 2):
            raise _bad(scheme)
        return bits[8 * (sep + 1):]
    if scheme in ("sha2", "md5"):
        lf = _len_field(block) if scheme == "sha2" else 64
        field = bits[-lf:]
        if scheme == "md5":
            field = to_bits(bytes(int(field[i:i + 8], 2) for i in range(0, lf, 8))[::-1])
        m = int(field, 2)
        if m >= len(bits) - lf or bits[m] != "1" or "1" in bits[m + 1:-lf] \
                or len(_pad_bits("0" * m, block, scheme)) != len(bits):
            raise _bad(scheme)
        return bits[:m]
    if scheme == "pad10_1":
        if not bits.endswith("1"):
            raise _bad(scheme)
        body = bits[:-1].rstrip("0")
        if not body.endswith("1") or len(bits) - len(body) > block:
            raise _bad(scheme)
        return body[:-1]
    if scheme in _KECCAK:
        d = _KECCAK[scheme]
        last = int(bits[-8:], 2)
        if last == d | 0x80:
            return bits[:-8]
        if last != 0x80:
            raise _bad(scheme)
        body = _strip(bits[:-8], "0", True)
        if not body.endswith(_byte(d)) or len(bits) - len(body) + 8 > block:
            raise _bad(scheme)
        return body[:-8]
    if scheme == "streebog":
        body = bits.lstrip("0")
        if not body.startswith("1") or len(bits) - len(body) >= block:
            raise _bad(scheme)
        return body[1:]


def _strip(bits: str, fill: str, whole_bytes: bool) -> str:
    if not whole_bytes:
        return bits.rstrip(fill)
    while bits.endswith(fill * 8):
        bits = bits[:-8]
    return bits


def pad(data: bytes | str, block_bits: int, scheme: str = DEFAULT) -> bytes | str:
    out = _pad_bits(to_bits(data), block_bits, _name(scheme))
    if isinstance(data, (bytes, bytearray)) and len(out) % 8:
        raise ValueError("для bytes блок должен быть кратен 8 битам")
    return _out(out, data)


def unpad(data: bytes | str, block_bits: int, scheme: str = DEFAULT) -> bytes | str:
    whole = isinstance(data, (bytes, bytearray))
    return _out(_unpad_bits(to_bits(data), block_bits, _name(scheme), whole), data)


def padded_len(length_bits: int, block_bits: int, scheme: str = DEFAULT) -> int:
    """Длина в битах после дополнения сообщения длиной length_bits."""
    return len(_pad_bits("1" * length_bits, block_bits, _name(scheme)))


def blocks(data: bytes | str, block_bits: int) -> list:
    """Нарезка уже дополненных данных на блоки по block_bits бит."""
    bits = to_bits(data)
    return [_out(bits[i:i + block_bits], data) for i in range(0, len(bits), block_bits)]


def _make(bits: int):
    def _pad(data, scheme=DEFAULT, with_len=False):
        out = pad(data, bits, scheme)
        return (out, len(to_bits(out))) if with_len else out
    _pad.__name__ = f"pad{bits}"
    _pad.__doc__ = f"Дополнить до кратности {bits} бит. with_len=True -> (данные, длина в битах)."
    return _pad


pad32, pad64, pad128, pad256, pad512, pad1024 = (_make(b) for b in (32, 64, 128, 256, 512, 1024))


def unpad32(data, scheme=DEFAULT): return unpad(data, 32, scheme)
def unpad64(data, scheme=DEFAULT): return unpad(data, 64, scheme)
def unpad128(data, scheme=DEFAULT): return unpad(data, 128, scheme)
def unpad256(data, scheme=DEFAULT): return unpad(data, 256, scheme)
def unpad512(data, scheme=DEFAULT): return unpad(data, 512, scheme)
def unpad1024(data, scheme=DEFAULT): return unpad(data, 1024, scheme)
