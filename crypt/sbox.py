"""S-блок: табличная подстановка.

Стандарт передаётся строкой: sbox(data, "aes"). Список — crypt.SBOXES.
Можно передать и свою таблицу на 16 (по 4 бита) или 256 (по 8 бит) значений.
Данные — строка битов "1101" (ответ строкой битов) или bytes.
"""
from .bits import to_bits, from_bits, _out


def _aes_sbox() -> list[int]:
    """S-блок AES (FIPS-197): обращение в GF(2^8) + аффинное преобразование."""
    def mul(a, b):
        r = 0
        while b:
            if b & 1:
                r ^= a
            a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
            b >>= 1
        return r

    def inv(a):
        if a == 0:
            return 0
        r = 1
        for _ in range(254):  # a^254 = a^-1
            r = mul(r, a)
        return r

    def rotl(x, n):
        return ((x << n) | (x >> (8 - n))) & 0xFF

    return [(b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63)
            for b in map(inv, range(256))]


AES = _aes_sbox()

# ГОСТ Р 34.12-2015 «Кузнечик», подстановка π
KUZNYECHIK = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
    50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
    224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
]

# 4-битные S-блоки
PRESENT = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]
GIFT = [0x1, 0xA, 0x4, 0xC, 0x6, 0xF, 0x3, 0x9, 0x2, 0xD, 0xB, 0x7, 0x5, 0x0, 0x8, 0xE]

# ГОСТ Р 34.12-2015 «Магма» (ГОСТ 28147-89, набор id-tc26-gost-28147-param-Z):
# 8 блоков по 4 бита, MAGMA[0] — для младшего полубайта 32-битного слова
MAGMA = [
    [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1],
    [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15],
    [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0],
    [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11],
    [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12],
    [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0],
    [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7],
    [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2],
]

# DES (FIPS 46-3): 8 блоков 6 бит -> 4 бита, DES[i][строка][столбец]
DES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]],
]

SBOXES = {
    "aes": "8 бит, AES / Rijndael (FIPS-197)",
    "kuznyechik": "8 бит, ГОСТ Р 34.12-2015 «Кузнечик»",
    "present": "4 бита, PRESENT (ISO/IEC 29192-2)",
    "gift": "4 бита, GIFT",
    "magma": "8×4 бита на 32-битное слово, ГОСТ «Магма» / 28147-89",
    "des": "8×(6→4 бита) на 48 бит -> 32 бита, DES (необратим)",
}
_SIMPLE = {"aes": AES, "kuznyechik": KUZNYECHIK, "present": PRESENT, "gift": GIFT}


def invert(table: list[int]) -> list[int]:
    if sorted(table) != list(range(len(table))):
        raise ValueError("S-блок должен быть биекцией")
    inv = [0] * len(table)
    for i, v in enumerate(table):
        inv[v] = i
    return inv


def _table(data: bytes, table: list[int]) -> bytes:
    if len(table) == 16:
        return bytes((table[b >> 4] << 4) | table[b & 0xF] for b in data)
    if len(table) == 256:
        return bytes(table[b] for b in data)
    raise ValueError("таблица должна быть на 16 или 256 элементов")


def _magma(data: bytes, boxes: list[list[int]]) -> bytes:
    if len(data) % 4:
        raise ValueError("Магма: длина должна быть кратна 4 байтам (32 бита)")
    out = b""
    for i in range(0, len(data), 4):
        w = int.from_bytes(data[i:i + 4], "big")
        r = sum(boxes[k][(w >> 4 * k) & 0xF] << 4 * k for k in range(8))
        out += r.to_bytes(4, "big")
    return out


def _des(data: bytes) -> bytes:
    if len(data) % 6:
        raise ValueError("DES: длина должна быть кратна 6 байтам (48 бит)")
    out = b""
    for i in range(0, len(data), 6):
        x = int.from_bytes(data[i:i + 6], "big")
        r = 0
        for k in range(8):
            six = (x >> (42 - 6 * k)) & 0x3F
            row = ((six >> 4) & 2) | (six & 1)   # крайние биты
            col = (six >> 1) & 0xF               # средние 4 бита
            r = (r << 4) | DES[k][row][col]
        out += r.to_bytes(4, "big")
    return out


def _bitwise(fn, data, table):
    """Строку битов прогоняем через байтовую реализацию; 4-битные таблицы — по 4 бита."""
    if isinstance(data, (bytes, bytearray)):
        return fn(bytes(data), table)
    bits = to_bits(data)
    if isinstance(table, str) and table.lower() in _SIMPLE:
        table = _SIMPLE[table.lower()]
    if isinstance(table, list) and len(table) == 16:
        if len(bits) % 4:
            raise ValueError(f"4-битный S-блок: {len(bits)} бит не делится на 4")
        tbl = table if fn is _sbox else invert(table)
        return "".join(f"{tbl[int(bits[i:i + 4], 2)]:04b}" for i in range(0, len(bits), 4))
    return _out(to_bits(fn(from_bits(bits), table)), data)


def sbox(data: bytes | str, table: str | list[int] = "present") -> bytes | str:
    """table — имя стандарта (см. SBOXES) или своя таблица на 16/256 элементов."""
    return _bitwise(_sbox, data, table)


def sbox_inv(data: bytes | str, table: str | list[int] = "present") -> bytes | str:
    return _bitwise(_sbox_inv, data, table)


def _sbox(data: bytes, table) -> bytes:
    if isinstance(table, str):
        name = table.lower()
        if name == "magma":
            return _magma(data, MAGMA)
        if name == "des":
            return _des(data)
        if name not in _SIMPLE:
            raise ValueError(f"неизвестный S-блок {table!r}, есть: {', '.join(SBOXES)}")
        table = _SIMPLE[name]
    return _table(data, table)


def _sbox_inv(data: bytes, table) -> bytes:
    if isinstance(table, str):
        name = table.lower()
        if name == "magma":
            return _magma(data, [invert(b) for b in MAGMA])
        if name == "des":
            raise ValueError("S-блоки DES сжимают 6 бит в 4 — обратного нет")
        if name not in _SIMPLE:
            raise ValueError(f"неизвестный S-блок {table!r}, есть: {', '.join(SBOXES)}")
        table = _SIMPLE[name]
    return _table(data, invert(table))


PRESENT_SBOX = PRESENT  # старое имя
