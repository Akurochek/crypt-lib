"""P-блок: перестановка битов.

perm[i] = номер входного бита, который встаёт на i-ю позицию выхода
(нумерация с 0 от старшего бита). Стандарт передаётся строкой: pbox(data, "des_ip").
Список — crypt.PBOXES. Если данных больше одного блока, таблица применяется к каждому.
Данные — строка битов ("1101", тогда таблица может быть на любое число бит) или bytes.
"""


from .bits import to_bits, _out


def _from1(table: list[int]) -> list[int]:
    """Стандарты DES пишут таблицы с 1 — переводим в нумерацию с 0."""
    return [x - 1 for x in table]


def present_perm(nbits: int = 64) -> list[int]:
    """Перестановка из PRESENT: бит i уходит на позицию i*16 mod 63."""
    out = [0] * nbits
    for i in range(nbits):
        j = nbits - 1 if i == nbits - 1 else (i * nbits // 4) % (nbits - 1)
        out[j] = i
    return out


def rotl_perm(nbits: int, n: int) -> list[int]:
    """Циклический сдвиг влево на n бит как перестановка."""
    return [(i + n) % nbits for i in range(nbits)]


DES_IP = _from1([
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7])
DES_FP = [DES_IP.index(i) for i in range(64)]  # IP^-1
DES_E = _from1([
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1])
DES_P = _from1([
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25])
DES_PC1 = _from1([
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4])
DES_PC2 = _from1([
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32])

# имя -> (таблица, сколько бит на входе)
PBOXES = {
    "des_ip":   (DES_IP, 64),       # начальная перестановка DES
    "des_fp":   (DES_FP, 64),       # конечная перестановка IP^-1
    "des_p":    (DES_P, 32),        # перестановка P в функции Фейстеля
    "des_e":    (DES_E, 32),        # расширение 32 -> 48 бит (необратимо)
    "des_pc1":  (DES_PC1, 64),      # выбор ключа 64 -> 56 бит (необратимо)
    "des_pc2":  (DES_PC2, 56),      # сжатие ключа 56 -> 48 бит (необратимо)
    "present":  (present_perm(64), 64),  # PRESENT, 64 бита
    "magma_rot11": (rotl_perm(32, 11), 32),  # «Магма»: сдвиг 32-битного слова на 11 влево
}


def _resolve(perm) -> tuple[list[int], int]:
    if isinstance(perm, str):
        if perm.lower() not in PBOXES:
            raise ValueError(f"неизвестный P-блок {perm!r}, есть: {', '.join(PBOXES)}")
        return PBOXES[perm.lower()]
    return list(perm), len(perm)


def pbox(data: bytes, perm: str | list[int]) -> bytes:
    """perm — имя стандарта (см. PBOXES) или своя таблица."""
    table, n_in = _resolve(perm)
    bits = to_bits(data)
    if len(bits) % n_in or not bits:
        raise ValueError(f"P-блок на {n_in} бит, а данных {len(bits)} бит")
    out = "".join(bits[i + p] for i in range(0, len(bits), n_in) for p in table)
    return _out(out, data)


def pbox_inv(data: bytes, perm: str | list[int]) -> bytes:
    table, n_in = _resolve(perm)
    if sorted(table) != list(range(n_in)):
        raise ValueError("это не перестановка (расширение/сжатие) — обратной нет")
    inv = [0] * n_in
    for i, p in enumerate(table):
        inv[p] = i
    return pbox(data, inv)
