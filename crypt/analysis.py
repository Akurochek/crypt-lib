"""Анализ стойкости: свойства S-блоков и лавинный эффект шифров.

    crypt.sbox_report("aes")   # {'n': 8, 'differential_uniformity': 4, 'nonlinearity': 112, ...}
    crypt.ddt("present")       # таблица распределения разностей
    crypt.avalanche(lambda x: crypt.AES(key).encrypt_block(x), 16)   # ≈ 0.5 у хорошего шифра
"""
import importlib
import math
import os
from collections import Counter

from .bits import to_bits, is_bitstr

_sb = importlib.import_module(".sbox", __package__)


def _table(s) -> list[int]:
    if isinstance(s, str):
        if s.lower() not in _sb._SIMPLE:
            raise ValueError(f"для анализа нужен S-блок-таблица: {', '.join(_sb._SIMPLE)} или свой список")
        return _sb._SIMPLE[s.lower()]
    s = list(s)
    if len(s) & (len(s) - 1) or len(s) < 2:
        raise ValueError("размер S-блока должен быть степенью двойки")
    return s


def _bits(n: int) -> int:
    return n.bit_length() - 1


def ddt(s) -> list[list[int]]:
    """Difference Distribution Table: ddt[a][b] = #{x : S(x) ^ S(x ^ a) = b}."""
    t = _table(s)
    n = len(t)
    out = [[0] * n for _ in range(n)]
    for a in range(n):
        row = out[a]
        for x in range(n):
            row[t[x] ^ t[x ^ a]] += 1
    return out


def differential_uniformity(s) -> int:
    """max ddt[a][b] при a ≠ 0. Меньше — лучше (у AES 4 — оптимум для 8 бит на практике)."""
    return max(max(r) for r in ddt(s)[1:])


def _walsh(f: list[int]) -> list[int]:
    w = [1 - 2 * v for v in f]
    h = 1
    while h < len(w):
        for i in range(0, len(w), 2 * h):
            for j in range(i, i + h):
                w[j], w[j + h] = w[j] + w[j + h], w[j] - w[j + h]
        h *= 2
    return w


def lat(s) -> list[list[int]]:
    """Linear Approximation Table: lat[a][b] = #{x : a·x = b·S(x)} - n/2 (смещение)."""
    t = _table(s)
    n = len(t)
    cols = [_walsh([bin(b & t[x]).count("1") & 1 for x in range(n)]) for b in range(n)]
    return [[cols[b][a] // 2 for b in range(n)] for a in range(n)]


def nonlinearity(s) -> int:
    """Нелинейность: расстояние до ближайшей аффинной функции. Больше — лучше (AES 112, максимум для 8 бит)."""
    t = _table(s)
    n = len(t)
    m = max(abs(v) for b in range(1, n) for v in _walsh([bin(b & t[x]).count("1") & 1 for x in range(n)]))
    return n // 2 - m // 2


def algebraic_degree(s) -> int:
    """Максимальная степень многочлена Жегалкина (АНФ) среди выходных битов."""
    t = _table(s)
    n = len(t)
    deg = 0
    for bit in range(_bits(n)):
        f = [(v >> bit) & 1 for v in t]
        h = 1
        while h < n:                                  # преобразование Мёбиуса
            for i in range(n):
                if i & h:
                    f[i] ^= f[i ^ h]
            h *= 2
        deg = max([deg] + [bin(u).count("1") for u in range(n) if f[u]])
    return deg


def fixed_points(s) -> list[int]:
    t = _table(s)
    return [x for x in range(len(t)) if t[x] == x]


def sbox_report(s) -> dict:
    t = _table(s)
    return {
        "n": _bits(len(t)),
        "bijective": sorted(t) == list(range(len(t))),
        "involution": all(t[t[x]] == x for x in range(len(t))),
        "differential_uniformity": differential_uniformity(t),
        "nonlinearity": nonlinearity(t),
        "algebraic_degree": algebraic_degree(t),
        "fixed_points": fixed_points(t),
    }


# ------------------------------------------------------------------ шифры и данные
def hamming_weight(x) -> int:
    """Число единичных бит (bytes или строка битов)."""
    return to_bits(x).count("1")


def hamming_distance(x, y) -> int:
    a, b = to_bits(x), to_bits(y)
    if len(a) != len(b):
        raise ValueError("разная длина")
    return sum(i != j for i, j in zip(a, b))


def avalanche(fn, in_len: int, trials: int = 50) -> float:
    """Лавинный эффект: средняя доля изменившихся выходных бит при смене одного входного.
    fn(bytes) -> bytes, in_len — длина входа в байтах. Идеал 0.5."""
    total = count = 0
    for _ in range(trials):
        x = os.urandom(in_len)
        y = fn(x)
        for i in range(in_len * 8):
            x2 = bytearray(x)
            x2[i // 8] ^= 0x80 >> (i % 8)
            total += hamming_distance(y, fn(bytes(x2))) / (len(y) * 8)
            count += 1
    return total / count


def sac_matrix(fn, in_len: int, trials: int = 100) -> list[list[float]]:
    """Strict Avalanche Criterion: m[i][j] — вероятность, что смена входного бита i меняет выходной бит j
    (у хорошего шифра все ≈ 0.5)."""
    m = None
    for _ in range(trials):
        x = os.urandom(in_len)
        y = int.from_bytes(fn(x), "big")
        out_bits = len(fn(x)) * 8
        if m is None:
            m = [[0] * out_bits for _ in range(in_len * 8)]
        for i in range(in_len * 8):
            x2 = bytearray(x)
            x2[i // 8] ^= 0x80 >> (i % 8)
            d = y ^ int.from_bytes(fn(bytes(x2)), "big")
            for j in range(out_bits):
                m[i][j] += (d >> (out_bits - 1 - j)) & 1
    return [[v / trials for v in row] for row in m]


def entropy(data) -> float:
    """Энтропия Шеннона в битах на байт (для строки битов — на бит). Шифртекст ≈ 8, текст ≈ 4–5."""
    if isinstance(data, str):
        seq = to_bits(data) if is_bitstr(data) else data.encode()
    else:
        seq = bytes(data)
    if not seq:
        return 0.0
    n = len(seq)
    return -sum(c / n * math.log2(c / n) for c in Counter(seq).values())
