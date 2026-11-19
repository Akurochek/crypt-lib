"""XOR данных с ключом (ключ повторяется по длине данных). Работает по битам."""
from itertools import cycle

from .bits import to_bits, _out


def xor(data: bytes | str, key: bytes | str) -> bytes | str:
    d, k = to_bits(data), to_bits(key)
    if not k:
        raise ValueError("пустой ключ")
    return _out("".join("1" if a != b else "0" for a, b in zip(d, cycle(k))), data)
