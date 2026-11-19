"""Битовые строки: "1101" — это 4 бита.

Правило для всей библиотеки:
  str из 0/1 (пробелы игнорируются) -> биты, ответ тоже строкой битов;
  другой str (текст)                 -> его UTF-8 байты в битах, ответ строкой битов;
  bytes                              -> байты, ответ bytes.
"""


def is_bitstr(s) -> bool:
    return isinstance(s, str) and set(s.replace(" ", "")) <= {"0", "1"}


def to_bits(x: bytes | str) -> str:
    if isinstance(x, str):
        return x.replace(" ", "") if is_bitstr(x) else to_bits(x.encode())
    return "".join(f"{b:08b}" for b in x)


def from_bits(s: str) -> bytes:
    s = s.replace(" ", "")
    if len(s) % 8:
        raise ValueError(f"{len(s)} бит не делится на 8 — в байты не переводится")
    return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def group(s: str, n: int = 8) -> str:
    """Для печати: '1101000001' -> '11010000 01'."""
    s = s.replace(" ", "")
    return " ".join(s[i:i + n] for i in range(0, len(s), n))


def _out(bits: str, like):
    """Вернуть результат того же типа, что и вход."""
    return from_bits(bits) if isinstance(like, (bytes, bytearray)) else bits
