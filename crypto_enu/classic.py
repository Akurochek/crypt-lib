"""Классические шифры (русский и английский алфавит) и их криптоанализ.

Регистр и знаки препинания сохраняются, шифруются только буквы алфавита.
Алфавит определяется сам по тексту, либо alphabet="ru" / "ru32" (без ё) / "en" / своя строка.

    crypt.caesar("Привет", 3)               -> 'Тулезх'
    crypt.vigenere("attack at dawn", "lemon")
    crypt.crack_vigenere(ct)                -> (ключ, открытый текст)
"""
from collections import Counter
from math import gcd

RU = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
RU32 = "абвгдежзийклмнопрстуфхцчшщъыьэюя"
EN = "abcdefghijklmnopqrstuvwxyz"
ALPHABETS = {"ru": RU, "ru32": RU32, "en": EN}

# частоты букв (доля), по корпусу НКРЯ и Lewand «Cryptological Mathematics»
FREQ = {
    "ru": dict(zip(RU, (.0801, .0159, .0454, .0170, .0298, .0845, .0004, .0094, .0165, .0735, .0121,
                        .0349, .0440, .0321, .0670, .1097, .0281, .0473, .0547, .0626, .0262, .0026,
                        .0097, .0048, .0144, .0073, .0036, .0004, .0190, .0174, .0032, .0064, .0201))),
    "en": dict(zip(EN, (.0817, .0149, .0278, .0425, .1270, .0223, .0202, .0609, .0697, .0015, .0077,
                        .0403, .0241, .0675, .0751, .0193, .0010, .0599, .0633, .0906, .0276, .0098,
                        .0236, .0015, .0197, .0007))),
}
FREQ["ru32"] = {k: v for k, v in FREQ["ru"].items() if k != "ё"}
FREQ["ru32"]["е"] += FREQ["ru"]["ё"]


def _alpha(text: str, alphabet=None) -> str:
    if alphabet is None:
        low = text.lower()
        ru = sum(ch in RU for ch in low)
        en = sum(ch in EN for ch in low)
        return RU if ru >= en and ru else EN
    return ALPHABETS.get(alphabet, alphabet)


def _lang(a: str):
    return next((k for k, v in ALPHABETS.items() if v == a), None)


def _letters(text: str, a: str) -> str:
    return "".join(ch for ch in text.lower() if ch in a)


def _map(text: str, a: str, f) -> str:
    """f(индекс буквы, номер буквы в тексте) -> новый индекс; регистр сохраняется."""
    out, k, m = [], 0, len(a)
    for ch in text:
        lo = ch.lower()
        if lo in a:
            new = a[f(a.index(lo), k) % m]
            out.append(new.upper() if ch != lo else new)
            k += 1
        else:
            out.append(ch)
    return "".join(out)


def _key_idx(key, a):
    if isinstance(key, int):
        return [key]
    idx = [a.index(ch) for ch in key.lower() if ch in a]
    if not idx:
        raise ValueError("в ключе нет ни одной буквы алфавита")
    return idx


# ------------------------------------------------------------------ подстановки
def caesar(text: str, shift: int = 3, decrypt=False, alphabet=None) -> str:
    """Шифр Цезаря: сдвиг каждой буквы на shift позиций."""
    a = _alpha(text, alphabet)
    s = -shift if decrypt else shift
    return _map(text, a, lambda i, _: i + s)


def rot13(text: str) -> str:
    return caesar(text, 13, alphabet="en")


def atbash(text: str, alphabet=None) -> str:
    """Атбаш: алфавит задом наперёд (а<->я). Сам себе обратный."""
    a = _alpha(text, alphabet)
    return _map(text, a, lambda i, _: len(a) - 1 - i)


def affine(text: str, a_key: int, b_key: int, decrypt=False, alphabet=None) -> str:
    """Аффинный шифр: y = a*x + b mod m; a должно быть взаимно просто с m (33 для ru, 26 для en)."""
    a = _alpha(text, alphabet)
    m = len(a)
    if gcd(a_key, m) != 1:
        raise ValueError(f"a={a_key} не взаимно просто с размером алфавита {m}")
    if decrypt:
        inv = pow(a_key, -1, m)
        return _map(text, a, lambda i, _: inv * (i - b_key))
    return _map(text, a, lambda i, _: a_key * i + b_key)


def substitution(text: str, key: str, decrypt=False, alphabet=None) -> str:
    """Простая замена: key — перемешанный алфавит той же длины."""
    a = _alpha(text, alphabet)
    key = key.lower()
    if sorted(key) != sorted(a):
        raise ValueError("ключ должен быть перестановкой всего алфавита")
    src, dst = (key, a) if decrypt else (a, key)
    return _map(text, a, lambda i, _: a.index(dst[src.index(a[i])]))


def vigenere(text: str, key: str, decrypt=False, alphabet=None) -> str:
    """Шифр Виженера: сдвиг на букву ключа, ключ повторяется."""
    a = _alpha(text, alphabet)
    k = _key_idx(key, a)
    sgn = -1 if decrypt else 1
    return _map(text, a, lambda i, n: i + sgn * k[n % len(k)])


def beaufort(text: str, key: str, alphabet=None) -> str:
    """Шифр Бофора: y = k - x. Сам себе обратный."""
    a = _alpha(text, alphabet)
    k = _key_idx(key, a)
    return _map(text, a, lambda i, n: k[n % len(k)] - i)


def autokey(text: str, key: str, decrypt=False, alphabet=None) -> str:
    """Самоключ Виженера: после ключа гаммой служит сам открытый текст."""
    a = _alpha(text, alphabet)
    stream = _key_idx(key, a)
    out, n = [], 0
    for ch in text:
        lo = ch.lower()
        if lo not in a:
            out.append(ch)
            continue
        i = a.index(lo)
        j = (i - stream[n]) % len(a) if decrypt else (i + stream[n]) % len(a)
        stream.append(j if decrypt else i)
        new = a[j]
        out.append(new.upper() if ch != lo else new)
        n += 1
    return "".join(out)


# ------------------------------------------------------------------ Хилл
def _det(mx):
    if len(mx) == 1:
        return mx[0][0]
    return sum((-1) ** j * mx[0][j] * _det([r[:j] + r[j + 1:] for r in mx[1:]]) for j in range(len(mx)))


def _inv_matrix(mx, m):
    n = len(mx)
    d = _det(mx) % m
    if gcd(d, m) != 1:
        raise ValueError(f"определитель {d} не взаимно прост с {m} — матрица необратима, ключ не годится")
    di = pow(d, -1, m)
    if n == 1:
        return [[di]]
    adj = [[(-1) ** (i + j) * _det([r[:i] + r[i + 1:] for k, r in enumerate(mx) if k != j]) for j in range(n)]
           for i in range(n)]
    return [[di * v % m for v in row] for row in adj]


def hill(text: str, key, decrypt=False, alphabet=None, filler=None) -> str:
    """Шифр Хилла: блок из n букв умножается на матрицу n×n по модулю размера алфавита.
    key — матрица [[..], ..] или слово длиной n² букв. Небуквенные символы выбрасываются,
    хвост дополняется filler (по умолчанию последняя буква алфавита)."""
    a = _alpha(text, alphabet)
    m = len(a)
    if isinstance(key, str):
        idx = _key_idx(key, a)
        n = int(round(len(idx) ** 0.5))
        if n * n != len(idx):
            raise ValueError("длина ключа-слова должна быть квадратом (4, 9, 16 букв)")
        key = [idx[i * n:(i + 1) * n] for i in range(n)]
    n = len(key)
    mx = _inv_matrix(key, m) if decrypt else _inv_matrix(_inv_matrix(key, m), m)
    v = [a.index(ch) for ch in _letters(text, a)]
    v += [a.index(filler or a[-1])] * (-len(v) % n)
    out = []
    for i in range(0, len(v), n):
        blk = v[i:i + n]
        out += [sum(mx[r][c] * blk[c] for c in range(n)) % m for r in range(n)]
    return "".join(a[x] for x in out)


# ------------------------------------------------------------------ перестановки
def rail_fence(text: str, rails: int = 3, decrypt=False) -> str:
    """Шифр «изгородь»: текст пишется зигзагом по rails строкам и читается построчно."""
    if rails < 2:
        return text
    pattern = [r for r in (list(range(rails)) + list(range(rails - 2, 0, -1)))] * (len(text) // (2 * rails - 2) + 1)
    pattern = pattern[:len(text)]
    order = sorted(range(len(text)), key=lambda i: (pattern[i], i))
    if not decrypt:
        return "".join(text[i] for i in order)
    out = [""] * len(text)
    for ch, i in zip(text, order):
        out[i] = ch
    return "".join(out)


def columnar(text: str, key: str, decrypt=False) -> str:
    """Столбцовая перестановка: текст пишется строками по len(key), столбцы читаются в порядке букв ключа."""
    n, L = len(key), len(text)
    order = sorted(range(n), key=lambda i: (key[i].lower(), i))
    if not decrypt:
        return "".join(text[c::n] for c in order)
    lens = [len(range(c, L, n)) for c in range(n)]
    cols, pos = [""] * n, 0
    for c in order:
        cols[c] = text[pos:pos + lens[c]]
        pos += lens[c]
    return "".join(cols[c][r] for r in range(max(lens) if lens else 0) for c in range(n) if r < lens[c])


# ------------------------------------------------------------------ криптоанализ
def frequencies(text: str, alphabet=None) -> dict:
    """Доли букв в тексте, по убыванию."""
    a = _alpha(text, alphabet)
    s = _letters(text, a)
    c = Counter(s)
    return {ch: c[ch] / len(s) for ch, _ in c.most_common()} if s else {}


def index_of_coincidence(text: str, alphabet=None) -> float:
    """Индекс совпадений Фридмана: вероятность, что две случайные буквы равны.
    Осмысленный текст: ru ≈ 0.055, en ≈ 0.066; случайный: 1/m (0.030 / 0.038)."""
    a = _alpha(text, alphabet)
    s = _letters(text, a)
    n = len(s)
    if n < 2:
        return 0.0
    return sum(v * (v - 1) for v in Counter(s).values()) / (n * (n - 1))


def chi_squared(text: str, alphabet=None) -> float:
    """Расстояние χ² от частот языка: чем меньше, тем больше похоже на осмысленный текст."""
    a = _alpha(text, alphabet)
    s = _letters(text, a)
    freq = FREQ.get(_lang(a))
    if not s or not freq:
        return float("inf")
    c = Counter(s)
    return sum((c[ch] - len(s) * p) ** 2 / (len(s) * p) for ch, p in freq.items())


def crack_caesar(text: str, alphabet=None):
    """Перебор всех сдвигов, лучший — по χ². -> (сдвиг, открытый текст)."""
    a = _alpha(text, alphabet)
    best = min(range(len(a)), key=lambda k: chi_squared(caesar(text, k, True, a), a))
    return best, caesar(text, best, True, a)


def crack_affine(text: str, alphabet=None):
    """Полный перебор ключей (a, b). -> ((a, b), открытый текст)."""
    al = _alpha(text, alphabet)
    m = len(al)
    keys = [(x, y) for x in range(1, m) if gcd(x, m) == 1 for y in range(m)]
    best = min(keys, key=lambda k: chi_squared(affine(text, *k, True, al), al))
    return best, affine(text, *best, True, al)


def kasiski(text: str, alphabet=None, size: int = 3, max_len: int = 20) -> list:
    """Тест Касиски: расстояния между повторами триграмм -> какие длины ключа их делят чаще всего.
    -> [(длина, число повторов, которые она делит), ...] по убыванию."""
    a = _alpha(text, alphabet)
    s = _letters(text, a)
    pos, dists = {}, []
    for i in range(len(s) - size + 1):
        g = s[i:i + size]
        if g in pos:
            dists.append(i - pos[g])
        pos[g] = i
    score = {L: sum(d % L == 0 for d in dists) for L in range(2, max_len + 1)}
    return sorted(score.items(), key=lambda kv: (-kv[1], kv[0]))


def vigenere_key_length(text: str, alphabet=None, max_len: int = 20) -> int:
    """Длина ключа Виженера по среднему индексу совпадений в столбцах (метод Фридмана)."""
    a = _alpha(text, alphabet)
    s = _letters(text, a)
    target = sum(p * p for p in FREQ.get(_lang(a), {}).values()) or 0.06
    scores = {}
    for L in range(1, min(max_len, max(1, len(s) // 4)) + 1):
        cols = [s[i::L] for i in range(L)]
        scores[L] = sum(index_of_coincidence(c, a) for c in cols) / L
    good = [L for L, v in scores.items() if v >= 0.85 * target]
    return min(good) if good else max(scores, key=scores.get)


def crack_vigenere(text: str, key_len: int = None, alphabet=None):
    """Взлом Виженера: длина ключа (Фридман), затем каждый столбец — как Цезарь по χ².
    -> (ключ, открытый текст)."""
    a = _alpha(text, alphabet)
    s = _letters(text, a)
    L = key_len or vigenere_key_length(text, a)
    key = "".join(a[crack_caesar(s[i::L], a)[0]] for i in range(L))
    return key, vigenere(text, key, True, a)
