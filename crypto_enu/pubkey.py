"""Асимметричная криптография: теория чисел, RSA, Диффи–Хеллман, Эль-Гамаль,
эллиптические кривые (ECDH, ECDSA, ГОСТ Р 34.10-2012), X25519.

    pub, priv = crypt.rsa_keygen(2048)
    ct = crypt.rsa_oaep_encrypt(b"secret", pub);  crypt.rsa_oaep_decrypt(ct, priv)
    d, Q = crypt.ec_keygen("p256");  r, s = crypt.ecdsa_sign(b"msg", d, "p256")
    crypt.gost_sign(b"msg", d, "gost_test")               # подпись ГОСТ на Стрибоге

Ключи — обычные int и кортежи, чтобы было видно математику. Сверено с пакетом `cryptography`
и контрольными примерами стандартов (RFC 7748, ГОСТ Р 34.10-2012 прил. А).
"""
import secrets
from typing import NamedTuple

from . import hashes as _h
from .padding import pad, unpad


# ================================================================== теория чисел
def egcd(a: int, b: int):
    """Расширенный алгоритм Евклида: (g, x, y), где a·x + b·y = g = НОД(a, b)."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, m: int) -> int:
    """Обратный элемент: a·x ≡ 1 (mod m)."""
    g, x, _ = egcd(a % m, m)
    if g != 1:
        raise ValueError(f"{a} необратимо по модулю {m}: НОД = {g}")
    return x % m


def crt(remainders, moduli) -> int:
    """Китайская теорема об остатках: x ≡ r_i (mod m_i), модули попарно взаимно просты."""
    x, m = 0, 1
    for r, mi in zip(remainders, moduli):
        x += (r - x) * modinv(m, mi) % mi * m
        m *= mi
    return x % m


_SMALL = [p for p in range(3, 1000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]


def is_prime(n: int, rounds: int = 40) -> bool:
    """Тест Миллера–Рабина: ошибка (составное назовём простым) не больше 4^-rounds."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    for p in [2] + _SMALL:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    """Случайное простое ровно из bits бит (два старших бита = 1, чтобы p·q имело 2·bits бит)."""
    while True:
        n = secrets.randbits(bits) | (0b11 << (bits - 2)) | 1
        if is_prime(n):
            return n


def isqrt_exact(n: int, k: int = 2):
    """Целый корень степени k, если n — точная степень, иначе None (нужно для атак на RSA)."""
    lo, hi = 0, 1 << (n.bit_length() // k + 1)
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** k < n:
            lo = mid + 1
        else:
            hi = mid
    return lo if lo ** k == n else None


def _i2b(x: int, n: int) -> bytes:
    return x.to_bytes(n, "big")


def _b2i(b: bytes) -> int:
    return int.from_bytes(b, "big")


# ================================================================== RSA (RFC 8017)
class RSAPublic(NamedTuple):
    n: int
    e: int

    @property
    def k(self):                     # длина модуля в байтах
        return (self.n.bit_length() + 7) // 8


class RSAPrivate(NamedTuple):
    n: int
    e: int
    d: int
    p: int
    q: int

    @property
    def k(self):
        return (self.n.bit_length() + 7) // 8

    @property
    def public(self):
        return RSAPublic(self.n, self.e)


def rsa_keygen(bits: int = 2048, e: int = 65537):
    """Генерация ключей: n = p·q, d = e⁻¹ mod λ(n), λ = НОК(p-1, q-1)."""
    while True:
        p, q = gen_prime(bits // 2), gen_prime(bits - bits // 2)
        lam = (p - 1) * (q - 1) // egcd(p - 1, q - 1)[0]
        if p != q and egcd(e, lam)[0] == 1:
            d = modinv(e, lam)
            return RSAPublic(p * q, e), RSAPrivate(p * q, e, d, p, q)


def rsa_encrypt_int(m: int, pub) -> int:
    """«Учебник» RSA: c = m^e mod n. Без паддинга небезопасен (детерминирован, гомоморфен)."""
    if not 0 <= m < pub.n:
        raise ValueError("m должно быть меньше n")
    return pow(m, pub.e, pub.n)


def rsa_decrypt_int(c: int, priv) -> int:
    """m = c^d mod n — через КТО (в ~4 раза быстрее): считаем по модулям p и q отдельно."""
    mp = pow(c, priv.d % (priv.p - 1), priv.p)
    mq = pow(c, priv.d % (priv.q - 1), priv.q)
    return crt([mp, mq], [priv.p, priv.q])


def rsa_pkcs1_encrypt(msg: bytes, pub) -> bytes:
    """RSAES-PKCS1-v1_5: 00 02 <случайные ненулевые> 00 M (паддинг "pkcs1_t2" из crypt.padding).
    Уязвим к атаке Блейхенбахера — в новых системах берут OAEP."""
    em = pad(bytes(msg), pub.k * 8, "pkcs1_t2")
    return _i2b(rsa_encrypt_int(_b2i(em), pub), pub.k)


def rsa_pkcs1_decrypt(ct: bytes, priv) -> bytes:
    return unpad(_i2b(rsa_decrypt_int(_b2i(ct), priv), priv.k), priv.k * 8, "pkcs1_t2")


def mgf1(seed: bytes, n: int, hash="sha256") -> bytes:
    """MGF1: растягивает seed хэшем со счётчиком до n байт."""
    h = _h._hash(hash)
    out, i = b"", 0
    while len(out) < n:
        out += h(seed + i.to_bytes(4, "big"))
        i += 1
    return out[:n]


def _xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def rsa_oaep_encrypt(msg: bytes, pub, label: bytes = b"", hash="sha256") -> bytes:
    """RSAES-OAEP: EM = 00 || maskedSeed || maskedDB, DB = lHash || 00..00 01 || M."""
    h = _h._hash(hash)
    hl, k = len(h(b"")), pub.k
    if len(msg) > k - 2 * hl - 2:
        raise ValueError(f"сообщение длиннее {k - 2 * hl - 2} байт")
    db = h(label) + bytes(k - len(msg) - 2 * hl - 2) + b"\x01" + bytes(msg)
    seed = secrets.token_bytes(hl)
    mdb = _xor(db, mgf1(seed, k - hl - 1, hash))
    em = b"\x00" + _xor(seed, mgf1(mdb, hl, hash)) + mdb
    return _i2b(rsa_encrypt_int(_b2i(em), pub), k)


def rsa_oaep_decrypt(ct: bytes, priv, label: bytes = b"", hash="sha256") -> bytes:
    h = _h._hash(hash)
    hl, k = len(h(b"")), priv.k
    em = _i2b(rsa_decrypt_int(_b2i(ct), priv), k)
    mseed, mdb = em[1:1 + hl], em[1 + hl:]
    db = _xor(mdb, mgf1(_xor(mseed, mgf1(mdb, hl, hash)), k - hl - 1, hash))
    rest = db[hl:].lstrip(b"\x00")
    if em[0] or db[:hl] != h(label) or not rest.startswith(b"\x01"):
        raise ValueError("ошибка расшифрования OAEP")
    return rest[1:]


# DigestInfo (ASN.1 DER) — префикс хэша в подписи PKCS#1 v1.5
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
}


def rsa_pkcs1_sign(msg: bytes, priv, hash="sha256") -> bytes:
    """RSASSA-PKCS1-v1_5: s = (00 01 FF..FF 00 || DigestInfo || H(m))^d mod n."""
    t = _DIGEST_INFO[hash] + _h._hash(hash)(bytes(msg))
    em = pad(t, priv.k * 8, "pkcs1_t1")
    return _i2b(rsa_decrypt_int(_b2i(em), priv), priv.k)


def rsa_pkcs1_verify(msg: bytes, sig: bytes, pub, hash="sha256") -> bool:
    t = _DIGEST_INFO[hash] + _h._hash(hash)(bytes(msg))
    em = _i2b(pow(_b2i(sig), pub.e, pub.n), pub.k)
    return em == pad(t, pub.k * 8, "pkcs1_t1")     # сравниваем ЦЕЛИКОМ, а не парсим (атака Блейхенбахера-2006)


def rsa_pss_sign(msg: bytes, priv, hash="sha256", salt_len: int = None) -> bytes:
    """RSASSA-PSS: вероятностная подпись, EM = maskedDB || H(00*8 || mHash || salt) || BC."""
    h = _h._hash(hash)
    hl = len(h(b""))
    embits = priv.n.bit_length() - 1
    emlen = (embits + 7) // 8
    salt = secrets.token_bytes(hl if salt_len is None else salt_len)
    hh = h(bytes(8) + h(bytes(msg)) + salt)
    db = bytes(emlen - len(salt) - hl - 2) + b"\x01" + salt
    mdb = bytearray(_xor(db, mgf1(hh, emlen - hl - 1, hash)))
    mdb[0] &= 0xFF >> (8 * emlen - embits)
    em = bytes(mdb) + hh + b"\xbc"
    return _i2b(rsa_decrypt_int(_b2i(em), priv), priv.k)


def rsa_pss_verify(msg: bytes, sig: bytes, pub, hash="sha256") -> bool:
    h = _h._hash(hash)
    hl = len(h(b""))
    embits = pub.n.bit_length() - 1
    emlen = (embits + 7) // 8
    m = pow(_b2i(sig), pub.e, pub.n)
    if m >> embits:
        return False
    em = _i2b(m, emlen)
    if em[-1] != 0xBC:
        return False
    mdb, hh = em[:emlen - hl - 1], em[emlen - hl - 1:-1]
    db = bytearray(_xor(mdb, mgf1(hh, emlen - hl - 1, hash)))
    db[0] &= 0xFF >> (8 * emlen - embits)
    rest = bytes(db).lstrip(b"\x00")
    if not rest.startswith(b"\x01"):
        return False
    return h(bytes(8) + h(bytes(msg)) + rest[1:]) == hh


# ------------------------------------------------------------------ атаки на «учебник» RSA
def rsa_small_e_attack(c: int, e: int = 3):
    """Если m^e < n (маленькое m, e = 3, без паддинга), то c = m^e без модуля: m = ∛c."""
    return isqrt_exact(c, e)


def rsa_hastad(cts, moduli, e: int = 3):
    """Атака Хостада: одно m, зашифрованное e получателям: по КТО собираем m^e, берём корень."""
    return isqrt_exact(crt(cts, moduli), e)


def rsa_common_modulus(c1: int, c2: int, e1: int, e2: int, n: int) -> int:
    """Общий модуль: одно m под (n, e1) и (n, e2), НОД(e1, e2) = 1 ⇒ m = c1^a · c2^b."""
    g, a, b = egcd(e1, e2)
    if g != 1:
        raise ValueError("нужно НОД(e1, e2) = 1")
    return pow(c1, a, n) * pow(c2, b, n) % n


def rsa_wiener(e: int, n: int):
    """Атака Винера: если d < n^¼ / 3, d — знаменатель одной из подходящих дробей e/n."""
    a, b = e, n
    h0, h1, k0, k1 = 0, 1, 1, 0          # подходящие дроби k/d
    while b:
        q, a, b = a // b, b, a % b
        h0, h1 = h1, q * h1 + h0
        k0, k1 = k1, q * k1 + k0
        k, d = h1, k1
        if k and (e * d - 1) % k == 0:
            phi = (e * d - 1) // k
            s = n - phi + 1                  # p + q
            disc = s * s - 4 * n
            if disc >= 0 and isqrt_exact(disc) is not None:
                return d
    return None


# ================================================================== Диффи–Хеллман и Эль-Гамаль
def _pi_bits(nbits: int) -> int:
    """⌊π · 2^nbits⌋ формулой Мэчина — из π построены группы RFC 2409/3526 («ничего в рукаве»)."""
    guard = 64
    one = 1 << (nbits + guard)

    def atan_inv(x):
        s, term, k, sign = 0, one // x, 1, 1
        while term:
            s += sign * (term // k)
            term //= x * x
            k += 2
            sign = -sign
        return s
    return (4 * (4 * atan_inv(5) - atan_inv(239))) >> guard


def modp_group(bits: int = 2048):
    """MODP-группа RFC 3526: p = 2^b - 2^(b-64) - 1 + 2^64·(⌊2^(b-130)·π⌋ + c), g = 2.
    p — безопасное простое (p = 2q + 1, q простое)."""
    c = {1536: 741804, 2048: 124476, 3072: 1690314, 4096: 240904}[bits]
    p = (1 << bits) - (1 << (bits - 64)) - 1 + (1 << 64) * (_pi_bits(bits - 130) + c)
    return p, 2


def dh_keygen(p: int, g: int):
    """Секрет a, публичное A = g^a mod p."""
    a = secrets.randbelow(p - 3) + 2
    return a, pow(g, a, p)


def dh_shared(their_public: int, my_secret: int, p: int) -> int:
    """Общий секрет g^(ab): каждый возводит чужой публичный ключ в свою степень."""
    if not 1 < their_public < p - 1:
        raise ValueError("плохой публичный ключ (1, p-1 или вне группы)")
    return pow(their_public, my_secret, p)


def elgamal_encrypt(m: int, y: int, p: int, g: int):
    """Эль-Гамаль: (g^k, m·y^k) — y = g^x публичный ключ, k случайный на каждое сообщение."""
    k = secrets.randbelow(p - 3) + 2
    return pow(g, k, p), m * pow(y, k, p) % p


def elgamal_decrypt(c, x: int, p: int) -> int:
    a, b = c
    return b * pow(a, p - 1 - x, p) % p                # a^(-x) по малой теореме Ферма


# ================================================================== эллиптические кривые
class Curve(NamedTuple):
    """y² = x³ + a·x + b над GF(p), G = (gx, gy) порядка n."""
    name: str
    p: int
    a: int
    b: int
    gx: int
    gy: int
    n: int

    @property
    def G(self):
        return (self.gx, self.gy)


CURVES = {
    "p256": Curve("NIST P-256 (secp256r1)",
                  0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                  -3 % 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
                  0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
                  0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
                  0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
                  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551),
    "secp256k1": Curve("secp256k1 (Bitcoin, Ethereum)",
                       (1 << 256) - (1 << 32) - 977, 0, 7,
                       0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8,
                       0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141),
    "gost_test": Curve("ГОСТ Р 34.10-2012, контрольный пример (прил. А.1)",
                       0x8000000000000000000000000000000000000000000000000000000000000431, 7,
                       0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E,
                       2, 0x08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8,
                       0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3),
}


def _curve(c):
    if isinstance(c, Curve):
        return c
    if c not in CURVES:
        raise ValueError(f"неизвестная кривая {c!r}, есть: {', '.join(CURVES)}")
    return CURVES[c]


def ec_on_curve(P, curve) -> bool:
    c = _curve(curve)
    if P is None:
        return True
    x, y = P
    return (y * y - x ** 3 - c.a * x - c.b) % c.p == 0


def ec_add(P, Q, curve):
    """Сложение точек (None — бесконечно удалённая точка, «ноль» группы)."""
    c = _curve(curve)
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % c.p == 0:
        return None                                              # P + (-P) = O
    if P == Q:
        lam = (3 * x1 * x1 + c.a) * modinv(2 * y1, c.p) % c.p    # касательная
    else:
        lam = (y2 - y1) * modinv(x2 - x1, c.p) % c.p             # секущая
    x3 = (lam * lam - x1 - x2) % c.p
    return x3, (lam * (x1 - x3) - y1) % c.p


def ec_mul(k: int, P, curve):
    """k·P методом «удвоение-сложение» по битам k (лестница не нужна — защиты по времени тут нет)."""
    c = _curve(curve)
    R = None
    for bit in bin(k % c.n)[2:]:
        R = ec_add(R, R, c)
        if bit == "1":
            R = ec_add(R, P, c)
    return R


def ec_keygen(curve="p256"):
    """Закрытый ключ d ∈ [1, n-1], открытый Q = d·G."""
    c = _curve(curve)
    d = secrets.randbelow(c.n - 1) + 1
    return d, ec_mul(d, c.G, c)


def ecdh(d: int, Q, curve="p256") -> bytes:
    """ECDH: общий секрет — x-координата d·Q (у обеих сторон d_A·d_B·G)."""
    c = _curve(curve)
    if not ec_on_curve(Q, c) or Q is None:
        raise ValueError("точка не на кривой — атака invalid curve")
    return ec_mul(d, Q, c)[0].to_bytes((c.p.bit_length() + 7) // 8, "big")


def _ecdsa_e(msg, c, hash):
    h = _h._hash(hash)(bytes(msg))
    e = int.from_bytes(h, "big")
    return e >> max(0, len(h) * 8 - c.n.bit_length())        # берём левые bits(n) бит хэша


def ecdsa_sign(msg: bytes, d: int, curve="p256", hash="sha256", k: int = None):
    """ECDSA: r = (k·G).x mod n, s = k⁻¹(e + r·d) mod n. Повтор k ⇒ утечка ключа (PS3, 2010)."""
    c = _curve(curve)
    e = _ecdsa_e(msg, c, hash)
    while True:
        kk = k or secrets.randbelow(c.n - 1) + 1
        r = ec_mul(kk, c.G, c)[0] % c.n
        s = modinv(kk, c.n) * (e + r * d) % c.n
        if r and s:
            return r, s


def ecdsa_verify(msg: bytes, sig, Q, curve="p256", hash="sha256") -> bool:
    c = _curve(curve)
    r, s = sig
    if not (0 < r < c.n and 0 < s < c.n):
        return False
    w = modinv(s, c.n)
    e = _ecdsa_e(msg, c, hash)
    X = ec_add(ec_mul(e * w, c.G, c), ec_mul(r * w, Q, c), c)
    return X is not None and X[0] % c.n == r


def ecdsa_recover_key(msg1, sig1, msg2, sig2, curve="p256", hash="sha256") -> int:
    """Две подписи с одинаковым k (одинаковое r): k = (e1-e2)/(s1-s2), d = (s·k - e)/r."""
    c = _curve(curve)
    (r, s1), (_, s2) = sig1, sig2
    e1, e2 = _ecdsa_e(msg1, c, hash), _ecdsa_e(msg2, c, hash)
    k = (e1 - e2) * modinv(s1 - s2, c.n) % c.n
    return (s1 * k - e1) * modinv(r, c.n) % c.n


# ------------------------------------------------------------------ ГОСТ Р 34.10-2012
def gost_digest_int(msg: bytes, curve="gost_test") -> int:
    """e = α mod q, α — число, двоичная запись которого — хэш Стрибога (у нас байты little-endian)."""
    c = _curve(curve)
    bits = 256 if c.n.bit_length() <= 256 else 512
    e = int.from_bytes(_h.streebog(bytes(msg), bits), "little") % c.n
    return e or 1


def gost_sign_digest(e: int, d: int, curve="gost_test", k: int = None):
    """Подпись ГОСТ по готовому e: r = (k·P).x mod q, s = (r·d + k·e) mod q."""
    c = _curve(curve)
    e = e % c.n or 1
    while True:
        kk = k or secrets.randbelow(c.n - 1) + 1
        r = ec_mul(kk, c.G, c)[0] % c.n
        s = (r * d + kk * e) % c.n
        if r and s:
            return r, s


def gost_verify_digest(e: int, sig, Q, curve="gost_test") -> bool:
    c = _curve(curve)
    r, s = sig
    if not (0 < r < c.n and 0 < s < c.n):
        return False
    v = modinv(e % c.n or 1, c.n)
    z1, z2 = s * v % c.n, -r * v % c.n
    C = ec_add(ec_mul(z1, c.G, c), ec_mul(z2, Q, c), c)
    return C is not None and C[0] % c.n == r


def gost_sign(msg: bytes, d: int, curve="gost_test", k: int = None):
    """Подпись ГОСТ Р 34.10-2012 с хэшем ГОСТ Р 34.11-2012 (Стрибог)."""
    return gost_sign_digest(gost_digest_int(msg, curve), d, curve, k)


def gost_verify(msg: bytes, sig, Q, curve="gost_test") -> bool:
    return gost_verify_digest(gost_digest_int(msg, curve), sig, Q, curve)


# ================================================================== X25519 (RFC 7748)
P25519 = (1 << 255) - 19


def x25519(k: bytes, u: bytes = None) -> bytes:
    """Скалярное умножение на кривой Монтгомери Curve25519 лестницей Монтгомери.
    u=None — базовая точка 9 (получаем открытый ключ). Так договариваются о ключе TLS 1.3, SSH, Signal."""
    kb = bytearray(k)
    kb[0] &= 248
    kb[31] &= 127
    kb[31] |= 64                                          # «зажим» скаляра
    k_int = int.from_bytes(kb, "little")
    u_int = 9 if u is None else int.from_bytes(u, "little") & ((1 << 255) - 1)
    p, a24 = P25519, 121665
    x1, x2, z2, x3, z3, swap = u_int, 1, 0, u_int, 1, 0
    for t in reversed(range(255)):
        bit = (k_int >> t) & 1
        swap ^= bit
        if swap:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = (x2 + z2) % p, (x2 - z2) % p
        aa, bb = a * a % p, b * b % p
        e = (aa - bb) % p
        c, d = (x3 + z3) % p, (x3 - z3) % p
        da, cb = d * a % p, c * b % p
        x3, z3 = (da + cb) ** 2 % p, x1 * (da - cb) ** 2 % p
        x2, z2 = aa * bb % p, e * (aa + a24 * e) % p
    if swap:
        x2, z2 = x3, z3
    return (x2 * pow(z2, p - 2, p) % p).to_bytes(32, "little")
