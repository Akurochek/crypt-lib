"""Хэш-функции «с нуля» поверх дополнения из crypt/padding.py (схемы "sha2" и "md5"),
SHA-2 (224/256/384/512, 512/t), SHA-3/SHAKE/Keccak (губка), Стрибог (ГОСТ Р 34.11-2012),
плюс HMAC, PBKDF2 и HKDF. Сверяются с hashlib и векторами стандартов в тестах.

    crypt.sha256(b"abc").hex()
    crypt.hmac(b"key", b"msg")                 # HMAC-SHA256
    crypt.pbkdf2(b"password", b"salt", 1000)   # 32 байта ключа
"""
import math
import struct

from .padding import pad

M32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & M32


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & M32


def _primes(n):
    out, k = [], 2
    while len(out) < n:
        if all(k % p for p in out if p * p <= k):
            out.append(k)
        k += 1
    return out


def _frac(x, root, bits=32):
    """Первые bits бит дробной части корня — так в FIPS 180-4 заданы константы SHA-2."""
    lo, hi = 0, 1 << (2 * bits)
    while hi - lo > 1:                          # целочисленный корень из x * 2^(bits*root)
        mid = (lo + hi) // 2
        if mid ** root <= x << (bits * root):
            lo = mid
        else:
            hi = mid
    return lo & ((1 << bits) - 1)


_P = _primes(64)
SHA256_K = [_frac(p, 3) for p in _P]
SHA256_H = [_frac(p, 2) for p in _P[:8]]
SHA224_H = [_frac(p, 2, 64) & M32 for p in _P[8:16]]      # младшие 32 бита начальных SHA-384
MD5_K = [int(abs(math.sin(i + 1)) * 2 ** 32) & M32 for i in range(64)]
MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4


def _sha256(data, h0, n):
    m = pad(bytes(data), 512, "sha2")
    h = h0[:]
    for off in range(0, len(m), 64):
        w = list(struct.unpack(">16I", m[off:off + 64]))
        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
        a, b, c, d, e, f, g, hh = h
        for i in range(64):
            t1 = (hh + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)) + ((e & f) ^ (~e & g))
                  + SHA256_K[i] + w[i]) & M32
            t2 = ((_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) & M32
            a, b, c, d, e, f, g, hh = (t1 + t2) & M32, a, b, c, (d + t1) & M32, e, f, g
        h = [(x + y) & M32 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return struct.pack(">8I", *h)[:n]


def sha256(data: bytes) -> bytes:
    """SHA-256 (FIPS 180-4): Меркл–Дамгор, блок 512 бит, 64 раунда."""
    return _sha256(data, SHA256_H, 32)


def sha224(data: bytes) -> bytes:
    """SHA-224: тот же SHA-256 с другими начальными значениями, выход обрезан до 224 бит."""
    return _sha256(data, SHA224_H, 28)


def sha1(data: bytes) -> bytes:
    """SHA-1 (FIPS 180-4). Коллизии найдены (SHAttered, 2017) — только для учёбы/совместимости."""
    m = pad(bytes(data), 512, "sha2")
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for off in range(0, len(m), 64):
        w = list(struct.unpack(">16I", m[off:off + 64]))
        for i in range(16, 80):
            w.append(_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h
        for i in range(80):
            if i < 20:
                f, k = (b & c) | (~b & d), 0x5A827999
            elif i < 40:
                f, k = b ^ c ^ d, 0x6ED9EBA1
            elif i < 60:
                f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
            else:
                f, k = b ^ c ^ d, 0xCA62C1D6
            a, b, c, d, e = (_rotl(a, 5) + f + e + k + w[i]) & M32, a, _rotl(b, 30), c, d
        h = [(x + y) & M32 for x, y in zip(h, (a, b, c, d, e))]
    return struct.pack(">5I", *h)


def md5(data: bytes) -> bytes:
    """MD5 (RFC 1321): слова и длина little-endian. Сломан (коллизии за секунды) — только для учёбы."""
    m = pad(bytes(data), 512, "md5")
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]
    for off in range(0, len(m), 64):
        x = struct.unpack("<16I", m[off:off + 64])
        a, b, c, d = h
        for i in range(64):
            if i < 16:
                f, g = (b & c) | (~b & d), i
            elif i < 32:
                f, g = (d & b) | (~d & c), (5 * i + 1) % 16
            elif i < 48:
                f, g = b ^ c ^ d, (3 * i + 5) % 16
            else:
                f, g = c ^ (b | ~d & M32), 7 * i % 16
            f = (f + a + MD5_K[i] + x[g]) & M32
            a, d, c, b = d, c, b, (b + _rotl(f, MD5_S[i])) & M32
        h = [(p + q) & M32 for p, q in zip(h, (a, b, c, d))]
    return struct.pack("<4I", *h)


# ---------------------------------------------------------------- SHA-512 / 384 / 512-t
M64 = (1 << 64) - 1
_P80 = _primes(80)
SHA512_K = [_frac(p, 3, 64) for p in _P80]
SHA512_H = [_frac(p, 2, 64) for p in _P80[:8]]
SHA384_H = [_frac(p, 2, 64) for p in _P80[8:16]]


def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & M64


def _sha512(data, h0, n):
    m = pad(bytes(data), 1024, "sha2")             # блок 1024 бита, длина — 128 бит
    h = h0[:]
    for off in range(0, len(m), 128):
        w = list(struct.unpack(">16Q", m[off:off + 128]))
        for i in range(16, 80):
            s0 = _rotr64(w[i - 15], 1) ^ _rotr64(w[i - 15], 8) ^ (w[i - 15] >> 7)
            s1 = _rotr64(w[i - 2], 19) ^ _rotr64(w[i - 2], 61) ^ (w[i - 2] >> 6)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & M64)
        a, b, c, d, e, f, g, hh = h
        for i in range(80):
            t1 = (hh + (_rotr64(e, 14) ^ _rotr64(e, 18) ^ _rotr64(e, 41)) + ((e & f) ^ (~e & g))
                  + SHA512_K[i] + w[i]) & M64
            t2 = ((_rotr64(a, 28) ^ _rotr64(a, 34) ^ _rotr64(a, 39)) + ((a & b) ^ (a & c) ^ (b & c))) & M64
            a, b, c, d, e, f, g, hh = (t1 + t2) & M64, a, b, c, (d + t1) & M64, e, f, g
        h = [(x + y) & M64 for x, y in zip(h, (a, b, c, d, e, f, g, hh))]
    return struct.pack(">8Q", *h)[:n]


def sha512(data: bytes) -> bytes:
    """SHA-512 (FIPS 180-4): 64-битные слова, блок 1024 бита, 80 раундов."""
    return _sha512(data, SHA512_H, 64)


def sha384(data: bytes) -> bytes:
    """SHA-384: SHA-512 с другими начальными значениями, выход 384 бита."""
    return _sha512(data, SHA384_H, 48)


def _sha512t_iv(t):
    """FIPS 180-4 п. 5.3.6: IV для SHA-512/t = SHA-512 с IV ^ a5a5... от строки "SHA-512/t"."""
    iv = [x ^ 0xA5A5A5A5A5A5A5A5 for x in SHA512_H]
    return list(struct.unpack(">8Q", _sha512(f"SHA-512/{t}".encode(), iv, 64)))


SHA512_256_H = _sha512t_iv(256)
SHA512_224_H = _sha512t_iv(224)


def sha512_256(data: bytes) -> bytes:
    """SHA-512/256: быстрее SHA-256 на 64-битных машинах и не уязвим к удлинению сообщения."""
    return _sha512(data, SHA512_256_H, 32)


def sha512_224(data: bytes) -> bytes:
    return _sha512(data, SHA512_224_H, 28)


# ---------------------------------------------------------------- SHA-3 (Keccak)
def _keccak_constants():
    """Сдвиги ρ и константы ι вычисляются, как описано в FIPS 202 (алгоритмы 2 и 5)."""
    rot = [[0] * 5 for _ in range(5)]
    x, y = 1, 0
    for t in range(24):
        rot[x][y] = (t + 1) * (t + 2) // 2 % 64
        x, y = y, (2 * x + 3 * y) % 5
    r, rc = 1, []
    for _ in range(24):
        c = 0
        for j in range(7):
            if r & 1:
                c |= 1 << ((1 << j) - 1)
            r = (r << 1) ^ (0x171 if r & 0x80 else 0)     # LFSR x^8 + x^6 + x^5 + x^4 + 1
        rc.append(c)
    return rot, rc


KECCAK_ROT, KECCAK_RC = _keccak_constants()


def _rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def keccak_f(a):
    """Перестановка Keccak-f[1600]: состояние 5×5 слов по 64 бита, a[x][y]; 24 раунда θ ρ π χ ι."""
    for rc in KECCAK_RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rotl64(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]                     # θ
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = _rotl64(a[x][y], KECCAK_ROT[x][y])          # ρ и π
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)]
             for x in range(5)]                                                        # χ
        a[0][0] ^= rc                                                                  # ι
    return a


def keccak_sponge(data: bytes, rate_bits: int, out_len: int, scheme: str = "sha3") -> bytes:
    """Губка: впитываем блоки по rate бит (паддинг из crypt/padding.py), потом выжимаем out_len байт."""
    r = rate_bits // 8
    m = pad(bytes(data), rate_bits, scheme)
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(m), r):
        blk = m[off:off + r] + bytes(200 - r)
        for i in range(25):
            a[i % 5][i // 5] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        a = keccak_f(a)
    out = b""
    while True:
        out += b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(25))[:r]
        if len(out) >= out_len:
            return out[:out_len]
        a = keccak_f(a)


def sha3_224(data: bytes) -> bytes:
    return keccak_sponge(data, 1152, 28)


def sha3_256(data: bytes) -> bytes:
    """SHA3-256 (FIPS 202): губка Keccak, rate = 1600 - 2·256 = 1088 бит."""
    return keccak_sponge(data, 1088, 32)


def sha3_384(data: bytes) -> bytes:
    return keccak_sponge(data, 832, 48)


def sha3_512(data: bytes) -> bytes:
    return keccak_sponge(data, 576, 64)


def shake128(data: bytes, n: int = 16) -> bytes:
    """SHAKE128: XOF — выход любой длины n байт."""
    return keccak_sponge(data, 1344, n, "shake")


def shake256(data: bytes, n: int = 32) -> bytes:
    return keccak_sponge(data, 1088, n, "shake")


def keccak256(data: bytes) -> bytes:
    """Исходный Keccak-256 (до стандартизации, другой паддинг) — так считает Ethereum."""
    return keccak_sponge(data, 1088, 32, "keccak")


# ---------------------------------------------------------------- Стрибог (ГОСТ Р 34.11-2012)
# Числа — 512-битные int, байты сообщения little-endian (как в эталонных реализациях:
# в стандарте векторы записаны от старшего байта к младшему, т. е. перевёрнуты).
STREEBOG_A = [  # матрица линейного преобразования l, строки от старшего бита к младшему
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
]
STREEBOG_C = [  # итерационные константы C1..C12
    0xb1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507,
    0x6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7,
    0xf574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2,
    0xef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e,
    0x4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57,
    0xae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e,
    0xf4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493,
    0x9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e,
    0x378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb,
    0xabbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced,
    0x7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b,
    0x378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720,
]
M512 = (1 << 512) - 1


def _streebog_tables():
    from .sbox import KUZNYECHIK as pi                  # π — та же подстановка, что в «Кузнечике»
    col = STREEBOG_A[::-1]                               # col[j] — вклад бита j слова

    def l(w):
        r = 0
        for j in range(64):
            if w >> j & 1:
                r ^= col[j]
        return r
    # S, P (транспонирование байтов 8×8) и L сразу: байт b на позиции k слова i -> T[k][b] в слове i
    return [[l(pi[b] << (8 * k)) for b in range(256)] for k in range(8)]


_LPS = None


def _lpsx(a, b):
    global _LPS
    if _LPS is None:
        _LPS = _streebog_tables()
    x = a ^ b
    w = [(x >> (64 * k)) & M64 for k in range(8)]
    out = 0
    for i in range(8):
        v = 0
        for k in range(8):
            v ^= _LPS[k][(w[k] >> (8 * i)) & 0xFF]
        out |= v << (64 * i)
    return out


def _g(n, h, m):
    k = _lpsx(h, n)
    s = _lpsx(k, m)                                    # E(K, m): 12 раундов X, S, P, L
    for i in range(11):
        k = _lpsx(k, STREEBOG_C[i])
        s = _lpsx(k, s)
    k = _lpsx(k, STREEBOG_C[11])
    return s ^ k ^ h ^ m


def streebog(data: bytes, bits: int = 512) -> bytes:
    """Стрибог (ГОСТ Р 34.11-2012), bits = 512 или 256. Сжатие g_N(h, m) = E(LPS(h⊕N), m) ⊕ h ⊕ m."""
    if bits not in (256, 512):
        raise ValueError("Стрибог бывает 256 или 512 бит")
    data = bytes(data)
    h = 0 if bits == 512 else int.from_bytes(b"\x01" * 64, "little")
    n = sigma = 0
    full = len(data) // 64 * 64
    for off in range(0, full, 64):
        m = int.from_bytes(data[off:off + 64], "little")
        h = _g(n, h, m)
        n = (n + 512) & M512
        sigma = (sigma + m) & M512
    tail = data[full:]
    m = int.from_bytes(tail + b"\x01" + bytes(63 - len(tail)), "little")   # дописываем 0..01
    h = _g(n, h, m)
    n = (n + 8 * len(tail)) & M512
    sigma = (sigma + m) & M512
    h = _g(0, h, n)
    h = _g(0, h, sigma)
    out = h.to_bytes(64, "little")
    return out if bits == 512 else out[32:]


def streebog256(data: bytes) -> bytes:
    return streebog(data, 256)


def streebog512(data: bytes) -> bytes:
    return streebog(data, 512)


HASHES = {"sha256": sha256, "sha224": sha224, "sha1": sha1, "md5": md5,
          "sha512": sha512, "sha384": sha384, "sha512_256": sha512_256, "sha512_224": sha512_224,
          "sha3_224": sha3_224, "sha3_256": sha3_256, "sha3_384": sha3_384, "sha3_512": sha3_512,
          "keccak256": keccak256, "streebog256": streebog256, "streebog512": streebog512}
# размер блока в байтах — нужен HMAC
BLOCK = {"sha256": 64, "sha224": 64, "sha1": 64, "md5": 64, "sha512": 128, "sha384": 128,
         "sha512_256": 128, "sha512_224": 128, "sha3_224": 144, "sha3_256": 136, "sha3_384": 104,
         "sha3_512": 72, "keccak256": 136, "streebog256": 64, "streebog512": 64}


def _hash(name):
    if callable(name):
        return name
    if name not in HASHES:
        raise ValueError(f"неизвестный хэш {name!r}, есть: {', '.join(HASHES)}")
    return HASHES[name]


def hmac(key: bytes, msg: bytes, hash="sha256", block_size: int = None) -> bytes:
    """HMAC (RFC 2104): H((K ^ opad) || H((K ^ ipad) || m)). hash — имя или своя функция.
    С "streebog256"/"streebog512" это HMAC_GOSTR3411_2012 (Р 50.1.113-2016)."""
    h = _hash(hash)
    if block_size is None:
        block_size = BLOCK.get(hash, 64) if isinstance(hash, str) else 64
    key = bytes(key)
    if len(key) > block_size:
        key = h(key)
    key += bytes(block_size - len(key))
    return h(bytes(b ^ 0x5C for b in key) + h(bytes(b ^ 0x36 for b in key) + bytes(msg)))


def pbkdf2(password: bytes, salt: bytes, iterations: int = 1000, dklen: int = 32, hash="sha256") -> bytes:
    """PBKDF2 (RFC 8018) с HMAC: выработка ключа из пароля. Чем больше iterations, тем дороже перебор."""
    out, i = b"", 1
    while len(out) < dklen:
        u = hmac(password, bytes(salt) + i.to_bytes(4, "big"), hash)
        t = int.from_bytes(u, "big")
        for _ in range(iterations - 1):
            u = hmac(password, u, hash)
            t ^= int.from_bytes(u, "big")
        out += t.to_bytes(len(u), "big")
        i += 1
    return out[:dklen]


def hkdf(ikm: bytes, length: int = 32, salt: bytes = b"", info: bytes = b"", hash="sha256") -> bytes:
    """HKDF (RFC 5869): extract (PRK = HMAC(salt, ikm)), затем expand (T(i) = HMAC(PRK, T(i-1)||info||i)).
    Так в TLS 1.3 и Signal из общего секрета DH получают ключи."""
    hlen = len(_hash(hash)(b""))
    prk = hmac(salt or bytes(hlen), ikm, hash)
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac(prk, t + bytes(info) + bytes([i]), hash)
        out += t
        i += 1
    return out[:length]
