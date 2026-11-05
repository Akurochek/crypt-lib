"""Хэш-функции «с нуля» поверх дополнения из crypt/padding.py (схемы "sha2" и "md5"),
плюс HMAC и PBKDF2. Сверяются с hashlib в тестах.

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


def _frac(x, root):
    """Первые 32 бита дробной части корня — так в FIPS 180-4 заданы константы SHA-256."""
    lo, hi = 0, 1 << 64
    while hi - lo > 1:                          # целочисленный корень из x * 2^(32*root)
        mid = (lo + hi) // 2
        if mid ** root <= x << (32 * root):
            lo = mid
        else:
            hi = mid
    return lo & M32


_P = _primes(64)
SHA256_K = [_frac(p, 3) for p in _P]
SHA256_H = [_frac(p, 2) for p in _P[:8]]
MD5_K = [int(abs(math.sin(i + 1)) * 2 ** 32) & M32 for i in range(64)]
MD5_S = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4


def sha256(data: bytes) -> bytes:
    """SHA-256 (FIPS 180-4): Меркл–Дамгор, блок 512 бит, 64 раунда."""
    m = pad(bytes(data), 512, "sha2")
    h = SHA256_H[:]
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
    return struct.pack(">8I", *h)


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


HASHES = {"sha256": sha256, "sha1": sha1, "md5": md5}


def _hash(name):
    if callable(name):
        return name
    if name not in HASHES:
        raise ValueError(f"неизвестный хэш {name!r}, есть: {', '.join(HASHES)}")
    return HASHES[name]


def hmac(key: bytes, msg: bytes, hash="sha256", block_size: int = 64) -> bytes:
    """HMAC (RFC 2104): H((K ^ opad) || H((K ^ ipad) || m)). hash — имя или своя функция."""
    h = _hash(hash)
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
