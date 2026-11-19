"""Режимы работы блочных шифров (NIST SP 800-38A/B/D, ГОСТ Р 34.13-2015).

Низкий уровень — шифр-объект + данные:
    c = crypt.cipher("aes", key)
    ct = crypt.cbc_encrypt(c, data, iv)          # данные уже кратны блоку
    pt = crypt.cbc_decrypt(c, ct, iv)

Высокий уровень — сам дополнит (padding из crypt/padding.py), сгенерирует IV и допишет его в начало:
    ct = crypt.encrypt(b"secret", key, "kuznyechik", "cbc")
    crypt.decrypt(ct, key, "kuznyechik", "cbc")  # -> b"secret"

Режимы: ecb, cbc, pcbc, cfb, ofb, ctr (шифрование), cmac, cbc_mac (имитовставка),
gcm (шифрование + аутентификация, только для блока 128 бит).
CTR, OFB, CFB, GCM — потоковые: дополнение не нужно, длина шифртекста = длине открытого текста.
"""
import hmac as _hmac
import os

from .bits import to_bits, from_bits, is_bitstr
from .ciphers import cipher as _cipher, BlockCipher
from .padding import pad as _pad, unpad as _unpad

MODES = {
    "ecb":  "Electronic Codebook — каждый блок отдельно (ГОСТ: режим простой замены). Видны повторы!",
    "cbc":  "Cipher Block Chaining — XOR с предыдущим шифроблоком (ГОСТ: простая замена с зацеплением)",
    "pcbc": "Propagating CBC — XOR с предыдущими открытым и шифроблоком (Kerberos v4)",
    "cfb":  "Cipher Feedback — шифруется предыдущий шифртекст (ГОСТ: гаммирование с обратной связью по шифртексту)",
    "ofb":  "Output Feedback — гамма из повторного шифрования IV (ГОСТ: гаммирование с обратной связью по выходу)",
    "ctr":  "Counter — гамма = E(счётчик) (ГОСТ: гаммирование; IV на полблока, вторая половина — счётчик)",
    "gcm":  "Galois/Counter Mode — CTR + имитовставка GHASH (AEAD, только блок 128 бит)",
}


def _x(a: bytes, b: bytes) -> bytes:
    return bytes(i ^ j for i, j in zip(a, b))


def _split(c: BlockCipher, data: bytes, what="данные"):
    n = c.block_size
    if len(data) % n:
        raise ValueError(f"{what}: {len(data)} байт не кратно блоку {n} байт — нужен padding")
    return [data[i:i + n] for i in range(0, len(data), n)]


def _iv(c: BlockCipher, iv: bytes):
    if len(iv) != c.block_size:
        raise ValueError(f"IV должен быть {c.block_size} байт (размер блока), а не {len(iv)}")
    return bytes(iv)


# ------------------------------------------------------------------ ECB / CBC / PCBC
def ecb_encrypt(c, data):
    return b"".join(c.encrypt_block(b) for b in _split(c, data))


def ecb_decrypt(c, data):
    return b"".join(c.decrypt_block(b) for b in _split(c, data))


def cbc_encrypt(c, data, iv):
    prev, out = _iv(c, iv), []
    for b in _split(c, data):
        prev = c.encrypt_block(_x(b, prev))
        out.append(prev)
    return b"".join(out)


def cbc_decrypt(c, data, iv):
    prev, out = _iv(c, iv), []
    for b in _split(c, data):
        out.append(_x(c.decrypt_block(b), prev))
        prev = b
    return b"".join(out)


def pcbc_encrypt(c, data, iv):
    v, out = _iv(c, iv), []
    for b in _split(c, data):
        e = c.encrypt_block(_x(b, v))
        out.append(e)
        v = _x(b, e)
    return b"".join(out)


def pcbc_decrypt(c, data, iv):
    v, out = _iv(c, iv), []
    for b in _split(c, data):
        p = _x(c.decrypt_block(b), v)
        out.append(p)
        v = _x(p, b)
    return b"".join(out)


# ------------------------------------------------------------------ CFB / OFB / CTR
def _cfb(c, data, iv, segment, decrypt):
    reg = _iv(c, iv)
    s = segment or c.block_size
    if not 1 <= s <= c.block_size:
        raise ValueError(f"сегмент CFB — от 1 до {c.block_size} байт")
    out = []
    for i in range(0, len(data), s):
        chunk = data[i:i + s]
        o = _x(chunk, c.encrypt_block(reg))
        out.append(o)
        reg = (reg + (chunk if decrypt else o))[-c.block_size:]
    return b"".join(out)


def cfb_encrypt(c, data, iv, segment=None):
    """segment — размер сегмента в байтах: None = весь блок (CFB-128 для AES), 1 = CFB-8."""
    return _cfb(c, data, iv, segment, False)


def cfb_decrypt(c, data, iv, segment=None):
    return _cfb(c, data, iv, segment, True)


def ofb(c, data, iv):
    """OFB: шифрование и расшифрование — одна и та же операция."""
    o, out = _iv(c, iv), []
    for i in range(0, len(data), c.block_size):
        o = c.encrypt_block(o)
        out.append(_x(data[i:i + c.block_size], o))
    return b"".join(out)


def ctr(c, data, nonce):
    """CTR: счётчик = nonce, дополненный нулями справа до блока, и +1 на каждый блок.
    NIST: nonce на весь блок. ГОСТ Р 34.13: IV на полблока (8 байт для «Кузнечика», 4 для «Магмы»).
    Шифрование и расшифрование — одна операция."""
    n = c.block_size
    if not 1 <= len(nonce) <= n:
        raise ValueError(f"nonce CTR — от 1 до {n} байт")
    ctr_ = int.from_bytes(bytes(nonce) + bytes(n - len(nonce)), "big")
    out = []
    for i in range(0, len(data), n):
        out.append(_x(data[i:i + n], c.encrypt_block(ctr_.to_bytes(n, "big"))))
        ctr_ = (ctr_ + 1) % (1 << 8 * n)
    return b"".join(out)


ofb_encrypt = ofb_decrypt = ofb
ctr_encrypt = ctr_decrypt = ctr


# ------------------------------------------------------------------ имитовставки
def _dbl(b: bytes) -> bytes:
    n = len(b)
    v = int.from_bytes(b, "big") << 1
    if v >> 8 * n:
        v ^= (1 << 8 * n) | (0x87 if n == 16 else 0x1B)
    return v.to_bytes(n, "big")


def cmac(c, data, tag_len=None):
    """CMAC / OMAC1 (NIST SP 800-38B, RFC 4493) = имитовставка ГОСТ Р 34.13-2015 (раздел 5.6).
    tag_len — сколько байт оставить (ГОСТ обычно берёт половину блока)."""
    n = c.block_size
    k1 = _dbl(c.encrypt_block(bytes(n)))
    k2 = _dbl(k1)
    if data and len(data) % n == 0:
        last = _x(data[-n:], k1)
        body = data[:-n]
    else:
        tail = len(data) % n
        cut = len(data) - tail
        last = _x(data[cut:] + b"\x80" + bytes(n - tail - 1), k2)
        body = data[:cut]
    v = bytes(n)
    for i in range(0, len(body), n):
        v = c.encrypt_block(_x(v, body[i:i + n]))
    return c.encrypt_block(_x(v, last))[:tag_len or n]


def cbc_mac(c, data, tag_len=None):
    """Классический CBC-MAC (ISO/IEC 9797-1 алгоритм 1, нулевой IV, данные дополняются нулями).
    Небезопасен для сообщений разной длины — для практики используйте cmac."""
    n = c.block_size
    data = data + bytes(-len(data) % n) if data else bytes(n)
    return cbc_encrypt(c, data, bytes(n))[-n:][:tag_len or n]


# ------------------------------------------------------------------ GCM
_R = 0xE1 << 120


def _gmul(x: int, y: int) -> int:
    z = 0
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= y
        y = (y >> 1) ^ _R if y & 1 else y >> 1
    return z


def ghash(h: bytes, aad: bytes, ct: bytes) -> bytes:
    hi, y = int.from_bytes(h, "big"), 0
    for part in (aad, ct):
        part = part + bytes(-len(part) % 16)
        for i in range(0, len(part), 16):
            y = _gmul(y ^ int.from_bytes(part[i:i + 16], "big"), hi)
    y = _gmul(y ^ ((len(aad) * 8) << 64 | len(ct) * 8), hi)
    return y.to_bytes(16, "big")


def _gcm(c, data, nonce, aad):
    if c.block_size != 16:
        raise ValueError("GCM определён только для шифров с блоком 128 бит (AES, «Кузнечик»)")
    if not nonce:
        raise ValueError("пустой nonce")
    h = c.encrypt_block(bytes(16))
    j0 = nonce + b"\x00\x00\x00\x01" if len(nonce) == 12 else ghash(h, b"", nonce)
    pre, cnt = j0[:12], int.from_bytes(j0[12:], "big")
    out = []
    for i in range(0, len(data), 16):
        cnt = (cnt + 1) & 0xFFFFFFFF                 # inc32
        out.append(_x(data[i:i + 16], c.encrypt_block(pre + cnt.to_bytes(4, "big"))))
    return b"".join(out), h, j0


def gcm_encrypt(c, data, nonce, aad=b"", tag_len=16):
    """-> (шифртекст, тег). nonce лучше 12 байт. aad — открытые данные, которые тоже защищаются тегом."""
    ct, h, j0 = _gcm(c, data, nonce, aad)
    return ct, _x(c.encrypt_block(j0), ghash(h, aad, ct))[:tag_len]


def gcm_decrypt(c, ct, nonce, tag, aad=b""):
    """Проверяет тег и только потом отдаёт открытый текст; при подделке — ValueError."""
    pt, h, j0 = _gcm(c, ct, nonce, aad)
    good = _x(c.encrypt_block(j0), ghash(h, aad, ct))[:len(tag)]
    if len(tag) < 4 or not _hmac.compare_digest(good, tag):
        raise ValueError("GCM: тег не совпал — данные или ключ подделаны")
    return pt


# ------------------------------------------------------------------ высокий уровень
_PADDED = {"ecb", "cbc", "pcbc"}


def _as_bytes(data):
    if isinstance(data, str):
        return from_bits(to_bits(data))
    return bytes(data)


def _like(out: bytes, data):
    return to_bits(out) if isinstance(data, str) and is_bitstr(data) else out


def encrypt(data, key, cipher="aes", mode="cbc", iv=None, padding="pkcs7", aad=b""):
    """Зашифровать целиком. Результат: IV/nonce + шифртекст (+ тег 16 байт для GCM).
    ECB/CBC/PCBC дополняются схемой padding (None — без дополнения, данные должны быть кратны блоку).
    data/key — bytes, текст или строка битов; строка битов -> ответ тоже строкой битов."""
    c, m = _cipher(cipher, _as_bytes(key)), mode.lower()
    n = c.block_size
    if m in _PADDED and padding:      # дополняем по битам: строка "1101" тоже годится
        d = _pad(to_bits(data) if isinstance(data, str) else bytes(data), 8 * n, padding)
        d = from_bits(d) if isinstance(d, str) else d
    else:
        d = _as_bytes(data)
    if m == "ecb":
        return _like(ecb_encrypt(c, d), data)
    if m == "gcm":
        iv = iv or os.urandom(12)
        ct, tag = gcm_encrypt(c, d, iv, aad)
        return _like(iv + ct + tag, data)
    if m not in MODES:
        raise ValueError(f"неизвестный режим {mode!r}, есть: {', '.join(MODES)}")
    iv = iv or os.urandom(n // 2 if m == "ctr" else n)
    fn = {"cbc": cbc_encrypt, "pcbc": pcbc_encrypt, "cfb": cfb_encrypt, "ofb": ofb, "ctr": ctr}[m]
    return _like(iv + fn(c, d, iv), data)


def decrypt(data, key, cipher="aes", mode="cbc", padding="pkcs7", aad=b"", iv_len=None):
    """Обратное к encrypt(): читает IV из начала. iv_len — если IV был нестандартной длины."""
    c, m = _cipher(cipher, _as_bytes(key)), mode.lower()
    d = _as_bytes(data)
    n = c.block_size
    if m == "ecb":
        out = ecb_decrypt(c, d)
    elif m == "gcm":
        k = iv_len or 12
        out = gcm_decrypt(c, d[k:-16], d[:k], d[-16:], aad)
    elif m in MODES:
        k = iv_len or (n // 2 if m == "ctr" else n)
        iv, body = d[:k], d[k:]
        fn = {"cbc": cbc_decrypt, "pcbc": pcbc_decrypt, "cfb": cfb_decrypt, "ofb": ofb, "ctr": ctr}[m]
        out = fn(c, body, iv)
    else:
        raise ValueError(f"неизвестный режим {mode!r}, есть: {', '.join(MODES)}")
    if m in _PADDED and padding:
        if isinstance(data, str) and is_bitstr(data):
            return _unpad(to_bits(out), 8 * n, padding)
        out = _unpad(out, 8 * n, padding)
    return _like(out, data)
