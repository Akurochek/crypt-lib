"""Блочные шифры, собранные из таблиц библиотеки (crypto_enu/sbox.py, crypto_enu/pbox.py).

Каждый шифр — класс с полями block_size (байт) и методами encrypt_block / decrypt_block
над ровно одним блоком bytes. Режимы (CBC, CTR, GCM, ...) — в crypto_enu/modes.py.

    c = crypt.cipher("aes", key)          # или crypt.AES(key)
    c.encrypt_block(b"16 байт ровно!!!")

Есть: DES, 3DES, AES-128/192/256, «Магма», «Кузнечик», PRESENT-80/128,
а также конструкторы своих шифров: Feistel и SPN.
"""
import importlib

# crypt.sbox / crypt.pbox в пакете — функции, поэтому модули берём явно
_sb = importlib.import_module(".sbox", __package__)
_pb = importlib.import_module(".pbox", __package__)

M32 = 0xFFFFFFFF


def _perm(x: int, table: list[int], n_in: int) -> int:
    """Перестановка битов int; table[i] — номер входного бита (с 0 от старшего)."""
    r = 0
    for p in table:
        r = (r << 1) | (x >> (n_in - 1 - p)) & 1
    return r


def _gf_mul(a: int, b: int, poly: int) -> int:
    """Умножение в GF(2^8) по модулю poly (0x11B для AES, 0x1C3 для «Кузнечика»)."""
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        if a & 0x100:
            a ^= poly
        b >>= 1
    return r


class BlockCipher:
    name = "?"
    block_size = 0
    key_sizes: tuple = ()

    def _check_key(self, key: bytes):
        if len(key) not in self.key_sizes:
            raise ValueError(f"{self.name}: ключ {len(key)} байт, нужен один из {self.key_sizes}")

    def _check_block(self, block: bytes):
        if len(block) != self.block_size:
            raise ValueError(f"{self.name}: блок должен быть {self.block_size} байт, а не {len(block)}")

    def encrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    def decrypt_block(self, block: bytes) -> bytes:
        raise NotImplementedError

    def __repr__(self):
        return f"<{self.name}, блок {self.block_size * 8} бит>"


# ------------------------------------------------------------------ DES / 3DES
class DES(BlockCipher):
    """DES (FIPS 46-3): сеть Фейстеля, 16 раундов, ключ 64 бита (56 значимых)."""
    name, block_size, key_sizes = "DES", 8, (8,)
    SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

    def __init__(self, key: bytes):
        self._check_key(key)
        cd = _perm(int.from_bytes(key, "big"), _pb.DES_PC1, 64)
        c, d = cd >> 28, cd & 0xFFFFFFF
        self.keys = []
        for s in self.SHIFTS:
            c = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF
            d = ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
            self.keys.append(_perm((c << 28) | d, _pb.DES_PC2, 56))

    @staticmethod
    def _f(r: int, k: int) -> int:
        e = _perm(r, _pb.DES_E, 32) ^ k
        s = 0
        for i in range(8):
            six = (e >> (42 - 6 * i)) & 0x3F
            s = (s << 4) | _sb.DES[i][((six >> 4) & 2) | (six & 1)][(six >> 1) & 0xF]
        return _perm(s, _pb.DES_P, 32)

    def _crypt(self, block: bytes, keys) -> bytes:
        self._check_block(block)
        x = _perm(int.from_bytes(block, "big"), _pb.DES_IP, 64)
        l, r = x >> 32, x & M32
        for k in keys:
            l, r = r, l ^ self._f(r, k)
        return _perm((r << 32) | l, _pb.DES_FP, 64).to_bytes(8, "big")

    def encrypt_block(self, block):
        return self._crypt(block, self.keys)

    def decrypt_block(self, block):
        return self._crypt(block, self.keys[::-1])


class TDES(BlockCipher):
    """Triple DES (NIST SP 800-67), схема EDE: E(K3, D(K2, E(K1, P))).
    Ключ 24 байта (три ключа), 16 байт (K3 = K1) или 8 байт (= обычный DES)."""
    name, block_size, key_sizes = "3DES", 8, (8, 16, 24)

    def __init__(self, key: bytes):
        self._check_key(key)
        k = (key * 3)[:24] if len(key) == 8 else key + key[:8] if len(key) == 16 else key
        self.d1, self.d2, self.d3 = DES(k[:8]), DES(k[8:16]), DES(k[16:])

    def encrypt_block(self, block):
        return self.d3.encrypt_block(self.d2.decrypt_block(self.d1.encrypt_block(block)))

    def decrypt_block(self, block):
        return self.d1.decrypt_block(self.d2.encrypt_block(self.d3.decrypt_block(block)))


# ------------------------------------------------------------------ AES
_AES_INV = _sb.invert(_sb.AES)
_AES_MUL = {c: [_gf_mul(c, x, 0x11B) for x in range(256)] for c in (2, 3, 9, 11, 13, 14)}


class AES(BlockCipher):
    """AES / Rijndael (FIPS-197): SPN, блок 128 бит, ключ 128/192/256 бит (10/12/14 раундов)."""
    name, block_size, key_sizes = "AES", 16, (16, 24, 32)

    def __init__(self, key: bytes):
        self._check_key(key)
        nk = len(key) // 4
        self.rounds = nk + 6
        w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
        rcon = 1
        for i in range(nk, 4 * (self.rounds + 1)):
            t = list(w[i - 1])
            if i % nk == 0:
                t = [_sb.AES[b] for b in t[1:] + t[:1]]
                t[0] ^= rcon
                rcon = _gf_mul(rcon, 2, 0x11B)
            elif nk > 6 and i % nk == 4:
                t = [_sb.AES[b] for b in t]
            w.append([a ^ b for a, b in zip(w[i - nk], t)])
        self.round_keys = [sum(w[4 * r:4 * r + 4], []) for r in range(self.rounds + 1)]
        self.name = f"AES-{len(key) * 8}"

    # состояние — 16 байт по столбцам: s[строка + 4*столбец]
    @staticmethod
    def _shift(s, inv=False):
        out = [0] * 16
        for r in range(4):
            for c in range(4):
                if inv:
                    out[r + 4 * ((c + r) % 4)] = s[r + 4 * c]
                else:
                    out[r + 4 * c] = s[r + 4 * ((c + r) % 4)]
        return out

    @staticmethod
    def _mix(s, coef):
        m = [_AES_MUL.get(c) for c in coef]
        out = []
        for c in range(4):
            col = s[4 * c:4 * c + 4]
            for r in range(4):
                v = 0
                for j in range(4):
                    k = coef[(j - r) % 4]
                    v ^= col[j] if k == 1 else m[(j - r) % 4][col[j]]
                out.append(v)
        return out

    def encrypt_block(self, block):
        self._check_block(block)
        s = [a ^ b for a, b in zip(block, self.round_keys[0])]
        for r in range(1, self.rounds + 1):
            s = self._shift([_sb.AES[b] for b in s])
            if r != self.rounds:
                s = self._mix(s, (2, 3, 1, 1))
            s = [a ^ b for a, b in zip(s, self.round_keys[r])]
        return bytes(s)

    def decrypt_block(self, block):
        self._check_block(block)
        s = [a ^ b for a, b in zip(block, self.round_keys[self.rounds])]
        for r in range(self.rounds - 1, -1, -1):
            s = [_AES_INV[b] for b in self._shift(s, inv=True)]
            s = [a ^ b for a, b in zip(s, self.round_keys[r])]
            if r:
                s = self._mix(s, (14, 11, 13, 9))
        return bytes(s)


# ------------------------------------------------------------------ «Кузнечик»
_K_COEF = (148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1)
_K_MUL = {c: [_gf_mul(c, x, 0x1C3) for x in range(256)] for c in set(_K_COEF)}
_K_INV = _sb.invert(_sb.KUZNYECHIK)


def _k_l(b) -> int:
    v = 0
    for c, x in zip(_K_COEF, b):
        v ^= _K_MUL[c][x]
    return v


def _k_L(b: list[int]) -> list[int]:
    for _ in range(16):                       # R: a15..a0 -> l(a15..a0) || a15..a1
        b = [_k_l(b)] + b[:15]
    return b


def _k_Linv(b: list[int]) -> list[int]:
    for _ in range(16):                       # R^-1: a15..a0 -> a14..a0 || l(a14..a0, a15)
        b = b[1:] + [_k_l(b[1:] + b[:1])]
    return b


class Kuznyechik(BlockCipher):
    """ГОСТ Р 34.12-2015 «Кузнечик»: LSX-шифр, блок 128 бит, ключ 256 бит, 10 раундовых ключей."""
    name, block_size, key_sizes = "Кузнечик", 16, (32,)

    def __init__(self, key: bytes):
        self._check_key(key)
        a1, a0 = list(key[:16]), list(key[16:])
        self.keys = [a1, a0]
        for j in range(4):
            for i in range(1, 9):
                c = _k_L([0] * 15 + [8 * j + i])
                t = _k_L([_sb.KUZNYECHIK[x ^ y] for x, y in zip(a1, c)])
                a1, a0 = [x ^ y for x, y in zip(t, a0)], a1
            self.keys += [a1, a0]

    def encrypt_block(self, block):
        self._check_block(block)
        x = list(block)
        for k in self.keys[:9]:
            x = _k_L([_sb.KUZNYECHIK[a ^ b] for a, b in zip(x, k)])
        return bytes(a ^ b for a, b in zip(x, self.keys[9]))

    def decrypt_block(self, block):
        self._check_block(block)
        x = [a ^ b for a, b in zip(block, self.keys[9])]
        for k in reversed(self.keys[:9]):
            x = [_K_INV[a] ^ b for a, b in zip(_k_Linv(x), k)]
        return bytes(x)


# ------------------------------------------------------------------ «Магма»
class Magma(BlockCipher):
    """ГОСТ Р 34.12-2015 «Магма» (бывший ГОСТ 28147-89): Фейстель, 32 раунда, блок 64, ключ 256 бит."""
    name, block_size, key_sizes = "Магма", 8, (32,)

    def __init__(self, key: bytes, sbox=None):
        self._check_key(key)
        self.sbox = sbox or _sb.MAGMA
        k = [int.from_bytes(key[4 * i:4 * i + 4], "big") for i in range(8)]
        self.keys = k * 3 + k[::-1]

    def _g(self, k: int, a: int) -> int:
        t = (a + k) & M32
        t = sum(self.sbox[i][(t >> 4 * i) & 0xF] << 4 * i for i in range(8))
        return ((t << 11) | (t >> 21)) & M32

    def _crypt(self, block, keys):
        self._check_block(block)
        x = int.from_bytes(block, "big")
        a1, a0 = x >> 32, x & M32
        for k in keys:
            a1, a0 = a0, self._g(k, a0) ^ a1
        return ((a0 << 32) | a1).to_bytes(8, "big")

    def encrypt_block(self, block):
        return self._crypt(block, self.keys)

    def decrypt_block(self, block):
        return self._crypt(block, self.keys[::-1])


# ------------------------------------------------------------------ PRESENT
_P_INV = _sb.invert(_sb.PRESENT)
_P_POS = [63 if i == 63 else 16 * i % 63 for i in range(64)]   # бит i (с младшего) -> позиция


def _present_layer(x: int, box, inverse=False) -> int:
    x = sum(box[(x >> 4 * i) & 0xF] << 4 * i for i in range(16)) if not inverse else x
    r = 0
    for i in range(64):
        if inverse:
            r |= ((x >> _P_POS[i]) & 1) << i
        else:
            r |= ((x >> i) & 1) << _P_POS[i]
    if inverse:
        r = sum(box[(r >> 4 * i) & 0xF] << 4 * i for i in range(16))
    return r


class Present(BlockCipher):
    """PRESENT (ISO/IEC 29192-2): лёгкий SPN, 31 раунд, блок 64 бита, ключ 80 или 128 бит."""
    name, block_size, key_sizes = "PRESENT", 8, (10, 16)

    def __init__(self, key: bytes):
        self._check_key(key)
        bits = len(key) * 8
        k, mask = int.from_bytes(key, "big"), (1 << bits) - 1
        self.keys = []
        for rnd in range(1, 33):
            self.keys.append(k >> (bits - 64))
            k = ((k << 61) | (k >> (bits - 61))) & mask
            if bits == 80:
                k = (_sb.PRESENT[k >> 76] << 76) | (k & ((1 << 76) - 1))
                k ^= rnd << 15
            else:
                top = (_sb.PRESENT[k >> 124] << 4) | _sb.PRESENT[(k >> 120) & 0xF]
                k = (top << 120) | (k & ((1 << 120) - 1))
                k ^= rnd << 62
        self.name = f"PRESENT-{bits}"

    def encrypt_block(self, block):
        self._check_block(block)
        x = int.from_bytes(block, "big")
        for k in self.keys[:31]:
            x = _present_layer(x ^ k, _sb.PRESENT)
        return (x ^ self.keys[31]).to_bytes(8, "big")

    def decrypt_block(self, block):
        self._check_block(block)
        x = int.from_bytes(block, "big") ^ self.keys[31]
        for k in reversed(self.keys[:31]):
            x = _present_layer(x, _P_INV, inverse=True) ^ k
        return x.to_bytes(8, "big")


# ------------------------------------------------------------------ свои шифры
class Feistel(BlockCipher):
    """Своя сеть Фейстеля. f(половина: bytes, раундовый_ключ) -> bytes той же длины.
    Расшифрование — те же раунды с ключами в обратном порядке, f обращать не нужно.

        f = lambda r, k: crypt.sbox(crypt.xor(r, k), "aes")
        c = crypt.Feistel(f, [b"k1k1", b"k2k2", b"k3k3"], block_size=8)
    """
    name = "Фейстель"

    def __init__(self, f, round_keys, block_size: int = 8):
        if block_size % 2:
            raise ValueError("блок сети Фейстеля должен делиться пополам")
        self.f, self.keys, self.block_size = f, list(round_keys), block_size

    def _crypt(self, block, keys):
        self._check_block(block)
        h = self.block_size // 2
        l, r = block[:h], block[h:]
        for k in keys:
            l, r = r, bytes(a ^ b for a, b in zip(l, self.f(r, k)))
        return r + l                          # последний обмен половин отменяется

    def encrypt_block(self, block):
        return self._crypt(block, self.keys)

    def decrypt_block(self, block):
        return self._crypt(block, self.keys[::-1])


class SPN(BlockCipher):
    """Своя SP-сеть: раунд = XOR ключа -> S-блок -> P-блок; в последнем раунде P нет,
    после него XOR последнего ключа (ключей на 1 больше, чем раундов).
    sbox / perm — имена из crypt.SBOXES / crypt.PBOXES или свои таблицы."""
    name = "SPN"

    def __init__(self, round_keys, sbox="present", perm="present", block_size: int = 8):
        if len(round_keys) < 2:
            raise ValueError("нужно минимум 2 раундовых ключа")
        self.keys = [bytes(k) for k in round_keys]
        if any(len(k) != block_size for k in self.keys):
            raise ValueError(f"каждый раундовый ключ — {block_size} байт")
        self.s, self.p, self.block_size = sbox, perm, block_size

    def encrypt_block(self, block):
        from .sbox import sbox
        from .pbox import pbox
        self._check_block(block)
        x = bytes(block)
        for i, k in enumerate(self.keys[:-1]):
            x = sbox(bytes(a ^ b for a, b in zip(x, k)), self.s)
            if i < len(self.keys) - 2:
                x = pbox(x, self.p)
        return bytes(a ^ b for a, b in zip(x, self.keys[-1]))

    def decrypt_block(self, block):
        from .sbox import sbox_inv
        from .pbox import pbox_inv
        self._check_block(block)
        x = bytes(a ^ b for a, b in zip(block, self.keys[-1]))
        for i in range(len(self.keys) - 2, -1, -1):
            if i < len(self.keys) - 2:
                x = pbox_inv(x, self.p)
            x = bytes(a ^ b for a, b in zip(sbox_inv(x, self.s), self.keys[i]))
        return x


CIPHERS = {
    "des": DES, "3des": TDES, "aes": AES,
    "magma": Magma, "kuznyechik": Kuznyechik, "present": Present,
}
_CIPHER_ALIASES = {"tdes": "3des", "tripledes": "3des", "des3": "3des", "des_ede": "3des",
                   "aes128": "aes", "aes192": "aes", "aes256": "aes", "rijndael": "aes",
                   "магма": "magma", "gost28147": "magma", "кузнечик": "kuznyechik",
                   "grasshopper": "kuznyechik", "kuz": "kuznyechik"}


def cipher(name: str | BlockCipher, key: bytes = b"") -> BlockCipher:
    """crypt.cipher("aes", key) -> объект шифра. Уже готовый объект возвращается как есть."""
    if isinstance(name, BlockCipher):
        return name
    n = name.lower().replace("-", "").replace("_", "").replace(" ", "")
    n = _CIPHER_ALIASES.get(n, n)
    if n not in CIPHERS:
        raise ValueError(f"неизвестный шифр {name!r}, есть: {', '.join(CIPHERS)}")
    return CIPHERS[n](bytes(key))
