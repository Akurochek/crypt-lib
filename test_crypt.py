import os
import random
import sys
import crypt


def _rand_bits(n):
    return "".join(random.choice("01") for _ in range(n))


BYTE_ONLY = {"pkcs7", "pkcs5", "ansi_x923", "iso10126", "space", "tls", "ssl3", "esp",
             "pkcs1_t1", "pkcs1_t2", "md5", "sha3", "shake", "keccak"}


def _block(s):
    return 64 if s == "pkcs5" else crypt.INFO[s][2]


def test_roundtrip_all():
    for s in crypt.SCHEMES:
        bs = _block(s)
        for ln in list(range(0, 70)) + [bs - 1, bs, bs + 1, 2 * bs]:
            if s in BYTE_ONLY and ln % 8:
                continue
            if s.startswith("pkcs1") and ln > bs - 88:
                continue
            if s == "gost_p3" and ln and ln % bs == 0:
                continue                   # процедура 3 не дополняет кратные — неоднозначно
            m = _rand_bits(ln)
            if s in ("zero", "iso9797_m1"):
                m = m.rstrip("0")          # нулевая схема неоднозначна для хвостовых нулей
            if s == "space":
                m = crypt.to_bits(crypt.from_bits(m).rstrip(b" "))
            p = crypt.pad(m, bs, s)
            assert len(p) % bs == 0, (s, ln)
            assert crypt.unpad(p, bs, s) == m, (s, ln, m, p)


def test_bytes_roundtrip():
    for s in crypt.SCHEMES:
        bs = _block(s)
        for ln in range(0, 20):
            if s == "gost_p3" and ln % (bs // 8) == 0 and ln:
                continue
            m = os.urandom(ln).rstrip(b"\x00 \xff") or b"D"   # 'D' = 01000100, кончается нулями
            assert crypt.unpad(crypt.pad(m, bs, s), bs, s) == m, (s, m)


def test_new_standards():
    abc = b"abc"
    assert crypt.pad(abc, 512, "sha256") == abc + b"\x80" + bytes(52) + (24).to_bytes(8, "big")
    assert crypt.pad(abc, 1024, "sha512") == abc + b"\x80" + bytes(108) + (24).to_bytes(16, "big")
    assert crypt.pad(abc, 512, "md5") == abc + b"\x80" + bytes(52) + (24).to_bytes(8, "little")
    assert len(crypt.pad(bytes(56), 512, "sha2")) == 128          # 448 бит — длина уже не влезает
    assert crypt.pad(b"", 1088, "sha3") == b"\x06" + bytes(134) + b"\x80"
    assert crypt.pad(bytes(135), 1088, "sha3")[-1] == 0x86
    assert crypt.pad(b"", 1344, "shake")[0] == 0x1F
    assert crypt.pad(b"", 1088, "keccak")[0] == 0x01
    assert crypt.pad("1101", 8, "pad10_1") == "11011001"
    assert crypt.pad("1111111", 8, "pad10_1") == "11111111" + "00000001"
    assert crypt.pad("1101", 16, "streebog") == "0" * 11 + "1" + "1101"
    assert crypt.pad(b"AB", 32, "tls") == b"AB\x01\x01"
    assert crypt.pad(b"", 32, "esp") == b"\x01\x02\x03\x03"
    assert crypt.pad(b"AB", 32, "gost_p3") == b"AB\x80\x00"
    assert crypt.pad(b"ABCD", 32, "gost_p3") == b"ABCD"
    assert crypt.pad(b"AB", 32, "gost_p2") == crypt.pad(b"AB", 32, "iso7816_4")
    eb = crypt.pad(b"hi", 1024, "pkcs1_t1")
    assert eb[:2] == b"\x00\x01" and eb[-3:] == b"\x00hi" and set(eb[2:-3]) == {0xFF} and len(eb) == 128
    eb = crypt.pad(b"hi", 1024, "pkcs1_t2")
    assert eb[:2] == b"\x00\x02" and 0 not in eb[2:-3]
    for bad, s, bs in ((b"AB\x02\x03", "pkcs7", 32), (b"AB\x02\x01", "esp", 32),
                       (b"AB\x00\x01", "tls", 32), (bytes(64), "sha2", 512)):
        try:
            crypt.unpad(bad, bs, s)
            raise AssertionError((s, bad))
        except ValueError:
            pass
    assert "Стрибог" in crypt.info("gost3411")


def test_known():
    assert crypt.pad32("1101") == "1101" + "1" + "0" * 27
    assert crypt.pad32("1101", "zero") == "1101" + "0" * 28
    assert crypt.pad32("1101", "tbc") == "1101" + "0" * 28
    assert crypt.pad32("1100", "tbc") == "1100" + "1" * 28
    assert crypt.pad(b"AB", 32, "pkcs7") == b"AB\x02\x02"
    assert crypt.pad(b"AB", 32, "ansi_x923") == b"AB\x00\x02"
    assert crypt.pad(b"AB", 32, "iso7816_4") == b"AB\x80\x00"
    assert crypt.pad(b"ABCD", 32, "pkcs7") == b"ABCD" + b"\x04" * 4
    assert crypt.pad32(b"ABCD", "zero") == b"ABCD"
    assert crypt.pad64("1101", with_len=True)[1] == 64
    assert crypt.pad64("A") == crypt.to_bits(b"A\x80" + bytes(6))   # текст -> UTF-8 -> биты


def test_sbox_pbox_xor():
    d = os.urandom(8)
    assert crypt.sbox_inv(crypt.sbox(d)) == d
    perm = crypt.present_perm()
    assert crypt.pbox_inv(crypt.pbox(d, perm), perm) == d
    assert crypt.xor(crypt.xor(d, b"k1"), b"k1") == d
    assert crypt.sbox("1101") == "0111" and crypt.sbox_inv("0111") == "1101"
    assert crypt.pbox("1101", [3, 2, 1, 0]) == "1011"
    assert crypt.xor("1101", "01") == "1000"


def test_standards():
    assert crypt.sbox(b"\x00\x53", "aes").hex() == "63ed"
    assert crypt.sbox(bytes.fromhex("ffeeddccbbaa99881122334455667700"), "kuznyechik").hex() \
        == "b66cd8887d38e8d77765aeea0c9a7efc"
    assert crypt.sbox(bytes.fromhex("fdb97531"), "magma").hex() == "2a196f34"
    d = os.urandom(8)
    for name in ("aes", "kuznyechik", "present", "gift", "magma"):
        assert crypt.sbox_inv(crypt.sbox(d, name), name) == d
    for name in ("des_ip", "des_fp", "present"):
        assert crypt.pbox_inv(crypt.pbox(d, name), name) == d
    assert crypt.pbox(crypt.pbox(d, "des_ip"), "des_fp") == d


def test_full_ciphers():
    sys.path.insert(0, "examples")
    from ex_standards import des_encrypt, present_encrypt
    assert des_encrypt(bytes.fromhex("0123456789ABCDEF"), bytes.fromhex("133457799BBCDFF1")).hex() == "85e813540f0ab405"
    assert present_encrypt(bytes(8), bytes(10)).hex() == "5579c1387b228445"


H = bytes.fromhex
GOST_K = H("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef")
GOST_M = H("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")


def test_block_ciphers():
    for c, pt, ct in (
        (crypt.DES(H("133457799BBCDFF1")), "0123456789abcdef", "85e813540f0ab405"),          # FIPS 46
        (crypt.AES(bytes(range(16))), "00112233445566778899aabbccddeeff", "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (crypt.AES(bytes(range(24))), "00112233445566778899aabbccddeeff", "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (crypt.AES(bytes(range(32))), "00112233445566778899aabbccddeeff", "8ea2b7ca516745bfeafc49904b496089"),
        (crypt.Kuznyechik(GOST_K), "1122334455667700ffeeddccbbaa9988", "7f679d90bebc24305a468d42b9d4edcd"),
        (crypt.Magma(GOST_M), "fedcba9876543210", "4ee901e5c2d8ca3d"),                         # ГОСТ 34.12
        (crypt.Present(bytes(10)), "0000000000000000", "5579c1387b228445"),
        (crypt.Present(b"\xff" * 10), "ffffffffffffffff", "3333dcd3213210d2"),
        (crypt.Present(bytes(16)), "0000000000000000", "96db702a2e6900af"),
        (crypt.TDES(H("133457799BBCDFF1") * 3), "0123456789abcdef", "85e813540f0ab405"),
    ):
        assert c.encrypt_block(H(pt)).hex() == ct, c
        assert c.decrypt_block(H(ct)) == H(pt), c
    f = lambda r, k: crypt.sbox(crypt.xor(r, k), "aes")
    for c in (crypt.Feistel(f, [b"k1k1", b"k2k2", b"k3k3"]), crypt.SPN([os.urandom(8) for _ in range(4)])):
        assert c.decrypt_block(c.encrypt_block(b"12345678")) == b"12345678"


def test_modes_nist():
    c = crypt.AES(H("2b7e151628aed2a6abf7158809cf4f3c"))                   # SP 800-38A, F.1–F.5
    p = H("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    iv = bytes(range(16))
    assert crypt.ecb_encrypt(c, p[:16]).hex() == "3ad77bb40d7a3660a89ecaf32466ef97"
    assert crypt.cbc_encrypt(c, p[:16], iv).hex() == "7649abac8119b246cee98e9b12e9197d"
    assert crypt.cfb_encrypt(c, p[:16], iv).hex() == "3b3fd92eb72dad20333449f8e83cfb4a"
    assert crypt.ofb(c, p, iv)[16:].hex() == "7789508d16918f03f53c52dac54ed825"
    assert crypt.ctr(c, p[:16], H("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")).hex() == "874d6191b620e3261bef6864990db6ce"
    assert crypt.cmac(c, b"").hex() == "bb1d6929e95937287fa37d129b756746"                  # RFC 4493
    assert crypt.cmac(c, p[:16]).hex() == "070a16b46b4d4144f79bdd9dd04a287c"
    z = crypt.AES(bytes(16))                                                   # GCM test case 1–2
    assert crypt.gcm_encrypt(z, b"", bytes(12))[1].hex() == "58e2fccefa7e3061367f1d57a4e7455a"
    ct, tag = crypt.gcm_encrypt(z, bytes(16), bytes(12))
    assert (ct + tag).hex() == "0388dace60b6a392f328c2b971b2fe78" "ab6e47d42cec13bdf53a67b21257bddf"
    try:
        crypt.gcm_decrypt(z, ct, bytes(12), bytes(16))
        raise AssertionError("поддельный тег принят")
    except ValueError:
        pass


def test_modes_gost():
    k = crypt.Kuznyechik(GOST_K)                                               # ГОСТ Р 34.13-2015, прил. А
    p = H("1122334455667700ffeeddccbbaa9988" "00112233445566778899aabbcceeff0a"
          "112233445566778899aabbcceeff0a00" "2233445566778899aabbcceeff0a0011")
    assert crypt.ctr(k, p, H("1234567890abcef0"))[:16].hex() == "f195d8bec10ed1dbd57b5fa240bda1b8"
    assert crypt.cmac(k, p, 8).hex() == "336f4d296059fbe3"
    m = crypt.Magma(GOST_M)
    p = H("92def06b3c130a59" "db54c704f8189d20" "4a98fb2e67a8024c" "8912409b17b57e41")
    assert crypt.ecb_encrypt(m, p[:8]).hex() == "2b073f0494f372a0"
    assert crypt.ctr(m, p, H("12345678"))[:8].hex() == "4e98110c97b7b93c"
    assert crypt.cmac(m, p, 4).hex() == "154e7210"


def test_encrypt_decrypt_all():
    keys = {"aes": 16, "3des": 24, "des": 8, "magma": 32, "kuznyechik": 32, "present": 10}
    for name, kl in keys.items():
        key = os.urandom(kl)
        for mode in crypt.MODES:
            if mode == "gcm" and name not in ("aes", "kuznyechik"):
                continue
            for d in (b"", b"hello", os.urandom(37)):
                assert crypt.decrypt(crypt.encrypt(d, key, name, mode), key, name, mode) == d, (name, mode)
    k = b"k" * 16
    assert crypt.decrypt(crypt.encrypt("1101", k, padding="iso7816_4"), k, padding="iso7816_4") == "1101"
    assert crypt.decrypt(crypt.encrypt(b"x" * 33, k, mode="cbc", padding="gost_p2"), k, padding="gost_p2") == b"x" * 33
    c = crypt.AES(k)
    d = os.urandom(50)
    assert crypt.cfb_decrypt(c, crypt.cfb_encrypt(c, d, bytes(16), 1), bytes(16), 1) == d


def test_stream():
    assert crypt.rc4(b"Plaintext", b"Key").hex() == "bbf316e8d940af0ad3"
    pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
          b"sunscreen would be it.")                                             # RFC 8439 2.4.2
    ct = crypt.chacha20(pt, bytes(range(32)), H("000000000000004a00000000"), 1)
    assert ct[:16].hex() == "6e2e359a2568f98041ba0728dd0d6981" and ct[-2:].hex() == "874d"
    assert crypt.poly1305(b"Cryptographic Forum Research Group",
                          H("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")).hex() \
        == "a8061dc1305136c6c22b8baf0c0127a9"                                   # RFC 8439 2.5.2
    k, n = os.urandom(32), os.urandom(12)
    e = crypt.chacha20_poly1305_encrypt(pt, k, n, b"hdr")
    assert crypt.chacha20_poly1305_decrypt(e, k, n, b"hdr") == pt


def test_hashes():
    import hashlib
    import hmac
    for ln in (0, 1, 55, 56, 63, 64, 65, 200):
        d = os.urandom(ln)
        for name in ("sha256", "sha1", "md5"):
            assert getattr(crypt, name)(d) == hashlib.new(name, d).digest(), (name, ln)
            assert crypt.hmac(b"key" * ln, d, name) == hmac.new(b"key" * ln, d, name).digest()
    assert crypt.pbkdf2(b"password", b"salt", 20, 40) == hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 20, 40)


RU_TEXT = ("Криптография это наука о методах обеспечения конфиденциальности и целостности информации. "
           "Долгое время она служила прежде всего военным и дипломатам, которые хотели сохранить свои "
           "сообщения в тайне от противника. Классические шифры, такие как шифр Цезаря или шифр Виженера, "
           "сегодня легко взламываются с помощью частотного анализа, потому что в любом естественном языке "
           "одни буквы встречаются гораздо чаще других. Например, в русском языке чаще всего встречаются "
           "буквы о, е, а и и. Современные шифры устроены иначе: они опираются на сложные математические "
           "преобразования и большие ключи, перебрать которые за разумное время невозможно.")


def test_classic():
    assert crypt.caesar("Привет, Мир!", 3) == "Тулезх, Плу!"
    assert crypt.vigenere("ATTACK AT DAWN", "LEMON") == "LXFOPV EF RNHR"
    assert crypt.hill("act", [[6, 24, 1], [13, 16, 10], [20, 17, 15]]) == "poh"
    assert crypt.rail_fence("WEAREDISCOVEREDFLEEATONCE", 3) == "WECRLTEERDSOEEFEAOCAIVDEN"
    assert crypt.columnar("WEAREDISCOVEREDFLEEATONCE", "ZEBRAS") == "EVLNACDTESEAROFODEECWIREE"
    assert crypt.rot13("Hello") == "Uryyb" and crypt.atbash("абв") == "яюэ"
    t = RU_TEXT[:120]
    for enc, dec in ((lambda x: crypt.affine(x, 5, 7), lambda x: crypt.affine(x, 5, 7, True)),
                     (lambda x: crypt.vigenere(x, "ключ"), lambda x: crypt.vigenere(x, "ключ", True)),
                     (lambda x: crypt.beaufort(x, "ключ"), lambda x: crypt.beaufort(x, "ключ")),
                     (lambda x: crypt.autokey(x, "ключ"), lambda x: crypt.autokey(x, "ключ", True)),
                     (lambda x: crypt.rail_fence(x, 4), lambda x: crypt.rail_fence(x, 4, True)),
                     (lambda x: crypt.columnar(x, "шифр"), lambda x: crypt.columnar(x, "шифр", True))):
        assert dec(enc(t)) == t
    assert crypt.hill(crypt.hill("шифрхилла", [[1, 2], [3, 5]]), [[1, 2], [3, 5]], True) == "шифрхиллая"
    k = [[3, 3], [2, 5]]
    assert crypt.hill(crypt.hill("helloworld", k), k, True) == "helloworld"
    assert crypt.crack_caesar(crypt.caesar(RU_TEXT, 11))[0] == 11
    assert crypt.crack_affine(crypt.affine(RU_TEXT, 5, 7))[0] == (5, 7)
    assert crypt.crack_vigenere(crypt.vigenere(RU_TEXT, "секрет")) == ("секрет", RU_TEXT)
    assert 0.05 < crypt.index_of_coincidence(RU_TEXT) < 0.06


def test_analysis():
    r = crypt.sbox_report("aes")
    assert (r["differential_uniformity"], r["nonlinearity"], r["algebraic_degree"]) == (4, 112, 7)
    r = crypt.sbox_report("kuznyechik")
    assert (r["differential_uniformity"], r["nonlinearity"], r["algebraic_degree"]) == (8, 100, 7)
    r = crypt.sbox_report("present")
    assert (r["differential_uniformity"], r["nonlinearity"], r["algebraic_degree"]) == (4, 4, 3)
    assert crypt.ddt("present")[0][0] == 16 and crypt.lat("present")[0][0] == 8
    assert crypt.hamming_distance(b"\x0f", b"\xff") == 4
    c = crypt.AES(os.urandom(16))
    assert 0.45 < crypt.avalanche(c.encrypt_block, 16, 5) < 0.55
    assert crypt.entropy(bytes(100)) == 0


if __name__ == "__main__":
    test_roundtrip_all(); test_bytes_roundtrip(); test_known(); test_new_standards(); test_sbox_pbox_xor(); test_standards(); test_full_ciphers()
    test_block_ciphers(); test_modes_nist(); test_modes_gost(); test_encrypt_decrypt_all()
    test_stream(); test_hashes(); test_classic(); test_analysis()
    print("все тесты прошли")
