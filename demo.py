import crypt

msg = "1101"
print("Сообщение (биты):", msg, "\n")
for s in ("zero", "iso7816_4", "iso9797_m1", "iso9797_m3", "tbc"):
    p = crypt.pad32(msg, s)
    print(f"{s:11} pad32 -> {crypt.group(p)}  | unpad -> {crypt.unpad32(p, s)}")

msg = b"HELLO"
print("\nСообщение (байты):", msg)
for s in ("pkcs7", "ansi_x923", "iso10126", "iso7816_4", "tls", "esp", "space"):
    p = crypt.pad64(msg, s)
    print(f"{s:11} pad64 -> {p.hex(' ')}  | unpad -> {crypt.unpad64(p, s)}")
p = crypt.pad512(msg, "sha256")
print(f"sha256      pad512 -> {p.hex()[:24]}...{p.hex()[-16:]}  | unpad -> {crypt.unpad512(p, 'sha256')}")

data, n = crypt.pad128("10110", with_len=True)
print("\npad128('10110'):", crypt.group(data), "длина", n, "бит")
print("блоки по 32:", crypt.blocks(data, 32))

print("\nS-блок  1101 0010 ->", crypt.group(crypt.sbox("11010010"), 4))
print("P-блок  1101 [3,2,1,0] ->", crypt.pbox("1101", [3, 2, 1, 0]))
print("XOR     1101 ^ 1010 ->", crypt.xor("1101", "1010"))
