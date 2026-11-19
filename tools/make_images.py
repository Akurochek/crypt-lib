"""Генерирует картинки для README в docs/img/:
  * term_*.png — «скриншоты» терминала: запускает примеры и рисует их настоящий вывод;
  * ecb_vs_cbc.png, ddt.png, avalanche_rounds.png — наглядные иллюстрации, посчитанные библиотекой.

    python tools/make_images.py          # нужен Pillow
"""
import os
import re
import subprocess
import sys

from PIL import Image, ImageDraw, ImageFont

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import crypto_enu as crypt  # noqa: E402

OUT = os.path.join(ROOT, "docs", "img")
FONTS = "/usr/share/fonts/TTF/"
REG = ImageFont.truetype(FONTS + "JetBrainsMono-Regular.ttf", 15)
BOLD = ImageFont.truetype(FONTS + "JetBrainsMono-Bold.ttf", 15)
FALLBACK = ImageFont.truetype(FONTS + "DejaVuSansMono.ttf", 15)
TITLE = ImageFont.truetype(FONTS + "JetBrainsMono-Regular.ttf", 13)

try:
    from fontTools.ttLib import TTFont
    _CMAP = TTFont(FONTS + "JetBrainsMono-Regular.ttf").getBestCmap()
except Exception:                                          # без fontTools — всё основным шрифтом
    _CMAP = None

# палитра (тёмная тема в духе One Dark)
BG, BAR, FG, DIM = (30, 33, 40), (44, 48, 58), (205, 211, 222), (110, 118, 135)
GREEN, RED, CYAN, YELLOW, BLUE, MAGENTA = ((152, 195, 121), (224, 108, 117), (86, 182, 194),
                                           (229, 192, 123), (97, 175, 239), (198, 120, 221))
CW, LH, PAD = 9, 21, 18                                    # ширина символа, высота строки, поля


def _font(ch, bold):
    if _CMAP is not None and ord(ch) not in _CMAP:
        return FALLBACK
    return BOLD if bold else REG


def _spans(line: str):
    """Подсветка: заголовки, ✓/True/OK — зелёным, ✗/False/ошибки — красным, hex — приглушённо."""
    if line.startswith("$ "):
        return [("$ ", GREEN, True), (line[2:], FG, True)]
    if line and not line.startswith(" ") and line.rstrip().endswith((":", ")")) or re.match(r"^\d\. ", line):
        return [(line, CYAN, True)]
    out, pos = [], 0
    pat = re.compile(r"(✓|\bTrue\b|\bOK\b|все тесты прошли[^\n]*|ключ найден[^\n]*)|(✗|\bFalse\b|отклонена|<- повтор!)"
                     r"|(\b[0-9a-f]{16,}\b|\b[0-9A-F]{16,}\b)|(b'[^']*')")
    for m in pat.finditer(line):
        out.append((line[pos:m.start()], FG, False))
        color = GREEN if m.group(1) else RED if m.group(2) else DIM if m.group(3) else YELLOW
        out.append((m.group(0), color, bool(m.group(1) or m.group(2))))
        pos = m.end()
    out.append((line[pos:], FG, False))
    return out


def terminal(name: str, title: str, cmd: str, lines: list[str], width: int = None):
    lines = [f"$ {cmd}"] + lines
    cols = width or max(60, max(len(s) for s in lines) + 2)
    w, h = cols * CW + 2 * PAD, len(lines) * LH + 2 * PAD + 34
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, w, 34], fill=BAR)
    for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        d.ellipse([14 + 20 * i, 11, 26 + 20 * i, 23], fill=c)
    tw = d.textlength(title, font=TITLE)
    d.text(((w - tw) / 2, 9), title, font=TITLE, fill=DIM)
    y = 34 + PAD
    for line in lines:
        x = PAD
        for text, color, bold in _spans(line):
            for ch in text:
                if x + CW > w - PAD:
                    break
                d.text((x, y), ch, font=_font(ch, bold), fill=color)
                x += CW
        y += LH
    # скруглённые углы окна
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, w - 1, h - 1], 10, fill=255)
    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out.paste(img, mask=mask)
    out.save(os.path.join(OUT, name))
    print("  ", name, f"{w}×{h}")


def run(script: str, head: int = None, cut: int = 110):
    p = subprocess.run([sys.executable, script], cwd=ROOT, capture_output=True, text=True, check=True)
    lines = p.stdout.rstrip("\n").split("\n")
    lines = lines[:head] if head else lines
    return [s if len(s) <= cut else s[:cut - 1] + "…" for s in lines]


# ------------------------------------------------------------------ иллюстрации
def _label(d, xy, text, size=18, fill=FG, anchor="la"):
    d.text(xy, text, font=ImageFont.truetype(FONTS + "JetBrainsMono-Bold.ttf", size), fill=fill, anchor=anchor)


def ecb_vs_cbc():
    """Классика: картинка, зашифрованная в ECB, остаётся узнаваемой."""
    W, H = 240, 160
    src = Image.new("RGB", (W, H), (245, 245, 245))
    d = ImageDraw.Draw(src)
    d.rounded_rectangle([70, 70, 170, 140], 8, fill=(40, 40, 40))           # замок
    d.arc([88, 25, 152, 105], 180, 360, fill=(40, 40, 40), width=14)
    d.line([88, 65, 88, 75], fill=(40, 40, 40), width=14)
    d.line([152, 65, 152, 75], fill=(40, 40, 40), width=14)
    d.ellipse([110, 92, 130, 112], fill=(245, 245, 245))
    d.rectangle([116, 105, 124, 125], fill=(245, 245, 245))
    raw = src.tobytes()
    key, iv = bytes(range(16)), bytes(16)
    c = crypt.AES(key)
    ecb = crypt.ecb_encrypt(c, raw)
    cbc = crypt.cbc_encrypt(c, raw, iv)
    panes = [("Исходное", src), ("AES-ECB", Image.frombytes("RGB", (W, H), ecb[:len(raw)])),
             ("AES-CBC", Image.frombytes("RGB", (W, H), cbc[:len(raw)]))]
    S, gap, top = 2, 24, 50
    img = Image.new("RGB", (3 * W * S + 4 * gap, H * S + top + gap), BG)
    d = ImageDraw.Draw(img)
    for i, (t, p) in enumerate(panes):
        x = gap + i * (W * S + gap)
        img.paste(p.resize((W * S, H * S), Image.NEAREST), (x, top))
        _label(d, (x + W * S // 2, 14), t, fill=[FG, RED, GREEN][i], anchor="ma")
    img.save(os.path.join(OUT, "ecb_vs_cbc.png"))
    print("   ecb_vs_cbc.png")


def _heat(v, vmax):
    t = v / vmax
    stops = [(0, (30, 33, 40)), (0.25, (40, 70, 140)), (0.5, (86, 182, 194)), (0.75, (229, 192, 123)),
             (1, (224, 108, 117))]
    for (a, ca), (b, cb) in zip(stops, stops[1:]):
        if t <= b:
            k = (t - a) / (b - a)
            return tuple(int(ca[j] + (cb[j] - ca[j]) * k) for j in range(3))
    return stops[-1][1]


def ddt_image():
    """DDT: у AES таблица ровная (максимум 4), у слабого S-блока — яркие пики."""
    weak = [x ^ (x >> 1) for x in ((3 * x + 5) % 256 for x in range(256))]   # почти линейный
    panes = [("AES", crypt.ddt("aes")), ("Кузнечик", crypt.ddt("kuznyechik")), ("слабый S-блок", crypt.ddt(weak))]
    S, gap, top = 2, 24, 50
    img = Image.new("RGB", (3 * 256 * S + 4 * gap, 256 * S + top + 40), BG)
    d = ImageDraw.Draw(img)
    for i, (t, tab) in enumerate(panes):
        vmax = 8
        p = Image.new("RGB", (256, 256))
        p.putdata([_heat(min(v, vmax), vmax) for row in tab for v in row])
        x = gap + i * (256 * S + gap)
        img.paste(p.resize((256 * S, 256 * S), Image.NEAREST), (x, top))
        du = max(max(r) for r in tab[1:])
        _label(d, (x + 128 * S, 14), f"{t}: max = {du}", fill=FG, anchor="ma")
    _label(d, (gap, 256 * S + top + 10), "строка — входная разность a, столбец — выходная b; ярче — предсказуемее",
           14, DIM)
    img.save(os.path.join(OUT, "ddt.png"))
    print("   ddt.png")


def avalanche_rounds():
    """Как растёт лавина в SP-сети PRESENT с числом раундов (идеал 0.5)."""
    keys = [os.urandom(8) for _ in range(12)]
    data = [(r, crypt.avalanche(crypt.SPN(keys[:r + 1]).encrypt_block, 8, 8)) for r in range(1, 11)]
    W, H, L, B = 760, 360, 70, 50
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    f = ImageFont.truetype(FONTS + "JetBrainsMono-Regular.ttf", 13)
    top, bottom = 50, H - B
    y = lambda v: bottom - v / 0.6 * (bottom - top)
    for v in (0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6):
        d.line([L, y(v), W - 20, y(v)], fill=BAR)
        d.text((L - 10, y(v)), f"{v:.1f}", font=f, fill=DIM, anchor="rm")
    d.line([L, y(0.5), W - 20, y(0.5)], fill=GREEN, width=1)
    d.text((L + 10, y(0.5) - 4), "идеал 0.5", font=f, fill=GREEN, anchor="lb")
    bw = (W - 20 - L) / len(data)
    for i, (r, v) in enumerate(data):
        x0 = L + i * bw + 8
        d.rectangle([x0, y(v), x0 + bw - 16, bottom], fill=BLUE if v > 0.45 else YELLOW)
        d.text((x0 + (bw - 16) / 2, y(v) - 4), f"{v:.2f}", font=f, fill=FG, anchor="mb")
        d.text((x0 + (bw - 16) / 2, bottom + 8), str(r), font=f, fill=DIM, anchor="ma")
    _label(d, (L, 14), "Лавинный эффект SP-сети PRESENT по числу раундов", 16)
    d.text((W // 2, H - 14), "раунды", font=f, fill=DIM, anchor="mm")
    img.save(os.path.join(OUT, "avalanche_rounds.png"))
    print("   avalanche_rounds.png")


def main():
    os.makedirs(OUT, exist_ok=True)
    terminal("term_tests.png", "crypt-lib — тесты", "python test_crypt.py", run("test_crypt.py"))
    terminal("term_ciphers.png", "crypt-lib — блочные шифры и режимы", "python examples/ex_ciphers.py",
             run("examples/ex_ciphers.py"))
    terminal("term_hashes.png", "crypt-lib — хэши, MAC, KDF, потоковые", "python examples/ex_hash_stream.py",
             run("examples/ex_hash_stream.py"))
    terminal("term_pubkey.png", "crypt-lib — асимметричная криптография", "python examples/ex_pubkey.py",
             run("examples/ex_pubkey.py"))
    terminal("term_stream_attacks.png", "crypt-lib — атаки на потоковые шифры",
             "python examples/ex_stream_attacks.py", run("examples/ex_stream_attacks.py"))
    terminal("term_analysis.png", "crypt-lib — анализ стойкости", "python examples/ex_analysis.py",
             run("examples/ex_analysis.py"))
    terminal("term_classic.png", "crypt-lib — классические шифры и взлом", "python examples/ex_classic.py",
             run("examples/ex_classic.py"))
    terminal("term_padding.png", "crypt-lib — схемы дополнения", "python examples/ex_padding.py",
             run("examples/ex_padding.py")[13:], width=118)
    ecb_vs_cbc()
    ddt_image()
    avalanche_rounds()


if __name__ == "__main__":
    main()
