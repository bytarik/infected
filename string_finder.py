#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Binary -> ASCII strings -> "mantıklı" kelimeler -> frekans tablosu
'Mantıklı' filtresi:
 - Sadece harflerden oluşmalı (isalpha)  →  Idw-Hdw&\"n\\ gibi token'lar elenir
 - Uzunluk 3–24
 - Aşırı tekrar yok (>=4 aynı harf ardışık)
 - En az 3 farklı harf içersin
 - Basit sesli harf oranı (y dahil) 0.2–0.9 arasında
 - Ayrıca teknik whitelist ile (http, dll, exe, api, dns, json, ... ) koruma
"""

import re
import json
import csv
from collections import Counter
from pathlib import Path

# --------- ayarlar ---------
INPUT_BIN = Path("/mnt/data/39c89f6d68ab171c2d939e194af781df185effc9069d27273ec96106a4f7ee26_002B0000.bin")
OUT_RAW_JSON   = Path("/mnt/data/strings_002B0000_raw.json")
OUT_WORDS_TXT  = Path("/mnt/data/strings_002B0000_words.txt")
OUT_TABLE_CSV  = Path("/mnt/data/strings_002B0000_table.csv")
OUT_TABLE_TXT  = Path("/mnt/data/strings_002B0000_table.txt")

MIN_ASCII_RUN = 4   # en az 4 karakterlik ASCII koşusu
TOP_N_TABLE   = 300 # tabloda gösterilecek en popüler N kelime

# ASCII string çıkarımı için regex yerine tek geçişli tarama (stabil ve hızlı)
def extract_ascii_strings(data: bytes, min_len: int = 4):
    out, buf = [], bytearray()
    for b in data:
        if 32 <= b <= 126:      # printable ASCII
            buf.append(b)
        else:
            if len(buf) >= min_len:
                out.append(buf.decode("ascii", "ignore"))
            buf.clear()
    if len(buf) >= min_len:
        out.append(buf.decode("ascii", "ignore"))
    return out

# Kelime yakalayıcı: sadece harflerden oluşan parçaları al
WORD_RE = re.compile(r"[A-Za-z]{3,}")

# Teknik terimleri korumak için basit whitelist
ALLOW = {
    "http","https","tcp","udp","dns","json","xml","dll","exe","api","url",
    "token","cookie","config","mutex","process","service","kernel","driver",
    "chrome","firefox","edge","opera","brave","mozilla","wallet","crypto",
    "windows","microsoft","thread","memory","virtual","protect","alloc",
    "shellcode","payload","packer","sandbox","vmware","virtualbox","wine",
    "cuckoo","antidebug","sleep","tickcount","registry","hkey","win","host",
    "server","client","domain","user","password","credential","stealer","hook",
    "module","plugin","inject","keylogger","mail","smtp","imap","ftp"
}

VOWELS = set("aeiouy")

def looks_meaningful(word: str) -> bool:
    w = word.lower()

    # 1) teknik whitelist
    if w in ALLOW:
        return True

    # 2) sadece harf (örn: Idw-Hdw&\"n\\ -> False)
    if not w.isalpha():
        return False

    # 3) uzunluk
    if not (3 <= len(w) <= 24):
        return False

    # 4) ardışık aşırı tekrar (aaaa vb.)
    if re.search(r"(.)\1\1\1", w):
        return False

    # 5) en az 3 farklı harf
    if len(set(w)) < 3:
        return False

    # 6) basit "sesli harf oranı" (çok uçlarda olanları ele)
    vr = sum(c in VOWELS for c in w) / len(w)
    if vr < 0.20 or vr > 0.90:
        return False

    return True

def main():
    # 1) bin oku ve ASCII stringleri çıkar
    data = INPUT_BIN.read_bytes()
    raw_strings = extract_ascii_strings(data, MIN_ASCII_RUN)

    # 2) ham stringleri kaydet (tekrar üretilebilirlik için)
    OUT_RAW_JSON.write_text(json.dumps(raw_strings, ensure_ascii=False, indent=2), encoding="utf-8")

    # 3) kelimeleri ayıkla
    words = []
    for s in raw_strings:
        words.extend(WORD_RE.findall(s))

    # 4) filtrele (mantıklı kelimeler)
    filtered = [w.lower() for w in words if looks_meaningful(w)]

    # 5) frekans sayımı
    freq = Counter(filtered)
    top_items = freq.most_common(TOP_N_TABLE)

    # 6) çıktı: kelimeler (satır satır)
    OUT_WORDS_TXT.write_text("\n".join(sorted(set(filtered))), encoding="utf-8")

    # 7) çıktı: CSV tablo (kelime,frekans)
    with OUT_TABLE_CSV.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["word", "count"])
        writer.writerows(top_items)

    # 8) çıktı: Markdown tablo (rapora hazır)
    lines = ["| Word | Count |", "|---|---|"]
    for w, c in top_items:
        lines.append(f"| {w} | {c} |")
    OUT_TABLE_TXT.write_text("\n".join(lines), encoding="utf-8")

    print("OK",
          str(OUT_RAW_JSON),
          str(OUT_TABLE_CSV),
          str(OUT_TABLE_TXT),
          str(OUT_WORDS_TXT))

if __name__ == "__main__":
    main()
