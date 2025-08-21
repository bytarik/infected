#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bin_strings_to_table.py
Bir .bin dosyasındaki ASCII ve UTF-16LE string'leri çıkarıp tablo olarak dışa verir.
"""


import argparse
import mmap
import os
import re
import csv
import json
from typing import Iterator, Tuple, List

# ASCII: 0x20-0x7E aralığı (boşluk dahil), en az N uzunluk
ASCII_PATTERN = rb'[\x20-\x7E]{%d,}'
# UTF-16LE: (ASCII byte + \x00) deseninin en az N tekrarı
UTF16LE_PATTERN = rb'(?:[\x20-\x7E]\x00){%d,}'

def extract_strings(path: str, min_len: int = 4) -> List[dict]:
    """Dosyadan ASCII ve UTF-16LE string'leri çıkarır."""
    results = []
    ascii_re = re.compile(ASCII_PATTERN % min_len, re.DOTALL)
    u16_re   = re.compile(UTF16LE_PATTERN % min_len, re.DOTALL)

    file_size = os.path.getsize(path)
    if file_size == 0:
        return results

    with open(path, 'rb') as f, \
         mmap.mmap(f.fileno(), length=0, access=mmap.ACCESS_READ) as mm:

        # ASCII
        for m in ascii_re.finditer(mm):
            s = m.group().decode('ascii', errors='ignore')
            results.append({
                "offset_dec": m.start(),
                "offset_hex": f"0x{m.start():X}",
                "encoding": "ASCII",
                "length": len(s),
                "string": s
            })

        # UTF-16LE
        for m in u16_re.finditer(mm):
            s = m.group().decode('utf-16le', errors='ignore')
            results.append({
                "offset_dec": m.start(),
                "offset_hex": f"0x{m.start():X}",
                "encoding": "UTF-16LE",
                "length": len(s),
                "string": s
            })

    # Offsete göre sırala
    results.sort(key=lambda x: x["offset_dec"])
    return results

def print_table(rows: List[dict], max_width: int = 120, max_str: int = 80) -> None:
    """Basit bir tabloyu ekrana yazar (harici kütüphane gerekmez)."""
    def truncate(s: str, n: int) -> str:
        return s if len(s) <= n else s[: n - 1] + "…"

    headers = ["offset_hex", "encoding", "length", "string"]
    # Sütun genişlikleri
    colw = {
        "offset_hex": max(10, max((len(r["offset_hex"]) for r in rows), default=10)),
        "encoding":  max(8,  max((len(r["encoding"]) for r in rows), default=8)),
        "length":    max(6,  max((len(str(r["length"])) for r in rows), default=6)),
        "string":    max(6,  min(max_str, max((len(r["string"]) for r in rows), default=6)))
    }
    bar = "+".join([
        "-" * (colw["offset_hex"] + 2),
        "-" * (colw["encoding"]  + 2),
        "-" * (colw["length"]    + 2),
        "-" * (colw["string"]    + 2),
    ])
    bar = "+" + bar + "+"

    def fmt_row(r):
        return "| " + " | ".join([
            f"{r['offset_hex']:<{colw['offset_hex']}}",
            f"{r['encoding']:<{colw['encoding']}}",
            f"{r['length']:<{colw['length']}}",
            f"{truncate(r['string'], colw['string']):<{colw['string']}}",
        ]) + " |"

    # Başlık
    print(bar)
    print(fmt_row({"offset_hex":"offset_hex","encoding":"encoding","length":"length","string":"string"}))
    print(bar)
    # Satırlar
    for r in rows:
        print(fmt_row(r))
    print(bar)

def save_csv(rows: List[dict], out_path: str) -> None:
    with open(out_path, "w", newline="", encoding="utf-8") as fp:
        writer = csv.DictWriter(fp, fieldnames=["offset_dec","offset_hex","encoding","length","string"])
        writer.writeheader()
        writer.writerows(rows)

def save_json(rows: List[dict], out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as fp:
        json.dump(rows, fp, ensure_ascii=False, indent=2)

def save_xlsx(rows: List[dict], out_path: str) -> None:
    """Pandas + openpyxl/xlsxwriter yüklüyse XLSX'e yazar, değilse CSV önerir."""
    try:
        import pandas as pd  # type: ignore
    except Exception:
        raise RuntimeError("XLSX için 'pandas' (ve openpyxl/xlsxwriter) gereklidir. Önce kurun: pip install pandas openpyxl")

    df = pd.DataFrame(rows, columns=["offset_dec","offset_hex","encoding","length","string"])
    df.to_excel(out_path, index=False)

def main():
    ap = argparse.ArgumentParser(description="BIN içindeki string'leri çıkar ve tablo oluştur.")
    ap.add_argument("bin_path", help=".bin / herhangi bir ikili dosya yolu")
    ap.add_argument("-m","--min-len", type=int, default=4, help="Minimum string uzunluğu (varsayılan: 4)")
    ap.add_argument("-o","--output", help="Çıktı dosyası (uzantıya göre CSV/JSON/XLSX)")
    ap.add_argument("--print", action="store_true", help="Tabloyu ekrana yazdır")
    args = ap.parse_args()

    rows = extract_strings(args.bin_path, min_len=args.min_len)

    if args.print or not args.output:
        print_table(rows)

    if args.output:
        ext = os.path.splitext(args.output)[1].lower()
        if ext in (".csv", ""):
            save_csv(rows, args.output or "strings.csv")
        elif ext == ".json":
            save_json(rows, args.output)
        elif ext in (".xlsx", ".xls"):
            save_xlsx(rows, args.output)
        else:
            # Tanınmayan uzantı -> CSV
            save_csv(rows, args.output)

if __name__ == "__main__":
    main()
