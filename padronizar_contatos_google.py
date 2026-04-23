#!/usr/bin/env python3
"""
Padroniza contatos CSV para importação no Google Contacts.

O script:
1) Detecta formato legado (ex.: "Phone 1 Label/Value") e converte para formato atual
   (ex.: "Phone 1 - Type/Value").
2) Padroniza telefones brasileiros para +55 DD NNNNN-NNNN / +55 DD NNNN-NNNN.
3) Corrige casos com 0 antes do DDD e celulares antigos de 8 dígitos.
4) Suporta múltiplos números na mesma célula separados por ":::".
"""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path

MULTI_SEPARATOR = re.compile(r"\s*:::\s*")
PHONE_VALUE_PATTERN = re.compile(r"^Phone\s+\d+\s+(?:-\s+)?Value$", re.IGNORECASE)
PHONE_TYPE_PATTERN = re.compile(r"^Phone\s+\d+\s+-\s+Type$", re.IGNORECASE)
TYPE_COL_PATTERN = re.compile(r".+\s+-\s+Type$", re.IGNORECASE)
CLEAR_COLUMNS = {"Group Membership", "Labels"}

LEGACY_EXACT_MAP = {
    "First Name": "Given Name",
    "Middle Name": "Additional Name",
    "Last Name": "Family Name",
    "Phonetic First Name": "Given Name Yomi",
    "Phonetic Middle Name": "Additional Name Yomi",
    "Phonetic Last Name": "Family Name Yomi",
    "File As": "Name",
    "Organization Name": "Organization 1 - Name",
    "Organization Title": "Organization 1 - Title",
    "Organization Department": "Organization 1 - Department",
    "Labels": "Group Membership",
}

LEGACY_SUFFIX_MAP = {
    "Label": "Type",
    "Value": "Value",
    "Formatted": "Formatted",
    "Street": "Street",
    "City": "City",
    "PO Box": "PO Box",
    "Region": "Region",
    "Postal Code": "Postal Code",
    "Country": "Country",
    "Extended Address": "Extended Address",
}


def normalize_single_phone(raw: str) -> str:
    original = (raw or "").strip()
    if not original:
        return ""

    if original.startswith("+") and not original.startswith("+55"):
        return original

    digits = re.sub(r"\D+", "", original)
    if not digits:
        return original

    # remove 0 de tronco (ex.: 071 9xxxx-xxxx)
    if digits.startswith("0") and len(digits) in (11, 12):
        digits = digits[1:]

    if digits.startswith("55") and len(digits) in (12, 13):
        local = digits[2:]
    elif len(digits) in (10, 11):
        local = digits
    else:
        return original

    ddd = local[:2]
    numero = local[2:]
    if len(numero) not in (8, 9):
        return original

    # celular antigo de 8 dígitos -> prefixa 9
    if len(numero) == 8 and numero[0] in "6789":
        numero = "9" + numero

    if len(numero) == 9:
        numero_fmt = f"{numero[:5]}-{numero[5:]}"
    else:
        numero_fmt = f"{numero[:4]}-{numero[4:]}"

    return f"+55 {ddd} {numero_fmt}"


def normalize_cell(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""

    parts = [p for p in MULTI_SEPARATOR.split(text) if p.strip()]
    if not parts:
        return ""

    return " ::: ".join(normalize_single_phone(p) for p in parts)


def normalize_header(old_header: str) -> str:
    h = (old_header or "").strip()
    if h in LEGACY_EXACT_MAP:
        return LEGACY_EXACT_MAP[h]

    m = re.match(r"^(.*\d+)\s+(Label|Value|Formatted|Street|City|PO Box|Region|Postal Code|Country|Extended Address)$", h)
    if m:
        left, suffix = m.groups()
        return f"{left} - {LEGACY_SUFFIX_MAP[suffix]}"

    return h


def build_header_map(fieldnames: list[str]) -> tuple[dict[str, str], list[str], int]:
    header_map: dict[str, str] = {}
    new_fieldnames: list[str] = []
    converted = 0

    for old in fieldnames:
        new = normalize_header(old)
        header_map[old] = new
        if new != old:
            converted += 1
        if new not in new_fieldnames:
            new_fieldnames.append(new)

    return header_map, new_fieldnames, converted


def merge_value(existing: str, incoming: str) -> str:
    a = (existing or "").strip()
    b = (incoming or "").strip()
    if not a:
        return b
    if not b or b == a:
        return a
    return b


def process_csv(input_path: Path, output_path: Path) -> tuple[int, int, int]:
    with input_path.open("r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None:
            raise ValueError("CSV sem cabeçalho.")

        fieldnames = [c or "" for c in reader.fieldnames]
        header_map, new_fieldnames, converted_headers = build_header_map(fieldnames)

        phone_value_columns = [c for c in new_fieldnames if PHONE_VALUE_PATTERN.match(c)]
        phone_type_columns = [c for c in new_fieldnames if PHONE_TYPE_PATTERN.match(c)]

        rows: list[dict[str, str]] = []
        normalized_count = 0
        adjusted_type_count = 0

        for old_row in reader:
            row = {k: "" for k in new_fieldnames}

            for old_col, val in old_row.items():
                new_col = header_map.get(old_col or "", old_col or "")
                row[new_col] = merge_value(row.get(new_col, ""), val or "")

            for col in phone_value_columns:
                old = row.get(col, "")
                new = normalize_cell(old)
                if new != old:
                    row[col] = new
                    normalized_count += 1

            # remove labels/grupos de importação antigos
            for col in CLEAR_COLUMNS:
                if col in row and row[col]:
                    row[col] = ""

            # limpa "* " em tipos e preenche tipo de telefone vazio quando houver número
            for col, val in list(row.items()):
                if TYPE_COL_PATTERN.match(col):
                    cleaned = re.sub(r"^\*\s*", "", (val or "").strip())
                    if cleaned != (val or ""):
                        row[col] = cleaned
                        adjusted_type_count += 1

            for type_col in phone_type_columns:
                m = re.match(r"^Phone\s+(\d+)\s+-\s+Type$", type_col, re.IGNORECASE)
                if not m:
                    continue
                idx = m.group(1)
                value_col = f"Phone {idx} - Value"
                if row.get(value_col, "").strip() and not row.get(type_col, "").strip():
                    row[type_col] = "Mobile"
                    adjusted_type_count += 1

            rows.append(row)

    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=new_fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    return normalized_count, converted_headers, adjusted_type_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Padroniza contatos CSV do Google.")
    parser.add_argument("input_csv", type=Path, help="Arquivo CSV de entrada")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=None,
        help="Arquivo CSV de saída (padrão: <entrada>_padronizado.csv)",
    )
    parser.add_argument("--inplace", action="store_true", help="Sobrescreve o arquivo de entrada")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    input_path = args.input_csv

    if not input_path.exists():
        print(f"Erro: arquivo não encontrado: {input_path}", file=sys.stderr)
        return 1

    if args.inplace and args.output is not None:
        print("Erro: use --inplace ou --output, não os dois.", file=sys.stderr)
        return 1

    output_path = input_path if args.inplace else (args.output or input_path.with_name(f"{input_path.stem}_padronizado.csv"))

    try:
        normalized, converted_headers, adjusted_types = process_csv(input_path, output_path)
    except Exception as exc:
        print(f"Erro ao processar CSV: {exc}", file=sys.stderr)
        return 1

    print(f"OK: arquivo salvo em {output_path}")
    print(f"Telefones padronizados: {normalized}")
    print(f"Cabeçalhos convertidos para formato Google atual: {converted_headers}")
    print(f"Tipos ajustados (limpeza/preenchimento): {adjusted_types}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
