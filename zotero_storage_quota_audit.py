#!/usr/bin/env python3
"""Audita quais anexos provavelmente consomem a quota de armazenamento do Zotero.

Escopo:
- Lê a biblioteca via API do Zotero.
- Classifica anexos por linkMode.
- Estima o espaço consumido a partir da cópia local conhecida em ~/Zotero/storage
  ou do path absoluto de linked_file quando existir.
- Destaca os maiores anexos que provavelmente contam para a quota remota.

Observação:
- `imported_file` e `imported_url` são tratados como anexos que provavelmente
  consomem a quota do Zotero File Storage.
- `linked_file` e `linked_url` são tratados como referências locais/externas e
  não entram na soma da quota remota.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Dict, Iterable, List

import zotero_sync_webdav as zsync

REMOTE_STORAGE_LINK_MODES = {"imported_file", "imported_url"}


def human_size(num_bytes: int | None) -> str:
    """Converte bytes em string curta legível."""
    if num_bytes is None:
        return "desconhecido"
    value = float(num_bytes)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if value < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(value)} {unit}"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num_bytes} B"


def attachment_link_mode(item: dict) -> str:
    """Retorna linkMode normalizado do anexo."""
    return str(item.get("data", {}).get("linkMode") or "").strip().lower()


def counts_toward_remote_storage(item: dict) -> bool:
    """Indica se o anexo provavelmente consome a quota remota do Zotero."""
    return attachment_link_mode(item) in REMOTE_STORAGE_LINK_MODES


def resolve_attachment_local_path(item: dict) -> str | None:
    """Resolve o path local de um anexo, se existir."""
    path = zsync.get_attachment_file_path(item)
    if path:
        return path

    data = item.get("data", {})
    key = item.get("key") or data.get("key")
    if key and zsync.attachment_is_pdf(item):
        return zsync.get_latest_pdf_path(os.path.join(zsync.LOCAL_COPY_DIR, key))
    return None


def build_attachment_audit_row(item: dict, parent_items_by_key: dict[str, dict]) -> dict:
    """Monta uma linha auditável para um anexo."""
    data = item.get("data", {})
    key = item.get("key") or data.get("key") or ""
    parent_key = data.get("parentItem") or ""
    parent_data = (parent_items_by_key.get(parent_key) or {}).get("data", {})

    local_path = resolve_attachment_local_path(item)
    local_exists = bool(local_path and os.path.exists(local_path))
    size_bytes = os.path.getsize(local_path) if local_exists else None

    return {
        "key": key,
        "link_mode": attachment_link_mode(item),
        "content_type": str(data.get("contentType") or ""),
        "filename": zsync.get_filename_from_item(item),
        "title": str(data.get("title") or ""),
        "parent_key": parent_key,
        "parent_title": str(parent_data.get("title") or ""),
        "collections": list(parent_data.get("collections") or data.get("collections") or []),
        "local_path": local_path,
        "local_exists": local_exists,
        "size_bytes": size_bytes,
        "counts_toward_remote_storage": counts_toward_remote_storage(item),
    }


def summarize_rows(rows: Iterable[dict]) -> dict:
    """Resume o inventário de anexos por tipo e quota estimada."""
    rows = list(rows)
    summary = {
        "attachment_total": len(rows),
        "remote_storage_total_bytes": 0,
        "remote_storage_known_size_count": 0,
        "remote_storage_missing_local_count": 0,
        "mode_breakdown": {},
    }

    for row in rows:
        mode = row["link_mode"] or "<vazio>"
        bucket = summary["mode_breakdown"].setdefault(
            mode,
            {
                "count": 0,
                "known_size_count": 0,
                "missing_local_count": 0,
                "total_size_bytes": 0,
                "counts_toward_remote_storage": mode in REMOTE_STORAGE_LINK_MODES,
            },
        )
        bucket["count"] += 1

        if row["size_bytes"] is not None:
            bucket["known_size_count"] += 1
            bucket["total_size_bytes"] += row["size_bytes"]
        else:
            bucket["missing_local_count"] += 1

        if row["counts_toward_remote_storage"]:
            if row["size_bytes"] is not None:
                summary["remote_storage_total_bytes"] += row["size_bytes"]
                summary["remote_storage_known_size_count"] += 1
            else:
                summary["remote_storage_missing_local_count"] += 1

    return summary


def top_remote_storage_rows(rows: Iterable[dict], limit: int) -> List[dict]:
    """Retorna os maiores anexos que provavelmente contam para a quota remota."""
    eligible = [row for row in rows if row["counts_toward_remote_storage"] and row["size_bytes"] is not None]
    eligible.sort(key=lambda row: row["size_bytes"], reverse=True)
    return eligible[:limit]


def print_human_report(summary: dict, rows: List[dict], top_limit: int) -> None:
    """Imprime relatório legível para terminal."""
    print("Relatório de armazenamento do Zotero")
    print(f"- anexos totais: {summary['attachment_total']}")
    print(
        "- quota remota estimada (attachments imported_* com tamanho local conhecido): "
        f"{human_size(summary['remote_storage_total_bytes'])}"
    )
    print(
        f"- attachments remotos com tamanho conhecido: {summary['remote_storage_known_size_count']}"
    )
    print(
        f"- attachments remotos sem cópia local mensurável: {summary['remote_storage_missing_local_count']}"
    )
    print()
    print("Por linkMode:")
    for mode, bucket in sorted(summary["mode_breakdown"].items()):
        remote_tag = "remoto" if bucket["counts_toward_remote_storage"] else "não remoto"
        print(
            f"- {mode}: {bucket['count']} anexos | {remote_tag} | "
            f"tamanho conhecido={bucket['known_size_count']} | "
            f"sem cópia local={bucket['missing_local_count']} | "
            f"total={human_size(bucket['total_size_bytes'])}"
        )

    top_rows = top_remote_storage_rows(rows, top_limit)
    if not top_rows:
        print()
        print("Nenhum anexo remoto com tamanho local conhecido foi encontrado.")
        return

    print()
    print(f"Top {len(top_rows)} anexos remotos por tamanho:")
    for row in top_rows:
        label = row["parent_title"] or row["title"] or row["filename"] or row["key"]
        print(
            f"- {human_size(row['size_bytes'])} | key={row['key']} | mode={row['link_mode']} | "
            f"arquivo={row['filename'] or '<sem nome>'} | pai={label}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audita quais anexos provavelmente consomem a quota do Zotero"
    )
    parser.add_argument("--top", type=int, default=25, help="Número de anexos maiores a mostrar")
    parser.add_argument("--json", action="store_true", help="Emite JSON em vez de texto")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    zot = zsync.connect_zotero_client()
    stats: dict = {}
    attachments, _, _ = zsync.collect_all_attachments(zot, stats)
    parents = zsync.build_item_by_key(zsync.collect_all_bibliographic_items(zot, stats))
    rows = [build_attachment_audit_row(item, parents) for item in attachments]
    summary = summarize_rows(rows)

    if args.json:
        payload = {
            "summary": summary,
            "top_remote_attachments": top_remote_storage_rows(rows, args.top),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    print_human_report(summary, rows, args.top)


if __name__ == "__main__":
    main()
