#!/usr/bin/env python3
"""Audita onde os anexos do Zotero provavelmente ocupam espaço.

Escopo:
- Lê a biblioteca via API do Zotero.
- Classifica anexos por `linkMode`.
- Estima o espaço consumido a partir da cópia local conhecida em `~/Zotero/storage`
  ou do path absoluto de `linked_file` quando existir.
- Lê a configuração local do Zotero Desktop para distinguir o backend de sync de
  arquivos configurado (`webdav`, `zotero`, etc.).
- Destaca os maiores anexos importados segundo o backend configurado.

Observação:
- `imported_file` e `imported_url` são anexos gerenciados pelo Zotero.
- Se o Zotero Desktop estiver configurado para `webdav`, eles devem ser tratados
  principalmente como ocupação do backend WebDAV, não da quota do zotero.org.
- `linked_file` e `linked_url` são referências locais/externas e não entram na
  soma de anexos gerenciados pelo Zotero.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from typing import Dict, Iterable, List

import zotero_sync_webdav as zsync

REMOTE_STORAGE_LINK_MODES = {"imported_file", "imported_url"}


def parse_pref_value(line: str) -> str | None:
    match = re.match(r'user_pref\("[^"]+",\s*(.+)\);$', line.strip())
    if not match:
        return None
    raw = match.group(1).strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if raw in {'true', 'false'}:
        return raw
    return raw


def get_desktop_storage_settings() -> dict:
    profile_dir = zsync.resolve_zotero_profile_dir()
    prefs_path = profile_dir / 'prefs.js' if profile_dir else None
    settings = {
        'profile_dir': str(profile_dir) if profile_dir else '',
        'prefs_path': str(prefs_path) if prefs_path else '',
        'protocol': 'unknown',
        'url': '',
        'username': '',
        'verified': '',
    }
    if not prefs_path or not prefs_path.exists():
        return settings

    by_key = {}
    for line in prefs_path.read_text(encoding='utf-8', errors='replace').splitlines():
        if 'extensions.zotero.sync.storage.' not in line:
            continue
        m = re.match(r'user_pref\("([^"]+)",', line.strip())
        if not m:
            continue
        key = m.group(1)
        value = parse_pref_value(line)
        if value is not None:
            by_key[key] = value
    settings['protocol'] = str(by_key.get('extensions.zotero.sync.storage.protocol') or 'unknown')
    settings['url'] = str(by_key.get('extensions.zotero.sync.storage.url') or '')
    settings['username'] = str(by_key.get('extensions.zotero.sync.storage.username') or '')
    settings['verified'] = str(by_key.get('extensions.zotero.sync.storage.verified') or '')
    return settings


def managed_attachment_backend(link_mode: str, storage_settings: dict) -> str:
    if link_mode in {'linked_file', 'linked_url'}:
        return 'linked'
    if link_mode not in REMOTE_STORAGE_LINK_MODES:
        return 'other'
    protocol = (storage_settings.get('protocol') or 'unknown').lower()
    if protocol == 'webdav':
        return 'webdav'
    if protocol in {'zotero', 'zotero.org'}:
        return 'zotero'
    return f'managed:{protocol}'


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


def build_attachment_audit_row(item: dict, parent_items_by_key: dict[str, dict], storage_settings: dict) -> dict:
    """Monta uma linha auditável para um anexo."""
    data = item.get("data", {})
    key = item.get("key") or data.get("key") or ""
    parent_key = data.get("parentItem") or ""
    parent_data = (parent_items_by_key.get(parent_key) or {}).get("data", {})
    link_mode = attachment_link_mode(item)

    local_path = resolve_attachment_local_path(item)
    local_exists = bool(local_path and os.path.exists(local_path))
    size_bytes = os.path.getsize(local_path) if local_exists else None

    return {
        "key": key,
        "link_mode": link_mode,
        "managed_backend": managed_attachment_backend(link_mode, storage_settings),
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


def summarize_rows(rows: Iterable[dict], storage_settings: dict) -> dict:
    """Resume o inventário de anexos por tipo e backend configurado."""
    rows = list(rows)
    managed_backend_name = managed_attachment_backend("imported_file", storage_settings)
    summary = {
        "attachment_total": len(rows),
        "desktop_storage_settings": storage_settings,
        "managed_backend_name": managed_backend_name,
        "managed_backend_total_bytes": 0,
        "managed_backend_known_size_count": 0,
        "managed_backend_missing_local_count": 0,
        "mode_breakdown": {},
        "backend_breakdown": {},
    }

    for row in rows:
        mode = row["link_mode"] or "<vazio>"
        backend = row["managed_backend"] or "unknown"

        mode_bucket = summary["mode_breakdown"].setdefault(
            mode,
            {
                "count": 0,
                "known_size_count": 0,
                "missing_local_count": 0,
                "total_size_bytes": 0,
                "managed_backend": backend,
            },
        )
        mode_bucket["count"] += 1

        backend_bucket = summary["backend_breakdown"].setdefault(
            backend,
            {
                "count": 0,
                "known_size_count": 0,
                "missing_local_count": 0,
                "total_size_bytes": 0,
            },
        )
        backend_bucket["count"] += 1

        if row["size_bytes"] is not None:
            mode_bucket["known_size_count"] += 1
            mode_bucket["total_size_bytes"] += row["size_bytes"]
            backend_bucket["known_size_count"] += 1
            backend_bucket["total_size_bytes"] += row["size_bytes"]
        else:
            mode_bucket["missing_local_count"] += 1
            backend_bucket["missing_local_count"] += 1

        if row["counts_toward_remote_storage"]:
            if row["size_bytes"] is not None:
                summary["managed_backend_total_bytes"] += row["size_bytes"]
                summary["managed_backend_known_size_count"] += 1
            else:
                summary["managed_backend_missing_local_count"] += 1

    return summary


def top_managed_rows(rows: Iterable[dict], limit: int) -> List[dict]:
    """Retorna os maiores anexos gerenciados pelo Zotero."""
    eligible = [row for row in rows if row["counts_toward_remote_storage"] and row["size_bytes"] is not None]
    eligible.sort(key=lambda row: row["size_bytes"], reverse=True)
    return eligible[:limit]


def print_human_report(summary: dict, rows: List[dict], top_limit: int) -> None:
    """Imprime relatório legível para terminal."""
    settings = summary["desktop_storage_settings"]
    print("Relatório de armazenamento do Zotero")
    print(f"- anexos totais: {summary['attachment_total']}")
    print(
        f"- backend de sync de arquivos no Zotero Desktop: {settings['protocol']}"
        + (f" ({settings['url']})" if settings.get('url') else "")
    )
    print(
        f"- anexos imported_* estimados sob backend {summary['managed_backend_name']}: "
        f"{human_size(summary['managed_backend_total_bytes'])}"
    )
    print(
        f"- anexos imported_* com tamanho conhecido: {summary['managed_backend_known_size_count']}"
    )
    print(
        f"- anexos imported_* sem cópia local mensurável: {summary['managed_backend_missing_local_count']}"
    )
    print()
    print("Por linkMode:")
    for mode, bucket in sorted(summary["mode_breakdown"].items()):
        print(
            f"- {mode}: {bucket['count']} anexos | backend={bucket['managed_backend']} | "
            f"tamanho conhecido={bucket['known_size_count']} | "
            f"sem cópia local={bucket['missing_local_count']} | "
            f"total={human_size(bucket['total_size_bytes'])}"
        )

    print()
    print("Por backend estimado:")
    for backend, bucket in sorted(summary["backend_breakdown"].items()):
        print(
            f"- {backend}: {bucket['count']} anexos | tamanho conhecido={bucket['known_size_count']} | "
            f"sem cópia local={bucket['missing_local_count']} | total={human_size(bucket['total_size_bytes'])}"
        )

    top_rows = top_managed_rows(rows, top_limit)
    if not top_rows:
        print()
        print("Nenhum anexo gerenciado pelo Zotero com tamanho local conhecido foi encontrado.")
        return

    print()
    print(f"Top {len(top_rows)} anexos gerenciados pelo Zotero por tamanho:")
    for row in top_rows:
        label = row["parent_title"] or row["title"] or row["filename"] or row["key"]
        print(
            f"- {human_size(row['size_bytes'])} | key={row['key']} | mode={row['link_mode']} | "
            f"backend={row['managed_backend']} | arquivo={row['filename'] or '<sem nome>'} | pai={label}"
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

    storage_settings = get_desktop_storage_settings()
    zot = zsync.connect_zotero_client()
    stats: dict = {}
    attachments, _, _ = zsync.collect_all_attachments(zot, stats)
    parents = zsync.build_item_by_key(zsync.collect_all_bibliographic_items(zot, stats))
    rows = [build_attachment_audit_row(item, parents, storage_settings) for item in attachments]
    summary = summarize_rows(rows, storage_settings)

    if args.json:
        payload = {
            "summary": summary,
            "top_managed_attachments": top_managed_rows(rows, args.top),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    print_human_report(summary, rows, args.top)


if __name__ == "__main__":
    main()
