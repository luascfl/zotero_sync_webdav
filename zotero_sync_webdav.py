"""Sincronizador bidirecional assistido entre uma pasta de PDFs no drive montado,
a biblioteca Zotero via API e o storage local em ~/Zotero/storage.

Workflow real deste script:
1. Lê configuração e resolve a pasta alvo montada no sistema de arquivos.
2. Consulta a API do Zotero para descobrir quais anexos já existem e qual chave cada
   nome conhecido aponta no servidor.
3. Indexa o storage local do Zotero em ~/Zotero/storage por hash SHA-256.
   Essa cópia local não é só cache. Ela é a âncora operacional do fluxo:
   - permite comparar conteúdo sem depender apenas do nome,
   - permite detectar renomeações entre drive e Zotero,
   - permite reconstruir a cópia local quando o Zotero conhece o anexo mas o storage
     local ainda não tem o PDF correspondente.
4. Varre os PDFs da pasta montada no drive.
5. Para cada PDF do drive, decide entre cinco caminhos:
   - caso 1: mesmo nome e mesmo conteúdo, então já está sincronizado;
   - caso 2: mesmo nome e conteúdo diferente, então o drive passou a ser a versão
     mais recente e a cópia local do Zotero é atualizada;
   - caso 3: mesmo conteúdo e nomes diferentes, então há conflito de nome e o lado
     mais recente por mtime define o título canônico temporário;
   - caso 4: o arquivo existe no drive, mas não existe no Zotero, então ele é enviado
     ao Zotero e também copiado para ~/Zotero/storage;
   - caso 5: o Zotero conhece o anexo, mas a cópia local em ~/Zotero/storage está
     ausente, então a cópia local é recriada a partir do drive.
6. Após a varredura do drive, reconcilia Zotero -> drive: anexos PDF que existem
   no Zotero e não têm correspondente no drive são materializados no drive a partir
   da cópia local ou, se ela faltar, baixados da API do Zotero primeiro.

Regras operacionais definidas pelo usuário para conflitos:
- presença é bidirecional: drive sem Zotero deve ir para o Zotero; Zotero sem drive
  deve ser materializado no drive automaticamente;
- em hash_match com nomes diferentes, o lado com mtime mais recente vira a fonte de
  verdade temporária para o título;
- se o Zotero estiver mais recente, renomeia-se o drive;
- se o drive estiver mais recente, modifica-se o Zotero para refletir o nome do drive,
  porque esse foi o ajuste manual mais recente do usuário.

Limites atuais importantes:
- a reconciliação bidirecional cobre nomes, hashes, cópia local e materialização de
  PDFs do Zotero para o drive;
- mounts FUSE/rclone podem listar arquivos mas travar na leitura do conteúdo, então o
  script faz probes e usa timeouts para distinguir lentidão de mount quebrado.
"""

import argparse
import atexit
import hashlib
import heapq
from difflib import SequenceMatcher
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Tuple
from urllib.parse import unquote
from pyzotero import zotero
from tqdm import tqdm

SCRIPT_DIR = Path(__file__).resolve().parent

CONFIG_ENV_FILE = Path.home() / ".config" / "zotero_sync_webdav" / "zotero_sync.env"
PROJECT_ENV_FILE = SCRIPT_DIR / ".env"
env_file_from_env = os.environ.get("ZOTERO_ENV_FILE")


def load_env_file(env_path: os.PathLike[str] | str, override: bool = False) -> None:
    """Carrega variáveis de ambiente a partir de um arquivo .env simples."""
    if not env_path:
        return
    env_file = Path(env_path)
    if not env_file.is_file():
        return
    try:
        for raw_line in env_file.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"').strip("'")
            if key and (override or key not in os.environ):
                os.environ[key] = value
    except OSError as exc:
        logging.warning("Falha ao carregar variáveis do arquivo %s: %s", env_file, exc)


if env_file_from_env:
    load_env_file(env_file_from_env, override=True)
else:
    # Prioriza a configuração operacional do serviço/autostart. O .env do projeto fica
    # como fallback local para desenvolvimento e não deve sobrescrever a configuração operacional.
    load_env_file(CONFIG_ENV_FILE, override=True)
    load_env_file(PROJECT_ENV_FILE, override=False)

# --- Configuração Final (via .env / variáveis de ambiente) ---
LIBRARY_ID = os.environ.get("ZOTERO_LIBRARY_ID")
LIBRARY_TYPE = os.environ.get("ZOTERO_LIBRARY_TYPE", "user")
API_KEY = os.environ.get("ZOTERO_API_KEY")

TARGET_FOLDER_RAW = os.environ.get("ZOTERO_SYNC_TARGET_FOLDER")

missing_env = [name for name, value in {
    "ZOTERO_LIBRARY_ID": LIBRARY_ID,
    "ZOTERO_API_KEY": API_KEY,
    "ZOTERO_SYNC_TARGET_FOLDER": TARGET_FOLDER_RAW,
}.items() if not value]

if missing_env:
    raise RuntimeError(
        f"Defina as variáveis de ambiente obrigatórias ({', '.join(missing_env)}). "
        "Use ~/.config/zotero_sync_webdav/zotero_sync.env, um .env na raiz do projeto, "
        "ZOTERO_ENV_FILE ou exporte-as antes de executar."
    )


def resolve_target_folder(raw_path: str) -> str:
    """Resolve o caminho da pasta alvo, tentando decodificar espaços/percent-encoding."""
    expanded = os.path.expanduser(raw_path)
    candidates = [expanded]

    if "%" in expanded:
        decoded_uri = unquote(expanded)
        if decoded_uri not in candidates:
            candidates.append(decoded_uri)
        decoded_spaces = expanded.replace("%20", " ")
        if decoded_spaces not in candidates:
            candidates.append(decoded_spaces)

    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return expanded


TARGET_FOLDER = resolve_target_folder(TARGET_FOLDER_RAW)

# Pasta onde o Zotero Desktop espera encontrar os anexos importados.
# Esta cópia local em ~/Zotero/storage é necessária para o workflow prático do projeto:
# sem ela, o script perde a referência de conteúdo usada para comparar hashes,
# reconstruir anexos locais ausentes e decidir renomeações entre drive e Zotero.
LOCAL_COPY_DIR = os.path.join(os.path.expanduser("~"), "Zotero", "storage")

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "zotero_sync_webdav")
CACHE_FILE = os.path.join(CACHE_DIR, "hash_cache.json")
CACHE_VERSION = 1

LOG_DIR = os.path.join(CACHE_DIR, "logs")
LOG_FILE_NAME = "zotero_sync_today.log"
LOG_DATE_FILE = os.path.join(LOG_DIR, ".last_log_date")
LOG_DESKTOP_ID = "zotero-sync-log"
LOG_DESKTOP_FILE = os.path.join(
    os.path.expanduser("~"),
    ".local",
    "share",
    "applications",
    f"{LOG_DESKTOP_ID}.desktop",
)

HASH_CACHE: Dict[str, dict] = {}

# FIX: Limites aumentados para cobrir bibliotecas grandes.
# 0 = sem limite (processa tudo).
MAX_FILES_TO_CHECK = 0        # 0 = todos os PDFs da pasta
MAX_ATTACHMENTS_TO_CHECK = 0  # 0 = todos os anexos do Zotero

# Ativar logs detalhados no console
DEBUG_DETAILED = True
HASH_READ_TIMEOUT_SECONDS_DEFAULT = 180
CONTENT_PROBE_TIMEOUT_SECONDS_DEFAULT = 60
PYZOTERO_UPLOAD_TIMEOUT_SECONDS_DEFAULT = 900


def get_env_int(name: str, default: int) -> int:
    """Lê inteiro de ambiente com fallback seguro."""
    raw_value = os.environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        value = int(raw_value)
    except ValueError:
        logging.warning("Valor inválido para %s=%r. Usando %d.", name, raw_value, default)
        return default
    return max(0, value)


HASH_READ_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_HASH_TIMEOUT_SECONDS",
    HASH_READ_TIMEOUT_SECONDS_DEFAULT,
)
CONTENT_PROBE_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_CONTENT_PROBE_TIMEOUT_SECONDS",
    CONTENT_PROBE_TIMEOUT_SECONDS_DEFAULT,
)
PYZOTERO_UPLOAD_TIMEOUT_SECONDS = get_env_int(
    "ZOTERO_UPLOAD_TIMEOUT_SECONDS",
    PYZOTERO_UPLOAD_TIMEOUT_SECONDS_DEFAULT,
)


def configure_pyzotero_upload_transport(
    timeout_seconds: int = PYZOTERO_UPLOAD_TIMEOUT_SECONDS,
) -> None:
    """Ajusta timeouts e exceções do upload Pyzotero/httpx para arquivos grandes.

    Pyzotero 1.7.3 chama `httpx.post(...)` diretamente no upload S3 usando o
    timeout padrão do httpx. Esse padrão é curto para PDFs grandes e pode gerar
    `WriteTimeout`. Além disso, essa versão tenta capturar `httpx.ConnectionError`,
    atributo que não existe em httpx 0.28.1, mascarando o erro real com
    `module 'httpx' has no attribute 'ConnectionError'`.
    """
    httpx_module = zotero.httpx

    if not hasattr(httpx_module, "ConnectionError"):
        httpx_module.ConnectionError = httpx_module.TransportError
        logging.info(
            "[ZOT-UPLOAD] Compatibilidade aplicada: httpx.ConnectionError -> httpx.TransportError."
        )

    if getattr(httpx_module, "_zotero_sync_webdav_post_patched", False):
        return

    original_post = httpx_module.post

    def post_with_upload_timeout(*args, **kwargs):
        if "timeout" not in kwargs:
            if timeout_seconds > 0:
                kwargs["timeout"] = httpx_module.Timeout(
                    timeout_seconds,
                    connect=min(timeout_seconds, 30),
                    read=timeout_seconds,
                    write=timeout_seconds,
                    pool=timeout_seconds,
                )
            else:
                kwargs["timeout"] = None
        return original_post(*args, **kwargs)

    httpx_module.post = post_with_upload_timeout
    httpx_module._zotero_sync_webdav_post_patched = True
    logging.info(
        "[ZOT-UPLOAD] Timeout padrão para upload Pyzotero configurado em %ss.",
        timeout_seconds if timeout_seconds > 0 else "sem limite",
    )


def probe_pdf_content_read(
    path: str,
    timeout_seconds: int = CONTENT_PROBE_TIMEOUT_SECONDS,
    bytes_to_read: int = 65536,
) -> bool:
    """Testa leitura curta de conteúdo em subprocesso para detectar mount travado."""
    if not path:
        return False
    if timeout_seconds <= 0:
        logging.info("[PROBE] Probe de conteúdo desativado para '%s'.", path)
        return True

    logging.info(
        "[PROBE] Testando leitura inicial de %d bytes de '%s' (timeout=%ss).",
        bytes_to_read,
        path,
        timeout_seconds,
    )
    probe_code = (
        "import sys\n"
        "path = sys.argv[1]\n"
        "size = int(sys.argv[2])\n"
        "with open(path, 'rb') as handle:\n"
        "    handle.read(size)\n"
    )
    started_at = time.monotonic()
    process: subprocess.Popen[str] | None = None
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", probe_code, path, str(bytes_to_read)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        while True:
            return_code = process.poll()
            if return_code is not None:
                break

            elapsed = time.monotonic() - started_at
            if elapsed >= timeout_seconds:
                process.kill()
                logging.error(
                    "[PROBE] Timeout após %.1fs lendo '%s'. Processo filho pid=%s pode ficar preso em I/O do mount; abortando o sync.",
                    elapsed,
                    path,
                    process.pid,
                )
                return False

            time.sleep(0.2)

        _, stderr = process.communicate()
        if return_code != 0:
            logging.error(
                "[PROBE] Falha ao ler conteúdo de '%s' (rc=%s): %s",
                path,
                return_code,
                (stderr or "").strip(),
            )
            return False
    except OSError as exc:
        logging.error("[PROBE] Erro ao executar probe de conteúdo para '%s': %s", path, exc)
        return False

    elapsed = time.monotonic() - started_at
    logging.info("[PROBE] Leitura inicial OK para '%s' em %.1fs.", path, elapsed)
    return True


def prepare_daily_log_file() -> str | None:
    """Garante um log diário único e retorna o caminho."""
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except OSError as exc:
        print(f"[LOG] Não foi possível preparar pasta de logs: {exc}")
        return None

    today_str = datetime.now().strftime("%Y-%m-%d")
    needs_reset = True
    try:
        last_date = Path(LOG_DATE_FILE).read_text(encoding="utf-8").strip()
        if last_date == today_str and os.path.exists(os.path.join(LOG_DIR, LOG_FILE_NAME)):
            needs_reset = False
    except FileNotFoundError:
        pass
    except OSError:
        pass

    log_path = os.path.join(LOG_DIR, LOG_FILE_NAME)
    mode = "w" if needs_reset else "a"
    try:
        with open(log_path, mode, encoding="utf-8") as fh:
            if needs_reset:
                fh.write(f"# Log diário do Zotero Sync - {today_str}\n\n")
            fh.write(f"--- Execução iniciada: {datetime.now().isoformat()} ---\n")
        Path(LOG_DATE_FILE).write_text(today_str, encoding="utf-8")
    except OSError as exc:
        print(f"[LOG] Não foi possível inicializar o log diário: {exc}")
        return None

    return log_path


LOG_FILE_PATH = prepare_daily_log_file()

handlers: List[logging.Handler] = [logging.StreamHandler()]
if LOG_FILE_PATH:
    try:
        file_handler = logging.FileHandler(LOG_FILE_PATH, encoding="utf-8")
        handlers.append(file_handler)
    except OSError as exc:
        print(f"[LOG] Não foi possível anexar handler de arquivo: {exc}")

logging.basicConfig(
    level=logging.DEBUG if DEBUG_DETAILED else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=handlers,
)

if LOG_FILE_PATH:
    logging.info("Log diário: %s", LOG_FILE_PATH)
else:
    logging.info("Log diário indisponível (falha ao criar arquivo).")


def ensure_log_desktop_entry(log_path: str) -> str | None:
    """Garante um .desktop que abre o log diário em um clique."""
    if not log_path:
        return None

    desktop_dir = os.path.dirname(LOG_DESKTOP_FILE)
    try:
        os.makedirs(desktop_dir, exist_ok=True)
    except OSError as exc:
        logging.warning("[LOG] Não foi possível preparar pasta de desktop entries: %s", exc)
        return None

    exec_cmd = f"xdg-open {shlex.quote(os.path.abspath(log_path))}"
    desktop_content = "\n".join(
        [
            "[Desktop Entry]",
            "Type=Application",
            "Terminal=false",
            "Name=Zotero Sync - Log de hoje",
            "Comment=Abre o log diário do sincronizador Zotero/WebDAV",
            f"Exec={exec_cmd}",
            "Icon=text-x-log",
            "Categories=Utility;",
        ]
    ) + "\n"

    try:
        if os.path.exists(LOG_DESKTOP_FILE):
            existing = Path(LOG_DESKTOP_FILE).read_text(encoding="utf-8")
            if existing == desktop_content:
                return LOG_DESKTOP_ID
        Path(LOG_DESKTOP_FILE).write_text(desktop_content, encoding="utf-8")
    except OSError as exc:
        logging.warning("[LOG] Não foi possível atualizar desktop entry: %s", exc)
        return None

    return LOG_DESKTOP_ID


def send_completion_notification(stats: dict, log_path: str | None) -> None:
    """Envia notificação sobre a execução e oferece abertura rápida do log."""
    if shutil.which("notify-send") is None:
        logging.debug("[NOTIFY] notify-send não encontrado; pulando notificação.")
        return

    body_parts = [
        f"Adicionados: {stats.get('added', 0)}",
        f"Existentes: {stats.get('skipped', 0)}",
        f"Erros: {stats.get('errors', 0)}",
    ]
    body = " • ".join(body_parts)
    if log_path:
        body += "\nClique para abrir o log de hoje."

    cmd = ["notify-send", "-a", "Zotero Sync", "-i", "text-x-log"]

    desktop_hint = ensure_log_desktop_entry(log_path) if log_path else None
    if desktop_hint:
        cmd.extend(["-h", f"string:desktop-entry:{desktop_hint}"])

    cmd.extend(["Sincronização Zotero/WebDAV concluída", body])

    try:
        subprocess.run(cmd, check=False)
    except Exception as exc:
        logging.warning("[NOTIFY] Falha ao enviar notificação: %s", exc)


def finalize_execution(stats: dict, summary_text: str | None = None) -> None:
    """Atualiza o log diário e dispara a notificação."""
    if LOG_FILE_PATH:
        try:
            with open(LOG_FILE_PATH, "a", encoding="utf-8") as fh:
                if summary_text:
                    fh.write("\n")
                    fh.write(summary_text)
                    fh.write("\n")
                fh.write(f"--- Execução finalizada: {datetime.now().isoformat()} ---\n")
        except OSError as exc:
            logging.warning("[LOG] Não foi possível gravar o resumo no log diário: %s", exc)

    send_completion_notification(stats, LOG_FILE_PATH)


if TARGET_FOLDER_RAW != TARGET_FOLDER:
    logging.info("Pasta alvo configurada: %s (valor original: %s)", TARGET_FOLDER, TARGET_FOLDER_RAW)
else:
    logging.info("Pasta alvo configurada: %s", TARGET_FOLDER)
logging.info("Biblioteca Zotero configurada: %s (%s)", LIBRARY_ID, LIBRARY_TYPE)


# --- Funções de Normalização ---

def normalize_filename(fname: str) -> str:
    """Normalização básica: NFC, minúsculas, sem espaços nas bordas."""
    if not fname:
        return ""
    try:
        return unicodedata.normalize('NFC', fname).lower().strip()
    except Exception as e:
        logging.warning(f"Erro ao normalizar '{fname}': {e}")
        return ""


def normalize_aggressive(fname: str) -> str:
    """Normalização agressiva: remove acentos, caracteres especiais e espaços extras."""
    if not fname:
        return ""
    try:
        nfkd_form = unicodedata.normalize('NFD', fname)
        normalized = "".join([c for c in nfkd_form if not unicodedata.combining(c)])
        normalized = normalized.lower()
        normalized = re.sub(r'[^a-z0-9\s._-]', '', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized
    except Exception as e:
        logging.warning(f"Erro na normalização agressiva de '{fname}': {e}")
        return ""


def get_filename_from_item(item: dict) -> str:
    """Extrai o nome do arquivo de um item de anexo da Pyzotero."""
    data = item.get('data', {})
    filename = data.get('filename', '')
    if filename:
        return filename
    path = data.get('path')
    if path:
        try:
            path_str = str(path)
            if path_str.startswith("file:///"):
                path_str = path_str[8:]
            elif path_str.startswith("file://"):
                path_str = path_str[7:]
            elif path_str.startswith("file:"):
                path_str = path_str[5:]
            elif path_str.startswith("storage:"):
                path_str = path_str.split(":", 1)[-1]
            path_str = path_str.replace("\\", "/")
            return os.path.basename(path_str)
        except Exception:
            pass
    return ""


def parse_zotero_date(date_str: str) -> datetime | None:
    """Converte a string de data do Zotero em datetime."""
    if not date_str:
        return None
    try:
        normalized = date_str.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized)
    except ValueError:
        logging.warning("[ZOT] Data inválida recebida: %s", date_str)
        return None

def normalize_bibliographic_text(value: str) -> str:
    """Normaliza texto bibliográfico para comparação conservadora de títulos."""
    if not value:
        return ""
    try:
        decomposed = unicodedata.normalize('NFD', str(value))
        without_accents = "".join(
            char for char in decomposed if not unicodedata.combining(char)
        )
        lowered = without_accents.lower()
        alnum_only = re.sub(r'[^a-z0-9]+', ' ', lowered)
        return re.sub(r'\s+', ' ', alnum_only).strip()
    except Exception as exc:
        logging.warning("[BIB] Erro ao normalizar texto bibliográfico %r: %s", value, exc)
        return ""


def normalize_doi(value: str | None) -> str:
    """Normaliza DOI para chave estável de comparação bibliográfica."""
    if not value:
        return ""
    doi = str(value).strip().lower()
    for prefix in ("https://doi.org/", "http://doi.org/", "doi:"):
        if doi.startswith(prefix):
            doi = doi[len(prefix):]
    return doi.strip()


def filename_title_candidates(filename: str) -> List[str]:
    """Gera candidatos de título a partir de um nome de PDF no padrão Zotero."""
    stem = Path(os.path.basename(filename)).stem
    raw_variants: list[str] = [stem]

    def clean(value: str) -> str:
        value = value.replace("_", " ")
        value = re.sub(r'\s*\(\d+\)\s*$', '', value)
        value = re.sub(r'(\b(?:18|19|20)\d{2})\s+\d+\s*$', r'\1', value)
        value = re.sub(r'\s+', ' ', value)
        return value.strip(" -_.")

    cleaned = clean(stem)
    raw_variants.append(cleaned)

    if " - " in cleaned:
        left, right = cleaned.rsplit(" - ", 1)
        if re.search(r'\b(?:18|19|20)\d{2}\b', right) or len(right.split()) <= 4:
            raw_variants.append(left)

    without_leading_citation = re.sub(
        r'^[A-Za-zÀ-ÿ0-9 ,._&+-]+?\(\s*(?:18|19|20)\d{2}\s*\)\s+',
        '',
        cleaned,
    )
    if without_leading_citation != cleaned:
        raw_variants.append(without_leading_citation)
        if " - " in without_leading_citation:
            raw_variants.append(without_leading_citation.rsplit(" - ", 1)[0])

    candidates: list[str] = []
    seen: set[str] = set()
    for variant in raw_variants:
        normalized = normalize_bibliographic_text(clean(variant))
        if len(normalized) < 20 or normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)
    return candidates


def title_match_score(candidate_title: str, item_title: str) -> float:
    """Pontua uma possível correspondência de título sem aceitar palpites fracos."""
    candidate = normalize_bibliographic_text(candidate_title)
    title = normalize_bibliographic_text(item_title)
    if len(candidate) < 20 or len(title) < 20:
        return 0.0

    if candidate == title:
        return 1.0

    if title.startswith(candidate):
        coverage = len(candidate) / len(title)
        if len(candidate) >= 35 or coverage >= 0.55:
            return min(0.95, 0.78 + (coverage * 0.17))

    if candidate.startswith(title):
        coverage = len(title) / len(candidate)
        if len(title) >= 35 or coverage >= 0.55:
            return min(0.94, 0.78 + (coverage * 0.16))

    if (candidate in title or title in candidate) and min(len(candidate), len(title)) >= 30:
        return 0.85

    ratio = SequenceMatcher(None, candidate, title).ratio()
    if ratio >= 0.92:
        return ratio
    return 0.0


def bibliographic_item_entry(item: dict) -> dict | None:
    """Converte um item bibliográfico Zotero em entrada pesquisável para parent matching."""
    data = item.get('data', {})
    if data.get('itemType') == 'attachment':
        return None
    title = data.get('title') or ''
    normalized_title = normalize_bibliographic_text(title)
    if len(normalized_title) < 20:
        return None
    return {
        'key': item.get('key') or data.get('key'),
        'title': title,
        'normalized_title': normalized_title,
        'doi': normalize_doi(data.get('DOI')),
        'itemType': data.get('itemType'),
        'dateAdded': data.get('dateAdded'),
        'dateModified': data.get('dateModified'),
    }


def build_bibliographic_parent_index(items: List[dict]) -> List[dict]:
    """Cria índice de itens bibliográficos que podem receber anexos novos."""
    entries: list[dict] = []
    seen_keys: set[str] = set()
    for item in items:
        entry = bibliographic_item_entry(item)
        key = entry.get('key') if entry else None
        if not entry or not key or key in seen_keys:
            continue
        seen_keys.add(key)
        entries.append(entry)
    return entries


def find_parent_candidates_for_pdf(
    filename: str,
    parent_index: List[dict],
    min_score: float = 0.82,
) -> List[dict]:
    """Encontra itens bibliográficos candidatos a pai de um PDF novo."""
    title_candidates = filename_title_candidates(filename)
    if not title_candidates:
        return []

    matches: list[dict] = []
    for entry in parent_index:
        best_score = 0.0
        best_candidate = ""
        for candidate in title_candidates:
            score = title_match_score(candidate, entry.get('normalized_title', ''))
            if score > best_score:
                best_score = score
                best_candidate = candidate
        if best_score >= min_score:
            match = dict(entry)
            match['score'] = round(best_score, 4)
            match['matched_candidate'] = best_candidate
            matches.append(match)

    matches.sort(key=lambda match: (-match['score'], match.get('dateAdded') or '', match['key']))
    return matches


def select_parent_for_new_attachment(
    filename: str,
    parent_index: List[dict],
    tie_margin: float = 0.03,
) -> tuple[dict | None, List[dict]]:
    """Seleciona pai único e seguro para anexar PDF novo, ou bloqueia ambiguidade."""
    candidates = find_parent_candidates_for_pdf(filename, parent_index)
    if not candidates:
        return None, []

    best_score = candidates[0]['score']
    top_candidates = [
        candidate for candidate in candidates
        if best_score - candidate['score'] <= tie_margin
    ]
    if len(top_candidates) == 1:
        return top_candidates[0], candidates
    return None, candidates


def collect_all_pdfs(directory: str, stats: dict) -> List[str]:
    """Retorna todos os PDFs da pasta, ordenados do mais recente ao mais antigo."""
    logging.info("[SCAN] Iniciando varredura de PDFs em %s", directory)

    entries: List[Tuple[float, str]] = []

    try:
        with os.scandir(directory) as it:
            for entry in it:
                if not entry.is_file():
                    continue
                if not entry.name.lower().endswith('.pdf'):
                    continue
                try:
                    mtime = entry.stat().st_mtime
                except OSError as exc:
                    logging.warning("[SCAN] Não foi possível ler mtime de '%s': %s", entry.path, exc)
                    continue
                entries.append((mtime, entry.path))

    except FileNotFoundError:
        logging.error("A pasta alvo não foi encontrada: %s", directory)
        return []
    except PermissionError:
        logging.error("Sem permissão para acessar a pasta: %s", directory)
        return []
    except Exception as exc:
        logging.error("Erro ao varrer a pasta '%s': %s", directory, exc)
        return []

    if not entries:
        logging.info("[SCAN] Nenhum PDF encontrado em %s.", directory)
        return []

    entries.sort(key=lambda x: x[0], reverse=True)

    stats['folder_total_pdfs'] = len(entries)
    stats['folder_checked_pdfs'] = len(entries)

    logging.info("[SCAN] PDFs encontrados: %d", len(entries))

    return [path for _, path in entries]


def collect_all_attachments(
    zot: zotero.Zotero,
    stats: dict,
) -> Tuple[List[dict], dict, dict]:
    """
    Busca TODOS os anexos da biblioteca sem limite de janela.

    FIX: A versão anterior limitava a janela de "recentes" a MAX_ATTACHMENTS_TO_CHECK,
    o que fazia o índice de nomes ficar incompleto — anexos antigos eram ignorados
    na comparação, causando duplicatas ao re-adicionar o mesmo arquivo.

    Agora:
    - existing_filenames / existing_filenames_aggressive indexam TODOS os anexos.
    - A lista retornada também é a lista completa (usada apenas para logging/debug).
    """
    page_size = 100
    start = 0
    total = 0
    all_items: List[dict] = []
    existing_filenames: dict = {}
    existing_filenames_aggressive: dict = {}

    logging.info("[ZOT] Iniciando varredura completa de anexos (sem limite).")

    while True:
        try:
            items = zot.items(
                itemType='attachment',
                limit=page_size,
                start=start,
                sort='dateAdded',
                direction='desc',
            )
        except Exception as exc:
            logging.error("[ZOT] Falha ao obter anexos (start=%d): %s", start, exc)
            break

        if not items:
            break

        total += len(items)
        logging.debug("[ZOT] Página recebida. start=%d | itens=%d | total=%d", start, len(items), total)

        for item in items:
            data = item.get('data', {})
            date_added = parse_zotero_date(data.get('dateAdded'))
            if date_added:
                item['_parsed_date_added'] = date_added
                item['_timestamp'] = date_added.timestamp()

            filename = get_filename_from_item(item)
            if filename:
                info = {
                    'original': filename,
                    'key': item['key'],
                    'dateModified': data.get('dateModified'),
                }
                norm_file = normalize_filename(filename)
                norm_agg_file = normalize_aggressive(filename)
                # Guarda o primeiro encontrado (mais recente, pois ordenamos desc)
                if norm_file and norm_file not in existing_filenames:
                    existing_filenames[norm_file] = info
                if norm_agg_file and norm_agg_file not in existing_filenames_aggressive:
                    existing_filenames_aggressive[norm_agg_file] = info

            all_items.append(item)

        if len(items) < page_size:
            break
        start += page_size

    stats['zotero_attachments_scanned'] = total

    logging.info(
        "[ZOT] Varredura concluída. Total: %d anexos | Nomes únicos (basic): %d | (aggressive): %d",
        total,
        len(existing_filenames),
        len(existing_filenames_aggressive),
    )

    # FIX: retorna tupla consistente mesmo quando vazio (bug anterior retornava [] sozinho)
    return all_items, existing_filenames, existing_filenames_aggressive

def collect_all_bibliographic_items(zot: zotero.Zotero, stats: dict) -> List[dict]:
    """Busca itens bibliográficos top-level para evitar anexos soltos duplicadores."""
    page_size = 100
    start = 0
    all_items: list[dict] = []

    logging.info("[BIB] Iniciando varredura completa de itens bibliográficos top-level.")

    while True:
        try:
            items = zot.top(
                limit=page_size,
                start=start,
                sort='dateAdded',
                direction='desc',
            )
        except Exception as exc:
            logging.error("[BIB] Falha ao obter itens bibliográficos (start=%d): %s", start, exc)
            raise

        if not items:
            break

        logging.debug("[BIB] Página recebida. start=%d | itens=%d.", start, len(items))
        for item in items:
            data = item.get('data', {})
            if data.get('itemType') == 'attachment':
                continue
            if data.get('title'):
                all_items.append(item)

        if len(items) < page_size:
            break
        start += page_size

    stats['zotero_bibliographic_scanned'] = len(all_items)
    logging.info("[BIB] Varredura concluída. Itens bibliográficos: %d.", len(all_items))
    return all_items


def build_duplicate_groups(attachments: List[dict]) -> List[dict]:
    """Agrupa anexos PDF duplicados por nome normalizado."""
    by_basic: Dict[str, List[dict]] = {}
    by_aggressive: Dict[str, List[dict]] = {}

    def push(bucket: Dict[str, List[dict]], norm_name: str, info: dict) -> None:
        bucket.setdefault(norm_name, []).append(info)

    for item in attachments:
        filename = get_filename_from_item(item)
        if not filename or not filename.lower().endswith('.pdf'):
            continue
        data = item.get('data', {})
        info = {
            'key': item.get('key', '?'),
            'filename': filename,
            'dateAdded': data.get('dateAdded', '?'),
            'parentItem': data.get('parentItem', ''),
        }
        norm_basic = normalize_filename(filename)
        norm_aggressive = normalize_aggressive(filename)
        if norm_basic:
            push(by_basic, norm_basic, info)
        if norm_aggressive and norm_aggressive != norm_basic:
            push(by_aggressive, norm_aggressive, info)

    groups: List[dict] = []
    seen_key_pairs: set[frozenset[str]] = set()

    def add_group(norm_name: str, items: List[dict], method: str) -> None:
        keys = frozenset(entry['key'] for entry in items)
        if len(keys) < 2 or keys in seen_key_pairs:
            return
        seen_key_pairs.add(keys)
        sorted_items = sorted(items, key=lambda entry: entry['dateAdded'])
        groups.append({
            'norm': norm_name,
            'method': method,
            'items': sorted_items,
            'keeper': sorted_items[0],
            'to_delete': sorted_items[1:],
        })

    for norm_name, items in by_basic.items():
        add_group(norm_name, items, 'nome normalizado')
    for norm_name, items in by_aggressive.items():
        add_group(norm_name, items, 'nome agressivo')

    return groups


def find_missing_drive_pdfs_in_zotero(
    attachments: List[dict],
    folder: str,
    ) -> dict:
    """Lista PDFs do drive que ainda não têm correspondência nominal no Zotero."""
    zotero_names_basic: set[str] = set()
    zotero_names_aggressive: set[str] = set()

    for item in attachments:
        filename = get_filename_from_item(item)
        if not filename:
            continue
        zotero_names_basic.add(normalize_filename(filename))
        zotero_names_aggressive.add(normalize_aggressive(filename))

    missing: List[dict] = []
    errors: List[str] = []
    if not os.path.isdir(folder):
        return {'missing': [], 'errors': [f'Pasta não encontrada: {folder}'], 'folder': folder}

    try:
        pdf_entries = [
            entry for entry in os.scandir(folder)
            if entry.is_file() and entry.name.lower().endswith('.pdf')
        ]
    except OSError as exc:
        return {'missing': [], 'errors': [f'Falha ao ler pasta {folder}: {exc}'], 'folder': folder}

    for entry in pdf_entries:
        norm_basic = normalize_filename(entry.name)
        norm_aggressive = normalize_aggressive(entry.name)
        if norm_basic in zotero_names_basic or norm_aggressive in zotero_names_aggressive:
            continue
        try:
            size_kb = entry.stat().st_size // 1024
        except OSError:
            size_kb = -1
        missing.append({'filename': entry.name, 'path': entry.path, 'size_kb': size_kb})

    return {
        'missing': missing,
        'errors': errors,
        'folder': folder,
        'total_pdfs': len(pdf_entries),
        'total_missing': len(missing),
    }


def print_diagnostic_report(duplicate_groups: List[dict], missing_result: dict) -> None:
    print(f"\n{'═'*60}")
    print('  RELATÓRIO DE DIAGNÓSTICO ZOTERO')
    print(f"{'═'*60}")

    print(f"\n{'━'*60}")
    print(f"  1. ANEXOS DUPLICADOS  ({len(duplicate_groups)} grupo(s))")
    print(f"{'━'*60}")
    if not duplicate_groups:
        print('  ✅ Nenhuma duplicata encontrada.')
    else:
        for index, group in enumerate(duplicate_groups, start=1):
            print(f"\n  Grupo #{index}  [{group['method']}]  norm='{group['norm']}'")
            for item in group['items']:
                parent = f"  parent={item['parentItem']}" if item['parentItem'] else '  (sem pai)'
                print(f"    • key={item['key']}  dateAdded={item['dateAdded']}")
                print(f"      filename='{item['filename']}'{parent}")

    print(f"\n{'━'*60}")
    print('  2. PDFs SEM CORRESPONDÊNCIA NO ZOTERO')
    print(f"     Pasta: {missing_result['folder']}")
    print(f"     Total PDFs: {missing_result.get('total_pdfs', '?')}  |  Ausentes: {missing_result.get('total_missing', '?')}")
    print(f"{'━'*60}")
    for error in missing_result.get('errors', []):
        print(f'  ⚠️  {error}')
    if not missing_result.get('missing'):
        print('  ✅ Todos os PDFs da pasta já estão no Zotero.')
    else:
        for item in missing_result['missing']:
            print(f"  • {item['filename']}  ({item['size_kb']} KB)")
            print(f"    {item['path']}")
    print(f"\n{'═'*60}\n")


def delete_attachment_keys(zot: zotero.Zotero, keys: List[str], dry_run: bool) -> tuple[int, int]:
    """Remove anexos pela chave, com dry-run opcional."""
    deleted_ok = 0
    deleted_err = 0
    for key in keys:
        if dry_run:
            print(f'    [DRY-RUN] Deletaria key={key}')
            deleted_ok += 1
            continue
        try:
            item = zot.item(key)
            zot.delete_item(item)
            print(f'    ✅ Deletado: key={key}')
            deleted_ok += 1
            time.sleep(0.3)
        except Exception as exc:
            print(f'    ❌ Falha ao deletar key={key}: {exc}')
            deleted_err += 1
    return deleted_ok, deleted_err


def connect_zotero_client() -> zotero.Zotero:
    """Conecta na API do Zotero usando a configuração ativa."""
    client = zotero.Zotero(LIBRARY_ID, LIBRARY_TYPE, API_KEY)
    client.key_info()
    return client


def run_diagnostic_mode() -> None:
    print(f'🔗 Conectando ao Zotero (library_id={LIBRARY_ID}, type={LIBRARY_TYPE})...')
    try:
        client = connect_zotero_client()
        print('✅ Conexão OK.')
    except Exception as exc:
        raise SystemExit(f'❌ Falha na conexão: {exc}')

    print('\n📥 Buscando TODOS os anexos da biblioteca...')
    attachments, _, _ = collect_all_attachments(client, {'zotero_attachments_scanned': 0})
    print('\n🔍 Verificando duplicatas...')
    duplicate_groups = build_duplicate_groups(attachments)
    print(f"\n📂 Verificando PDFs ausentes no Zotero (pasta: {TARGET_FOLDER})...")
    missing_result = find_missing_drive_pdfs_in_zotero(attachments, TARGET_FOLDER)
    print_diagnostic_report(duplicate_groups, missing_result)


def run_duplicate_cleanup_mode(execute: bool) -> None:
    dry_run = not execute
    mode_label = '🔍 DRY-RUN (simulação)' if dry_run else '⚠️  MODO REAL (vai deletar)'
    print(f"\n{'═'*60}")
    print(f'  REMOÇÃO DE DUPLICATAS ZOTERO  —  {mode_label}')
    print(f'  library_id={LIBRARY_ID}, type={LIBRARY_TYPE}')
    print(f"{'═'*60}\n")

    if not dry_run:
        print("⚠️  ATENÇÃO: você está prestes a deletar anexos da sua biblioteca Zotero.")
        print('   Esta operação é IRREVERSÍVEL pela API.')
        confirm = input("   Digite 'sim' para continuar: ").strip().lower()
        if confirm not in ('sim', 's', 'yes', 'y'):
            print('Operação cancelada.')
            return
        print()

    print('🔗 Conectando ao Zotero...')
    try:
        client = connect_zotero_client()
        print('✅ Conexão OK.\n')
    except Exception as exc:
        raise SystemExit(f'❌ Falha na conexão: {exc}')

    print('📥 Buscando todos os anexos...')
    attachments, _, _ = collect_all_attachments(client, {'zotero_attachments_scanned': 0})
    print('\n🔍 Detectando duplicatas de PDFs...')
    groups = build_duplicate_groups(attachments)

    if not groups:
        print('\n✅ Nenhuma duplicata de PDF encontrada. Nada a fazer.')
        return

    total_to_delete = sum(len(group['to_delete']) for group in groups)
    print(f"\nEncontrados {len(groups)} grupo(s) de duplicatas → {total_to_delete} anexo(s) a remover.\n")

    deleted_ok = 0
    deleted_err = 0
    for index, group in enumerate(groups, start=1):
        keeper = group['keeper']
        print(f"  Grupo #{index}  [{group['method']}]")
        print(f"  Arquivo: '{keeper['filename']}'")
        print(
            f"  ✔ Mantendo: key={keeper['key']}  dateAdded={keeper['dateAdded']}"
            f"  parent={keeper['parentItem'] or '(sem pai)'}"
        )
        for item in group['to_delete']:
            print(
                f"  ✗ Removendo: key={item['key']}  dateAdded={item['dateAdded']}"
                f"  parent={item['parentItem'] or '(sem pai)'}"
            )
        keys_to_delete = [item['key'] for item in group['to_delete']]
        ok, err = delete_attachment_keys(client, keys_to_delete, dry_run=dry_run)
        deleted_ok += ok
        deleted_err += err
        print()

    print(f"{'═'*60}")
    if dry_run:
        print('  DRY-RUN concluído.')
        print(f'  {deleted_ok} anexo(s) seriam deletados.')
        print('\n  Para executar de verdade, rode:')
        print(f'    python3 {Path(__file__).name} remove-duplicatas --executar')
    else:
        print(f'  Concluído: {deleted_ok} deletado(s) | {deleted_err} erro(s).')
    print(f"{'═'*60}\n")


SETUP_AUTOSTART_SHELL = '#!/usr/bin/env bash\n#\n# Configura a montagem WebDAV e o serviço de sincronização Zotero em modo usuário.\n# - Copia o script Python para ~/.local/bin/\n# - Gera arquivo de configuração com variáveis compartilhadas\n# - Cria helper de montagem + unidades systemd de usuário\n# - Integra com secret-tool para guardar credenciais WebDAV\n\nset -euo pipefail\n\nreadonly CONFIG_DIR="$HOME/.config/zotero_sync_webdav"\nreadonly ENV_FILE="$CONFIG_DIR/zotero_sync.env"\nreadonly DEFAULT_REMOTE_SUBPATH="Google Drive/zoterodb"\n\ndie() {\n  echo "Erro: $*" >&2\n  exit 1\n}\n\nrequire_command() {\n  local cmd\n  for cmd in "$@"; do\n    if ! command -v "$cmd" >/dev/null 2>&1; then\n      die "Dependência ausente: $cmd"\n    fi\n  done\n}\n\nprompt_value() {\n  local prompt="$1"\n  local default="${2-}"\n  local allow_empty="${3:-0}"\n  local value\n  while true; do\n    if [[ -n "$default" ]]; then\n      read -r -p "$prompt [$default]: " value || exit 1\n      [[ -z "$value" ]] && value="$default"\n    else\n      read -r -p "$prompt: " value || exit 1\n    fi\n    if [[ -n "$value" || "$allow_empty" == "1" ]]; then\n      printf \'%s\' "$value"\n      return\n    fi\n    echo "Valor obrigatório." >&2\n  done\n}\n\nprompt_secret() {\n  local prompt="$1"\n  local secret confirm\n  while true; do\n    read -r -s -p "$prompt: " secret || exit 1\n    echo\n    if [[ -z "$secret" ]]; then\n      echo "A senha não pode ser vazia." >&2\n      continue\n    fi\n    read -r -s -p "Confirme a senha: " confirm || exit 1\n    echo\n    if [[ "$secret" != "$confirm" ]]; then\n      echo "As senhas não conferem. Tente novamente." >&2\n      continue\n    fi\n    printf \'%s\' "$secret"\n    return\n  done\n}\n\nprompt_yes_no() {\n  local prompt="$1"\n  local default="${2:-s}"\n  local answer default_hint\n  case "$default" in\n    [sS]|[yY]) default_hint=" [S/n]" ;;\n    [nN]) default_hint=" [s/N]" ;;\n    *) default_hint=" [s/n]"; default="" ;;\n  esac\n  while true; do\n    read -r -p "$prompt$default_hint " answer || exit 1\n    [[ -z "$answer" && -n "$default" ]] && answer="$default"\n    case "${answer,,}" in\n      s|sim|y|yes) return 0 ;;\n      n|nao|não|no) return 1 ;;\n      *) echo "Responda com \'s\' ou \'n\'." >&2 ;;\n    esac\n  done\n}\n\ndeclare -a SECRET_ENTRIES=()\ndeclare -a MOUNTED_WEBDAV=()\n\nload_env_file_simple() {\n  local env_path="$1"\n  [[ -f "$env_path" ]] || return\n  while IFS= read -r line || [[ -n "$line" ]]; do\n    line="${line%$\'\\r\'}"\n    [[ -z "$line" || "${line:0:1}" == "#" || "$line" != *"="* ]] && continue\n    local key="${line%%=*}"\n    local value="${line#*=}"\n    key="${key#"${key%%[![:space:]]*}"}"\n    key="${key%"${key##*[![:space:]]}"}"\n    value="${value#"${value%%[![:space:]]*}"}"\n    value="${value%"${value##*[![:space:]]}"}"\n    # Remove aspas simples ou duplas ao redor do valor, se presentes.\n    if [[ "$value" == \\"*\\" && "$value" == *\\" ]]; then\n      value="${value:1:${#value}-2}"\n    elif [[ "$value" == \\\'*\\\' && "$value" == *\\\' ]]; then\n      value="${value:1:${#value}-2}"\n    fi\n    export "$key=$value"\n  done <"$env_path"\n}\n\ndecode_mount_entry() {\n  local entry="$1"\n  IFS=\'|\' read -r _ label user host scheme port remote_path mount_path <<<"$entry"\n  label="$(decode_field "$label")"\n  user="$(decode_field "$user")"\n  host="$(decode_field "$host")"\n  scheme="$(decode_field "$scheme")"\n  port="$(decode_field "$port")"\n  remote_path="$(decode_field "$remote_path")"\n  mount_path="$(decode_field "$mount_path")"\n  printf \'%s|%s|%s|%s|%s|%s|%s\\n\' "$label" "$user" "$host" "$scheme" "$port" "$remote_path" "$mount_path"\n}\n\nencode_field() {\n  local value="$1"\n  value="${value//\\\\/\\\\\\\\}"\n  value="${value//|/\\\\u007c}"\n  printf \'%s\' "$value"\n}\n\ndecode_field() {\n  local value="$1"\n  value="${value//\\\\u007c/|}"\n  value="${value//\\\\\\\\/\\\\}"\n  printf \'%s\' "$value"\n}\n\ncollect_secret_entries() {\n  SECRET_ENTRIES=()\n  local proto output line label user server url remote_path port attr_proto encoded\n\n  for proto in davs dav; do\n    output="$(secret-tool search --all protocol "$proto" 2>/dev/null)" || continue\n\n    label=""; user=""; server=""; url=""; remote_path=""; port=""; attr_proto="$proto"\n\n    while IFS= read -r line || [[ -n "$line" ]]; do\n      line="${line%$\'\\r\'}"\n\n      if [[ -z "$line" ]]; then\n        if [[ -n "$label" || -n "$user" || -n "$server" || -n "$url" ]]; then\n          encoded="$(encode_field "$label")|$(encode_field "$user")|$(encode_field "$server")|$(encode_field "$url")|$(encode_field "$remote_path")|$(encode_field "$port")|$(encode_field "$attr_proto")"\n          SECRET_ENTRIES+=("$encoded")\n        fi\n        label=""; user=""; server=""; url=""; remote_path=""; port=""; attr_proto="$proto"\n        continue\n      fi\n\n      case "$line" in\n        \\[*\\]) continue ;;\n        secret\\ =*) continue ;;\n        created\\ =*) continue ;;\n        modified\\ =*) continue ;;\n        schema\\ =*) continue ;;\n        label\\ =*)\n          label="${line#*= }"\n          ;;\n        attribute.user\\ =*)\n          user="${line#*= }"\n          ;;\n        attribute.server\\ =*)\n          server="${line#*= }"\n          ;;\n        attribute.url\\ =*)\n          url="${line#*= }"\n          ;;\n        attribute.remote_path\\ =*)\n          remote_path="${line#*= }"\n          ;;\n        attribute.port\\ =*)\n          port="${line#*= }"\n          ;;\n        attribute.protocol\\ =*)\n          attr_proto="${line#*= }"\n          ;;\n      esac\n    done <<<"$output"\n\n    if [[ -n "$label" || -n "$user" || -n "$server" || -n "$url" ]]; then\n      encoded="$(encode_field "$label")|$(encode_field "$user")|$(encode_field "$server")|$(encode_field "$url")|$(encode_field "$remote_path")|$(encode_field "$port")|$(encode_field "$attr_proto")"\n      SECRET_ENTRIES+=("$encoded")\n    fi\n  done\n}\n\ncollect_mounted_webdav() {\n  MOUNTED_WEBDAV=()\n  local gvfs_dir="/run/user/$(id -u)/gvfs"\n  [[ -d "$gvfs_dir" ]] || return\n\n  shopt -s nullglob\n  local mount_path name part host user port ssl prefix decoded dec_user dec_prefix scheme label\n  for mount_path in "$gvfs_dir"/dav:*; do\n    name="${mount_path##*/}"\n    host=""; user=""; port=""; ssl=""; prefix=""\n    IFS=\',\' read -ra parts <<<"${name#dav:}"\n    for part in "${parts[@]}"; do\n      case "$part" in\n        host=*) host="${part#host=}" ;;\n        user=*) user="${part#user=}" ;;\n        port=*) port="${part#port=}" ;;\n        ssl=*) ssl="${part#ssl=}" ;;\n        prefix=*) prefix="${part#prefix=}" ;;\n      esac\n    done\n\n    mapfile -t decoded < <(U="$user" P="$prefix" python3 - <<\'PY\'\nimport os, urllib.parse\nprint(urllib.parse.unquote(os.environ.get("U","")))\nprint(urllib.parse.unquote(os.environ.get("P","")))\nPY\n)\n    dec_user="${decoded[0]}"\n    dec_prefix="${decoded[1]}"\n    [[ -z "$dec_prefix" ]] && dec_prefix="/"\n    scheme="dav"\n    [[ "${ssl,,}" == "true" ]] && scheme="davs"\n    label="Mount ${name}"\n    MOUNTED_WEBDAV+=("$(encode_field "$label")|$(encode_field "$dec_user")|$(encode_field "$host")|$(encode_field "$scheme")|$(encode_field "$port")|$(encode_field "$dec_prefix")|$(encode_field "$mount_path")")\n  done\n  shopt -u nullglob\n}\n\nchoose_secret_entry() {\n  local count="${#SECRET_ENTRIES[@]}"\n  [[ "$count" -eq 0 ]] && return 1\n\n  local fallback_user="" fallback_host="" fallback_scheme="" fallback_port="" fallback_remote=""\n  if [[ "${#MOUNTED_WEBDAV[@]}" -gt 0 ]]; then\n    IFS=\'|\' read -r _ fallback_user fallback_host fallback_scheme fallback_port fallback_remote _ <<<"$(decode_mount_entry "${MOUNTED_WEBDAV[0]}")"\n  fi\n\n  echo\n  echo "Credenciais WebDAV encontradas no keyring:"\n\n  local idx=1 entry label user server url remote_path port protocol\n  for entry in "${SECRET_ENTRIES[@]}"; do\n    IFS=\'|\' read -r label user server url remote_path port protocol <<<"$entry"\n    label="$(decode_field "$label")"\n    user="$(decode_field "$user")"\n    server="$(decode_field "$server")"\n    url="$(decode_field "$url")"\n    remote_path="$(decode_field "$remote_path")"\n    port="$(decode_field "$port")"\n    protocol="$(decode_field "$protocol")"\n\n    [[ -z "$user" && -n "$fallback_user" ]] && user="$fallback_user"\n    [[ -z "$server" && -n "$fallback_host" ]] && server="$fallback_host"\n    [[ -z "$protocol" && -n "$fallback_scheme" ]] && protocol="$fallback_scheme"\n    [[ -z "$remote_path" && -n "$fallback_remote" ]] && remote_path="$fallback_remote"\n\n    [[ -z "$label" ]] && label="(sem label)"\n    [[ -z "$user" ]] && user="(usuário desconhecido)"\n    [[ -z "$server" ]] && server="(servidor desconhecido)"\n    if [[ -z "$url" ]]; then\n      local inferred_url=""\n      if [[ -n "$server" ]]; then\n        local scheme="$protocol"\n        [[ -z "$scheme" ]] && scheme="davs"\n        if [[ "$scheme" != "dav" && "$scheme" != "davs" ]]; then\n          scheme="davs"\n        fi\n        local path="$remote_path"\n        [[ -z "$path" ]] && path="/"\n        [[ "$path" != /* ]] && path="/$path"\n        if [[ -n "$port" ]]; then\n          inferred_url="$scheme://$server:$port$path"\n        else\n          inferred_url="$scheme://$server$path"\n        fi\n      fi\n      [[ -n "$inferred_url" ]] && url="$inferred_url" || url="(URL não registrada)"\n    fi\n\n    printf "  [%d] %s -> %s@%s (%s)\\n" "$idx" "$label" "$user" "$server" "$url"\n    ((idx++))\n  done\n  echo "  [0] Registrar nova credencial"\n\n  local choice\n  while true; do\n    read -r -p "Escolha uma opção [0-${count}]: " choice || exit 1\n    if [[ -z "$choice" ]]; then\n      choice=0\n    fi\n    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -le "$count" ]]; then\n      break\n    fi\n    echo "Opção inválida." >&2\n  done\n\n  if [[ "$choice" -eq 0 ]]; then\n    SELECTED_SECRET_ENTRY=""\n    return 1\n  fi\n\n  SELECTED_SECRET_ENTRY="${SECRET_ENTRIES[$((choice-1))]}"\n  return 0\n}\n\nchoose_mounted_entry() {\n  local count="${#MOUNTED_WEBDAV[@]}"\n  [[ "$count" -eq 0 ]] && return 1\n\n  echo\n  echo "Perfis WebDAV já montados detectados:"\n\n  local idx=1 entry label user host scheme port remote_path mount_path\n  for entry in "${MOUNTED_WEBDAV[@]}"; do\n    IFS=\'|\' read -r label user host scheme port remote_path mount_path <<<"$entry"\n    label="$(decode_field "$label")"\n    user="$(decode_field "$user")"\n    host="$(decode_field "$host")"\n    scheme="$(decode_field "$scheme")"\n    port="$(decode_field "$port")"\n    remote_path="$(decode_field "$remote_path")"\n    mount_path="$(decode_field "$mount_path")"\n\n    [[ -z "$label" ]] && label="(sem label)"\n    [[ -z "$user" ]] && user="(usuário desconhecido)"\n    [[ -z "$host" ]] && host="(servidor desconhecido)"\n    [[ -z "$remote_path" ]] && remote_path="/"\n\n    local host_display="$host"\n    [[ -n "$port" ]] && host_display="$host_display:$port"\n    printf "  [%d] %s -> %s@%s (%s://%s%s | %s)\\n" "$idx" "$label" "$user" "$host_display" "$scheme" "$host_display" "$remote_path" "$mount_path"\n    ((idx++))\n  done\n  echo "  [0] Não usar montagens existentes"\n\n  local choice\n  while true; do\n    read -r -p "Escolha uma opção [0-${count}]: " choice || exit 1\n    if [[ -z "$choice" ]]; then\n      choice=0\n    fi\n    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -le "$count" ]]; then\n      break\n    fi\n    echo "Opção inválida." >&2\n  done\n\n  if [[ "$choice" -eq 0 ]]; then\n    SELECTED_MOUNT_ENTRY=""\n    return 1\n  fi\n\n  SELECTED_MOUNT_ENTRY="${MOUNTED_WEBDAV[$((choice-1))]}"\n  return 0\n}\n\nlookup_secret_exists() {\n  local scheme="$1" host="$2" port="$3" user="$4"\n  local -a args=(protocol "$scheme" server "$host" user "$user")\n  if [[ -n "$port" ]]; then\n    args+=(port "$port")\n  fi\n  if secret-tool lookup "${args[@]}" >/dev/null 2>&1; then\n    return 0\n  fi\n  return 1\n}\n\nstore_secret() {\n  local scheme="$1" host="$2" port="$3" user="$4" label="$5" url="$6" remote_path="$7"\n  local password\n  password="$(prompt_secret "Senha WebDAV")"\n  local -a attrs=(protocol "$scheme" server "$host" user "$user")\n  [[ -n "$port" ]] && attrs+=(port "$port")\n  attrs+=(url "$url" remote_path "$remote_path" display "$label")\n  printf "%s" "$password" | secret-tool store --label="$label" "${attrs[@]}"\n  echo "Senha armazenada no keyring com o label \'$label\'."\n}\n\ncompute_paths() {\n  local server_url="$1"\n  local username="$2"\n  local remote_subpath="$3"\n  local result\n\n  result="$(SERVER_URL="$server_url" WEBDAV_USER="$username" REMOTE_SUBPATH="$remote_subpath" python3 - <<\'PY\'\nimport os\nfrom pathlib import PurePosixPath\nfrom urllib.parse import urlparse, quote\n\nserver_url = os.environ["SERVER_URL"].strip()\nuser = os.environ["WEBDAV_USER"]\nremote_subpath = os.environ.get("REMOTE_SUBPATH", "")\n\nif not server_url:\n    raise SystemExit("A URL base do servidor não pode ser vazia.")\n\nparsed = urlparse(server_url)\nif not parsed.scheme:\n    raise SystemExit("Informe a URL com o esquema (ex: davs://servidor/dav/).")\n\nscheme = parsed.scheme.lower()\nif scheme in ("https", "davs"):\n    scheme = "davs"\n    ssl = "true"\nelif scheme in ("http", "dav"):\n    scheme = "dav"\n    ssl = "false"\nelse:\n    raise SystemExit(f"Esquema não suportado: {parsed.scheme}")\n\nhost = parsed.hostname\nif not host:\n    raise SystemExit("A URL precisa conter o host.")\n\nport = parsed.port\nbase_path = parsed.path or "/"\nif not base_path.startswith("/"):\n    base_path = "/" + base_path\n\nif not base_path.endswith("/"):\n    base_path = base_path + "/"\n\nremote_path = base_path.rstrip("/")\nif remote_subpath:\n    remote_path = str(PurePosixPath(remote_path or "/") / remote_subpath)\nelif not remote_path:\n    remote_path = "/"\n\nremote_path = remote_path or "/"\n\nuser_enc = quote(user, safe=\'\')\nhost_display = host if port is None else f"{host}:{port}"\nremote_path_enc = quote(remote_path, safe=\'/\')\nmount_uri = f"{scheme}://{user_enc}@{host_display}{remote_path_enc}"\n\nprefix = remote_path\nif prefix.startswith(\'/\'):\n    prefix = \'%2F\' + prefix[1:]\n\nuid = os.getuid()\nparts = [f"dav:host={host}"]\nif port is not None:\n    parts.append(f"port={port}")\nparts.append(f"ssl={\'true\' if scheme == \'davs\' else \'false\'}")\nparts.append(f"user={user_enc}")\nparts.append(f"prefix={prefix}")\ntarget_folder = f"/run/user/{uid}/gvfs/" + ",".join(parts)\n\nprint(f"SCHEME={scheme}")\nprint(f"SSL={\'true\' if scheme == \'davs\' else \'false\'}")\nprint(f"HOST={host}")\nprint(f"PORT={port or \'\'}")\nprint(f"BASE_PATH={base_path}")\nprint(f"REMOTE_PATH={remote_path}")\nprint(f"MOUNT_URI={mount_uri}")\nprint(f"TARGET_FOLDER={target_folder}")\nPY\n)" || {\n    die "Falha ao processar a URL WebDAV."\n  }\n\n  declare -gA COMPUTED=()\n  local line key value\n  while IFS=\'=\' read -r key value; do\n    [[ -z "$key" ]] && continue\n    COMPUTED["$key"]="$value"\n  done <<<"$result"\n}\n\nwrite_env_file() {\n  mkdir -p "$CONFIG_DIR"\n  : >"$ENV_FILE"\n  local key value\n  {\n    echo "# Arquivo gerado automaticamente por setup_autostart.sh"\n    echo "# Modifique com cuidado."\n    for key in "${!ENV_VARS[@]}"; do\n      value="${ENV_VARS[$key]}"\n      printf \'%s=%q\\n\' "$key" "$value"\n    done\n  } >>"$ENV_FILE"\n}\n\ninstall_helper_script() {\n  local helper_path="$1"\n  cat <<\'EOF\' >"$helper_path"\n#!/usr/bin/env bash\nset -euo pipefail\n\nENV_FILE="$HOME/.config/zotero_sync_webdav/zotero_sync.env"\n[[ -f "$ENV_FILE" ]] || { echo "Arquivo de configuração não encontrado: $ENV_FILE" >&2; exit 1; }\n\n# shellcheck disable=SC1090\nsource "$ENV_FILE"\n\nGIO_BIN="${ZSW_GIO_BIN:-gio}"\nMOUNT_URI="${ZSW_GIO_MOUNT_URI:?ZSW_GIO_MOUNT_URI não definido}"\n\ncleanup() {\n  [[ -z "${TMP_FILE:-}" ]] || rm -f "$TMP_FILE"\n}\n\nalready_mounted_msg() {\n  grep -qiE \'already mounted|já está montad\' "$TMP_FILE"\n}\n\nnot_mounted_msg() {\n  grep -qiE \'not mounted|não está montad\' "$TMP_FILE"\n}\n\ncase "${1:-start}" in\n  start)\n    TMP_FILE="$(mktemp)"\n    trap cleanup EXIT\n    if "$GIO_BIN" mount "$MOUNT_URI" 2>"$TMP_FILE"; then\n      exit 0\n    fi\n    if already_mounted_msg; then\n      exit 0\n    fi\n    cat "$TMP_FILE" >&2\n    exit 1\n    ;;\n  stop|unmount)\n    TMP_FILE="$(mktemp)"\n    trap cleanup EXIT\n    if "$GIO_BIN" mount -u "$MOUNT_URI" 2>"$TMP_FILE"; then\n      exit 0\n    fi\n    if not_mounted_msg; then\n      exit 0\n    fi\n    cat "$TMP_FILE" >&2\n    exit 1\n    ;;\n  status)\n    if "$GIO_BIN" mount -l | grep -F "$MOUNT_URI" >/dev/null 2>&1; then\n      exit 0\n    fi\n    exit 1\n    ;;\n  *)\n    echo "Uso: $0 [start|stop|status]" >&2\n    exit 2\n    ;;\nesac\nEOF\n  chmod 755 "$helper_path"\n}\n\ncreate_webdav_service() {\n  local service_path="$1"\n  local helper_path="$2"\n  local wait_net="$(dirname "$helper_path")/wait_network.sh"\n\n  cat >"$wait_net" <<\'WAITEOF\'\n#!/usr/bin/env bash\nsource "$HOME/.config/zotero_sync_webdav/zotero_sync.env"\ni=0\nwhile [ $i -lt 30 ]; do\n    ping -c1 -W2 "$ZSW_HOST" >/dev/null 2>&1 && exit 0\n    sleep 2\n    i=$((i+1))\ndone\necho "Timeout: host $ZSW_HOST nao respondeu." >&2\nexit 1\nWAITEOF\n  chmod 755 "$wait_net"\n\n  cat <<EOF >"$service_path"\n[Unit]\nDescription=Montar WebDAV (gio)\nAfter=graphical-session.target network-online.target\nWants=network-online.target\n\n[Service]\nType=oneshot\nRemainAfterExit=yes\nEnvironmentFile=%h/.config/zotero_sync_webdav/zotero_sync.env\nExecStartPre=$wait_net\nExecStart=$helper_path start\nExecStop=$helper_path stop\n\n[Install]\nWantedBy=default.target\nEOF\n}\n\ncreate_sync_service() {\n  local service_path="$1"\n  local python_bin="$2"\n  local python_script="$3"\n  local wait_folder="$(dirname "$python_script")/wait_webdav.sh"\n\n  cat >"$wait_folder" <<\'WAITEOF\'\n#!/usr/bin/env bash\nsource "$HOME/.config/zotero_sync_webdav/zotero_sync.env"\ni=0\nwhile [ $i -lt 20 ]; do\n    test -d "$ZSW_TARGET_FOLDER" && exit 0\n    sleep 3\n    i=$((i+1))\ndone\necho "Timeout: pasta WebDAV nao ficou disponivel." >&2\nexit 1\nWAITEOF\n  chmod 755 "$wait_folder"\n\n  cat <<EOF >"$service_path"\n[Unit]\nDescription=Zotero WebDAV Sync (Python)\nAfter=webdav-koofr.service\nRequires=webdav-koofr.service\n\n[Service]\nType=oneshot\nEnvironment=PYTHONUNBUFFERED=1\nEnvironmentFile=%h/.config/zotero_sync_webdav/zotero_sync.env\nExecStartPre=$wait_folder\nExecStart=$python_bin $python_script\n\n[Install]\nWantedBy=default.target\nEOF\n}\n\nmain() {\n  if [[ $EUID -eq 0 ]]; then\n    die "Execute este script como usuário normal, não como root."\n  fi\n\n  require_command python3 gio systemctl install secret-tool\n\n  local script_dir python_name python_src python_bin gio_bin\n  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n  python_name="${1:-zotero_sync_webdav.py}"\n  python_src="$script_dir/$python_name"\n  [[ -f "$python_src" ]] || die "Arquivo Python não encontrado: $python_src"\n\n  python_bin="$(command -v python3)"\n  gio_bin="$(command -v gio)"\n\n  local bin_dir="$HOME/.local/bin"\n  local python_target="$bin_dir/$python_name"\n  mkdir -p "$bin_dir"\n  install -m 755 "$python_src" "$python_target"\n\n  [[ -d "$CONFIG_DIR" ]] || mkdir -p "$CONFIG_DIR"\n  if [[ -f "$ENV_FILE" ]]; then\n    # shellcheck disable=SC1091\n    source "$ENV_FILE"\n  fi\n  # Se existir um .env na pasta do script, use-o como base (ex.: já configurado manualmente).\n  local project_env="$script_dir/.env"\n  if [[ -f "$project_env" ]]; then\n    load_env_file_simple "$project_env"\n  fi\n\n  collect_secret_entries\n  collect_mounted_webdav\n  local secret_entries_count="${#SECRET_ENTRIES[@]}"\n  local default_user="${ZSW_USERNAME-}"\n  local default_label="${ZSW_SECRET_LABEL-}"\n  local default_server_url="${ZSW_SERVER_URL-}"\n  local default_remote_subpath="${ZSW_REMOTE_SUBPATH:-$DEFAULT_REMOTE_SUBPATH}"\n  local default_scheme="${ZSW_SCHEME-}"\n  local default_port="${ZSW_PORT-}"\n  local default_target_folder="${ZSW_TARGET_FOLDER-}"\n  local default_library_id="${ZOTERO_LIBRARY_ID:-10830189}"\n  local default_library_type="${ZOTERO_LIBRARY_TYPE:-user}"\n  local default_api_key="${ZOTERO_API_KEY-}"\n\n  [[ -n "$default_user" ]] || default_user="$USER"\n  [[ -n "$default_label" ]] || default_label="WebDAV Sync"\n  [[ -n "$default_server_url" ]] || default_server_url="davs://app.koofr.net/dav/"\n\n  local auto_defaults=0\n\n  if [[ "$secret_entries_count" -gt 0 ]]; then\n    if choose_secret_entry; then\n      local selected_label selected_user selected_server selected_url selected_remote selected_port selected_protocol\n      IFS=\'|\' read -r selected_label selected_user selected_server selected_url selected_remote selected_port selected_protocol <<<"$SELECTED_SECRET_ENTRY"\n      selected_label="$(decode_field "$selected_label")"\n      selected_user="$(decode_field "$selected_user")"\n      selected_server="$(decode_field "$selected_server")"\n      selected_url="$(decode_field "$selected_url")"\n      selected_remote="$(decode_field "$selected_remote")"\n      selected_port="$(decode_field "$selected_port")"\n      selected_protocol="$(decode_field "$selected_protocol")"\n\n      # Completar campos ausentes com o primeiro mount detectado (se existir).\n      if [[ "${#MOUNTED_WEBDAV[@]}" -gt 0 ]]; then\n        IFS=\'|\' read -r _ fallback_user fallback_host fallback_scheme fallback_port fallback_remote _ <<<"$(decode_mount_entry "${MOUNTED_WEBDAV[0]}")"\n        [[ -z "$selected_user" && -n "$fallback_user" ]] && selected_user="$fallback_user"\n        [[ -z "$selected_server" && -n "$fallback_host" ]] && selected_server="$fallback_host"\n        [[ -z "$selected_protocol" && -n "$fallback_scheme" ]] && selected_protocol="$fallback_scheme"\n        [[ -z "$selected_port" && -n "$fallback_port" ]] && selected_port="$fallback_port"\n        [[ -z "$selected_remote" && -n "$fallback_remote" ]] && selected_remote="$fallback_remote"\n      fi\n\n      [[ -n "$selected_user" ]] && default_user="$selected_user"\n      [[ -z "$selected_label" ]] && selected_label="(sem label)"\n      if [[ "$selected_label" != "(sem label)" ]]; then\n        default_label="$selected_label"\n      fi\n      [[ -n "$selected_url" ]] && default_server_url="$selected_url"\n      if [[ -n "$selected_remote" ]]; then\n        default_remote_subpath="$selected_remote"\n      fi\n      if [[ -n "$selected_protocol" ]]; then\n        default_scheme="$selected_protocol"\n      fi\n      if [[ -n "$selected_port" ]]; then\n        default_port="$selected_port"\n      fi\n\n      local display_server="$selected_server"\n      [[ -z "$display_server" ]] && display_server="(servidor desconhecido)"\n\n      echo\n      echo "Usando a credencial selecionada (${selected_label} -> ${default_user}@${display_server}) para preencher os campos padrão."\n      auto_defaults=1\n    else\n      echo\n      echo "Nenhuma credencial existente selecionada. Informe novos dados."\n    fi\n  fi\n\n  if choose_mounted_entry; then\n    local selected_label selected_user selected_host selected_scheme selected_port selected_remote_path selected_mount_path\n    IFS=\'|\' read -r selected_label selected_user selected_host selected_scheme selected_port selected_remote_path selected_mount_path <<<"$SELECTED_MOUNT_ENTRY"\n    selected_label="$(decode_field "$selected_label")"\n    selected_user="$(decode_field "$selected_user")"\n    selected_host="$(decode_field "$selected_host")"\n    selected_scheme="$(decode_field "$selected_scheme")"\n    selected_port="$(decode_field "$selected_port")"\n    selected_remote_path="$(decode_field "$selected_remote_path")"\n    selected_mount_path="$(decode_field "$selected_mount_path")"\n\n    [[ -n "$selected_user" ]] && default_user="$selected_user"\n    [[ -n "$selected_host" ]] || selected_host="(servidor desconhecido)"\n    if [[ -n "$selected_scheme" ]]; then\n      default_scheme="$selected_scheme"\n    fi\n    if [[ -n "$selected_port" ]]; then\n      default_port="$selected_port"\n    fi\n    if [[ -n "$selected_remote_path" ]]; then\n      # Se a montagem já tem um prefixo, usamos ele como caminho base.\n      default_server_url="${selected_scheme}://${selected_host}"\n      [[ -n "$selected_port" ]] && default_server_url+=":${selected_port}"\n      default_server_url+="$selected_remote_path"\n      [[ "$default_server_url" != */ ]] && default_server_url+="/"\n      default_remote_subpath=""\n    fi\n    if [[ -n "$selected_mount_path" ]]; then\n      default_target_folder="$selected_mount_path"\n    fi\n\n    echo\n    echo "Usando dados da montagem existente (${selected_label}) como padrão:"\n    echo "  Usuário........: ${default_user}"\n    echo "  URL base.......: ${default_server_url}"\n    [[ -n "$default_target_folder" ]] && echo "  Pasta local....: ${default_target_folder}"\n    auto_defaults=1\n  fi\n\n  echo\n  echo "Informe os dados para montar o WebDAV:"\n  local webdav_user webdav_label server_url remote_subpath\n  local accepted_defaults=0\n  if [[ "$auto_defaults" -eq 1 ]]; then\n    echo "Detectei valores padrão: usuário=${default_user}, URL=${default_server_url}, subpasta=\'${default_remote_subpath}\', pasta local=\'${default_target_folder:-(não definida)}\'."\n    if prompt_yes_no "Usar esses valores sem alterar?" "s"; then\n      webdav_user="$default_user"\n      webdav_label="$default_label"\n      server_url="$default_server_url"\n      remote_subpath="$default_remote_subpath"\n      accepted_defaults=1\n    fi\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${webdav_user-}" ]]; then\n    webdav_user="$(prompt_value "Usuário WebDAV" "$default_user")"\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${webdav_label-}" ]]; then\n    webdav_label="$(prompt_value "Label para salvar no keyring" "$default_label")"\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${server_url-}" ]]; then\n    server_url="$(prompt_value "URL base do servidor WebDAV (ex: davs://servidor/dav/)" "$default_server_url")"\n  fi\n  if [[ "$accepted_defaults" -ne 1 && -z "${remote_subpath-}" ]]; then\n    remote_subpath="$(prompt_value "Subpasta remota (relativa ao caminho base ou caminho completo)" "${default_remote_subpath}" 1)"\n  fi\n\n  compute_paths "$server_url" "$webdav_user" "$remote_subpath"\n\n  echo\n  echo "Resumo da configuração sugerida:"\n  echo "  Servidor.......: ${COMPUTED[HOST]}"\n  [[ -n "${COMPUTED[PORT]}" ]] && echo "  Porta..........: ${COMPUTED[PORT]}"\n  echo "  Esquema........: ${COMPUTED[SCHEME]}"\n  echo "  Caminho base...: ${COMPUTED[BASE_PATH]}"\n  echo "  Caminho remoto.: ${COMPUTED[REMOTE_PATH]}"\n  echo "  URI de montagem: ${COMPUTED[MOUNT_URI]}"\n  echo "  Pasta local....: ${COMPUTED[TARGET_FOLDER]}"\n\n  local target_confirmed=0\n  if ! prompt_yes_no "Essas informações estão corretas?" "s"; then\n    remote_subpath="$(prompt_value "Informe novamente a subpasta/remoto (relativa ao caminho base)" "$remote_subpath" 1)"\n    compute_paths "$server_url" "$webdav_user" "$remote_subpath"\n    echo\n    echo "Ajuste aplicado:"\n    echo "  Caminho remoto.: ${COMPUTED[REMOTE_PATH]}"\n    echo "  URI de montagem: ${COMPUTED[MOUNT_URI]}"\n    echo "  Pasta local....: ${COMPUTED[TARGET_FOLDER]}"\n  else\n    target_confirmed=1\n  fi\n\n  local target_folder="${COMPUTED[TARGET_FOLDER]}"\n  if [[ -n "$default_target_folder" ]]; then\n    target_folder="$default_target_folder"\n  fi\n  if [[ "$target_confirmed" -ne 1 ]]; then\n    if ! prompt_yes_no "Pasta local inferida (${target_folder}) está correta?" "s"; then\n      target_folder="$(prompt_value "Informe o caminho local completo da pasta WebDAV" "$target_folder")"\n    fi\n  fi\n\n  echo\n  echo "Configuração Zotero:"\n  local library_id library_type api_key\n  library_id="$(prompt_value "Library ID" "$default_library_id")"\n  library_type="$(prompt_value "Library type (user/group)" "$default_library_type")"\n\n  if [[ -n "$default_api_key" ]]; then\n    local masked_api="****${default_api_key: -4}"\n    echo "API key atual (mascarada): $masked_api"\n    if prompt_yes_no "Manter API key existente?" "s"; then\n      api_key="$default_api_key"\n    else\n      api_key="$(prompt_secret "Nova API key do Zotero")"\n    fi\n  else\n    api_key="$(prompt_secret "API key do Zotero")"\n  fi\n\n  local scheme="${COMPUTED[SCHEME]}"\n  local host="${COMPUTED[HOST]}"\n  local port="${COMPUTED[PORT]}"\n  local remote_path="${COMPUTED[REMOTE_PATH]}"\n  local mount_uri="${COMPUTED[MOUNT_URI]}"\n\n  if lookup_secret_exists "$scheme" "$host" "$port" "$webdav_user"; then\n    echo "Credencial WebDAV já encontrada no keyring para $webdav_user@$host."\n  else\n    echo\n    echo "Nenhuma credencial encontrada para $webdav_user@$host. Será necessário informar a senha."\n    store_secret "$scheme" "$host" "$port" "$webdav_user" "$webdav_label" "$server_url" "$remote_path"\n  fi\n\n  declare -gA ENV_VARS=()\n  ENV_VARS[ZSW_CONFIG_VERSION]="2"\n  ENV_VARS[ZSW_GIO_BIN]="$gio_bin"\n  ENV_VARS[ZSW_USERNAME]="$webdav_user"\n  ENV_VARS[ZSW_SECRET_LABEL]="$webdav_label"\n  ENV_VARS[ZSW_SERVER_URL]="$server_url"\n  ENV_VARS[ZSW_REMOTE_SUBPATH]="$remote_subpath"\n  ENV_VARS[ZSW_REMOTE_PATH]="$remote_path"\n  ENV_VARS[ZSW_SCHEME]="$scheme"\n  ENV_VARS[ZSW_HOST]="$host"\n  ENV_VARS[ZSW_PORT]="$port"\n  ENV_VARS[ZSW_GIO_MOUNT_URI]="$mount_uri"\n  ENV_VARS[ZSW_TARGET_FOLDER]="$target_folder"\n  ENV_VARS[ZOTERO_SYNC_TARGET_FOLDER]="$target_folder"\n  ENV_VARS[ZOTERO_LIBRARY_ID]="$library_id"\n  ENV_VARS[ZOTERO_LIBRARY_TYPE]="$library_type"\n  ENV_VARS[ZOTERO_API_KEY]="$api_key"\n\n  write_env_file\n\n  local helper_path="$bin_dir/mount_webdav.sh"\n  install_helper_script "$helper_path"\n\n  local systemd_dir="$HOME/.config/systemd/user"\n  mkdir -p "$systemd_dir"\n\n  local webdav_service="$systemd_dir/webdav-koofr.service"\n  create_webdav_service "$webdav_service" "$helper_path"\n\n  local sync_service="$systemd_dir/zotero-sync.service"\n  create_sync_service "$sync_service" "$python_bin" "$python_target"\n\n  systemctl --user daemon-reload\n\n  systemctl --user enable webdav-koofr.service\n  systemctl --user enable zotero-sync.service\n\n  local webdav_failed=0\n  if ! systemctl --user start webdav-koofr.service; then\n    webdav_failed=1\n    echo\n    echo "Aviso: webdav-koofr.service não conseguiu montar automaticamente." >&2\n    echo "Execute manualmente para testar:" >&2\n    echo "  $gio_bin mount ${COMPUTED[MOUNT_URI]}" >&2\n    echo "Confirme que a senha está salva no keyring e tente novamente com:" >&2\n    echo "  systemctl --user restart webdav-koofr.service" >&2\n  fi\n\n  if [[ "$webdav_failed" -eq 0 ]]; then\n    systemctl --user start zotero-sync.service || true\n  else\n    echo\n    echo "O serviço de sincronização será iniciado após a montagem bem-sucedida." >&2\n    echo "Comandos sugeridos:" >&2\n    echo "  systemctl --user restart webdav-koofr.service" >&2\n    echo "  systemctl --user start zotero-sync.service" >&2\n  fi\n\n  cat <<MSG\n\nConfiguração concluída.\n  Script Python: $python_target\n  Arquivo de configuração: $ENV_FILE\n  Serviços habilitados: webdav-koofr.service e zotero-sync.service\n\nUse \'journalctl --user -u webdav-koofr -f\' para acompanhar a montagem.\nSe alterar a senha WebDAV, execute novamente este script para atualizar o keyring.\nMSG\n}\n\nmain "$@"\n'


def run_setup_autostart_mode(extra_args: List[str]) -> None:
    """Executa o configurador de autostart integrado sem depender de arquivo separado."""
    import tempfile

    with tempfile.TemporaryDirectory(prefix="zsw-autostart-") as temp_dir:
        temp_script = Path(temp_dir) / 'setup_autostart.sh'
        temp_script.write_text(SETUP_AUTOSTART_SHELL, encoding='utf-8')
        temp_script.chmod(0o755)
        cmd = ['bash', str(temp_script), Path(__file__).name, *extra_args]
        raise SystemExit(subprocess.run(cmd, check=False).returncode)



def _coerce_response_items(items):
    """Normaliza estruturas retornadas pela Pyzotero em listas de anexos."""
    if not items:
        return []
    if isinstance(items, dict):
        return list(items.values())
    if isinstance(items, list):
        return items
    return [items]


def cleanup_failed_attachment_upload(zot: zotero.Zotero, source_path: str) -> int:
    """Remove anexos preliminares quebrados após falha de upload Pyzotero.

    Quando o Pyzotero cria o item preliminar no Zotero, mas o upload S3 falha,
    podem sobrar anexos sem pai, sem contentType e com `filename` derivado do
    caminho absoluto local. Esses itens não representam um anexo funcional e
    causam duplicatas em execuções futuras.
    """
    basename = os.path.basename(source_path)
    path_filename = os.path.abspath(source_path).replace(os.sep, "_")
    deleted = 0

    try:
        candidates = zot.items(
            itemType="attachment",
            limit=100,
            start=0,
            sort="dateAdded",
            direction="desc",
        )
    except Exception as exc:
        logging.warning(
            "[ZOT-UPLOAD] Não foi possível buscar anexos recentes para limpar falha de upload de '%s': %s",
            basename,
            exc,
        )
        return 0

    for item in candidates:
        data = item.get("data", {})
        if data.get("title") != basename:
            continue
        if data.get("filename") != path_filename:
            continue
        if data.get("parentItem") or data.get("contentType"):
            continue
        if data.get("linkMode") != "imported_file":
            continue

        key = item.get("key")
        try:
            zot.delete_item(item)
            deleted += 1
            logging.warning(
                "[ZOT-UPLOAD] Anexo preliminar quebrado removido após falha de upload: key=%s filename='%s'.",
                key,
                data.get("filename"),
            )
        except Exception as exc:
            logging.error(
                "[ZOT-UPLOAD] Falha ao remover anexo preliminar quebrado key=%s: %s",
                key,
                exc,
            )

    return deleted


def _normalize_cache_path(path: str) -> str:
    return os.path.abspath(path)


def load_hash_cache() -> Dict[str, dict]:
    """Carrega o cache de hashes persistido em disco."""
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except FileNotFoundError:
        return {}
    except Exception as exc:
        logging.warning("[CACHE] Falha ao carregar cache: %s", exc)
        return {}

    if not isinstance(payload, dict):
        return {}

    version = payload.get("version")
    entries = payload.get("entries")
    if version != CACHE_VERSION or not isinstance(entries, dict):
        return {}
    return entries


def save_hash_cache(cache: Dict[str, dict]) -> None:
    """Persiste o cache de hashes em disco."""
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        payload = {
            "version": CACHE_VERSION,
            "updated": datetime.now(timezone.utc).isoformat(),
            "entries": cache,
        }
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=True, indent=2)
    except Exception as exc:
        logging.warning("[CACHE] Falha ao salvar cache: %s", exc)


def get_cached_hash(path: str, cache: Dict[str, dict], stat_result: os.stat_result | None = None) -> str | None:
    """Recupera um hash do cache se mtime e tamanho coincidirem."""
    abspath = _normalize_cache_path(path)
    entry = cache.get(abspath)
    if not entry:
        return None

    try:
        stat = stat_result or os.stat(abspath)
    except OSError:
        return None

    size = entry.get("size")
    cached_mtime_ns = entry.get("mtime_ns")
    cached_mtime = entry.get("mtime")

    if size is None:
        return None

    if cached_mtime_ns is not None:
        if getattr(stat, "st_mtime_ns", None) != cached_mtime_ns or stat.st_size != size:
            return None
    elif cached_mtime is not None:
        if abs(stat.st_mtime - cached_mtime) > 1e-6 or stat.st_size != size:
            return None
    else:
        return None

    return entry.get("hash")


def set_cached_hash(path: str, file_hash: str, cache: Dict[str, dict], stat_result: os.stat_result | None = None) -> None:
    """Armazena no cache o hash calculado para um arquivo."""
    abspath = _normalize_cache_path(path)
    try:
        stat = stat_result or os.stat(abspath)
    except OSError:
        return

    entry = {
        "hash": file_hash,
        "size": stat.st_size,
    }
    if hasattr(stat, "st_mtime_ns"):
        entry["mtime_ns"] = stat.st_mtime_ns  # type: ignore[attr-defined]
    else:
        entry["mtime"] = stat.st_mtime
    cache[abspath] = entry


def rename_cache_entry(cache: Dict[str, dict], old_path: str, new_path: str) -> None:
    """Atualiza o cache quando um arquivo é renomeado."""
    old_abs = _normalize_cache_path(old_path)
    new_abs = _normalize_cache_path(new_path)
    if old_abs == new_abs:
        return
    entry = cache.pop(old_abs, None)
    if entry:
        cache[new_abs] = entry


def remove_cache_entry(cache: Dict[str, dict], path: str) -> None:
    """Remove uma entrada do cache quando um arquivo deixa de existir."""
    cache.pop(_normalize_cache_path(path), None)


def delete_redundant_webdav_duplicate(
    redundant_path: str,
    canonical_path: str,
    canonical_hash: str | None = None,
    ) -> bool:
    """Remove um duplicado redundante no drive quando o canônico já existe.

    Só remove automaticamente quando os dois arquivos têm o mesmo hash. Isso permite
    consolidar colisões de nome no caso 3 sem sobrescrever conteúdo diferente.
    """
    if not redundant_path or not canonical_path or redundant_path == canonical_path:
        return False
    if not os.path.exists(redundant_path) or not os.path.exists(canonical_path):
        return False

    keep_hash = canonical_hash or compute_sha256(canonical_path)
    redundant_hash = compute_sha256(redundant_path)
    if not keep_hash or not redundant_hash:
        logging.warning(
            "[RENOMEIO] Não foi possível validar hashes para consolidar '%s' e '%s'.",
            redundant_path,
            canonical_path,
        )
        return False
    if keep_hash != redundant_hash:
        logging.warning(
            "[RENOMEIO] Colisão de nome entre '%s' e '%s' com conteúdo diferente. Revisão manual necessária.",
            redundant_path,
            canonical_path,
        )
        return False

    try:
        os.remove(redundant_path)
        remove_cache_entry(HASH_CACHE, redundant_path)
        logging.info(
            "[RENOMEIO] Duplicado redundante removido do drive: '%s'. Canônico preservado: '%s'.",
            redundant_path,
            canonical_path,
        )
        return True
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Falha ao remover duplicado redundante '%s': %s",
            redundant_path,
            exc,
        )
        return False


def compute_sha256(
    path: str,
    cache: Dict[str, dict] | None = None,
    timeout_seconds: int | None = None,
) -> str | None:
    """Calcula o hash SHA-256 do arquivo fornecido com suporte a cache e timeout."""
    cache_ref = cache if cache is not None else HASH_CACHE
    abspath = _normalize_cache_path(path)
    try:
        stat = os.stat(abspath)
    except OSError as exc:
        logging.warning("[HASH] Não foi possível acessar '%s': %s", path, exc)
        return None

    if cache_ref is not None:
        cached = get_cached_hash(abspath, cache_ref, stat)
        if cached:
            logging.debug("[HASH] Cache hit para '%s'.", path)
            return cached

    effective_timeout = HASH_READ_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    size_mb = stat.st_size / (1024 * 1024)
    logging.info(
        "[HASH] Calculando SHA-256 de '%s' (%.1f MiB, timeout=%ss).",
        path,
        size_mb,
        effective_timeout if effective_timeout else "sem",
    )

    alarm_enabled = False
    previous_handler = None

    def raise_hash_timeout(signum, frame):
        raise TimeoutError(f"timeout ao calcular hash de {path}")

    try:
        if effective_timeout and effective_timeout > 0:
            try:
                previous_handler = signal.getsignal(signal.SIGALRM)
                signal.signal(signal.SIGALRM, raise_hash_timeout)
                signal.alarm(effective_timeout)
                alarm_enabled = True
            except ValueError:
                logging.debug("[HASH] Timeout por SIGALRM indisponível neste contexto.")

        started_at = time.monotonic()
        hasher = hashlib.sha256()
        with open(abspath, "rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                hasher.update(chunk)
        file_hash = hasher.hexdigest()
        elapsed = time.monotonic() - started_at
        logging.info("[HASH] SHA-256 concluído para '%s' em %.1fs.", path, elapsed)
    except TimeoutError:
        logging.error(
            "[HASH] Timeout após %ss ao calcular SHA-256 de '%s'. Arquivo ignorado nesta execução.",
            effective_timeout,
            path,
        )
        return None
    except OSError as exc:
        logging.warning("[HASH] Não foi possível calcular hash de '%s': %s", path, exc)
        return None
    finally:
        if alarm_enabled:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_handler)

    if cache_ref is not None:
        set_cached_hash(abspath, file_hash, cache_ref, stat)
    return file_hash


HASH_CACHE.update(load_hash_cache())
atexit.register(save_hash_cache, HASH_CACHE)


def get_latest_pdf_path(directory: str) -> str | None:
    """Retorna o PDF mais recente dentro de um diretório."""
    if not os.path.isdir(directory):
        return None
    try:
        candidates = [
            os.path.join(directory, name)
            for name in os.listdir(directory)
            if name.lower().endswith('.pdf')
        ]
    except OSError as exc:
        logging.warning("[HASH] Falha ao listar '%s': %s", directory, exc)
        return None

    if not candidates:
        return None

    candidates.sort(key=lambda path: os.path.getmtime(path), reverse=True)
    return candidates[0]


def build_local_storage_index(existing_filenames: Dict[str, dict]) -> Tuple[Dict[str, List[dict]], Dict[str, str]]:
    """Indexa por hash a cópia local do Zotero em ~/Zotero/storage.

    O storage local funciona como espelho operacional dos anexos já conhecidos pelo
    Zotero. Quando a API conhece um item, mas o PDF local sumiu, o script tenta
    reconstruir essa cópia. Quando drive e Zotero têm o mesmo conteúdo com nomes
    diferentes, o storage local permite comparar mtime e decidir qual lado deve ceder.
    """
    hash_index: Dict[str, List[dict]] = {}
    key_to_path: Dict[str, str] = {}
    seen_keys: set[str] = set()

    for info in existing_filenames.values():
        key = info.get('key')
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)

        local_dir = os.path.join(LOCAL_COPY_DIR, key)
        if not os.path.isdir(local_dir):
            continue
        local_file = get_latest_pdf_path(local_dir)
        if not local_file:
            continue
        file_hash = compute_sha256(local_file)
        if not file_hash:
            continue

        entry = {
            'key': key,
            'path': local_file,
            'filename': os.path.basename(local_file),
            'info': info,
        }
        hash_index.setdefault(file_hash, []).append(entry)
        key_to_path[key] = local_file

    return hash_index, key_to_path


def rename_webdav_file(src_path: str, desired_name: str) -> str:
    """Renomeia o arquivo no WebDAV para alinhar com o Zotero."""
    current_name = os.path.basename(src_path)
    if current_name == desired_name or not desired_name:
        return src_path

    dest_path = os.path.join(os.path.dirname(src_path), desired_name)
    if os.path.exists(dest_path):
        logging.warning(
            "[RENOMEIO] Destino '%s' já existe ao tentar renomear '%s'. Mantido nome original.",
            dest_path,
            src_path,
        )
        return src_path

    try:
        os.rename(src_path, dest_path)
        logging.info("[RENOMEIO] '%s' renomeado para '%s'.", current_name, desired_name)
        rename_cache_entry(HASH_CACHE, src_path, dest_path)
        return dest_path
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Falha ao renomear '%s' para '%s': %s",
            current_name,
            desired_name,
            exc,
        )
        return src_path


def register_local_hash(
    hash_index: Dict[str, List[dict]],
    key_to_path: Dict[str, str],
    key: str,
    file_path: str,
    info: dict,
) -> None:
    """Atualiza o índice de hashes com uma nova cópia local."""
    if not key or not file_path or not os.path.exists(file_path):
        return
    file_hash = compute_sha256(file_path)
    if not file_hash:
        return
    entry = {
        'key': key,
        'path': file_path,
        'filename': os.path.basename(file_path),
        'info': info,
    }
    bucket = hash_index.setdefault(file_hash, [])
    if not any(existing['key'] == key for existing in bucket):
        bucket.append(entry)
    key_to_path[key] = file_path


def rename_local_attachment(
    zot: zotero.Zotero,
    key: str,
    current_path: str,
    new_filename: str,
) -> str:
    """Renomeia o anexo local do Zotero e atualiza metadados via API."""
    if not key or not current_path or not os.path.exists(current_path) or not new_filename:
        return current_path

    current_name = os.path.basename(current_path)
    if current_name == new_filename:
        return current_path

    dest_path = os.path.join(os.path.dirname(current_path), new_filename)
    if os.path.exists(dest_path):
        logging.warning(
            "[RENOMEIO] Já existe '%s' ao renomear anexo %s. Mantido nome '%s'.",
            dest_path,
            key,
            current_name,
        )
        return current_path

    try:
        item = zot.item(key)
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao obter anexo %s: %s", key, exc)
        return current_path

    try:
        os.rename(current_path, dest_path)
    except OSError as exc:
        logging.warning(
            "[RENOMEIO] Não foi possível renomear arquivo local '%s' para '%s': %s",
            current_name,
            new_filename,
            exc,
        )
        return current_path

    rename_cache_entry(HASH_CACHE, current_path, dest_path)

    try:
        item_data = item.get('data', {})
        item_data['filename'] = new_filename
        item_data['title'] = new_filename
        item['data'] = item_data
        zot.update_item(item)
        logging.info("[RENOMEIO] Anexo %s atualizado para '%s'.", key, new_filename)
    except Exception as exc:
        logging.warning("[RENOMEIO] Falha ao atualizar metadados do anexo %s: %s", key, exc)

    return dest_path


def copy_to_local_storage(src_path: str, attachment_key: str, known_hash: str | None = None) -> str | None:
    """Garante uma cópia local para o anexo recém-processado."""
    if not LOCAL_COPY_DIR:
        return None

    try:
        os.makedirs(LOCAL_COPY_DIR, exist_ok=True)
    except Exception as exc:
        logging.error("[COPIA-LOCAL] Falha ao preparar diretório local '%s': %s", LOCAL_COPY_DIR, exc)
        return None

    dest_dir = os.path.join(LOCAL_COPY_DIR, attachment_key)
    dest_file = os.path.join(dest_dir, os.path.basename(src_path))

    if os.path.exists(dest_file):
        logging.info("[COPIA-LOCAL] '%s' já existe. Nenhuma nova cópia criada.", dest_file)
        if known_hash:
            set_cached_hash(dest_file, known_hash, HASH_CACHE)
        return "exists"

    try:
        os.makedirs(dest_dir, exist_ok=True)
        shutil.copy2(src_path, dest_file)
        logging.info("[COPIA-LOCAL] Arquivo copiado para %s", dest_file)
        if known_hash:
            set_cached_hash(dest_file, known_hash, HASH_CACHE)
        else:
            compute_sha256(dest_file)
        return "copied"
    except Exception as exc:
        logging.error("[COPIA-LOCAL] Falha ao copiar '%s' para '%s': %s", src_path, dest_file, exc)
        return None


def set_mtime_from_zotero_date(path: str, date_modified: str | None) -> None:
    """Alinha o mtime de uma cópia materializada com o dateModified do Zotero."""
    parsed = parse_zotero_date(date_modified or "")
    if not parsed:
        return
    timestamp = parsed.timestamp()
    try:
        os.utime(path, (timestamp, timestamp))
    except OSError as exc:
        logging.warning("[ZOT->DRIVE] Não foi possível ajustar mtime de '%s': %s", path, exc)


def download_zotero_attachment_to_local(
    zot: zotero.Zotero,
    item: dict,
    filename: str,
    ) -> str | None:
    """Baixa o arquivo do anexo Zotero para ~/Zotero/storage/<key>/ quando a cópia local falta."""
    key = item.get('key')
    if not key or not filename:
        return None

    dest_dir = os.path.join(LOCAL_COPY_DIR, key)
    dest_file = os.path.join(dest_dir, os.path.basename(filename))
    if os.path.exists(dest_file):
        return dest_file

    try:
        os.makedirs(dest_dir, exist_ok=True)
        zot.dump(key, filename=os.path.basename(filename), path=dest_dir)
    except Exception as exc:
        logging.warning("[ZOT->DRIVE] Falha ao baixar anexo %s do Zotero: %s", key, exc)
        return None

    if not os.path.exists(dest_file):
        logging.warning("[ZOT->DRIVE] Download do anexo %s não gerou o arquivo esperado: %s", key, dest_file)
        return None

    data = item.get('data', {})
    set_mtime_from_zotero_date(dest_file, data.get('dateModified'))
    compute_sha256(dest_file)
    logging.info("[ZOT->DRIVE] Anexo %s baixado para cópia local: %s", key, dest_file)
    return dest_file


def build_drive_pdf_index(directory: str, stats: dict | None = None) -> tuple[dict, dict, dict]:
    """Indexa PDFs atuais do drive por nome normalizado e hash."""
    name_index: dict[str, str] = {}
    aggressive_index: dict[str, str] = {}
    hash_index: dict[str, list[dict]] = {}

    temp_stats = {'folder_total_pdfs': 0, 'folder_checked_pdfs': 0}
    for path in collect_all_pdfs(directory, temp_stats):
        filename = os.path.basename(path)
        norm = normalize_filename(filename)
        norm_aggressive = normalize_aggressive(filename)
        if norm and norm not in name_index:
            name_index[norm] = path
        if norm_aggressive and norm_aggressive not in aggressive_index:
            aggressive_index[norm_aggressive] = path

        file_hash = compute_sha256(path)
        if not file_hash:
            if stats is not None:
                stats['errors'] += 1
            logging.warning("[ZOT->DRIVE] Não foi possível hashear arquivo do drive durante índice final: %s", path)
            continue

        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = 0.0
        hash_index.setdefault(file_hash, []).append({
            'path': path,
            'filename': filename,
            'mtime': mtime,
        })

    logging.info(
        "[ZOT->DRIVE] Índice final do drive: %d nomes | %d hashes únicos.",
        len(name_index),
        len(hash_index),
    )
    return name_index, aggressive_index, hash_index


def materialize_zotero_attachments_to_drive(
    zot: zotero.Zotero,
    attachments: List[dict],
    drive_name_index: dict,
    drive_aggressive_index: dict,
    drive_hash_index: dict,
    key_to_path: Dict[str, str],
    stats: dict,
    tie_conflicts: list[dict[str, str]],
    ) -> None:
    """Materializa no drive PDFs conhecidos pelo Zotero que não existem no drive."""
    seen_keys: set[str] = set()

    for item in attachments:
        data = item.get('data', {})
        key = item.get('key')
        if not key or key in seen_keys:
            continue
        seen_keys.add(key)

        filename = get_filename_from_item(item)
        if not filename or not filename.lower().endswith('.pdf'):
            continue
        filename = os.path.basename(filename)

        norm = normalize_filename(filename)
        norm_aggressive = normalize_aggressive(filename)
        if (norm and norm in drive_name_index) or (norm_aggressive and norm_aggressive in drive_aggressive_index):
            continue

        local_path = key_to_path.get(key) or get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, key))
        if not local_path or not os.path.exists(local_path):
            local_path = download_zotero_attachment_to_local(zot, item, filename)
            if local_path:
                stats['downloaded_zotero'] += 1
                stats['local_copies'] += 1

        if not local_path or not os.path.exists(local_path):
            stats['errors'] += 1
            logging.warning(
                "[ZOT->DRIVE] Anexo %s existe no Zotero, mas não há arquivo local nem download disponível. Não materializado.",
                key,
            )
            continue

        local_hash = compute_sha256(local_path)
        if not local_hash:
            stats['errors'] += 1
            logging.warning("[ZOT->DRIVE] Não foi possível calcular hash da origem local para anexo %s.", key)
            continue

        hash_matches = drive_hash_index.get(local_hash, [])
        if hash_matches:
            drive_entry = max(hash_matches, key=lambda entry: entry.get('mtime', 0.0))
            drive_path = drive_entry['path']
            drive_name = drive_entry['filename']
            drive_mtime = drive_entry.get('mtime', 0.0)
            zotero_date_modified = parse_zotero_date(data.get('dateModified', ''))
            zotero_mtime = zotero_date_modified.timestamp() if zotero_date_modified else os.path.getmtime(local_path)

            if drive_name == filename:
                continue

            if zotero_mtime > drive_mtime:
                new_path = rename_webdav_file(drive_path, filename)
                if new_path != drive_path:
                    stats['renamed_webdav'] += 1
                    drive_entry['path'] = new_path
                    drive_entry['filename'] = filename
                    drive_entry['mtime'] = os.path.getmtime(new_path)
                    drive_name_index[norm] = new_path
                    drive_aggressive_index[norm_aggressive] = new_path
                    logging.info("[ZOT->DRIVE] Drive renomeado pelo Zotero mais recente: '%s'.", filename)
            elif drive_mtime > zotero_mtime:
                updated_path = rename_local_attachment(zot, key, local_path, drive_name)
                if updated_path != local_path:
                    key_to_path[key] = updated_path
                    stats['renamed_local'] += 1
                    logging.info("[ZOT->DRIVE] Zotero atualizado pelo drive mais recente: '%s'.", drive_name)
            else:
                stats['mtime_ties'] += 1
                tie_conflicts.append({
                    'key': key,
                    'drive_name': drive_name,
                    'zotero_name': filename,
                })
                logging.warning("[ZOT->DRIVE] Empate de mtime entre drive e Zotero para key=%s.", key)
            continue

        dest_path = os.path.join(TARGET_FOLDER, filename)
        if os.path.exists(dest_path):
            dest_hash = compute_sha256(dest_path)
            if dest_hash and dest_hash == local_hash:
                logging.info("[ZOT->DRIVE] '%s' já existe no drive com mesmo hash.", filename)
                continue
            stats['errors'] += 1
            logging.warning(
                "[ZOT->DRIVE] Destino já existe com conteúdo diferente. Não sobrescrito: %s",
                dest_path,
            )
            continue

        try:
            shutil.copy2(local_path, dest_path)
            set_mtime_from_zotero_date(dest_path, data.get('dateModified'))
            set_cached_hash(dest_path, local_hash, HASH_CACHE)
            drive_name_index[norm] = dest_path
            drive_aggressive_index[norm_aggressive] = dest_path
            drive_hash_index.setdefault(local_hash, []).append({
                'path': dest_path,
                'filename': filename,
                'mtime': os.path.getmtime(dest_path),
            })
            stats['materialized_drive'] += 1
            logging.info("[ZOT->DRIVE] Anexo %s materializado no drive: %s", key, dest_path)
        except Exception as exc:
            stats['errors'] += 1
            logging.error("[ZOT->DRIVE] Falha ao materializar anexo %s em '%s': %s", key, dest_path, exc)

def build_cli_parser() -> argparse.ArgumentParser:
    """Constrói a CLI unificada do workflow Zotero/WebDAV."""
    parser = argparse.ArgumentParser(
        description='Entry point unificado do workflow Zotero/WebDAV',
    )
    subparsers = parser.add_subparsers(dest='command')

    subparsers.add_parser('sync', help='Executa a sincronização principal')
    subparsers.add_parser('diagnostico', help='Roda o diagnóstico de duplicatas e ausências')

    remove_parser = subparsers.add_parser(
        'remove-duplicatas',
        help='Detecta e remove duplicatas na biblioteca Zotero',
    )
    remove_parser.add_argument(
        '--executar',
        action='store_true',
        help='Apaga de verdade os anexos duplicados',
    )

    setup_parser = subparsers.add_parser(
        'setup-autostart',
        help='Executa o configurador de autostart integrado',
    )
    setup_parser.add_argument(
        'setup_args',
        nargs=argparse.REMAINDER,
        help='Argumentos extras repassados ao configurador embutido',
    )
    return parser


def run_sync_mode():
    """Executa a sincronização observando API do Zotero, drive montado e storage local."""
    configure_pyzotero_upload_transport()
    print("Iniciando o sincronizador Zotero/WebDAV (v2.0)")

    stats = {
        'added': 0,
        'skipped': 0,
        'errors': 0,
        'zotero_attachments_scanned': 0,
        'zotero_unique_filenames': 0,
        'folder_total_pdfs': 0,
        'folder_checked_pdfs': 0,
        'local_copies': 0,
        'processed': 0,
        'hash_matches': 0,
        'renamed_webdav': 0,
        'renamed_local': 0,
        'updated_content': 0,
        'mtime_ties': 0,
        'pruned_drive_duplicates': 0,
        'materialized_drive': 0,
        'downloaded_zotero': 0,
        'zotero_bibliographic_scanned': 0,
        'zotero_bibliographic_indexed': 0,
        'attached_to_existing_parent': 0,
        'blocked_duplicate_risk': 0,
    }
    tie_conflicts: list[dict[str, str]] = []

    # 1. Conectar ao Zotero
    try:
        zot = zotero.Zotero(LIBRARY_ID, LIBRARY_TYPE, API_KEY)
        zot.key_info()
        print("✓ Conexão com a Zotero API bem-sucedida.")
    except Exception as e:
        logging.error(f"Falha ao conectar à Zotero API. Verifique suas credenciais. Erro: {e}")
        finalize_execution(stats)
        return

    # 2. Coletar TODOS os anexos existentes no Zotero
    print("\nColetando anexos da biblioteca Zotero... (pode levar alguns instantes)")
    try:
        (
            all_attachments,
            existing_filenames,
            existing_filenames_aggressive,
        ) = collect_all_attachments(zot, stats)

        stats['zotero_unique_filenames'] = len(existing_filenames)

        if not existing_filenames:
            logging.warning("[ZOT] Nenhum nome de arquivo indexado. A biblioteca pode estar vazia.")

        print(f"✓ {stats['zotero_attachments_scanned']} anexos escaneados | "
              f"{stats['zotero_unique_filenames']} nomes únicos indexados.")

    except Exception as e:
        logging.error(f"Erro ao coletar anexos do Zotero: {e}")
        finalize_execution(stats)
        return

    print("\nColetando itens bibliográficos para evitar anexos soltos duplicadores...")
    try:
        bibliographic_items = collect_all_bibliographic_items(zot, stats)
        bibliographic_parent_index = build_bibliographic_parent_index(bibliographic_items)
        stats['zotero_bibliographic_indexed'] = len(bibliographic_parent_index)
        print(
            f"✓ {stats['zotero_bibliographic_scanned']} itens bibliográficos escaneados | "
            f"{stats['zotero_bibliographic_indexed']} títulos candidatos indexados."
        )
    except Exception as e:
        stats['errors'] += 1
        logging.error(
            "[BIB] Erro ao coletar itens bibliográficos: %s. "
            "Sincronização abortada para evitar criação de anexos soltos que podem virar duplicatas.",
            e,
        )
        finalize_execution(stats)
        return


    hash_index, key_to_path = build_local_storage_index(existing_filenames)

    # 3. Processar arquivos da pasta montada no drive.
    #
    print(f"\nVerificando a pasta: {TARGET_FOLDER}")
    if not os.path.isdir(TARGET_FOLDER):
        logging.error(f"A pasta alvo não foi encontrada ou não é um diretório: {TARGET_FOLDER}")
        finalize_execution(stats)
        return

    try:
        files_to_process = collect_all_pdfs(TARGET_FOLDER, stats)

        if not files_to_process:
            print("Nenhum arquivo PDF encontrado na pasta.")
            finalize_execution(stats)
            return

        print(f"Encontrados {stats['folder_total_pdfs']} PDFs. Processando todos.")

        if not probe_pdf_content_read(files_to_process[0]):
            stats['errors'] += 1
            logging.error(
                "[PROBE] Sincronização abortada: o mount não conseguiu ler conteúdo do primeiro PDF. "
                "Verifique o rclone/Koofr antes de tentar adicionar ou comparar anexos.",
            )
            finalize_execution(stats)
            return

        # 4. Processar cada PDF da pasta WebDAV
        #
        # Ordem de verificação para cada arquivo:
        #
        # CASO 1 — Nome encontrado no Zotero, hash igual ao storage local
        #          → Já sincronizado. Ignora.
        #
        # CASO 2 — Nome encontrado no Zotero, hash diferente do storage local
        #          → Conteúdo do drive é tratado como versão mais recente para a cópia local.
        #
        # CASO 3 — Nome NÃO encontrado, hash encontrado no storage local
        #          → Mesmo conteúdo com nomes diferentes. Decide o nome canônico por mtime/dateModified.
        #
        # CASO 4 — Nome NÃO encontrado, hash NÃO encontrado
        #          → Arquivo novo. Adiciona ao Zotero e copia para storage local.
        #
        # CASO 5 — Nome encontrado mas não há cópia local (storage vazio para essa key)
        #          → Garante a cópia local sem re-adicionar ao Zotero.
        #
        # Nota de performance: hashes podem ser calculados em qualquer caso que precise
        # confirmar conteúdo, detectar atualização, reconciliar rename ou criar cópia local.
        # Em mounts FUSE/rclone isso pode ler o PDF inteiro pela rede; logs e timeout ajudam a diferenciar lentidão de travamento.

        total_files_to_process = len(files_to_process)

        for index, file_path in enumerate(tqdm(files_to_process, desc="Verificando arquivos locais"), start=1):
            stats['processed'] += 1
            file_name = os.path.basename(file_path)
            logging.info("[LOOP] Processando %d/%d: '%s'.", index, total_files_to_process, file_name)
            norm_local = normalize_filename(file_name)
            norm_local_aggressive = normalize_aggressive(file_name)

            nome_info = (
                existing_filenames.get(norm_local)
                or existing_filenames_aggressive.get(norm_local_aggressive)
            )
            nome_encontrado = nome_info is not None and nome_info.get('key') != '__pending__'

            if nome_encontrado:
                zotero_key = nome_info['key']
                local_dir = os.path.join(LOCAL_COPY_DIR, zotero_key)
                local_file = get_latest_pdf_path(local_dir)

                if local_file and os.path.exists(local_file):
                    # Temos cópia local — compara hash para detectar atualização de conteúdo
                    local_hash = compute_sha256(local_file)
                    webdav_hash = compute_sha256(file_path)

                    if not local_hash or not webdav_hash:
                        stats['errors'] += 1
                        logging.error(
                            "[HASH] Falha ao comparar hashes de '%s' (local_hash=%s, webdav_hash=%s). Arquivo ignorado.",
                            file_name,
                            "ok" if local_hash else "falhou",
                            "ok" if webdav_hash else "falhou",
                        )
                        continue

                    if local_hash and webdav_hash and local_hash == webdav_hash:
                        # CASO 1: nome ok, conteúdo igual → já sincronizado
                        logging.info("[CASO 1] '%s' já sincronizado (key=%s).", file_name, zotero_key)
                        stats['skipped'] += 1
                        stats['hash_matches'] += 1
                        continue

                    elif local_hash and webdav_hash and local_hash != webdav_hash:
                        # CASO 2: nome ok, conteúdo diferente → WebDAV tem versão mais nova
                        logging.info("[CASO 2] '%s' atualizado no WebDAV. Atualizando storage local (key=%s).", file_name, zotero_key)
                        try:
                            shutil.copy2(file_path, local_file)
                            set_cached_hash(local_file, webdav_hash, HASH_CACHE)
                            register_local_hash(hash_index, key_to_path, zotero_key, local_file, nome_info)
                            stats['local_copies'] += 1
                            stats['updated_content'] += 1
                            logging.info("[CASO 2] Storage local atualizado: '%s'.", local_file)
                        except Exception as exc:
                            logging.warning("[CASO 2] Falha ao atualizar storage local de '%s': %s", file_name, exc)
                            stats['errors'] += 1
                        stats['skipped'] += 1
                        continue

                else:
                    # CASO 5: nome encontrado no Zotero mas sem cópia local
                    logging.info("[CASO 5] '%s' existe no Zotero mas sem cópia local. Copiando (key=%s).", file_name, zotero_key)
                    webdav_hash = compute_sha256(file_path)
                    if not webdav_hash:
                        stats['errors'] += 1
                        logging.error(
                            "[HASH] Não foi possível obter hash de '%s' para recriar cópia local. Arquivo ignorado.",
                            file_name,
                        )
                        continue
                    copy_outcome = copy_to_local_storage(file_path, zotero_key, webdav_hash)
                    if copy_outcome == "copied":
                        stats['local_copies'] += 1
                        new_local = get_latest_pdf_path(local_dir)
                        if new_local:
                            register_local_hash(hash_index, key_to_path, zotero_key, new_local, nome_info)
                    stats['skipped'] += 1
                    continue

            # Nome não encontrado — calcula hash para casos 3 e 4
            file_hash = compute_sha256(file_path)
            if not file_hash:
                stats['errors'] += 1
                logging.error("[HASH] Não foi possível obter hash de '%s'. Arquivo ignorado.", file_name)
                continue

            if DEBUG_DETAILED:
                logging.debug(
                    "[LOCAL] arquivo='%s' | norm='%s' | norm_agg='%s' | hash=%s",
                    file_name, norm_local, norm_local_aggressive, file_hash,
                )

            hash_matches = hash_index.get(file_hash, [])
            if hash_matches:
                # CASO 3: hash encontrado, nome diferente → reconciliar nomes pelo mtime
                entry = hash_matches[0]
                canonical_key = entry['key']
                canonical_path = entry.get('path')
                webdav_name = file_name
                webdav_mtime = os.path.getmtime(file_path)

                if canonical_path and os.path.exists(canonical_path):
                    entry_info = entry.get('info', {}) or {}
                    zotero_name = entry_info.get('original') or os.path.basename(canonical_path)
                    local_copy_name = os.path.basename(canonical_path)
                    canonical_name = zotero_name
                    local_copy_mtime = os.path.getmtime(canonical_path)
                    zotero_date_modified = parse_zotero_date(entry_info.get('dateModified', ''))
                    zotero_mtime = zotero_date_modified.timestamp() if zotero_date_modified else local_copy_mtime

                    logging.info(
                        "[CASO 3] Mesmo conteúdo, nomes diferentes: drive='%s' | zotero='%s' | local_copy='%s' (key=%s).",
                        webdav_name, zotero_name, local_copy_name, canonical_key,
                    )
                    logging.info(
                        "[CASO 3] Datas: drive=%.6f | zotero=%.6f | local_copy=%.6f.",
                        webdav_mtime,
                        zotero_mtime,
                        local_copy_mtime,
                    )

                    if webdav_mtime > zotero_mtime:
                        updated_path = rename_local_attachment(zot, canonical_key, canonical_path, webdav_name)
                        if updated_path != canonical_path:
                            entry['path'] = updated_path
                            entry['filename'] = webdav_name
                            key_to_path[canonical_key] = updated_path
                            entry_info['original'] = webdav_name
                            entry_info['dateModified'] = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
                            stats['renamed_local'] += 1
                            logging.info("[CASO 3] Zotero atualizado para o nome mais recente do drive: '%s'.", webdav_name)

                        canonical_drive_path = os.path.join(os.path.dirname(file_path), zotero_name)
                        if canonical_drive_path != file_path and os.path.exists(canonical_drive_path):
                            if delete_redundant_webdav_duplicate(canonical_drive_path, file_path, canonical_hash=file_hash):
                                stats['pruned_drive_duplicates'] += 1
                    elif zotero_mtime > webdav_mtime:
                        if local_copy_name != zotero_name:
                            updated_path = rename_local_attachment(zot, canonical_key, canonical_path, zotero_name)
                            if updated_path != canonical_path:
                                entry['path'] = updated_path
                                entry['filename'] = zotero_name
                                key_to_path[canonical_key] = updated_path
                                stats['renamed_local'] += 1

                        canonical_drive_path = os.path.join(os.path.dirname(file_path), zotero_name)
                        if canonical_drive_path != file_path and os.path.exists(canonical_drive_path):
                            if delete_redundant_webdav_duplicate(file_path, canonical_drive_path):
                                file_path = canonical_drive_path
                                file_name = zotero_name
                                stats['pruned_drive_duplicates'] += 1
                        else:
                            new_path = rename_webdav_file(file_path, zotero_name)
                            if new_path != file_path:
                                file_path = new_path
                                file_name = zotero_name
                                stats['renamed_webdav'] += 1
                                logging.info("[CASO 3] Drive atualizado para o nome mais recente do Zotero: '%s'.", zotero_name)
                    else:
                        stats['mtime_ties'] += 1
                        tie_conflicts.append({
                            'key': canonical_key,
                            'drive_name': webdav_name,
                            'zotero_name': zotero_name,
                        })
                        logging.warning(
                            "[CASO 3] Empate de mtime entre drive e Zotero para key=%s. Mantidos os nomes atuais para revisão manual.",
                            canonical_key,
                        )
                else:
                    canonical_name = webdav_name

                norm_local = normalize_filename(file_name)
                norm_local_aggressive = normalize_aggressive(file_name)
                info = {
                    'original': canonical_name,
                    'key': canonical_key,
                    'dateModified': (entry.get('info') or {}).get('dateModified'),
                }
                existing_filenames[norm_local] = info
                existing_filenames_aggressive[norm_local_aggressive] = info
                stats['skipped'] += 1
                stats['hash_matches'] += 1
                continue

            # CASO 4: nome e hash não encontrados → arquivo novo
            # Registra como pendente antes de chamar a API para evitar duplicatas
            # caso o mesmo arquivo apareça duas vezes no loop.
            existing_filenames[norm_local] = {'original': file_name, 'key': '__pending__'}
            existing_filenames_aggressive[norm_local_aggressive] = {'original': file_name, 'key': '__pending__'}

            parent_match, parent_candidates = select_parent_for_new_attachment(
                file_name,
                bibliographic_parent_index,
            )
            parent_key = parent_match['key'] if parent_match else None
            if parent_candidates and not parent_match:
                existing_filenames.pop(norm_local, None)
                existing_filenames_aggressive.pop(norm_local_aggressive, None)
                stats['errors'] += 1
                stats['blocked_duplicate_risk'] += 1
                candidate_summary = "; ".join(
                    f"{candidate['key']} score={candidate['score']:.2f} title='{candidate['title'][:90]}'"
                    for candidate in parent_candidates[:5]
                )
                logging.error(
                    "[DUP-RISK] '%s' parece pertencer a mais de um item bibliográfico existente. "
                    "Upload bloqueado para não criar nova duplicata. Candidatos: %s",
                    file_name,
                    candidate_summary,
                )
                continue


            try:
                if parent_key:
                    logging.info(
                        "[CASO 4] Anexando '%s' ao item bibliográfico existente key=%s score=%.2f title='%s'.",
                        file_name,
                        parent_key,
                        parent_match['score'],
                        parent_match['title'],
                    )
                else:
                    logging.info("[CASO 4] Adicionando '%s' ao Zotero como anexo top-level...", file_name)
                response = zot.attachment_simple([file_path], parentid=parent_key)
                if not response:
                    existing_filenames.pop(norm_local, None)
                    existing_filenames_aggressive.pop(norm_local_aggressive, None)
                    stats['errors'] += 1
                    logging.error("[ERRO] Resposta vazia ao adicionar '%s'.", file_name)
                    continue

                success_items = _coerce_response_items(response.get("success"))
                unchanged_items = _coerce_response_items(response.get("unchanged"))
                failure_items = _coerce_response_items(response.get("failure"))
                handled = False

                if success_items:
                    new_key = success_items[0].get("key")
                    if not new_key:
                        existing_filenames.pop(norm_local, None)
                        existing_filenames_aggressive.pop(norm_local_aggressive, None)
                        stats['errors'] += 1
                        logging.error("[ERRO] Chave não retornada para '%s'. Resposta: %s", file_name, response)
                        continue
                    stats['added'] += 1
                    if parent_key:
                        stats['attached_to_existing_parent'] += 1
                    info = {'original': file_name, 'key': new_key, 'dateModified': None}
                    existing_filenames[norm_local] = info
                    existing_filenames_aggressive[norm_local_aggressive] = info
                    copy_outcome = copy_to_local_storage(file_path, new_key, file_hash)
                    if copy_outcome == "copied":
                        stats['local_copies'] += 1
                    elif copy_outcome is None:
                        logging.warning("[COPIA-LOCAL] Não foi possível copiar '%s'.", file_name)
                    local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, new_key))
                    if local_path and os.path.exists(local_path):
                        register_local_hash(hash_index, key_to_path, new_key, local_path, info)
                    if parent_key:
                        logging.info(
                            "[CASO 4] '%s' anexado ao item existente parent=%s com sucesso (key=%s).",
                            file_name,
                            parent_key,
                            new_key,
                        )
                    else:
                        logging.info("[CASO 4] '%s' adicionado como top-level com sucesso (key=%s).", file_name, new_key)
                    handled = True

                if unchanged_items:
                    existing_key = unchanged_items[0].get("key")
                    if not existing_key:
                        existing_filenames.pop(norm_local, None)
                        existing_filenames_aggressive.pop(norm_local_aggressive, None)
                        stats['errors'] += 1
                        logging.error("[ERRO] Chave ausente para '%s' (unchanged). Resposta: %s", file_name, response)
                    else:
                        stats['skipped'] += 1
                        info = {'original': file_name, 'key': existing_key, 'dateModified': None}
                        existing_filenames[norm_local] = info
                        existing_filenames_aggressive[norm_local_aggressive] = info
                        copy_outcome = copy_to_local_storage(file_path, existing_key, file_hash)
                        if copy_outcome == "copied":
                            stats['local_copies'] += 1
                        local_path = get_latest_pdf_path(os.path.join(LOCAL_COPY_DIR, existing_key))
                        if local_path and os.path.exists(local_path):
                            register_local_hash(hash_index, key_to_path, existing_key, local_path, info)
                        logging.info("[CASO 4] '%s' já existia no Zotero (unchanged, key=%s).", file_name, existing_key)
                    handled = True

                if not handled:
                    existing_filenames.pop(norm_local, None)
                    existing_filenames_aggressive.pop(norm_local_aggressive, None)
                    stats['errors'] += 1
                    logging.error("[ERRO] Falha ao adicionar '%s'. Falhas: %s", file_name, failure_items or response)

            except Exception as e:
                existing_filenames.pop(norm_local, None)
                existing_filenames_aggressive.pop(norm_local_aggressive, None)
                stats['errors'] += 1
                logging.error("[ERRO] Exceção ao adicionar '%s': %s", file_name, e)
                cleanup_failed_attachment_upload(zot, file_path)


        logging.info("[ZOT->DRIVE] Iniciando reconciliação Zotero -> drive para anexos ausentes.")
        drive_name_index, drive_aggressive_index, drive_hash_index = build_drive_pdf_index(TARGET_FOLDER, stats)
        materialize_zotero_attachments_to_drive(
            zot,
            all_attachments,
            drive_name_index,
            drive_aggressive_index,
            drive_hash_index,
            key_to_path,
            stats,
            tie_conflicts,
        )
    except Exception as e:
        logging.error(f"Erro ao processar arquivos da pasta: {e}")
        finalize_execution(stats)
        return

    # 5. Relatório final
    total_verificados = stats['processed'] or stats['folder_checked_pdfs']
    pct_adicionados = ((stats['added'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_ignorados = ((stats['skipped'] / total_verificados) * 100) if total_verificados > 0 else 0
    pct_erros = ((stats['errors'] / total_verificados) * 100) if total_verificados > 0 else 0

    tie_summary = ""
    if tie_conflicts:
        tie_lines = ["", f"⚖️ Empates de mtime para revisão manual: {len(tie_conflicts)}"]
        for conflict in tie_conflicts:
            tie_lines.append(
                f"- key={conflict['key']} | drive='{conflict['drive_name']}' | zotero='{conflict['zotero_name']}'"
            )
        tie_summary = "\n".join(tie_lines)

    summary = f"""
╔════════════════════════════════════════════════════════╗
║           RELATÓRIO FINAL  (v2.0)                      ║
╚════════════════════════════════════════════════════════╝

📂 Pasta: {TARGET_FOLDER}
🏠 Cópia local: {LOCAL_COPY_DIR}

┌─── 📊 COLETA DE ANEXOS ──────────────────────────────┐
│ Anexos varridos (total): {stats['zotero_attachments_scanned']:<25} │
│ Nomes únicos indexados:  {stats['zotero_unique_filenames']:<25} │
│ Itens bib. varridos:   {stats['zotero_bibliographic_scanned']:<25} │
│ Títulos bib. indexados:{stats['zotero_bibliographic_indexed']:<25} │
└──────────────────────────────────────────────────────┘

┌─── 📈 RESULTADOS DA VERIFICAÇÃO ───────────────────────┐
│ PDFs totais na pasta: {stats['folder_total_pdfs']:<30} │
│ 🔍 Processados: {total_verificados:<36} │
│ ──────────────────────────────────────────────────── │
│ ✅ Adicionados: {stats['added']} ({pct_adicionados:.1f}%) {' ' * (33 - len(str(stats['added']) + str(round(pct_adicionados,1))))}│
│ 🔗 Anexados a item existente: {stats['attached_to_existing_parent']:<17} │
│ ⏭️  Existentes: {stats['skipped']} ({pct_ignorados:.1f}%) {' ' * (33 - len(str(stats['skipped']) + str(round(pct_ignorados,1))))}│
│ 💾 Cópias locais: {stats['local_copies']:<34} │
│ ❌ Erros: {stats['errors']} ({pct_erros:.1f}%) {' ' * (38 - len(str(stats['errors']) + str(round(pct_erros,1))))}│
│ 🔁 Hash reaproveitados: {stats['hash_matches']:<23} │
│ 🔄 Conteúdo atualizado: {stats['updated_content']:<23} │
│ ✏️  Renomes WebDAV: {stats['renamed_webdav']:<27} │
│ 📝 Renomes storage: {stats['renamed_local']:<27} │
│ 🧹 Duplicados removidos: {stats['pruned_drive_duplicates']:<22} │
│ ⬇️  Baixados do Zotero: {stats['downloaded_zotero']:<24} │
│ 📤 Materializados no drive: {stats['materialized_drive']:<20} │
│ ⚖️  Empates de mtime: {stats['mtime_ties']:<25} │
│ 🛑 Bloqueios anti-duplicata: {stats['blocked_duplicate_risk']:<18} │
└──────────────────────────────────────────────────────┘
{tie_summary}

✨ Processamento concluído!
"""
    print(summary)
    finalize_execution(stats, summary)


def main(argv: List[str] | None = None) -> None:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    if args.command in (None, 'sync'):
        run_sync_mode()
        return
    if args.command == 'diagnostico':
        run_diagnostic_mode()
        return
    if args.command == 'remove-duplicatas':
        run_duplicate_cleanup_mode(execute=args.executar)
        return
    if args.command == 'setup-autostart':
        run_setup_autostart_mode(args.setup_args)
        return

    parser.error(f'Comando não suportado: {args.command}')


if __name__ == "__main__":
    main()
