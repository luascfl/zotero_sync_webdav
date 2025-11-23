#!/usr/bin/env bash
#
# Configura a montagem WebDAV e o serviço de sincronização Zotero em modo usuário.
# - Copia o script Python para ~/.local/bin/
# - Gera arquivo de configuração com variáveis compartilhadas
# - Cria helper de montagem + unidades systemd de usuário
# - Integra com secret-tool para guardar credenciais WebDAV

set -euo pipefail

readonly CONFIG_DIR="$HOME/.config/zotero_sync_webdav"
readonly ENV_FILE="$CONFIG_DIR/zotero_sync.env"
readonly DEFAULT_REMOTE_SUBPATH="Google Drive/zoterodb"

die() {
  echo "Erro: $*" >&2
  exit 1
}

require_command() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      die "Dependência ausente: $cmd"
    fi
  done
}

prompt_value() {
  local prompt="$1"
  local default="${2-}"
  local allow_empty="${3:-0}"
  local value
  while true; do
    if [[ -n "$default" ]]; then
      read -r -p "$prompt [$default]: " value || exit 1
      [[ -z "$value" ]] && value="$default"
    else
      read -r -p "$prompt: " value || exit 1
    fi
    if [[ -n "$value" || "$allow_empty" == "1" ]]; then
      printf '%s' "$value"
      return
    fi
    echo "Valor obrigatório." >&2
  done
}

prompt_secret() {
  local prompt="$1"
  local secret confirm
  while true; do
    read -r -s -p "$prompt: " secret || exit 1
    echo
    if [[ -z "$secret" ]]; then
      echo "A senha não pode ser vazia." >&2
      continue
    fi
    read -r -s -p "Confirme a senha: " confirm || exit 1
    echo
    if [[ "$secret" != "$confirm" ]]; then
      echo "As senhas não conferem. Tente novamente." >&2
      continue
    fi
    printf '%s' "$secret"
    return
  done
}

prompt_yes_no() {
  local prompt="$1"
  local default="${2:-s}"
  local answer default_hint
  case "$default" in
    [sS]|[yY]) default_hint=" [S/n]" ;;
    [nN]) default_hint=" [s/N]" ;;
    *) default_hint=" [s/n]"; default="" ;;
  esac
  while true; do
    read -r -p "$prompt$default_hint " answer || exit 1
    [[ -z "$answer" && -n "$default" ]] && answer="$default"
    case "${answer,,}" in
      s|sim|y|yes) return 0 ;;
      n|nao|não|no) return 1 ;;
      *) echo "Responda com 's' ou 'n'." >&2 ;;
    esac
  done
}

declare -a SECRET_ENTRIES=()
declare -a MOUNTED_WEBDAV=()

load_env_file_simple() {
  local env_path="$1"
  [[ -f "$env_path" ]] || return
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    [[ -z "$line" || "${line:0:1}" == "#" || "$line" != *"="* ]] && continue
    local key="${line%%=*}"
    local value="${line#*=}"
    key="${key#"${key%%[![:space:]]*}"}"
    key="${key%"${key##*[![:space:]]}"}"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    # Remove aspas simples ou duplas ao redor do valor, se presentes.
    if [[ "$value" == \"*\" && "$value" == *\" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' ]]; then
      value="${value:1:${#value}-2}"
    fi
    export "$key=$value"
  done <"$env_path"
}

decode_mount_entry() {
  local entry="$1"
  IFS='|' read -r _ label user host scheme port remote_path mount_path <<<"$entry"
  label="$(decode_field "$label")"
  user="$(decode_field "$user")"
  host="$(decode_field "$host")"
  scheme="$(decode_field "$scheme")"
  port="$(decode_field "$port")"
  remote_path="$(decode_field "$remote_path")"
  mount_path="$(decode_field "$mount_path")"
  printf '%s|%s|%s|%s|%s|%s|%s\n' "$label" "$user" "$host" "$scheme" "$port" "$remote_path" "$mount_path"
}

encode_field() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//|/\\u007c}"
  printf '%s' "$value"
}

decode_field() {
  local value="$1"
  value="${value//\\u007c/|}"
  value="${value//\\\\/\\}"
  printf '%s' "$value"
}

collect_secret_entries() {
  SECRET_ENTRIES=()
  local proto output line label user server url remote_path port attr_proto encoded

  for proto in davs dav; do
    output="$(secret-tool search --all protocol "$proto" 2>/dev/null)" || continue

    label=""; user=""; server=""; url=""; remote_path=""; port=""; attr_proto="$proto"

    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%$'\r'}"

      if [[ -z "$line" ]]; then
        if [[ -n "$label" || -n "$user" || -n "$server" || -n "$url" ]]; then
          encoded="$(encode_field "$label")|$(encode_field "$user")|$(encode_field "$server")|$(encode_field "$url")|$(encode_field "$remote_path")|$(encode_field "$port")|$(encode_field "$attr_proto")"
          SECRET_ENTRIES+=("$encoded")
        fi
        label=""; user=""; server=""; url=""; remote_path=""; port=""; attr_proto="$proto"
        continue
      fi

      case "$line" in
        \[*\]) continue ;;
        secret\ =*) continue ;;
        created\ =*) continue ;;
        modified\ =*) continue ;;
        schema\ =*) continue ;;
        label\ =*)
          label="${line#*= }"
          ;;
        attribute.user\ =*)
          user="${line#*= }"
          ;;
        attribute.server\ =*)
          server="${line#*= }"
          ;;
        attribute.url\ =*)
          url="${line#*= }"
          ;;
        attribute.remote_path\ =*)
          remote_path="${line#*= }"
          ;;
        attribute.port\ =*)
          port="${line#*= }"
          ;;
        attribute.protocol\ =*)
          attr_proto="${line#*= }"
          ;;
      esac
    done <<<"$output"

    if [[ -n "$label" || -n "$user" || -n "$server" || -n "$url" ]]; then
      encoded="$(encode_field "$label")|$(encode_field "$user")|$(encode_field "$server")|$(encode_field "$url")|$(encode_field "$remote_path")|$(encode_field "$port")|$(encode_field "$attr_proto")"
      SECRET_ENTRIES+=("$encoded")
    fi
  done
}

collect_mounted_webdav() {
  MOUNTED_WEBDAV=()
  local gvfs_dir="/run/user/$(id -u)/gvfs"
  [[ -d "$gvfs_dir" ]] || return

  shopt -s nullglob
  local mount_path name part host user port ssl prefix decoded dec_user dec_prefix scheme label
  for mount_path in "$gvfs_dir"/dav:*; do
    name="${mount_path##*/}"
    host=""; user=""; port=""; ssl=""; prefix=""
    IFS=',' read -ra parts <<<"${name#dav:}"
    for part in "${parts[@]}"; do
      case "$part" in
        host=*) host="${part#host=}" ;;
        user=*) user="${part#user=}" ;;
        port=*) port="${part#port=}" ;;
        ssl=*) ssl="${part#ssl=}" ;;
        prefix=*) prefix="${part#prefix=}" ;;
      esac
    done

    mapfile -t decoded < <(U="$user" P="$prefix" python3 - <<'PY'
import os, urllib.parse
print(urllib.parse.unquote(os.environ.get("U","")))
print(urllib.parse.unquote(os.environ.get("P","")))
PY
)
    dec_user="${decoded[0]}"
    dec_prefix="${decoded[1]}"
    [[ -z "$dec_prefix" ]] && dec_prefix="/"
    scheme="dav"
    [[ "${ssl,,}" == "true" ]] && scheme="davs"
    label="Mount ${name}"
    MOUNTED_WEBDAV+=("$(encode_field "$label")|$(encode_field "$dec_user")|$(encode_field "$host")|$(encode_field "$scheme")|$(encode_field "$port")|$(encode_field "$dec_prefix")|$(encode_field "$mount_path")")
  done
  shopt -u nullglob
}

choose_secret_entry() {
  local count="${#SECRET_ENTRIES[@]}"
  [[ "$count" -eq 0 ]] && return 1

  local fallback_user="" fallback_host="" fallback_scheme="" fallback_port="" fallback_remote=""
  if [[ "${#MOUNTED_WEBDAV[@]}" -gt 0 ]]; then
    IFS='|' read -r _ fallback_user fallback_host fallback_scheme fallback_port fallback_remote _ <<<"$(decode_mount_entry "${MOUNTED_WEBDAV[0]}")"
  fi

  echo
  echo "Credenciais WebDAV encontradas no keyring:"

  local idx=1 entry label user server url remote_path port protocol
  for entry in "${SECRET_ENTRIES[@]}"; do
    IFS='|' read -r label user server url remote_path port protocol <<<"$entry"
    label="$(decode_field "$label")"
    user="$(decode_field "$user")"
    server="$(decode_field "$server")"
    url="$(decode_field "$url")"
    remote_path="$(decode_field "$remote_path")"
    port="$(decode_field "$port")"
    protocol="$(decode_field "$protocol")"

    [[ -z "$user" && -n "$fallback_user" ]] && user="$fallback_user"
    [[ -z "$server" && -n "$fallback_host" ]] && server="$fallback_host"
    [[ -z "$protocol" && -n "$fallback_scheme" ]] && protocol="$fallback_scheme"
    [[ -z "$remote_path" && -n "$fallback_remote" ]] && remote_path="$fallback_remote"

    [[ -z "$label" ]] && label="(sem label)"
    [[ -z "$user" ]] && user="(usuário desconhecido)"
    [[ -z "$server" ]] && server="(servidor desconhecido)"
    if [[ -z "$url" ]]; then
      local inferred_url=""
      if [[ -n "$server" ]]; then
        local scheme="$protocol"
        [[ -z "$scheme" ]] && scheme="davs"
        if [[ "$scheme" != "dav" && "$scheme" != "davs" ]]; then
          scheme="davs"
        fi
        local path="$remote_path"
        [[ -z "$path" ]] && path="/"
        [[ "$path" != /* ]] && path="/$path"
        if [[ -n "$port" ]]; then
          inferred_url="$scheme://$server:$port$path"
        else
          inferred_url="$scheme://$server$path"
        fi
      fi
      [[ -n "$inferred_url" ]] && url="$inferred_url" || url="(URL não registrada)"
    fi

    printf "  [%d] %s -> %s@%s (%s)\n" "$idx" "$label" "$user" "$server" "$url"
    ((idx++))
  done
  echo "  [0] Registrar nova credencial"

  local choice
  while true; do
    read -r -p "Escolha uma opção [0-${count}]: " choice || exit 1
    if [[ -z "$choice" ]]; then
      choice=0
    fi
    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -le "$count" ]]; then
      break
    fi
    echo "Opção inválida." >&2
  done

  if [[ "$choice" -eq 0 ]]; then
    SELECTED_SECRET_ENTRY=""
    return 1
  fi

  SELECTED_SECRET_ENTRY="${SECRET_ENTRIES[$((choice-1))]}"
  return 0
}

choose_mounted_entry() {
  local count="${#MOUNTED_WEBDAV[@]}"
  [[ "$count" -eq 0 ]] && return 1

  echo
  echo "Perfis WebDAV já montados detectados:"

  local idx=1 entry label user host scheme port remote_path mount_path
  for entry in "${MOUNTED_WEBDAV[@]}"; do
    IFS='|' read -r label user host scheme port remote_path mount_path <<<"$entry"
    label="$(decode_field "$label")"
    user="$(decode_field "$user")"
    host="$(decode_field "$host")"
    scheme="$(decode_field "$scheme")"
    port="$(decode_field "$port")"
    remote_path="$(decode_field "$remote_path")"
    mount_path="$(decode_field "$mount_path")"

    [[ -z "$label" ]] && label="(sem label)"
    [[ -z "$user" ]] && user="(usuário desconhecido)"
    [[ -z "$host" ]] && host="(servidor desconhecido)"
    [[ -z "$remote_path" ]] && remote_path="/"

    local host_display="$host"
    [[ -n "$port" ]] && host_display="$host_display:$port"
    printf "  [%d] %s -> %s@%s (%s://%s%s | %s)\n" "$idx" "$label" "$user" "$host_display" "$scheme" "$host_display" "$remote_path" "$mount_path"
    ((idx++))
  done
  echo "  [0] Não usar montagens existentes"

  local choice
  while true; do
    read -r -p "Escolha uma opção [0-${count}]: " choice || exit 1
    if [[ -z "$choice" ]]; then
      choice=0
    fi
    if [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 0 && "$choice" -le "$count" ]]; then
      break
    fi
    echo "Opção inválida." >&2
  done

  if [[ "$choice" -eq 0 ]]; then
    SELECTED_MOUNT_ENTRY=""
    return 1
  fi

  SELECTED_MOUNT_ENTRY="${MOUNTED_WEBDAV[$((choice-1))]}"
  return 0
}

lookup_secret_exists() {
  local scheme="$1" host="$2" port="$3" user="$4"
  local -a args=(protocol "$scheme" server "$host" user "$user")
  if [[ -n "$port" ]]; then
    args+=(port "$port")
  fi
  if secret-tool lookup "${args[@]}" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

store_secret() {
  local scheme="$1" host="$2" port="$3" user="$4" label="$5" url="$6" remote_path="$7"
  local password
  password="$(prompt_secret "Senha WebDAV")"
  local -a attrs=(protocol "$scheme" server "$host" user "$user")
  [[ -n "$port" ]] && attrs+=(port "$port")
  attrs+=(url "$url" remote_path "$remote_path" display "$label")
  printf "%s" "$password" | secret-tool store --label="$label" "${attrs[@]}"
  echo "Senha armazenada no keyring com o label '$label'."
}

compute_paths() {
  local server_url="$1"
  local username="$2"
  local remote_subpath="$3"
  local result

  result="$(SERVER_URL="$server_url" WEBDAV_USER="$username" REMOTE_SUBPATH="$remote_subpath" python3 - <<'PY'
import os
from pathlib import PurePosixPath
from urllib.parse import urlparse, quote

server_url = os.environ["SERVER_URL"].strip()
user = os.environ["WEBDAV_USER"]
remote_subpath = os.environ.get("REMOTE_SUBPATH", "")

if not server_url:
    raise SystemExit("A URL base do servidor não pode ser vazia.")

parsed = urlparse(server_url)
if not parsed.scheme:
    raise SystemExit("Informe a URL com o esquema (ex: davs://servidor/dav/).")

scheme = parsed.scheme.lower()
if scheme in ("https", "davs"):
    scheme = "davs"
    ssl = "true"
elif scheme in ("http", "dav"):
    scheme = "dav"
    ssl = "false"
else:
    raise SystemExit(f"Esquema não suportado: {parsed.scheme}")

host = parsed.hostname
if not host:
    raise SystemExit("A URL precisa conter o host.")

port = parsed.port
base_path = parsed.path or "/"
if not base_path.startswith("/"):
    base_path = "/" + base_path

if not base_path.endswith("/"):
    base_path = base_path + "/"

remote_path = base_path.rstrip("/")
if remote_subpath:
    remote_path = str(PurePosixPath(remote_path or "/") / remote_subpath)
elif not remote_path:
    remote_path = "/"

remote_path = remote_path or "/"

user_enc = quote(user, safe='')
host_display = host if port is None else f"{host}:{port}"
remote_path_enc = quote(remote_path, safe='/')
mount_uri = f"{scheme}://{user_enc}@{host_display}{remote_path_enc}"

prefix = remote_path
if prefix.startswith('/'):
    prefix = '%2F' + prefix[1:]

uid = os.getuid()
parts = [f"dav:host={host}"]
if port is not None:
    parts.append(f"port={port}")
parts.append(f"ssl={'true' if scheme == 'davs' else 'false'}")
parts.append(f"user={user_enc}")
parts.append(f"prefix={prefix}")
target_folder = f"/run/user/{uid}/gvfs/" + ",".join(parts)

print(f"SCHEME={scheme}")
print(f"SSL={'true' if scheme == 'davs' else 'false'}")
print(f"HOST={host}")
print(f"PORT={port or ''}")
print(f"BASE_PATH={base_path}")
print(f"REMOTE_PATH={remote_path}")
print(f"MOUNT_URI={mount_uri}")
print(f"TARGET_FOLDER={target_folder}")
PY
)" || {
    die "Falha ao processar a URL WebDAV."
  }

  declare -gA COMPUTED=()
  local line key value
  while IFS='=' read -r key value; do
    [[ -z "$key" ]] && continue
    COMPUTED["$key"]="$value"
  done <<<"$result"
}

write_env_file() {
  mkdir -p "$CONFIG_DIR"
  : >"$ENV_FILE"
  local key value
  {
    echo "# Arquivo gerado automaticamente por setup_autostart.sh"
    echo "# Modifique com cuidado."
    for key in "${!ENV_VARS[@]}"; do
      value="${ENV_VARS[$key]}"
      printf '%s=%q\n' "$key" "$value"
    done
  } >>"$ENV_FILE"
}

install_helper_script() {
  local helper_path="$1"
  cat <<'EOF' >"$helper_path"
#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="$HOME/.config/zotero_sync_webdav/zotero_sync.env"
[[ -f "$ENV_FILE" ]] || { echo "Arquivo de configuração não encontrado: $ENV_FILE" >&2; exit 1; }

# shellcheck disable=SC1090
source "$ENV_FILE"

GIO_BIN="${ZSW_GIO_BIN:-gio}"
MOUNT_URI="${ZSW_GIO_MOUNT_URI:?ZSW_GIO_MOUNT_URI não definido}"

cleanup() {
  [[ -z "${TMP_FILE:-}" ]] || rm -f "$TMP_FILE"
}

already_mounted_msg() {
  grep -qiE 'already mounted|já está montad' "$TMP_FILE"
}

not_mounted_msg() {
  grep -qiE 'not mounted|não está montad' "$TMP_FILE"
}

case "${1:-start}" in
  start)
    TMP_FILE="$(mktemp)"
    trap cleanup EXIT
    if "$GIO_BIN" mount "$MOUNT_URI" 2>"$TMP_FILE"; then
      exit 0
    fi
    if already_mounted_msg; then
      exit 0
    fi
    cat "$TMP_FILE" >&2
    exit 1
    ;;
  stop|unmount)
    TMP_FILE="$(mktemp)"
    trap cleanup EXIT
    if "$GIO_BIN" mount -u "$MOUNT_URI" 2>"$TMP_FILE"; then
      exit 0
    fi
    if not_mounted_msg; then
      exit 0
    fi
    cat "$TMP_FILE" >&2
    exit 1
    ;;
  status)
    if "$GIO_BIN" mount -l | grep -F "$MOUNT_URI" >/dev/null 2>&1; then
      exit 0
    fi
    exit 1
    ;;
  *)
    echo "Uso: $0 [start|stop|status]" >&2
    exit 2
    ;;
esac
EOF
  chmod 755 "$helper_path"
}

create_webdav_service() {
  local service_path="$1"
  local helper_path="$2"
  cat <<EOF >"$service_path"
[Unit]
Description=Montar WebDAV (gio)
After=graphical-session.target network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
EnvironmentFile=%h/.config/zotero_sync_webdav/zotero_sync.env
ExecStart=$helper_path start
ExecStartPre=/usr/bin/sleep 5
ExecStop=$helper_path stop

[Install]
WantedBy=default.target
EOF
}

create_sync_service() {
  local service_path="$1"
  local python_bin="$2"
  local python_script="$3"
  cat <<EOF >"$service_path"
[Unit]
Description=Zotero WebDAV Sync (Python)
After=webdav-koofr.service
Requires=webdav-koofr.service

[Service]
Type=simple
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=%h/.config/zotero_sync_webdav/zotero_sync.env
ExecStart=$python_bin $python_script
Restart=on-failure
RestartSec=10

[Install]
WantedBy=default.target
EOF
}

main() {
  if [[ $EUID -eq 0 ]]; then
    die "Execute este script como usuário normal, não como root."
  fi

  require_command python3 gio systemctl install secret-tool

  local script_dir python_name python_src python_bin gio_bin
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  python_name="${1:-zotero_sync_webdav.py}"
  python_src="$script_dir/$python_name"
  [[ -f "$python_src" ]] || die "Arquivo Python não encontrado: $python_src"

  python_bin="$(command -v python3)"
  gio_bin="$(command -v gio)"

  local bin_dir="$HOME/.local/bin"
  local python_target="$bin_dir/$python_name"
  mkdir -p "$bin_dir"
  install -m 755 "$python_src" "$python_target"

  [[ -d "$CONFIG_DIR" ]] || mkdir -p "$CONFIG_DIR"
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1091
    source "$ENV_FILE"
  fi
  # Se existir um .env na pasta do script, use-o como base (ex.: já configurado manualmente).
  local project_env="$script_dir/.env"
  if [[ -f "$project_env" ]]; then
    load_env_file_simple "$project_env"
  fi

  collect_secret_entries
  collect_mounted_webdav
  local secret_entries_count="${#SECRET_ENTRIES[@]}"
  local default_user="${ZSW_USERNAME-}"
  local default_label="${ZSW_SECRET_LABEL-}"
  local default_server_url="${ZSW_SERVER_URL-}"
  local default_remote_subpath="${ZSW_REMOTE_SUBPATH:-$DEFAULT_REMOTE_SUBPATH}"
  local default_scheme="${ZSW_SCHEME-}"
  local default_port="${ZSW_PORT-}"
  local default_target_folder="${ZSW_TARGET_FOLDER-}"
  local default_library_id="${ZOTERO_LIBRARY_ID:-10830189}"
  local default_library_type="${ZOTERO_LIBRARY_TYPE:-user}"
  local default_api_key="${ZOTERO_API_KEY-}"

  [[ -n "$default_user" ]] || default_user="$USER"
  [[ -n "$default_label" ]] || default_label="WebDAV Sync"
  [[ -n "$default_server_url" ]] || default_server_url="davs://app.koofr.net/dav/"

  local auto_defaults=0

  if [[ "$secret_entries_count" -gt 0 ]]; then
    if choose_secret_entry; then
      local selected_label selected_user selected_server selected_url selected_remote selected_port selected_protocol
      IFS='|' read -r selected_label selected_user selected_server selected_url selected_remote selected_port selected_protocol <<<"$SELECTED_SECRET_ENTRY"
      selected_label="$(decode_field "$selected_label")"
      selected_user="$(decode_field "$selected_user")"
      selected_server="$(decode_field "$selected_server")"
      selected_url="$(decode_field "$selected_url")"
      selected_remote="$(decode_field "$selected_remote")"
      selected_port="$(decode_field "$selected_port")"
      selected_protocol="$(decode_field "$selected_protocol")"

      # Completar campos ausentes com o primeiro mount detectado (se existir).
      if [[ "${#MOUNTED_WEBDAV[@]}" -gt 0 ]]; then
        IFS='|' read -r _ fallback_user fallback_host fallback_scheme fallback_port fallback_remote _ <<<"$(decode_mount_entry "${MOUNTED_WEBDAV[0]}")"
        [[ -z "$selected_user" && -n "$fallback_user" ]] && selected_user="$fallback_user"
        [[ -z "$selected_server" && -n "$fallback_host" ]] && selected_server="$fallback_host"
        [[ -z "$selected_protocol" && -n "$fallback_scheme" ]] && selected_protocol="$fallback_scheme"
        [[ -z "$selected_port" && -n "$fallback_port" ]] && selected_port="$fallback_port"
        [[ -z "$selected_remote" && -n "$fallback_remote" ]] && selected_remote="$fallback_remote"
      fi

      [[ -n "$selected_user" ]] && default_user="$selected_user"
      [[ -z "$selected_label" ]] && selected_label="(sem label)"
      if [[ "$selected_label" != "(sem label)" ]]; then
        default_label="$selected_label"
      fi
      [[ -n "$selected_url" ]] && default_server_url="$selected_url"
      if [[ -n "$selected_remote" ]]; then
        default_remote_subpath="$selected_remote"
      fi
      if [[ -n "$selected_protocol" ]]; then
        default_scheme="$selected_protocol"
      fi
      if [[ -n "$selected_port" ]]; then
        default_port="$selected_port"
      fi

      local display_server="$selected_server"
      [[ -z "$display_server" ]] && display_server="(servidor desconhecido)"

      echo
      echo "Usando a credencial selecionada (${selected_label} -> ${default_user}@${display_server}) para preencher os campos padrão."
      auto_defaults=1
    else
      echo
      echo "Nenhuma credencial existente selecionada. Informe novos dados."
    fi
  fi

  if choose_mounted_entry; then
    local selected_label selected_user selected_host selected_scheme selected_port selected_remote_path selected_mount_path
    IFS='|' read -r selected_label selected_user selected_host selected_scheme selected_port selected_remote_path selected_mount_path <<<"$SELECTED_MOUNT_ENTRY"
    selected_label="$(decode_field "$selected_label")"
    selected_user="$(decode_field "$selected_user")"
    selected_host="$(decode_field "$selected_host")"
    selected_scheme="$(decode_field "$selected_scheme")"
    selected_port="$(decode_field "$selected_port")"
    selected_remote_path="$(decode_field "$selected_remote_path")"
    selected_mount_path="$(decode_field "$selected_mount_path")"

    [[ -n "$selected_user" ]] && default_user="$selected_user"
    [[ -n "$selected_host" ]] || selected_host="(servidor desconhecido)"
    if [[ -n "$selected_scheme" ]]; then
      default_scheme="$selected_scheme"
    fi
    if [[ -n "$selected_port" ]]; then
      default_port="$selected_port"
    fi
    if [[ -n "$selected_remote_path" ]]; then
      # Se a montagem já tem um prefixo, usamos ele como caminho base.
      default_server_url="${selected_scheme}://${selected_host}"
      [[ -n "$selected_port" ]] && default_server_url+=":${selected_port}"
      default_server_url+="$selected_remote_path"
      [[ "$default_server_url" != */ ]] && default_server_url+="/"
      default_remote_subpath=""
    fi
    if [[ -n "$selected_mount_path" ]]; then
      default_target_folder="$selected_mount_path"
    fi

    echo
    echo "Usando dados da montagem existente (${selected_label}) como padrão:"
    echo "  Usuário........: ${default_user}"
    echo "  URL base.......: ${default_server_url}"
    [[ -n "$default_target_folder" ]] && echo "  Pasta local....: ${default_target_folder}"
    auto_defaults=1
  fi

  echo
  echo "Informe os dados para montar o WebDAV:"
  local webdav_user webdav_label server_url remote_subpath
  local accepted_defaults=0
  if [[ "$auto_defaults" -eq 1 ]]; then
    echo "Detectei valores padrão: usuário=${default_user}, URL=${default_server_url}, subpasta='${default_remote_subpath}', pasta local='${default_target_folder:-(não definida)}'."
    if prompt_yes_no "Usar esses valores sem alterar?" "s"; then
      webdav_user="$default_user"
      webdav_label="$default_label"
      server_url="$default_server_url"
      remote_subpath="$default_remote_subpath"
      accepted_defaults=1
    fi
  fi
  if [[ "$accepted_defaults" -ne 1 && -z "${webdav_user-}" ]]; then
    webdav_user="$(prompt_value "Usuário WebDAV" "$default_user")"
  fi
  if [[ "$accepted_defaults" -ne 1 && -z "${webdav_label-}" ]]; then
    webdav_label="$(prompt_value "Label para salvar no keyring" "$default_label")"
  fi
  if [[ "$accepted_defaults" -ne 1 && -z "${server_url-}" ]]; then
    server_url="$(prompt_value "URL base do servidor WebDAV (ex: davs://servidor/dav/)" "$default_server_url")"
  fi
  if [[ "$accepted_defaults" -ne 1 && -z "${remote_subpath-}" ]]; then
    remote_subpath="$(prompt_value "Subpasta remota (relativa ao caminho base ou caminho completo)" "${default_remote_subpath}" 1)"
  fi

  compute_paths "$server_url" "$webdav_user" "$remote_subpath"

  echo
  echo "Resumo da configuração sugerida:"
  echo "  Servidor.......: ${COMPUTED[HOST]}"
  [[ -n "${COMPUTED[PORT]}" ]] && echo "  Porta..........: ${COMPUTED[PORT]}"
  echo "  Esquema........: ${COMPUTED[SCHEME]}"
  echo "  Caminho base...: ${COMPUTED[BASE_PATH]}"
  echo "  Caminho remoto.: ${COMPUTED[REMOTE_PATH]}"
  echo "  URI de montagem: ${COMPUTED[MOUNT_URI]}"
  echo "  Pasta local....: ${COMPUTED[TARGET_FOLDER]}"

  local target_confirmed=0
  if ! prompt_yes_no "Essas informações estão corretas?" "s"; then
    remote_subpath="$(prompt_value "Informe novamente a subpasta/remoto (relativa ao caminho base)" "$remote_subpath" 1)"
    compute_paths "$server_url" "$webdav_user" "$remote_subpath"
    echo
    echo "Ajuste aplicado:"
    echo "  Caminho remoto.: ${COMPUTED[REMOTE_PATH]}"
    echo "  URI de montagem: ${COMPUTED[MOUNT_URI]}"
    echo "  Pasta local....: ${COMPUTED[TARGET_FOLDER]}"
  else
    target_confirmed=1
  fi

  local target_folder="${COMPUTED[TARGET_FOLDER]}"
  if [[ -n "$default_target_folder" ]]; then
    target_folder="$default_target_folder"
  fi
  if [[ "$target_confirmed" -ne 1 ]]; then
    if ! prompt_yes_no "Pasta local inferida (${target_folder}) está correta?" "s"; then
      target_folder="$(prompt_value "Informe o caminho local completo da pasta WebDAV" "$target_folder")"
    fi
  fi

  echo
  echo "Configuração Zotero:"
  local library_id library_type api_key
  library_id="$(prompt_value "Library ID" "$default_library_id")"
  library_type="$(prompt_value "Library type (user/group)" "$default_library_type")"

  if [[ -n "$default_api_key" ]]; then
    local masked_api="****${default_api_key: -4}"
    echo "API key atual (mascarada): $masked_api"
    if prompt_yes_no "Manter API key existente?" "s"; then
      api_key="$default_api_key"
    else
      api_key="$(prompt_secret "Nova API key do Zotero")"
    fi
  else
    api_key="$(prompt_secret "API key do Zotero")"
  fi

  local scheme="${COMPUTED[SCHEME]}"
  local host="${COMPUTED[HOST]}"
  local port="${COMPUTED[PORT]}"
  local remote_path="${COMPUTED[REMOTE_PATH]}"
  local mount_uri="${COMPUTED[MOUNT_URI]}"

  if lookup_secret_exists "$scheme" "$host" "$port" "$webdav_user"; then
    echo "Credencial WebDAV já encontrada no keyring para $webdav_user@$host."
  else
    echo
    echo "Nenhuma credencial encontrada para $webdav_user@$host. Será necessário informar a senha."
    store_secret "$scheme" "$host" "$port" "$webdav_user" "$webdav_label" "$server_url" "$remote_path"
  fi

  declare -gA ENV_VARS=()
  ENV_VARS[ZSW_CONFIG_VERSION]="2"
  ENV_VARS[ZSW_GIO_BIN]="$gio_bin"
  ENV_VARS[ZSW_USERNAME]="$webdav_user"
  ENV_VARS[ZSW_SECRET_LABEL]="$webdav_label"
  ENV_VARS[ZSW_SERVER_URL]="$server_url"
  ENV_VARS[ZSW_REMOTE_SUBPATH]="$remote_subpath"
  ENV_VARS[ZSW_REMOTE_PATH]="$remote_path"
  ENV_VARS[ZSW_SCHEME]="$scheme"
  ENV_VARS[ZSW_HOST]="$host"
  ENV_VARS[ZSW_PORT]="$port"
  ENV_VARS[ZSW_GIO_MOUNT_URI]="$mount_uri"
  ENV_VARS[ZSW_TARGET_FOLDER]="$target_folder"
  ENV_VARS[ZOTERO_SYNC_TARGET_FOLDER]="$target_folder"
  ENV_VARS[ZOTERO_LIBRARY_ID]="$library_id"
  ENV_VARS[ZOTERO_LIBRARY_TYPE]="$library_type"
  ENV_VARS[ZOTERO_API_KEY]="$api_key"

  write_env_file

  local helper_path="$bin_dir/mount_webdav.sh"
  install_helper_script "$helper_path"

  local systemd_dir="$HOME/.config/systemd/user"
  mkdir -p "$systemd_dir"

  local webdav_service="$systemd_dir/webdav-koofr.service"
  create_webdav_service "$webdav_service" "$helper_path"

  local sync_service="$systemd_dir/zotero-sync.service"
  create_sync_service "$sync_service" "$python_bin" "$python_target"

  systemctl --user daemon-reload

  systemctl --user enable webdav-koofr.service
  systemctl --user enable zotero-sync.service

  local webdav_failed=0
  if ! systemctl --user start webdav-koofr.service; then
    webdav_failed=1
    echo
    echo "Aviso: webdav-koofr.service não conseguiu montar automaticamente." >&2
    echo "Execute manualmente para testar:" >&2
    echo "  $gio_bin mount ${COMPUTED[MOUNT_URI]}" >&2
    echo "Confirme que a senha está salva no keyring e tente novamente com:" >&2
    echo "  systemctl --user restart webdav-koofr.service" >&2
  fi

  if [[ "$webdav_failed" -eq 0 ]]; then
    systemctl --user start zotero-sync.service || true
  else
    echo
    echo "O serviço de sincronização será iniciado após a montagem bem-sucedida." >&2
    echo "Comandos sugeridos:" >&2
    echo "  systemctl --user restart webdav-koofr.service" >&2
    echo "  systemctl --user start zotero-sync.service" >&2
  fi

  cat <<MSG

Configuração concluída.
  Script Python: $python_target
  Arquivo de configuração: $ENV_FILE
  Serviços habilitados: webdav-koofr.service e zotero-sync.service

Use 'journalctl --user -u webdav-koofr -f' para acompanhar a montagem.
Se alterar a senha WebDAV, execute novamente este script para atualizar o keyring.
MSG
}

main "$@"
