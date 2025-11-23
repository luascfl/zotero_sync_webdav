#!/usr/bin/env bash

set -euo pipefail

# Globals -------------------------------------------------------------------
declare -a __UNTRACKED_BACKUPS=()
declare -a __SUBCONTAINERS_TO_PUSH=()
declare -a __SUBCONTAINERS_TO_CLEAR=()
declare -A __SUBCONTAINER_COMMITS=()
SUBCONTAINER_STATE_FILE=".subcontainers"
SUBCONTAINER_MODE=false
ROOT_REMOTE_URL=""
ROOT_REPO_DIR=""
trap '__restore_all_backups; restore_root_remote' EXIT INT TERM

main() {
  ensure_dependencies
  ensure_token

  local repo_dir repo_name script_rel action current_branch remote_url
  repo_dir=$(pwd)
  repo_name=$(basename "$repo_dir")
  ROOT_REPO_DIR="$repo_dir"
  script_rel=$(script_relative_path "$repo_dir")
  action=$(prompt_repo_action "$repo_name")

  ensure_git_lfs

  init_git_repo
  current_branch=$(ensure_main_branch)
  remote_url=$(resolve_remote_url "$repo_name")
  ROOT_REMOTE_URL="$remote_url"

  case "$action" in
    pull)
      SUBCONTAINER_MODE=false
      ensure_remote "$remote_url"
      sync_with_remote "$current_branch"
      echo "Pull completed successfully from: $remote_url"
      ;;
    push)
      SUBCONTAINER_MODE=false
      ensure_remote_repo_exists "$repo_name" "$(repo_visibility_from_folder "$repo_name")"
      ensure_remote "$remote_url"
      sync_with_remote "$current_branch"
      perform_push "$script_rel" "$current_branch" "$remote_url"
      ensure_remote "$remote_url"
      ;;
    push-subfolders)
      SUBCONTAINER_MODE=true
      prepare_subcontainer_plan "$repo_name"
      ensure_remote_repo_exists "$repo_name" "$(repo_visibility_from_folder "$repo_name")"
      ensure_remote "$remote_url"
      sync_with_remote "$current_branch"
      ensure_subcontainers_ready
      perform_push "$script_rel" "$current_branch" "$remote_url"
      ensure_remote "$remote_url"
      clear_removed_subcontainers
      ;;
    *)
      echo "Unknown action '$action'." >&2
      exit 1
      ;;
  esac
}

# Dependency / token helpers -------------------------------------------------
ensure_dependencies() {
  local dep
  for dep in git curl python3 git-lfs; do
    if ! command -v "$dep" >/dev/null 2>&1; then
      echo "Error: dependency '$dep' was not found in PATH." >&2
      exit 1
    fi
  done
}

ensure_git_lfs() {
  if ! command -v git-lfs >/dev/null 2>&1; then
    echo "Error: git-lfs is required but not installed." >&2
    exit 1
  fi
  git lfs install --skip-repo >/dev/null 2>&1 || true
}

ensure_token() {
  if [[ -n "${GITHUB_TOKEN:-}" ]]; then
    return
  fi

  local token_file
  if token_file=$(find_token_file); then
    if load_token_from_file "$token_file"; then
      export GITHUB_TOKEN
      return
    fi
  fi

  echo "Error: provide GITHUB_TOKEN via environment variable or file." >&2
  exit 1
}

find_token_file() {
  local dir=$PWD candidate
  while true; do
    for candidate in "$dir/GITHUB_TOKEN" "$dir/GITHUB_TOKEN.txt"; do
      if [[ -f "$candidate" ]]; then
        printf "%s\n" "$candidate"
        return 0
      fi
    done
    if [[ "$dir" == "/" ]]; then
      break
    fi
    dir=$(dirname "$dir")
  done
  return 1
}

load_token_from_file() {
  local token_file=$1 token
  token=$(python3 - "$token_file" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
try:
    text = path.read_text(encoding="utf-8")
except Exception:
    sys.exit(1)
line = text.splitlines()[0] if text else ""
print(line.lstrip("\ufeff"), end="")
PY
) || return 1

  if [[ -n "$token" ]]; then
    GITHUB_TOKEN=$token
    return 0
  fi
  return 1
}

# Repo setup -----------------------------------------------------------------
script_relative_path() {
  local repo_dir=$1
  if command -v realpath >/dev/null 2>&1; then
    realpath --relative-to="$repo_dir" "$0" 2>/dev/null || basename "$0"
    return
  fi

  python3 - "$repo_dir" "$0" <<'PY'
import os, sys
repo, script = map(os.path.abspath, sys.argv[1:])
try:
    print(os.path.relpath(script, repo))
except ValueError:
    print(os.path.basename(script))
PY
}

prompt_repo_action() {
  local repo_name=$1 choice
  while true; do
    if ! read -rp "Choose action for repository '$repo_name' [push/pull/push-subfolders] (default: push): " choice; then
      choice=""
    fi
    case "${choice,,}" in
      ""|push) echo "push"; return ;;
      pull) echo "pull"; return ;;
      push-subfolders|push+subfolders|push_subfolders)
        echo "push-subfolders"
        return
        ;;
      *) echo "Invalid input. Type 'push', 'pull', or 'push-subfolders'." >&2 ;;
    esac
  done
}

init_git_repo() {
  if [[ ! -d .git ]]; then
    git init >/dev/null 2>&1
  fi
}

ensure_main_branch() {
  local current
  current=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  if [[ -z "$current" || "$current" == "HEAD" ]]; then
    git symbolic-ref HEAD refs/heads/main >/dev/null 2>&1 || git branch -M main
    current="main"
  elif [[ "$current" != "main" ]]; then
    git branch -M "$current" main
    current="main"
  fi
  echo "$current"
}

resolve_remote_url() {
  local repo_name=$1
  case "${GITHUB_REMOTE_PROTOCOL:-https}" in
    ssh) echo "git@github.com:luascfl/$repo_name.git" ;;
    https|*) echo "https://github.com/luascfl/$repo_name.git" ;;
  esac
}

repo_visibility_from_folder() {
  local folder_name=$1
  if [[ "$folder_name" == tmp_* ]]; then
    echo "private"
  else
    echo "public"
  fi
}

ensure_remote_repo_exists() {
  local repo_name=$1 visibility=${2:-public} private_flag
  case "$visibility" in
    private|true|1) private_flag=true ;;
    *) private_flag=false ;;
  esac
  local response http_status
  response=$(mktemp)
  http_status=$(curl -sS -w "%{http_code}" -o "$response" \
    -X POST "https://api.github.com/user/repos" \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -d "{\"name\":\"$repo_name\",\"private\":$private_flag}")

  case "$http_status" in
    201) ;;
    422) echo "Warning: repository '$repo_name' already exists in luascfl. Continuing." >&2 ;;
    *) echo "Error creating repository (status $http_status):" >&2
       cat "$response" >&2
       rm -f "$response"
       exit 1 ;;
  esac
  rm -f "$response"
}

ensure_remote() {
  local expected=$1 repo_path=${ROOT_REPO_DIR:-.}
  if git -C "$repo_path" remote get-url origin >/dev/null 2>&1; then
    local current
    current=$(git -C "$repo_path" remote get-url origin)
    if [[ "$current" != "$expected" ]]; then
      echo "Remote 'origin' pointed to $current. Updating to $expected." >&2
      git -C "$repo_path" remote set-url origin "$expected"
    fi
  else
    git -C "$repo_path" remote add origin "$expected"
  fi
}

restore_root_remote() {
  if [[ -z "${ROOT_REMOTE_URL:-}" ]]; then
    return
  fi
  ensure_remote "$ROOT_REMOTE_URL"
}

# Sync -----------------------------------------------------------------------
sync_with_remote() {
  local branch=$1
  if git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1; then
    echo "Remote branch '$branch' found. Syncing (pull --rebase)..." >&2
    if pull_with_credentials "$branch"; then
      echo "Sync completed." >&2
    else
      echo "Warning: pull could not be completed automatically." >&2
    fi
  else
    echo "Remote branch '$branch' not found. Assuming first push/pull." >&2
  fi
}

# Push -----------------------------------------------------------------------
perform_push() {
  local script_rel=$1 branch=$2 remote_url=$3
  stage_files_excluding_script "$script_rel"
  if commit_changes; then
    echo "Commit created." >&2
  else
    echo "No changes to commit." >&2
  fi

  if push_with_credentials "$branch"; then
    echo "Push completed successfully: $remote_url"
  else
    echo "Push failed." >&2
    exit 1
  fi
}

prepare_subcontainer_plan() {
  local root_repo_name=$1
  __SUBCONTAINERS_TO_PUSH=()
  __SUBCONTAINERS_TO_CLEAR=()
  __SUBCONTAINER_COMMITS=()

  declare -A previous=()
  if [[ -f "$SUBCONTAINER_STATE_FILE" ]]; then
    while IFS="|" read -r prev_dir prev_repo; do
      [[ -z "$prev_dir" || -z "$prev_repo" ]] && continue
      previous["$prev_dir"]="$prev_repo"
    done <"$SUBCONTAINER_STATE_FILE"
  fi

  declare -A current=()
  local -a subdirs=()
  while IFS= read -r -d '' path; do
    path=${path#./}
    [[ "$path" == ".git" ]] && continue
    [[ "$path" == .* ]] && continue
    subdirs+=("$path")
  done < <(find . -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null || true)

  local subdir repo_name visibility
  for subdir in "${subdirs[@]}"; do
    repo_name=$(format_subcontainer_repo_name "$root_repo_name" "$subdir")
    visibility=$(repo_visibility_from_folder "$subdir")
    current["$subdir"]="$repo_name"
    __SUBCONTAINERS_TO_PUSH+=("$subdir|$repo_name|$visibility")
  done

  local prev_dir
  for prev_dir in "${!previous[@]}"; do
    if [[ -z "${current[$prev_dir]+_}" ]]; then
      __SUBCONTAINERS_TO_CLEAR+=("$prev_dir|${previous[$prev_dir]}")
      remove_submodule_config "$prev_dir"
    fi
  done

  {
    for subdir in "${!current[@]}"; do
      printf "%s|%s\n" "$subdir" "${current[$subdir]}"
    done | sort
  } >"$SUBCONTAINER_STATE_FILE"
}

ensure_subcontainers_ready() {
  if [[ ${#__SUBCONTAINERS_TO_PUSH[@]} -eq 0 ]]; then
    echo "No subfolders detected to manage as submodules." >&2
    return
  fi

  local entry subdir repo visibility
  for entry in "${__SUBCONTAINERS_TO_PUSH[@]}"; do
    IFS="|" read -r subdir repo visibility <<<"$entry"
    ensure_single_subcontainer_ready "$subdir" "$repo" "$visibility"
  done
}

ensure_single_subcontainer_ready() {
  local subdir=$1 repo_name=$2 visibility=$3 remote_url

  if [[ ! -d "$subdir" ]]; then
    echo "Skipping '$subdir' because it no longer exists locally." >&2
    return
  fi

  ensure_remote_repo_exists "$repo_name" "$visibility"
  remote_url=$(resolve_remote_url "$repo_name")

  ensure_submodule_repo_initialized "$subdir"
  ensure_submodule_branch "$subdir"
  ensure_submodule_remote "$subdir" "$remote_url"
  commit_and_push_submodule "$subdir"
  record_subcontainer_commit "$subdir"
  register_submodule_reference "$subdir" "$remote_url"
}

ensure_submodule_repo_initialized() {
  local subdir=$1
  if [[ -e "$subdir/.git" ]]; then
    return
  fi
  git -C "$subdir" init >/dev/null
}

ensure_submodule_branch() {
  local subdir=$1 current
  current=$(git -C "$subdir" rev-parse --abbrev-ref HEAD 2>/dev/null || true)
  if [[ -z "$current" || "$current" == "HEAD" ]]; then
    git -C "$subdir" symbolic-ref HEAD refs/heads/main >/dev/null 2>&1 || git -C "$subdir" branch -M main
    current="main"
  elif [[ "$current" != "main" ]]; then
    git -C "$subdir" branch -M "$current" main >/dev/null 2>&1 || git -C "$subdir" switch -C main >/dev/null 2>&1
    current="main"
  fi
}

ensure_submodule_remote() {
  local subdir=$1 remote_url=$2 current_remote
  if current_remote=$(git -C "$subdir" remote get-url origin 2>/dev/null); then
    if [[ "$current_remote" != "$remote_url" ]]; then
      git -C "$subdir" remote set-url origin "$remote_url"
    fi
  else
    git -C "$subdir" remote add origin "$remote_url"
  fi
}

commit_and_push_submodule() {
  local subdir=$1
  git -C "$subdir" add --all
  ensure_lfs_for_large_files "$subdir"
  if git -C "$subdir" diff --staged --quiet; then
    :
  else
    git -C "$subdir" commit -m "push"
  fi
  ensure_submodule_initial_commit "$subdir"
  push_submodule_with_credentials "$subdir"
}

ensure_submodule_initial_commit() {
  local subdir=$1
  if git -C "$subdir" rev-parse --verify HEAD >/dev/null 2>&1; then
    return
  fi
  git -C "$subdir" commit --allow-empty -m "Initial subcontainer commit" >/dev/null
}

record_subcontainer_commit() {
  local subdir=$1 commit
  commit=$(git -C "$subdir" rev-parse HEAD 2>/dev/null || true)
  if [[ -n "$commit" ]]; then
    __SUBCONTAINER_COMMITS["$subdir"]="$commit"
  else
    unset "__SUBCONTAINER_COMMITS[$subdir]"
  fi
}

push_submodule_with_credentials() {
  local subdir=$1 branch=${2:-main} output status
  if [[ "${GITHUB_REMOTE_PROTOCOL:-https}" == "https" ]]; then
    if output=$(run_with_https_credentials git -C "$subdir" push -u origin "$branch" 2>&1); then
      status=0
    else
      status=$?
    fi
  else
    if output=$(git -C "$subdir" push -u origin "$branch" 2>&1); then
      status=0
    else
      status=$?
    fi
  fi
  printf "%s\n" "$output"
  if [[ $status -ne 0 ]]; then
    if handle_large_file_push_rejection "$subdir" "$output"; then
      echo "Retrying submodule push for '$subdir' after enabling Git LFS..." >&2
      push_submodule_with_credentials "$subdir" "$branch"
      return $?
    fi
  fi
  return $status
}

handle_large_file_push_rejection() {
  local repo_path=$1 push_output=$2
  local -a files=()
  mapfile -t files < <(extract_large_file_paths "$push_output")
  if [[ ${#files[@]} -eq 0 ]]; then
    return 1
  fi
  echo "Push rejected: files exceed GitHub's 100 MB limit. Configuring Git LFS for: ${files[*]}" >&2
  apply_lfs_tracking_for_paths "$repo_path" "${files[@]}"
  if amend_last_commit_with_lfs "$repo_path"; then
    return 0
  fi
  return 1
}

apply_lfs_tracking_for_paths() {
  local repo_path=$1
  shift
  if [[ $# -eq 0 ]]; then
    return
  fi
  git -C "$repo_path" lfs install >/dev/null 2>&1 || true
  local file
  declare -A seen=()
  local -a unique=()
  for file in "$@"; do
    [[ -z "$file" ]] && continue
    if [[ -n "${seen[$file]+_}" ]]; then
      continue
    fi
    seen["$file"]=1
    unique+=("$file")
  done
  for file in "${unique[@]}"; do
    git -C "$repo_path" lfs track -- "$file" >/dev/null 2>&1 || true
  done
  git -C "$repo_path" add .gitattributes >/dev/null 2>&1 || true
  git -C "$repo_path" add -- "${unique[@]}" >/dev/null 2>&1 || true
}

amend_last_commit_with_lfs() {
  local repo_path=$1
  if ! git -C "$repo_path" rev-parse HEAD >/dev/null 2>&1; then
    return 1
  fi
  if git -C "$repo_path" diff --cached --quiet; then
    return 1
  fi
  git -C "$repo_path" commit --amend --no-edit >/dev/null 2>&1 || return 1
  return 0
}

extract_large_file_paths() {
  python3 - "$1" <<'PY'
import sys
import re
text = sys.argv[1]
patterns = [
    re.compile(r'File (.+?) is .*?exceeds GitHub', re.IGNORECASE),
    re.compile(r'File (.+?) exceeds GitHub', re.IGNORECASE),
]
found = []
for line in text.splitlines():
    for pat in patterns:
        m = pat.search(line)
        if m:
            path = m.group(1).strip()
            if path and path not in found:
                found.append(path)
            break
print("\n".join(found))
PY
}

register_submodule_reference() {
  local subdir=$1 remote_url=$2
  git config -f .gitmodules "submodule.$subdir.path" "$subdir"
  git config -f .gitmodules "submodule.$subdir.url" "$remote_url"
  git config "submodule.$subdir.path" "$subdir"
  git config "submodule.$subdir.url" "$remote_url"
  git config "submodule.$subdir.update" "checkout"
  git submodule absorbgitdirs "$subdir" >/dev/null 2>&1 || true
}

remove_submodule_config() {
  local subdir=$1
  git config -f .gitmodules --remove-section "submodule.$subdir" >/dev/null 2>&1 || true
  git config --remove-section "submodule.$subdir" >/dev/null 2>&1 || true
  if [[ -d ".git/modules/$subdir" ]]; then
    rm -rf ".git/modules/$subdir"
  fi
}

clear_removed_subcontainers() {
  if [[ ${#__SUBCONTAINERS_TO_CLEAR[@]} -eq 0 ]]; then
    return
  fi
  local entry subdir repo
  for entry in "${__SUBCONTAINERS_TO_CLEAR[@]}"; do
    IFS="|" read -r subdir repo <<<"$entry"
    clear_subcontainer_repo "$repo" "$subdir"
  done
}

format_subcontainer_repo_name() {
  local _root_repo=$1 subdir=$2 segment
  segment=$(sanitize_repo_segment "$subdir")
  printf "%s" "$segment"
}

sanitize_repo_segment() {
  local value=$1
  value=${value//\//-}
  value=$(printf '%s' "$value" | tr '[:upper:]' '[:lower:]')
  value=${value//[^a-z0-9_-]/-}
  while [[ "$value" == *--* ]]; do
    value=${value//--/-}
  done
  while [[ "$value" == *__* ]]; do
    value=${value//__/_}
  done
  value=${value##-}
  value=${value%%-}
  value=${value##_}
  value=${value%%_}
  if [[ -z "$value" ]]; then
    value="subfolder"
  fi
  printf "%s" "$value"
}

push_commit_to_remote() {
  local remote_url=$1 refspec=$2 force_flag=${3:-} output status
  local -a args=("git" "push")
  if [[ -n "$force_flag" ]]; then
    args+=("$force_flag")
  fi
  args+=("$remote_url" "$refspec")
  if [[ "${GITHUB_REMOTE_PROTOCOL:-https}" == "https" ]]; then
    output=$(run_with_https_credentials "${args[@]}" 2>&1)
  else
    output=$("${args[@]}" 2>&1)
  fi
  status=$?
  printf "%s\n" "$output"
  return $status
}

fetch_remote_head_into_ref() {
  local remote_url=$1 target_ref=$2 output status
  output=$(run_git_with_credentials git fetch --no-tags "$remote_url" "refs/heads/main:$target_ref" 2>&1)
  status=$?
  if [[ $status -ne 0 ]]; then
    printf "%s\n" "$output"
    return $status
  fi
  return 0
}

clear_subcontainer_repo() {
  local repo_name=$1 subdir=$2 remote_url tmp_ref parent empty_tree empty_commit fetch_output
  remote_url=$(resolve_remote_url "$repo_name")
  echo "Clearing subcontainer for removed folder '$subdir' (repo '$repo_name')." >&2
  tmp_ref="refs/tmp/subcontainer-${RANDOM}-${RANDOM}"
  parent=""
  if fetch_output=$(fetch_remote_head_into_ref "$remote_url" "$tmp_ref"); then
    parent=$(git rev-parse "$tmp_ref" 2>/dev/null || true)
  else
    if [[ "$fetch_output" == *"couldn't find remote ref"* || "$fetch_output" == *"could not find remote ref"* ]]; then
      parent=""
    else
      printf "%s\n" "$fetch_output" >&2
    fi
  fi
  git update-ref -d "$tmp_ref" >/dev/null 2>&1 || true

  empty_tree=$(git hash-object -t tree /dev/null)
  if [[ -n "$parent" ]]; then
    empty_commit=$(git commit-tree "$empty_tree" -p "$parent" -m "Remove folder '$subdir' after deletion")
  else
    empty_commit=$(git commit-tree "$empty_tree" -m "Remove folder '$subdir' after deletion")
  fi

  if push_commit_to_remote "$remote_url" "$empty_commit:refs/heads/main"; then
    echo "Subcontainer '$repo_name' cleared successfully." >&2
  else
    echo "Failed to clear subcontainer '$repo_name'." >&2
  fi
}

stage_files_excluding_script() {
  local script_rel=$1
  ensure_token_gitignore
  cleanup_local_backup_artifacts
  ensure_submodules_populated
  git add --all
  if [[ "$SUBCONTAINER_MODE" == "true" ]]; then
    enforce_subcontainer_gitlinks
  fi
  ensure_lfs_for_large_files "."
  protect_path "GITHUB_TOKEN"
  protect_path "GITHUB_TOKEN.txt"
  protect_path "AMO_API_KEY.txt"
  protect_path "AMO_API_SECRET.txt"
}

ensure_submodules_populated() {
  if [[ ! -f .gitmodules ]]; then
    return
  fi
  if ! git config -f .gitmodules --get-regexp '^submodule\.' >/dev/null 2>&1; then
    return
  fi
  if run_git_with_credentials git submodule update --init --recursive >/dev/null 2>&1; then
    return
  fi
  echo "Warning: failed to populate existing submodules automatically. Run 'git submodule update --init --recursive' and retry if issues persist." >&2
}

enforce_subcontainer_gitlinks() {
  local entry subdir repo visibility commit
  if [[ ${#__SUBCONTAINERS_TO_PUSH[@]} -eq 0 ]]; then
    return
  fi
  for entry in "${__SUBCONTAINERS_TO_PUSH[@]}"; do
    IFS="|" read -r subdir repo visibility <<<"$entry"
    [[ -d "$subdir" ]] || continue
    commit=${__SUBCONTAINER_COMMITS[$subdir]:-}
    if [[ -z "$commit" ]]; then
      commit=$(git -C "$subdir" rev-parse HEAD 2>/dev/null || true)
    fi
    if [[ -z "$commit" ]]; then
      echo "Warning: subcontainer '$subdir' has no commits to reference; keeping it as a normal folder in this push." >&2
      continue
    fi
    stage_subcontainer_gitlink "$subdir" "$commit"
  done
}

stage_subcontainer_gitlink() {
  local subdir=$1 commit=$2
  git rm -r --cached --ignore-unmatch -- "$subdir" >/dev/null 2>&1 || true
  git update-index --add --cacheinfo 160000 "$commit" "$subdir" >/dev/null
}

ensure_lfs_for_large_files() {
  local repo_path=$1
  local threshold=${GIT_LFS_THRESHOLD_BYTES:-104857600}
  local -a to_track=()
  local path full size attr
  while IFS= read -r path; do
    [[ -z "$path" ]] && continue
    full="$repo_path/$path"
    [[ ! -f "$full" ]] && continue
    size=$(stat -c%s -- "$full" 2>/dev/null || echo 0)
    if (( size < threshold )); then
      continue
    fi
    attr=$(git -C "$repo_path" check-attr filter -- "$path" 2>/dev/null || true)
    if [[ "$attr" == *"filter: lfs" ]]; then
      continue
    fi
    to_track+=("$path")
  done < <(git -C "$repo_path" diff --cached --name-only --diff-filter=AM 2>/dev/null || true)

  if [[ ${#to_track[@]} -eq 0 ]]; then
    return
  fi

  git -C "$repo_path" lfs install >/dev/null 2>&1 || true
  local target
  for target in "${to_track[@]}"; do
    git -C "$repo_path" lfs track -- "$target" >/dev/null 2>&1 || true
  done
  git -C "$repo_path" add .gitattributes >/dev/null 2>&1 || true
  git -C "$repo_path" add -- "${to_track[@]}" >/dev/null 2>&1 || true
  echo "Large files routed through Git LFS in '$repo_path': ${to_track[*]}" >&2
}

cleanup_local_backup_artifacts() {
  local -a backups=()
  while IFS= read -r -d '' path; do
    path=${path#./}
    backups+=("$path")
  done < <(find . -path ./.git -prune -o -name "*.local-backup-*" -print0 2>/dev/null || true)

  if [[ ${#backups[@]} -eq 0 ]]; then
    return
  fi

  local path
  for path in "${backups[@]}"; do
    git rm -rf --cached --ignore-unmatch -- "$path" >/dev/null 2>&1 || true
    rm -rf -- "$path"
  done
  echo "Temporary backups removed: ${backups[*]}" >&2
}

ensure_token_gitignore() {
  local gitignore=.gitignore
  local entries=("GITHUB_TOKEN" "GITHUB_TOKEN.txt" "AMO_API_KEY.txt" "AMO_API_SECRET.txt" "*API*")
  if [[ ! -f $gitignore ]]; then
    printf "%s\n" "${entries[@]}" > "$gitignore"
    return
  fi

  local entry
  for entry in "${entries[@]}"; do
    if ! grep -Fxq "$entry" "$gitignore"; then
      printf "%s\n" "$entry" >> "$gitignore"
    fi
  done
}

protect_path() {
  local path=$1
  [[ -z "$path" ]] && return
  git restore --staged -- "$path" >/dev/null 2>&1 || git reset HEAD -- "$path" >/dev/null 2>&1 || true
  if git ls-files --error-unmatch "$path" >/dev/null 2>&1; then
    return
  fi
  git rm --cached -- "$path" >/dev/null 2>&1 || true
}

commit_changes() {
  if git diff --staged --quiet; then
    return 1
  fi
  git commit -m "push"
  return 0
}

# Credentials helpers --------------------------------------------------------
run_with_https_credentials() {
  local askpass status
  askpass=$(mktemp)
  cat >"$askpass" <<'ASKPASS'
#!/usr/bin/env bash
if [[ "$1" == *Username* ]]; then
  printf '%s\n' "luascfl"
else
  printf '%s\n' "${GITHUB_TOKEN}"
fi
ASKPASS
  chmod +x "$askpass"
  GIT_TERMINAL_PROMPT=0 GIT_ASKPASS="$askpass" "$@"
  status=$?
  rm -f "$askpass"
  return $status
}

run_git_with_credentials() {
  if [[ "${GITHUB_REMOTE_PROTOCOL:-https}" == "https" ]]; then
    run_with_https_credentials "$@"
  else
    "$@"
  fi
}

push_with_credentials() {
  local branch=$1 output status
  if [[ "${GITHUB_REMOTE_PROTOCOL:-https}" == "https" ]]; then
    if output=$(run_with_https_credentials git push -u origin "$branch" 2>&1); then
      status=0
    else
      status=$?
    fi
  else
    if output=$(git push -u origin "$branch" 2>&1); then
      status=0
    else
      status=$?
    fi
  fi
  printf "%s\n" "$output"
  if [[ $status -ne 0 && "$output" =~ non-fast-forward ]]; then
    echo "Push rejected (non-fast-forward). Trying automatic pull before retrying..." >&2
    if pull_with_credentials "$branch" && push_with_credentials "$branch"; then
      return 0
    fi
  fi
  if [[ $status -ne 0 ]]; then
    if handle_large_file_push_rejection "." "$output"; then
      echo "Retrying push after enabling Git LFS for large files..." >&2
      push_with_credentials "$branch"
      return $?
    fi
  fi
  return $status
}

# Pull / rebase --------------------------------------------------------------
pull_with_credentials() {
  local branch=$1 output
  if output=$(run_git_pull_command "$branch"); then
    printf "%s\n" "$output"
    __restore_all_backups
    return 0
  fi

  if is_untracked_overwrite_error "$output"; then
    if resolve_untracked_overwrite_conflicts "$branch" "$output"; then
      __restore_all_backups
      return 0
    fi
  fi

  if rebase_in_progress && auto_resolve_rebase_conflicts "$branch"; then
    __restore_all_backups
    return 0
  fi

  __restore_all_backups
  printf "%s\n" "$output" >&2
  echo "Warning: 'pull --rebase' failed. There may be conflicts that require manual intervention." >&2
  return 1
}

run_git_pull_command() {
  local branch=$1 output status
  if [[ "${GITHUB_REMOTE_PROTOCOL:-https}" == "https" ]]; then
    output=$(run_with_https_credentials git pull --rebase --autostash origin "$branch" 2>&1)
  else
    output=$(git pull --rebase --autostash origin "$branch" 2>&1)
  fi
  status=$?
  printf "%s" "$output"
  return $status
}

is_untracked_overwrite_error() {
  grep -q "untracked working tree files would be overwritten" <<<"$1"
}

resolve_untracked_overwrite_conflicts() {
  local branch=$1 message=$2 path backup timestamp
  timestamp=$(date +%s)

  while read -r path; do
    [[ -z "$path" ]] && continue
    [[ ! -e "$path" ]] && continue

    backup="${path}.local-backup-${timestamp}"
    while [[ -e "$backup" ]]; do
      backup="${backup}-${RANDOM}"
    done

    cp -a -- "$path" "$backup"
    rm -rf -- "$path"
    __register_backup "$path" "$backup"
    echo "Local file '$path' was temporarily saved in '$backup' to allow pull to continue." >&2
  done < <(extract_untracked_conflict_paths "$message")

  local retry
  if retry=$(run_git_pull_command "$branch"); then
    printf "%s\n" "$retry"
    return 0
  fi

  printf "%s\n" "$retry" >&2
  return 1
}

extract_untracked_conflict_paths() {
  awk '
    /untracked working tree files would be overwritten by checkout:/ {collect=1; next}
    /Please move or remove them before you switch branches/ {collect=0}
    collect && NF { gsub(/^[[:space:]]+/, "", $0); print }
  ' <<<"$1"
}

__register_backup() {
  __UNTRACKED_BACKUPS+=("$1|$2")
}

__restore_all_backups() {
  local entry original backup
  if [[ ${#__UNTRACKED_BACKUPS[@]} -eq 0 ]]; then
    return
  fi

  for entry in "${__UNTRACKED_BACKUPS[@]}"; do
    original=${entry%%|*}
    backup=${entry#*|}
    [[ -z "$original" || -z "$backup" ]] && continue
    if [[ -e "$backup" ]]; then
      rm -rf -- "$original"
      mv -- "$backup" "$original"
      echo "Restored local version: $original" >&2
    fi
  done
  __UNTRACKED_BACKUPS=()
}

rebase_in_progress() {
  [[ -d .git/rebase-apply || -d .git/rebase-merge ]]
}

auto_resolve_rebase_conflicts() {
  local branch=$1
  local -a conflicts
  mapfile -t conflicts < <(git diff --name-only --diff-filter=U)

  if [[ ${#conflicts[@]} -eq 0 ]]; then
    abort_rebase_with_warning "Rebase in progress, but no conflicted files were detected automatically."
    return 1
  fi

  local file
  for file in "${conflicts[@]}"; do
    if ! resolve_conflict_for_file "$file"; then
      abort_rebase_with_warning "Conflict in '$file' requires manual resolution."
      return 1
    fi
  done

  if git rebase --continue >/tmp/rebase-continue.log 2>&1; then
    cat /tmp/rebase-continue.log
    rm -f /tmp/rebase-continue.log
    return 0
  fi

  abort_rebase_with_warning "Unable to complete the rebase automatically."
  return 1
}

resolve_conflict_for_file() {
  local file=$1
  case "$file" in
    .gitignore)
      git checkout --theirs -- .gitignore >/dev/null 2>&1 || return 1
      ensure_token_gitignore
      git add .gitignore
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

abort_rebase_with_warning() {
  local message=$1
  local status_output
  status_output=$(git status --short 2>/dev/null || true)
  git rebase --abort >/dev/null 2>&1 || true
  echo "$message" >&2
  if [[ -n "$status_output" ]]; then
    echo "Files in conflict:" >&2
    echo "$status_output" >&2
  fi
}

main "$@"
