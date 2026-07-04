# GSD state

Updated: 2026-05-01

## Current state
- Context bootstrap is complete enough to propose the next Ralph cycle.
- User clarified that this repository is script automation, not a set of official products.
- Main sync should remain automatic.
- Target environment is Linux with mounted WebDAV.
- Active technical priority is hardening.
- `padronizar_contatos_google.py` removal is intentional because it did not belong to this repository.

- Active sync target is now the direct rclone Google Drive mount at `/home/lucas/Google Drive/zoterodb`; GVFS/WebDAV remains manual-only.
## Active milestone
Milestone 0: governance bootstrap.

### Milestone 0 dependencies
- User clarification: complete.
- AI Coders Context scaffold: complete for `.context/docs/`.
- PRD JSON: created and JSON-validated at `.context/prd_ralph/prd.json`.
- GSD project plan: created at `.context/docs/planning_gsd/PROJECT.md`.
- Workflow status: initialized at `.context/workflow/status.yaml` with current phase P.
- Syntax validation: `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed on 2026-04-30.

## Next milestone
Milestone 1: main synchronizer hardening.

Dependencies:
- Milestone 0 complete.
- US-001 must land before deeper filesystem, preflight, and outcome hardening stories.

## Next Ralph story
- ID: US-001
- Title: Make main sync import-safe and testable
- Reason: current `zotero_sync_webdav.py` performs required environment validation and log setup at import time [observed in code], which blocks unit tests and hides runtime boundaries. Import-safety is the correct first hardening seam.

## Definition of done for next story
- `zotero_sync_webdav.py` can be imported without `ZOTERO_*` environment variables.
- Runtime config validation still fails clearly before live Zotero calls when required values are missing.
- Initial `tests/` suite exists and uses standard-library `unittest`.
- Tests cover import-safety, path resolution, filename normalization, and malformed response coercion.
- Syntax and test quality gates pass.

## Validation checklist for next story
- `python3 -m py_compile zotero_sync_webdav.py zotero_storage_quota_audit.py`
- `python3 -m unittest discover -s tests`
- Confirm no live Zotero API call is made during unit tests.
- Confirm `.context/docs/planning_gsd/STATE.md` is updated with evidence.
- Confirm PRD story status is advanced by Ralph or recorded manually only if Ralph is not used.

## Gemini prompt for next story
```text
You are Gemini executing one Ralph story in /home/lucas/Downloads/zotero_sync_webdav.

Read first:
1. AGENTS.md
2. GEMINI.md
3. .context/docs/README.md
4. .context/docs/planning_gsd/STATE.md
5. .context/prd_ralph/prd.json

Execute only story US-001: Make main sync import-safe and testable.

Scope:
- Touch zotero_sync_webdav.py and add tests/ files only if needed.
- Do not touch the helper scripts unless a syntax gate reveals an issue caused by this story.
- Do not contact Zotero API in tests.
- Preserve automated operation of the main sync path.

Required behavior:
- Importing zotero_sync_webdav with no ZOTERO_* environment variables must not raise.
- Runtime config validation must still fail clearly before any Zotero API call when required values are missing.
- Move import-time side effects that block tests into explicit runtime setup used by main().
- Add unittest coverage for import-safety, resolve_target_folder, normalize_filename, normalize_aggressive, and _coerce_response_items malformed/empty cases.

Verification:
- Run: python3 -m py_compile zotero_sync_webdav.py zotero_storage_quota_audit.py
- Run: python3 -m unittest discover -s tests
- Update .context/docs/planning_gsd/STATE.md with exact validation evidence.

Return a concise result with files changed and command results.
```

## Evidence log
- 2026-04-30: AI Coders Context mapped 4 Python scripts and symbol lists.
- 2026-04-30: `ralph --help` observed available commands: `install`, `prd`, `ping`, `log`, `build`, `overview`, `help`.
- 2026-04-30: PRD skill instructions observed in Ralph package at `/home/lucas/.nvm/versions/node/v22.21.1/lib/node_modules/@iannuttall/ralph/skills/prd/SKILL.md` because `skill://prd` was unavailable in this harness.
- 2026-04-30: `python3 -m json.tool .context/prd_ralph/prd.json` passed.
- 2026-04-30: removed generated non-canonical graphify/opencode artifacts from the bootstrap workspace; official context remains under `.context/docs`, `.context/prd_ralph`, and `.context/workflow`.
- 2026-04-30: operational sync attempt connected to Zotero API and found 827 API attachments, 794 unique attachment names, and 451 PDFs in `/home/lucas/Koofr WebDAV GDrive/zoterodb`.
- 2026-04-30: pre-sync diagnostic found 4 duplicate attachment groups and 61 WebDAV PDFs without Zotero filename match before sync.
- 2026-04-30: `findmnt -T /home/lucas/Koofr WebDAV GDrive/zoterodb` showed `fuse.rclone` mount from `Koofr WebDAV GDrive:`.
- 2026-04-30: reading content from the mount stalled: a 1.11 MiB PDF did not hash within 45s, and `rclone cat --head 65536` returned `unexpected EOF` for sampled PDFs.
- 2026-04-30: lazy-unmounted and restarted the rclone mount with the observed mount command, but sampled remote reads still failed with `unexpected EOF`.
- 2026-04-30: added `ZOTERO_CONTENT_PROBE_TIMEOUT_SECONDS` and per-file/probe logs to `zotero_sync_webdav.py` so future runs abort before the progress bar stalls at `0/451` when the mount cannot deliver file content.
- 2026-04-30: validation passed: `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`.
- 2026-04-30: probe validation passed locally: `.gitignore` read probe returned `True`; mount probe for `/home/lucas/Koofr WebDAV GDrive/zoterodb/Breve histórico das mudanças na regulação do trabalho no Brasil.pdf` timed out after 5s and returned `False`.
- 2026-04-30: sync is blocked by the rclone/Koofr content-read failure, not by Zotero API credentials or Zotero DB availability.
- 2026-04-30: alternate rclone path test showed `Google Drive:zoterodb/Breve histórico das mudanças na regulação do trabalho no Brasil.pdf` reads successfully, while `Koofr WebDAV GDrive:zoterodb/...` fails with `unexpected EOF`.
- 2026-04-30: stopped user service `rclone-koofr-webdav-gdrive.service` for the session and mounted `Google Drive:` at `/home/lucas/Koofr WebDAV GDrive`; `findmnt` then showed source `Google Drive:` and the 1.11 MiB probe file hashed in 2.11s.
- 2026-04-30: first successful sync pass over `Google Drive:` source processed 461 PDFs and reported 15 added, 442 existing, 39 local copies, 3 content updates, 25 WebDAV renames, and 4 errors.
- 2026-04-30: second sync pass with warmed cache reported 1 added, 457 existing, 2 local copies, 0 content updates, 0 WebDAV renames, and 3 errors.
- 2026-04-30: final diagnostic found 862 Zotero API attachments, 461 PDFs in target folder, 7 duplicate groups, and 18 PDFs without filename match.
- 2026-04-30: hash classification of the 18 remaining filename misses found most have matching content under different Zotero storage names; `Clínica pulsional do bebê - Marie Couvert 2020.pdf`, `Orientação vocacional e de carreira - Rosane Levenfus.pdf`, and `Pós-verdade.pdf` had no local-storage hash match after the sync attempts.
- 2026-04-30: sync created duplicate path-named Zotero attachments for the three upload-timeout files; cleanup would require explicit deletion/metadata repair through the Zotero API.
- 2026-04-30: local Zotero SQLite counts after sync remained `items=2841`, `itemAttachments=896`, `collections=51`; API attachment count differs because local Zotero DB has not necessarily synced down the remote API changes yet.
- 2026-04-30: inspected six path-named attachments created by failed uploads; all were top-level `attachment` items with `linkMode='imported_file'`, empty `contentType`, no `parentItem`, and filenames starting with `_home_lucas_Koofr WebDAV GDrive_zoterodb_`.
- 2026-04-30: deleted the six broken duplicate attachments via Zotero API: `DT4QCBQU`, `VFMK3A88`, `KFRHAFIC`, `AWXFJA8W`, `ZVRAXFXU`, and `45V9BWT6`.
- 2026-04-30: post-cleanup diagnostic dropped duplicate groups from 7 back to 4; remaining unmatched PDFs stayed at 18.
- 2026-04-30: the 18 remaining unmatched PDFs are not all new uploads; most already match existing Zotero storage by hash under different filenames and represent naming drift or duplicate-content files in the mount rather than missing Zotero content.
- 2026-04-30: decisão do usuário para casos com `hash_match`: quando o nome do Zotero estiver mais estruturado e o `mtime` do arquivo do Zotero for maior que o do drive, o Zotero deve ser tratado como canônico para nomeação. Exemplo observado: `MANUAL_DAS_EMPRESAS_JUNIORES.pdf` no drive versus `MANUAL  EMPRESAS JUNIORES - Júnior .pdf` no Zotero, com `mtime` do Zotero 5s maior.
- 2026-04-30: refinamento da regra de canonização para casos com `hash_match`: o lado com `mtime` mais recente é a fonte de verdade temporária para o título. Se o Zotero estiver mais recente, renomeia-se o drive para o título do Zotero. Se o drive estiver mais recente, modifica-se o Zotero para refletir o título do drive, entendendo que esse é o nome que o usuário ajustou mais recentemente, mesmo que ainda seja provisório.
- 2026-04-30: regra de presença entre as duas pontas: se um arquivo existir no drive e não existir no Zotero, ele deve ser enviado ao Zotero. Se um arquivo existir no Zotero e não existir no drive, ele deve ser materializado no drive. A reconciliação esperada é bidirecional, não apenas ingestão do drive para o Zotero.
- 2026-04-30: adicionada documentação extensa do workflow diretamente em `zotero_sync_webdav.py`, explicando a função do drive montado, da API do Zotero e da cópia local em `~/Zotero/storage` como âncora operacional para hash, rename e reconstrução local.
- 2026-04-30: após documentar o workflow, o script voltou a passar em `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`.
- 2026-04-30: nova execução de sync com o mount `Google Drive:` concluiu em `2026-04-30T07:11:17.860980` com `0` adicionados, `458` existentes, `0` cópias locais, `0` renomes WebDAV e `3` erros.
- 2026-04-30: os 3 erros remanescentes continuam sendo uploads falhos de `Clínica pulsional do bebê - Marie Couvert 2020.pdf`, `Pós-verdade.pdf` e `Orientação vocacional e de carreira - Rosane Levenfus.pdf`, todos quebrando na exceção `module 'httpx' has no attribute 'ConnectionError'` durante `zot.attachment_simple(...)`.
- 2026-04-30: identificado no `pyzotero 1.7.3` com `httpx 0.28.1` que `Zupload._upload_file()` captura `httpx.ConnectionError`, atributo inexistente nessa versão do httpx, mascarando `WriteTimeout` como `module 'httpx' has no attribute 'ConnectionError'`.
- 2026-04-30: adicionada função `configure_pyzotero_upload_transport()` em `zotero_sync_webdav.py` para aplicar compatibilidade `httpx.ConnectionError -> httpx.TransportError` e forçar timeout explícito de upload via `httpx.Timeout` em `httpx.post(...)` usado pelo Pyzotero.
- 2026-04-30: adicionada função `cleanup_failed_attachment_upload()` para remover anexos preliminares quebrados criados após falha de upload, identificados por `filename` derivado do caminho absoluto local, `linkMode='imported_file'`, ausência de `parentItem` e `contentType` vazio.
- 2026-04-30: removidos novamente os três anexos quebrados recriados na execução com o bug original: `CBN5PRCZ`, `6EG8BPHJ` e `GSG8K48S`.
- 2026-04-30: com o patch de upload e o mount em `Google Drive:`, a sincronização concluída em `2026-04-30T19:35:19.764787` registrou `3` adicionados, `458` existentes, `3` cópias locais e `0` erros.
- 2026-04-30: diagnóstico final após o patch mostrou `859` anexos na API, `461` PDFs no drive e apenas `15` ausentes por nome; os três uploads problemáticos (`Clínica pulsional do bebê - Marie Couvert 2020.pdf`, `Pós-verdade.pdf`, `Orientação vocacional e de carreira - Rosane Levenfus.pdf`) deixaram de aparecer como ausentes.
- 2026-04-30: `zotero_sync_webdav.py` passou a carregar `dateModified` dos anexos Zotero durante a coleta, usar esse campo como fonte principal de `mtime` no caso 3 e atualizar `title` e `filename` do Zotero quando o drive for mais recente.
- 2026-04-30: o relatório final do script agora inclui `⚖️ Empates de mtime` e lista detalhada de conflitos empatados quando existirem.
- 2026-04-30: sync executado com a nova regra de `mtime` em `2026-04-30T20:08:41.566923` concluiu com `0` adicionados, `461` existentes, `0` erros e `0` empates de `mtime`.
- 2026-04-30: os 15 casos remanescentes não foram renomeados porque o nome canônico já existia como outro arquivo no drive; o script tentou renomear e encontrou colisão de destino, preservando ambos os nomes em vez de sobrescrever ou apagar automaticamente.
- 2026-04-30: diagnóstico pós-sync permaneceu em `15` ausentes por nome no Zotero, confirmando que o restante do problema agora é colisão de arquivos duplicados no drive, não regra de `mtime` nem falha de upload.
- 2026-04-30: os 15 casos remanescentes com `hash_match` e nomes divergentes foram classificados para tratamento futuro. Seguros para ação automática no drive, porque o nome canônico já existe como outro arquivo no drive e o nome alternativo parece apenas variante estrutural: `A Mulher Na Língua Do Povo - Leitão 2007.pdf`, `A situação atual dos cursos de licenciatura no Brasil frente à hegemonia da - Diniz-Pereira 2015.pdf`, `As consolações da filosofia - Botton_Santos 2021.pdf`, `MANUAL_DAS_EMPRESAS_JUNIORES.pdf`, `Os limites do poder do leitor - Oliveira 2009.pdf`, `Repensando a prática de alfabetização - as idéias de Emilia Ferreiro na sala de aula.pdf`, `Sendo índio em português - Signorini_Maher 2002.pdf`, `Skinner, B. F. (1948). Walden II - uma sociedade do futuro.pdf` e `Uma introdução - atitude revolucionária - Hooks 2019.pdf`.
- 2026-04-30: classificados como suspeitos demais para ação automática, porque o `hash_match` existe, mas a divergência de nome é semântica demais para consolidar sem revisão humana: `Hübner, Borloti, Almeida & Cruvinel (2012). Linguagem, In Fundamentos de psicologia.pdf`, `Moreira e medeiros (2019) Princípios Básicos De Análise Do Comportamento - 2 ed.-29-83.pdf`, `Psicologia social o homem em movimento - Lane_Godo 2007.pdf`, `Psicología de la convivencia aportaciones prácticas - Cañizares .pdf` e `cristinaacunzo,+Gerente+da+revista,+v29nspea07.pdf`.
- 2026-04-30: `TEORIA HISTÓRICO-SOCIAL DA PERSONALIDADE.pdf` ficou em categoria especial. Pela regra de `mtime`, o canônico atual é `Cópia de TEORIA HISTÓRICO-SOCIAL DA PERSONALIDADE.pdf`, mas o prefixo `Cópia de` sugere nome provisório; manter em revisão manual é mais seguro do que consolidar automaticamente.
- 2026-04-30: `zotero_sync_webdav.py` passou a remover automaticamente duplicados redundantes no drive quando o nome canônico já existe e os dois arquivos têm o mesmo hash. A remoção ocorre só após validação binária do conteúdo; colisões com conteúdo diferente continuam bloqueadas para revisão manual.
- 2026-04-30: sync executado em `2026-04-30T20:38:11.717068` com a lógica de consolidação automática concluiu com `0` erros e consolidou os casos de colisão por `mtime` e hash.
- 2026-04-30: diagnóstico final após a consolidação automática mostrou `446` PDFs no drive e `0` ausentes por nome no Zotero. O delta de `461 -> 446` PDFs confirma a remoção dos 15 redundantes que antes impediam a reconciliação nominal.
- 2026-04-30: `zotero_sync_webdav.py` passou a expor uma CLI unificada com subcomandos `sync`, `diagnostico`, `remove-duplicatas` e `setup-autostart`, mantendo o modo sem argumentos como sincronização principal.
- 2026-04-30: o diagnóstico, a remoção de duplicatas e o autostart foram incorporados ao script principal com reutilização das funções existentes e backend embutido; os arquivos separados antigos deixaram de ser entrypoints necessários.
- 2026-04-30: validação da integração passou em `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` e `python3 zotero_sync_webdav.py --help`.
- 2026-04-30: os modos integrados `python3 zotero_sync_webdav.py diagnostico` e `python3 zotero_sync_webdav.py remove-duplicatas` também executaram corretamente contra a biblioteca real durante a validação.
- 2026-04-30: os arquivos separados antigos `zotero_diagnostico.py`, `zotero_remove_duplicatas.py` e `setup_autostart.sh` foram removidos da raiz do repositório após a integração completa.

- 2026-05-01: changed operational config in `~/.config/zotero_sync_webdav/zotero_sync.env` so both `ZOTERO_SYNC_TARGET_FOLDER` and `ZSW_TARGET_FOLDER` point to `/home/lucas/Google Drive/zoterodb`.
- 2026-05-01: updated `zotero_sync_webdav.py` to load `~/.config/zotero_sync_webdav/zotero_sync.env` by default before project `.env`, so manual runs and installed service use the same operational target unless `ZOTERO_ENV_FILE` overrides it.
- 2026-05-01: updated `zotero-sync.service` to require `rclone-google-drive.service` instead of `webdav-koofr.service`, installed the updated script to `~/.local/bin/zotero_sync_webdav.py`, and verified the wait helper succeeds against `/home/lucas/Google Drive/zoterodb`.
- 2026-05-01: validation passed: `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`; import checks for both repo and installed script printed `/home/lucas/Google Drive/zoterodb`.
- 2026-05-01: tightened hash-match rename reconciliation so the Zotero side uses the API filename/dateModified as canonical, not merely the local storage filename; if drive mtime is newer, Zotero/local storage adopt the drive name, and if Zotero dateModified is newer, drive/local storage adopt the Zotero API name.
- 2026-05-01: validation passed after the canonical-name fix: `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`; import check still resolved `/home/lucas/Google Drive/zoterodb`.
- 2026-05-01: implemented Zotero -> drive reconciliation after the main drive scan. The sync now builds a final drive hash/name index, materializes Zotero PDF attachments missing from the drive using `~/Zotero/storage` as source, downloads from Zotero via `zot.dump(...)` when local storage is absent, preserves Zotero `dateModified` as file mtime, and still resolves same-hash name conflicts by the newer side.
- 2026-05-01: validation passed for Zotero -> drive materialization changes: `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`; `python3 zotero_sync_webdav.py --help`; installed script import from `/home/lucas/.local/bin/zotero_sync_webdav.py` resolved `/home/lucas/Google Drive/zoterodb`.

## Evidence log update
 - 2026-05-08: duplicate-source investigation found that top-level `zot.attachment_simple([file_path])` uploads can later become duplicate bibliographic items when Zotero/Linter derives metadata for an already-known work; observed examples included `A situação atual dos cursos de licenciatura...` and `Oficinas de identidade com adolescentes...`.
 - 2026-05-08: `zotero_sync_webdav.py` now scans top-level bibliographic items, builds a conservative title index, attaches new PDFs to a single confident existing parent via `attachment_simple(..., parentid=...)`, and blocks ambiguous parent matches instead of creating top-level attachments.
 - 2026-05-08: added `tests/test_bibliographic_matching.py` covering truncated Zotero filenames, existing parent selection, ambiguous duplicate blocking, and leading author/year filename matching.
 - 2026-05-08: validation passed: `python3 -m unittest tests.test_bibliographic_matching`; `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`.
 - 2026-05-08: read-only live dry-run of the new matcher against current Zotero/drive state classified existing duplicate-risk files as `block_ambiguous` when multiple bibliographic parents already exist, and classified Baum chapter PDFs as `attach` to a single existing parent; no live mutation was performed in that verification.
 - 2026-05-08: added explicit copy-name handling for `Cópia de ...`, `Copy of ...`, `(1)` and trailing ` 1` variants. Same-hash copy names can no longer become canonical by newer mtime; the script now renames the drive copy to the Zotero canonical name or deletes it when the canonical drive file already exists with the same hash.
 - 2026-05-08: case 4 now blocks top-level upload of copy-marked files when no single bibliographic parent is found, preventing persistent `Cópia de ...` entries from becoming new duplicate Zotero items.
 - 2026-05-08: extended `tests/test_bibliographic_matching.py` to cover copy-prefix parent matching, copy-name canonical preference, same-hash drive copy deletion, and copy rename when canonical destination is absent.
 - 2026-05-08: validation passed after copy-name hardening: `python3 -m unittest tests.test_bibliographic_matching` ran 9 tests OK; `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed.
 - 2026-05-08: sync now runs safe bibliographic duplicate cleanup automatically, without a CLI flag. The cleanup groups top-level items by exact DOI or normalized title, chooses a keeper that preserves PDF children, merges duplicate collections/tags into the keeper, deletes only duplicates with no unsafe children and no non-redundant PDF hash, then refreshes attachment state before Zotero -> drive materialization.
 - 2026-05-08: automatic cleanup intentionally skips title-only metadata duplicates without DOI/PDF evidence, items with notes/non-PDF children, items with Zotero relations, attachments whose local hash cannot be validated, and duplicates whose PDF hash is not already present on the keeper.
 - 2026-05-08: extended duplicate tests to cover DOI grouping, keeper selection that preserves PDFs, redundant PDF deletion allowance, non-redundant PDF blocking, and title-only metadata blocking.
 - 2026-05-08: validation passed after automatic cleanup integration: `python3 -m unittest tests.test_bibliographic_matching` ran 14 tests OK; `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed; read-only live cleanup classification found `duplicate_groups=9`, `would_delete=3`, `would_skip=6`.
 - 2026-05-08: duplicate cleanup now classifies unsafe child blockers explicitly, distinguishing `nota`, `highlight`, generic `anotação`, `snapshot HTML`, and other non-PDF attachments instead of the former generic “notas ou anexos não-PDF”.
 - 2026-05-08: verified live examples that current blocker causes include a Zotero child note under `8W8XDT6E` and an imported HTML snapshot under `A8BKZSPQ`; highlight support is now explicit in the classifier even when not present in the sampled duplicate set.
 - 2026-05-08: extended `tests/test_bibliographic_matching.py` with explicit highlight and snapshot blocker assertions; validation passed with `python3 -m unittest tests.test_bibliographic_matching` running 17 tests OK and `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passing.
 - 2026-05-08: duplicate cleanup now treats duplicate bibliographic items with no child content as removable by default when the keeper has child content or the DOI is identical; relations on those empty duplicates are merged into the keeper before deletion instead of blocking cleanup.
 - 2026-05-08: extended `tests/test_bibliographic_matching.py` with no-attachment duplicate deletion and relation-merge coverage; validation passed with `python3 -m unittest tests.test_bibliographic_matching` running 20 tests OK and `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passing.
 - 2026-05-08: live sync after the no-attachment default removed 3 Zotero duplicate items and reduced API duplicate groups from 5 to 1; the remaining duplicate group is `Cultura Organizacional`, blocked because both sides have non-redundant PDF attachments. The same run reported 5 errors from existing Zotero attachments that could not be materialized, including 404 file downloads for `24MFJCFZ`, `DGFBH8FQ`, and `8SRIKPJH`.
 - 2026-05-08: attachment naming is now normalized during sync from parent metadata whenever a bibliographic parent exists. Canonical form is `título - sobrenome ano.pdf`; copy markers such as `Cópia de`, `Copy of`, `(1)` and similar variants are stripped before canonicalization.
 - 2026-05-08: imported attachments are updated through Zotero API with `filename` and `title`; linked-file attachments are updated with `title` plus canonical `path`, because Zotero rejects `filename` on `linked_file` attachments. The sync now verifies the post-update API state before considering the rename successful.
 - 2026-05-08: same-hash collisions between two different bibliographic items no longer oscillate by mtime when both have distinct canonical metadata names. If one canonical name is already present in the drive, the other attachment is materialized as an additional same-content file under its own canonical name instead of renaming the existing file away.
 - 2026-05-08: failed-upload cleanup now also removes broken imported-file placeholders that already have a parent item when they still have path-derived `_home_lucas_...` filenames and no content metadata; this prevents malformed attached duplicates from surviving future syncs.
 - 2026-05-08: validation passed after canonical attachment naming changes: `python3 -m unittest tests.test_bibliographic_matching` ran 23 tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed, and repeated live runs of `python3 zotero_sync_webdav.py` converged with `0` bibliographic duplicate groups and no remaining parented PDF attachments whose API filename diverged from the derived canonical metadata name.
 - 2026-05-09: standalone top-level PDF attachments now have a conservative canonicalization pass that removes copy markers such as `Cópia de`, `Copy of`, and `(1)` without inventing bibliographic metadata. Imported-file standalones are renamed in Zotero/storage, and linked-file standalones are renamed on disk plus in Zotero metadata only if the API confirms the change.
 - 2026-05-09: the repository now carries a local desktop recognizer plugin source tree in `zotero_sync_recognizer/` and a packaged installer at `zotero-sync-recognizer.xpi` in the project root so the user can install it from Zotero Add-ons. The sync includes a desktop-recognition hook for standalone PDFs, but in this environment the connector endpoint remains `404 No endpoint found` until the plugin is installed and accepted by Zotero itself, so auto-recognition did not activate during validation.
 - 2026-05-09: validation passed for the standalone-name and recognizer packaging changes: `python3 -m unittest tests.test_bibliographic_matching` ran 25 tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed, and live sync converged with `0` remaining top-level standalone PDF attachments matching `cópia de` or `(1).pdf`. The same live sync reported `Reconhecimento desktop: 0/9` and the usual 2 residual materialization errors from preexisting Zotero attachments without downloadable file content.
 - 2026-05-09: adjusted the packaged desktop recognizer metadata to match the compatibility pattern used by installed Zotero 9 beta plugins in this profile, setting `strict_min_version=6.999` and `strict_max_version=9.*` in both `manifest.json` and `install.rdf`, and rebuilt `zotero-sync-recognizer.xpi` in the project root. Validation passed again with `python3 -m unittest tests.test_bibliographic_matching` and `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`.
 - 2026-05-09: rebuilt `zotero-sync-recognizer.xpi` without bundling `install.rdf`, leaving a Zotero 7/9-style package with only `manifest.json` and `bootstrap.js`, matching the packaging shape of working bootstrapped plugins already installed in this profile. Validation passed again with `python3 -m unittest tests.test_bibliographic_matching` and `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`.
 - 2026-05-09: Zotero's own add-on loader logs showed the packaged recognizer was being rejected before bootstrap with `Reading manifest: applications.zotero.update_url not provided`. The packaged `zotero-sync-recognizer.xpi` was rebuilt with a required `applications.zotero.update_url` field in `manifest.json`, while keeping the manifest-only XPI structure (`manifest.json` + `bootstrap.js`). The rebuilt archive was verified by reading its embedded manifest from the XPI.
 - 2026-05-09: after the user activated the addon in Zotero, the local recognizer endpoint responded on `http://127.0.0.1:23119/zoteroSyncRecognize/ping`, and the next live sync reported `Reconhecimento desktop: 9/9`. This confirms the standalone-PDF recognition hook is now wired into the normal sync path on this workstation.
 - 2026-05-09: the desktop recognizer plugin now creates a generic Zotero `document` parent for standalone PDFs that remain top-level after `RecognizeDocument.recognizeItems()` returns. The parent title is derived conservatively from the cleaned attachment title/filename, the attachment is moved under it, collections are preserved on the new parent, and the new parents are selected in the Zotero UI when possible.
 - 2026-05-09: validation passed after adding the parent-creation fallback: `python3 -m unittest tests.test_bibliographic_matching` ran 27 tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed, the recognizer endpoint stayed active after restart, and a live sync reported `Reconhecimento desktop: 9/9` with `Itens pai fallback: 9` and `0` remaining standalone PDF attachments in the Zotero API.
 - 2026-05-10: merged Obsidian profile portability into `zotero_sync_webdav.py` as new CLI commands `obsidian-verify`, `obsidian-export`, `obsidian-apply`, `obsidian-mirror`, and `obsidian-setup`. The old `zotero_mirror_collections_to_obsidian.py` now acts as a compatibility wrapper that forwards to `obsidian-mirror`.
 - 2026-05-10: `obsidian-setup` was implemented conservatively. It applies an Obsidian bundle and mirrors Zotero collections only when `--apply` is passed; otherwise it behaves as a dry-run. This keeps the main unattended sync path unchanged while still exposing the combined Obsidian workflow from the primary CLI.
 - 2026-05-10: validation passed for the merged Obsidian workflow: `python3 -m unittest tests.test_bibliographic_matching` ran 31 tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed, `python3 zotero_sync_webdav.py obsidian-verify --kind auto` reported a valid local Obsidian config, `python3 zotero_sync_webdav.py obsidian-export --source auto --out /tmp/obsidian-bundle-zsync --force --dry-run` completed, `python3 zotero_sync_webdav.py obsidian-apply --target deb --bundle /tmp/obsidian-bundle-sample --create-missing-vaults --dry-run` completed against a synthetic bundle, `python3 zotero_sync_webdav.py obsidian-mirror --dry-run` enumerated 51 Zotero collections into the Obsidian target tree, and `python3 zotero_sync_webdav.py obsidian-setup --target deb --bundle /tmp/obsidian-bundle-sample --create-missing-vaults --dry-run` completed the combined dry-run flow.
 - 2026-05-10: collection hierarchy is now modeled centrally in `zotero_sync_webdav.py` with stable helpers for `collection -> relative_path`, `relative_path -> collection`, and primary-collection selection. The same sanitization is reused for drive and Obsidian folder names.
 - 2026-05-10: the main script now scans the Zotero drive recursively, creates missing collection directories in both the drive root and the Obsidian mirror root, and includes a fast pre-sync relocation pass that moves already-known Zotero PDFs into the collection subfolder implied by their current Zotero collection membership before the heavier upload loop begins.
 - 2026-05-10: Obsidian staging ingestion was added in conservative form. PDFs placed inside mapped Obsidian collection folders are detected before the main drive scan and moved into the corresponding drive collection folder, with same-name/same-hash dedupe and same-name/different-content blocking. The source file remains in Obsidian on failure.
 - 2026-05-10: live collection-path reconciliation was validated directly through the script helpers against the real library and drive without touching Zotero upload quota. The relocation pass moved `135` existing drive files into their collection folders, and a post-check found `645/645` collection-backed Zotero PDF attachments already present at their expected relative paths in the Google Drive tree.
 - 2026-05-10: validation passed after collection-path integration: `python3 -m unittest tests.test_bibliographic_matching` ran 35 tests OK and `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py` passed. A full `python3 zotero_sync_webdav.py` run still encountered the preexisting Zotero storage quota problem (`413 File would exceed quota`) on genuinely new PDFs, but the collection-relocation portion completed independently and was verified separately.
 - 2026-05-11: added standalone script `zotero_storage_quota_audit.py` to explain what consumes Zotero storage quota. The script classifies attachments by `linkMode`, estimates size from local attachment files when present, totals probable remote storage for `imported_file` and `imported_url`, and lists the largest remote attachments.
 - 2026-05-11: validation passed for the storage audit script: `python3 -m unittest discover -s tests` ran 40 tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py zotero_storage_quota_audit.py` passed, and `python3 zotero_storage_quota_audit.py --top 10` reported `895` attachments total, `5.6 GB` estimated remote storage with known local sizes, `127` remote attachments without measurable local copy, and top remote files led by `História da psicologia - Hothersall 2021.pdf` at `318.5 MB`.
 - 2026-05-11: `zotero_storage_quota_audit.py` now reads the active Zotero Desktop file-sync prefs from `prefs.js` and separates imported attachments by the configured backend. On this workstation the configured backend is `webdav` at `app.koofr.net/dav/Koofr`, so the script reports `imported_file` and `imported_url` bytes as WebDAV-managed rather than zotero.org quota usage.
 - 2026-05-11: the desktop recognizer plugin was extended with `/zoteroSyncRecognize/import`, backed by `Zotero.Attachments.importFromFile()`, so new PDFs can enter the library through Zotero Desktop and follow the user's configured WebDAV backend instead of the Web API file-upload path. The sync now blocks fallback to `attachment_simple()` when the desktop endpoint is unavailable, to avoid consuming zotero.org quota by accident.
 - 2026-05-11: focused live validation of the new desktop import route succeeded on a real pending file from `UNEB Psicologia 2025.2`. Importing `FECS BA Certificado de participação - Lucas Camilo Carvalho.pdf` via `import_attachment_via_desktop()` returned attachment key `ZW9KUV3Y` and fallback parent `UBV2ITQW`, confirming that the new endpoint imports, recognizes/fallback-parents, and keeps the file path under the WebDAV-backed Zotero Desktop flow.
 - 2026-05-11: added a pre-sync drive copy-marker normalization pass. Before entering the expensive main scan loop, the script now rewrites drive filenames such as `Cópia de ...` and `(1).pdf` to their canonical names in place, reusing the same safe rename/dedupe logic as the rest of the sync. If a canonical target already exists with different content, the file stays blocked and is reported explicitly.
 - 2026-05-11: validation passed for the copy-marker prepass: `python3 -m unittest discover -s tests` ran 45 tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py zotero_storage_quota_audit.py` passed, and a focused real prepass over the current Google Drive tree processed `1728` PDFs, consolidating `205` copy-marked filenames before the main sync loop with `0` blocked copy-marker collisions.
 - 2026-05-11: refined copy-marker detection to stop treating plain titles ending in `1.pdf` as copies. The copy normalization rule now strips only explicit copy prefixes (`Cópia de`, `Copy of`) and parenthesized suffixes like `(1)`, avoiding false positives such as `Slides 1.pdf` or `PEBR - prova versão 1.pdf`.
 - 2026-05-11: validation passed for the refined copy prepass: `python3 -m unittest discover -s tests` ran 46 tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py zotero_storage_quota_audit.py` passed, and a real recursive scan over `/home/lucas/Google Drive/zoterodb` found `0` remaining copy-variant filenames after the prepass cleanup.
 - 2026-05-11: unified the local plugin artifact naming. The source tree was renamed from `zotero_desktop_recognizer/` to `zotero_sync_recognizer/`, while the packaged installer remains `zotero-sync-recognizer.xpi`. The XPI and source tree still represent the same single plugin: the folder is the editable source and the `.xpi` is the installable package built from it.
 - 2026-05-11: removed the obsolete compatibility wrapper `zotero_mirror_collections_to_obsidian.py` after confirming that its functionality had already been merged into `zotero_sync_webdav.py` as the `obsidian-mirror` subcommand. Current syntax validation now targets `zotero_sync_webdav.py` and `zotero_storage_quota_audit.py`.
 - 2026-05-12: drive path authority is now applied for already-known PDFs during the main sync loop. When a known attachment is found in a mapped non-empty Google Drive collection folder, the script treats that folder as authoritative among mirrored collections and updates the Zotero item or parent so the mirrored collection membership follows the drive path instead of forcing the file back to the old Zotero collection path.
 - 2026-05-12: empty-directory cleanup is now built into the helper layer for the active drive root and `ObsidianLocal`. A focused live cleanup removed `9` empty directories from `/home/lucas/Google Drive/zoterodb` and `114` from `/home/lucas/Documentos/ObsidianLocal`; a later verification pass found `0` additional empty directories pending removal in either root.
 - 2026-05-12: validation passed for the drive-authoritative collection pass: `python3 -m unittest discover -s tests` ran `48` tests OK, `python3 -m py_compile zotero_sync_webdav.py zotero_storage_quota_audit.py` passed, and a focused real reconciliation against the current library/drive completed with `drive_authoritative_collection_updates=0`, indicating that the current non-empty collection folders in Google Drive were already aligned with Zotero after the previous restructuring.
- 2026-06-18: collection auto-creation from drive content is now implemented. During sync setup, the script scans non-empty directories under `/home/lucas/Google Drive/zoterodb`, ignores empty folders, and creates missing Zotero collections for the discovered path chain before the main reconciliation. The Google Drive path can therefore establish new mirrored collections when it contains actual files.
- 2026-06-18: focused live reconciliation after the new drive-content collection pass created `17` missing Zotero collections from existing non-empty drive folders, removed `2` additional empty directories from `zoterodb`, and required `0` further collection-alignment updates because the remaining known PDFs were already consistent with their drive paths.
- 2026-06-18: validation passed for the drive-content collection creation flow: `python3 -m unittest discover -s tests` ran `50` tests OK and `python3 -m py_compile zotero_sync_webdav.py zotero_storage_quota_audit.py` passed.
- 2026-07-03: implemented rclone timeout resilience and hashing bypass (US-005). The default hash timeout was reduced from 180s to 30s. If a file times out over the rclone mount, a `"QUARANTINE_TIMEOUT"` string is cached as its hash value.
- 2026-07-03: updated `get_cached_hash` and `compute_sha256` to skip files in quarantine without waiting for the timeout again on subsequent runs (fast-fail).
- 2026-07-03: added `test_compute_sha256_quarantine.py` to verify the quarantine caching behavior. Quality gates passed (`python3 -m unittest discover -s tests` and `python3 -m py_compile zotero_sync_webdav.py`).
- 2026-07-03: completed US-001 (import-safety). Module-level env loading deferred to `load_config()`. Globals init to empty strings; `check_environment_requirements()` validates on demand. Import with no ZOTERO_ vars no longer raises. Tests: `test_import_safety.py` (10 tests).
- 2026-07-03: completed US-002 (filesystem mutation tests). Added `test_filesystem_mutations.py` covering `rename_webdav_file`, `copy_to_local_storage`, hash cache set/get/rename/remove/invalidation, and `relocate_drive_file` (14 tests).
- 2026-07-03: completed US-003 (preflight checks). Added `preflight_checks()` validating env vars, target folder existence/readability, and local storage writability. Integrated into `run_sync_mode()` with `sys.exit(1)` on failure. Tests in `test_preflight_and_outcomes.py` (10 tests).
- 2026-07-03: completed US-004 (truthful run outcome). `run_sync_mode()` now exits nonzero when `stats['errors'] > 0`. Zotero connection failure exits nonzero. `main()` wrapped in try/except for uncaught exceptions (exit code 2). Tests in `test_preflight_and_outcomes.py`.
- 2026-07-03: completed US-006 (orphaned file recovery). Added `recover-orphans` CLI sub-command with `--dry-run` support. Detects Zotero PDF attachments missing from the drive and materializes them. Tests in `test_recover_orphans.py` (6 tests).
- 2026-07-03: all 6 stories (US-001 through US-006) marked done in `prd.json`. Quality gates passed: `python3 -m py_compile zotero_sync_webdav.py zotero_storage_quota_audit.py` clean, `python3 -m unittest discover -s tests` ran 92 tests OK.