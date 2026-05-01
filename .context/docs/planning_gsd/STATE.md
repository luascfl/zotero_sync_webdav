# GSD state

Updated: 2026-04-30

## Current state
- Context bootstrap is complete enough to propose the next Ralph cycle.
- User clarified that this repository is script automation, not a set of official products.
- Main sync should remain automatic.
- Target environment is Linux with mounted WebDAV.
- Active technical priority is hardening.
- `padronizar_contatos_google.py` removal is intentional because it did not belong to this repository.

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
- `python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py`
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
- Run: python3 -m py_compile zotero_sync_webdav.py zotero_mirror_collections_to_obsidian.py
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
