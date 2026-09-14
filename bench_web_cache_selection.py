#!/usr/bin/env python3
"""Deterministic benchmark for the production Zotero Web cache selection policy."""
from __future__ import annotations

import random
import time

from zotero_sync_webdav import select_recent_web_cache_candidates


BUDGET_BYTES = 270 * 1024 * 1024
CANDIDATE_COUNT = 1_962
REPETITIONS = 250
SEED = 6670846


def build_candidates() -> list[dict[str, object]]:
    randomizer = random.Random(SEED)
    candidates: list[dict[str, object]] = []
    for index in range(CANDIDATE_COUNT):
        if index % 31 == 0:
            continue
        candidates.append(
            {
                "date_added": f"2026-01-{(index % 28) + 1:02d}T{index % 24:02d}:00:00Z",
                "size_bytes": randomizer.randint(24 * 1024, 36 * 1024 * 1024),
                "source_attachment_key": f"attachment-{index:04d}",
            }
        )
    return candidates


def select_recent(candidates: list[dict[str, object]]) -> tuple[int, int]:
    selected, selected_bytes = select_recent_web_cache_candidates(candidates, BUDGET_BYTES)
    return len(selected), selected_bytes


def main() -> None:
    candidates = build_candidates()
    started = time.perf_counter_ns()
    selected_count = 0
    selected_bytes = 0
    for _ in range(REPETITIONS):
        selected_count, selected_bytes = select_recent(candidates)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000
    print(f"METRIC cache_plan_ms={elapsed_ms:.3f}")
    print(f"METRIC selected_count={selected_count}")
    print(f"METRIC selected_bytes={selected_bytes}")


if __name__ == "__main__":
    main()
