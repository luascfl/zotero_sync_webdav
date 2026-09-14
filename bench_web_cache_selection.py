#!/usr/bin/env python3
"""Deterministic benchmark for the Zotero Web cache selection policy."""
from __future__ import annotations

import random
import time

BUDGET_BYTES = 270 * 1024 * 1024
CANDIDATE_COUNT = 1_962
REPETITIONS = 250
SEED = 6670846


def build_candidates() -> list[tuple[int, int, str, bool]]:
    randomizer = random.Random(SEED)
    candidates: list[tuple[int, int, str, bool]] = []
    for index in range(CANDIDATE_COUNT):
        added_rank = CANDIDATE_COUNT - index
        size_bytes = randomizer.randint(24 * 1024, 36 * 1024 * 1024)
        candidates.append((added_rank, size_bytes, f"attachment-{index:04d}", index % 31 != 0))
    return candidates


def select_recent(candidates: list[tuple[int, int, str, bool]]) -> tuple[int, int]:
    selected_bytes = 0
    selected_count = 0
    for _, size_bytes, _, local_available in sorted(candidates, reverse=True):
        if not local_available or size_bytes > BUDGET_BYTES:
            continue
        if selected_bytes + size_bytes > BUDGET_BYTES:
            continue
        selected_bytes += size_bytes
        selected_count += 1
    return selected_count, selected_bytes


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
