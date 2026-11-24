"""Audit a whole file of (synthetic) passwords, using every CPU core.

Large files are read in chunks of lines; each chunk is analysed in a worker process and
only counters come back, so memory stays small and no password is kept or returned.
"""

from __future__ import annotations

import os
import threading
from collections import Counter
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path

from . import report
from .analyzer import analyze
from .reuse import ReuseTracker

CHUNK_LINES = 4000
MAX_WORKERS = 8
SMALL_FILE_BYTES = 256 * 1024  # below this, starting worker processes costs more than it saves

# progress(lines_done, fraction_of_file_read)
Progress = Callable[[int, float], None]


@dataclass
class ChunkStats:
    """Everything a worker sends back for one chunk (no password text)."""

    n: int
    labels: Counter
    kinds: Counter
    bits: float
    length: int
    reuse: ReuseTracker

    def merge(self, other: "ChunkStats") -> None:
        self.n += other.n
        self.labels.update(other.labels)
        self.kinds.update(other.kinds)
        self.bits += other.bits
        self.length += other.length
        self.reuse.merge(other.reuse)


def analyze_chunk(lines: list[bytes]) -> ChunkStats:
    """Analyse raw lines. Module-level so worker processes can import it."""
    stats = ChunkStats(0, Counter(), Counter(), 0.0, 0, ReuseTracker())
    for raw in lines:
        pw = raw.rstrip(b"\r\n").decode("utf-8", "replace")
        if not pw:
            continue
        a = analyze(pw)
        stats.n += 1
        stats.labels[a.label] += 1
        stats.kinds.update(a.pattern_kinds)
        stats.bits += a.estimated_bits
        stats.length += a.length
        stats.reuse.add(pw)
    return stats


def _chunks(path: Path, chunk_lines: int):
    """Yield (lines, bytes_consumed_so_far)."""
    done = 0
    with path.open("rb") as fh:
        batch: list[bytes] = []
        for line in fh:
            batch.append(line)
            done += len(line)
            if len(batch) >= chunk_lines:
                yield batch, done
                batch = []
        if batch:
            yield batch, done


def default_workers() -> int:
    return max(1, min(os.cpu_count() or 1, MAX_WORKERS))


def audit_file(path: str | Path, *, workers: int | None = None, progress: Progress | None = None,
               cancel: threading.Event | None = None, chunk_lines: int = CHUNK_LINES) -> dict | None:
    """Aggregate statistics for one-password-per-line `path`.

    Returns the aggregate dict (see report.aggregate_counts), or None when `cancel` was set.
    Raises OSError if the file cannot be read. `workers=1` stays in this process.
    """
    path = Path(path)
    size = max(path.stat().st_size, 1)
    if workers is None:
        workers = 1 if size < SMALL_FILE_BYTES else default_workers()
    total = ChunkStats(0, Counter(), Counter(), 0.0, 0, ReuseTracker())

    def report_progress(consumed: int) -> None:
        if progress:
            progress(total.n, min(consumed / size, 1.0))

    if workers <= 1:
        for lines, consumed in _chunks(path, chunk_lines):
            if cancel and cancel.is_set():
                return None
            total.merge(analyze_chunk(lines))
            report_progress(consumed)
    else:
        pending: dict[Future, int] = {}
        with ProcessPoolExecutor(max_workers=workers) as pool:
            def collect(block: bool) -> bool:
                """Merge finished chunks. Returns False if cancelled."""
                if not pending:
                    return True
                finished, _ = wait(list(pending), timeout=None if block else 0.0,
                                   return_when=FIRST_COMPLETED)
                for fut in finished:
                    consumed = pending.pop(fut)
                    total.merge(fut.result())
                    report_progress(consumed)
                return not (cancel and cancel.is_set())

            for lines, consumed in _chunks(path, chunk_lines):
                if cancel and cancel.is_set():
                    break
                pending[pool.submit(analyze_chunk, lines)] = consumed
                while len(pending) >= workers * 2:  # keep memory bounded
                    if not collect(block=True):
                        break
                collect(block=False)
            else:
                while pending and collect(block=True):
                    pass
            if cancel and cancel.is_set():
                pool.shutdown(wait=True, cancel_futures=True)  # drop queued chunks
                return None

    return report.aggregate_counts(total.n, total.labels, total.kinds, total.bits, total.length,
                                   total.reuse.summary())
