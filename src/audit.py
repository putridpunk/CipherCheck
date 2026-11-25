"""Audit a whole file of (synthetic) passwords, using every CPU core.

Large files are read in chunks of lines; each chunk is analysed in a worker process and
only counters come back, so memory stays small and no password is kept or returned.

A `.csv` file (e.g. a password manager export) is read as CSV: the header row is used to
find a column that looks like it holds passwords, and only that column is read. Nothing
else in the file (sites, usernames, notes, ...) is ever opened or kept.
"""

from __future__ import annotations

import csv
import os
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ProcessPoolExecutor, wait
from dataclasses import dataclass, field
from pathlib import Path

from . import policy as policy_mod
from . import report
from .analyzer import analyze
from .reuse import ReuseTracker

CHUNK_LINES = 4000
MAX_WORKERS = 8
SMALL_FILE_BYTES = 256 * 1024  # below this, starting worker processes costs more than it saves

# Column names (lower-case) a password-manager export is likely to use.
PASSWORD_HEADERS = ("password", "login_password", "pass", "pwd", "passwd")

# progress(lines_done, fraction_of_file_read)
Progress = Callable[[int, float], None]


class NoPasswordColumn(ValueError):
    """Raised when a .csv file has no column that looks like it holds passwords."""


@dataclass
class ChunkStats:
    """Everything a worker sends back for one chunk (no password text)."""

    n: int
    labels: Counter
    kinds: Counter
    bits: float
    length: int
    reuse: ReuseTracker
    policy_passed: int = 0
    policy_failed: int = 0
    policy_reasons: Counter = field(default_factory=Counter)

    def merge(self, other: "ChunkStats") -> None:
        self.n += other.n
        self.labels.update(other.labels)
        self.kinds.update(other.kinds)
        self.bits += other.bits
        self.length += other.length
        self.reuse.merge(other.reuse)
        self.policy_passed += other.policy_passed
        self.policy_failed += other.policy_failed
        self.policy_reasons.update(other.policy_reasons)


def _empty_stats() -> ChunkStats:
    return ChunkStats(0, Counter(), Counter(), 0.0, 0, ReuseTracker())


def analyze_chunk(lines: list[bytes], policy: policy_mod.Policy | None = None) -> ChunkStats:
    """Analyse raw lines. Module-level so worker processes can import it."""
    stats = _empty_stats()
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
        if policy is not None:
            result = policy_mod.evaluate(a, policy)
            if result.passed:
                stats.policy_passed += 1
            else:
                stats.policy_failed += 1
                stats.policy_reasons.update(result.reasons)
    return stats


def _password_column(header: list[str]) -> int | None:
    """Index of the column most likely to hold passwords, or None if none looks like it."""
    lower = [h.strip().lower() for h in header]
    for name in PASSWORD_HEADERS:
        if name in lower:
            return lower.index(name)
    for i, h in enumerate(lower):
        if "password" in h or "pass" in h or "pwd" in h:
            return i
    return None


def _csv_column(path: Path) -> int:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        try:
            header = next(csv.reader(fh))
        except StopIteration:
            raise NoPasswordColumn("the CSV file is empty") from None
        col = _password_column(header)
        if col is None:
            raise NoPasswordColumn("no password-like column found in the CSV header")
        return col


def _csv_lines(path: Path, col: int) -> Iterator[tuple[bytes, int]]:
    """Yield (password line, bytes consumed so far) for one CSV column.

    `fh.tell()` cannot be used here (Python disallows it once a text file has been
    iterated), so progress is an estimate based on each row's own size; it is clamped
    to the file size by the caller and is only ever used for the progress bar.
    """
    consumed = 0
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        next(reader, None)  # header, already used to pick `col`
        for row in reader:
            consumed += len(",".join(row).encode("utf-8", "replace")) + 2
            if col < len(row) and row[col]:
                yield row[col].encode("utf-8", "replace") + b"\n", consumed


def _raw_lines(path: Path) -> Iterator[tuple[bytes, int]]:
    done = 0
    with path.open("rb") as fh:
        for line in fh:
            done += len(line)
            yield line, done


def _chunks(path: Path, chunk_lines: int, csv_col: int | None):
    """Yield (lines, bytes_consumed_so_far)."""
    source = _csv_lines(path, csv_col) if csv_col is not None else _raw_lines(path)
    batch: list[bytes] = []
    consumed = 0
    for line, done in source:
        batch.append(line)
        consumed = done
        if len(batch) >= chunk_lines:
            yield batch, consumed
            batch = []
    if batch:
        yield batch, consumed


def default_workers() -> int:
    return max(1, min(os.cpu_count() or 1, MAX_WORKERS))


def audit_file(path: str | Path, *, workers: int | None = None, progress: Progress | None = None,
               cancel: threading.Event | None = None, chunk_lines: int = CHUNK_LINES,
               policy: policy_mod.Policy | None = None) -> dict | None:
    """Aggregate statistics for one-password-per-line `path`, or a `.csv` export (the
    password column is detected from the header; raises NoPasswordColumn if none is found).

    Returns the aggregate dict (see report.aggregate_counts), or None when `cancel` was set.
    Raises OSError if the file cannot be read. `workers=1` stays in this process.
    """
    path = Path(path)
    size = max(path.stat().st_size, 1)
    csv_col = _csv_column(path) if path.suffix.lower() == ".csv" else None
    if workers is None:
        workers = 1 if size < SMALL_FILE_BYTES else default_workers()
    total = _empty_stats()

    def report_progress(consumed: int) -> None:
        if progress:
            progress(total.n, min(consumed / size, 1.0))

    if workers <= 1:
        for lines, consumed in _chunks(path, chunk_lines, csv_col):
            if cancel and cancel.is_set():
                return None
            total.merge(analyze_chunk(lines, policy))
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

            for lines, consumed in _chunks(path, chunk_lines, csv_col):
                if cancel and cancel.is_set():
                    break
                pending[pool.submit(analyze_chunk, lines, policy)] = consumed
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

    policy_result = None
    if policy is not None:
        policy_result = {
            "key": policy.key, "passed": total.policy_passed, "failed": total.policy_failed,
            "reasons": dict(total.policy_reasons),
        }
    return report.aggregate_counts(total.n, total.labels, total.kinds, total.bits, total.length,
                                   total.reuse.summary(), policy_result)
