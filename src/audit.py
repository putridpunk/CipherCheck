"""Audit a whole file of (synthetic) passwords, using every CPU core.

Large files are read in chunks of lines; each chunk is analysed in a worker process and
only counters come back, so memory stays small and no password is kept or returned.

A `.csv` file (e.g. a password manager export) is read as CSV: the header row is used to
find a column that looks like it holds passwords, and only that column is read. If the
header also has a column that looks like a site/account name, that (never the password
itself) is kept alongside the weakest entries and alongside groups of accounts that share
a password, so the dashboard can say *which* accounts to fix, not just how many.
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
MAX_LABEL_LENGTH = 80
MAX_WORST_ENTRIES = 15
# Only these are worth flagging as "fix this first"; STRONG/VERY STRONG never are.
WORST_LABELS = ("VERY WEAK", "WEAK", "MODERATE")
_WORST_ORDER = {lbl: i for i, lbl in enumerate(WORST_LABELS)}

# Column names (lower-case) a password-manager export is likely to use.
PASSWORD_HEADERS = ("password", "login_password", "pass", "pwd", "passwd")
LABEL_HEADERS = ("name", "site", "url", "login_uri", "title", "hostname", "domain", "account")

# progress(lines_done, fraction_of_file_read)
Progress = Callable[[int, float], None]


class NoPasswordColumn(ValueError):
    """Raised when a .csv file has no column that looks like it holds passwords."""


@dataclass(frozen=True)
class WorstEntry:
    """One weak entry worth fixing first: the (non-secret) label and why, never the password."""

    label: str
    assessment: str
    kinds: tuple[str, ...]


class WorstTracker:
    """Keeps only the worst `MAX_WORST_ENTRIES` labelled entries seen, however many pass through."""

    def __init__(self) -> None:
        self.entries: list[WorstEntry] = []

    def add(self, label: str, assessment: str, kinds: list[str]) -> None:
        if assessment in _WORST_ORDER:
            self.entries.append(WorstEntry(label[:MAX_LABEL_LENGTH], assessment, tuple(kinds)))

    def trim(self, n: int = MAX_WORST_ENTRIES) -> None:
        self.entries.sort(key=lambda e: (_WORST_ORDER[e.assessment], -len(e.kinds)))
        del self.entries[n:]

    def merge(self, other: "WorstTracker") -> None:
        self.entries.extend(other.entries)
        self.trim()

    def summary(self, n: int = MAX_WORST_ENTRIES) -> list[dict]:
        self.trim(n)
        return [{"label": e.label, "assessment": e.assessment, "kinds": list(e.kinds)} for e in self.entries]


@dataclass
class ChunkStats:
    """Everything a worker sends back for one chunk (no password text)."""

    n: int
    labels: Counter
    kinds: Counter
    bits: float
    length: int
    reuse: ReuseTracker
    worst: WorstTracker
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
        self.worst.merge(other.worst)
        self.policy_passed += other.policy_passed
        self.policy_failed += other.policy_failed
        self.policy_reasons.update(other.policy_reasons)


def _empty_stats() -> ChunkStats:
    return ChunkStats(0, Counter(), Counter(), 0.0, 0, ReuseTracker(), WorstTracker())


def analyze_chunk(lines: list[tuple[bytes, str | None]], policy: policy_mod.Policy | None = None) -> ChunkStats:
    """Analyse raw (password line, optional label) pairs. Module-level so workers can import it."""
    stats = _empty_stats()
    for raw, label in lines:
        pw = raw.rstrip(b"\r\n").decode("utf-8", "replace")
        if not pw:
            continue
        a = analyze(pw)
        stats.n += 1
        stats.labels[a.label] += 1
        stats.kinds.update(a.pattern_kinds)
        stats.bits += a.estimated_bits
        stats.length += a.length
        stats.reuse.add(pw, label)
        if label:
            stats.worst.add(label, a.label, a.pattern_kinds)
        if policy is not None:
            result = policy_mod.evaluate(a, policy)
            if result.passed:
                stats.policy_passed += 1
            else:
                stats.policy_failed += 1
                stats.policy_reasons.update(result.reasons)
    stats.worst.trim()  # bound what a worker sends back, regardless of chunk size
    return stats


def _best_column(header: list[str], names: tuple[str, ...], contains: tuple[str, ...]) -> int | None:
    lower = [h.strip().lower() for h in header]
    for name in names:
        if name in lower:
            return lower.index(name)
    for i, h in enumerate(lower):
        if any(c in h for c in contains):
            return i
    return None


def _password_column(header: list[str]) -> int | None:
    """Index of the column most likely to hold passwords, or None if none looks like it."""
    return _best_column(header, PASSWORD_HEADERS, ("password", "pass", "pwd"))


def _label_column(header: list[str], password_col: int) -> int | None:
    """Index of a column that looks like a site/account name, if any (never the password one)."""
    col = _best_column(header, LABEL_HEADERS, ("name", "site", "url", "uri", "title", "host", "domain"))
    return col if col is not None and col != password_col else None


def _csv_columns(path: Path) -> tuple[int, int | None]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        try:
            header = next(csv.reader(fh))
        except StopIteration:
            raise NoPasswordColumn("the CSV file is empty") from None
        col = _password_column(header)
        if col is None:
            raise NoPasswordColumn("no password-like column found in the CSV header")
        return col, _label_column(header, col)


def _csv_lines(path: Path, col: int, label_col: int | None) -> Iterator[tuple[bytes, str | None, int]]:
    """Yield (password line, label, bytes consumed so far) for one CSV column.

    `fh.tell()` cannot be used here (Python disallows it once a text file has been
    iterated), so progress is an estimate based on each row's own size; it is clamped
    to the file size by the caller and is only ever used for the progress bar.
    """
    consumed = 0
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        reader = csv.reader(fh)
        next(reader, None)  # header, already used to pick the columns
        for row in reader:
            consumed += len(",".join(row).encode("utf-8", "replace")) + 2
            if col < len(row) and row[col]:
                label = row[label_col].strip() if label_col is not None and label_col < len(row) else None
                yield row[col].encode("utf-8", "replace") + b"\n", label or None, consumed


def _raw_lines(path: Path) -> Iterator[tuple[bytes, None, int]]:
    done = 0
    with path.open("rb") as fh:
        for line in fh:
            done += len(line)
            yield line, None, done


def _chunks(path: Path, chunk_lines: int, csv_cols: tuple[int, int | None] | None):
    """Yield (lines, bytes_consumed_so_far); each line is (password_bytes, label_or_none)."""
    source = _csv_lines(path, *csv_cols) if csv_cols is not None else _raw_lines(path)
    batch: list[tuple[bytes, str | None]] = []
    consumed = 0
    for line, label, done in source:
        batch.append((line, label))
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
    A site/account-name column, if found, is used only to name the weakest entries and
    accounts that share a password - the password itself is never kept or returned.

    Returns the aggregate dict (see report.aggregate_counts), or None when `cancel` was set.
    Raises OSError if the file cannot be read. `workers=1` stays in this process.
    """
    path = Path(path)
    size = max(path.stat().st_size, 1)
    csv_cols = _csv_columns(path) if path.suffix.lower() == ".csv" else None
    if workers is None:
        workers = 1 if size < SMALL_FILE_BYTES else default_workers()
    total = _empty_stats()

    def report_progress(consumed: int) -> None:
        if progress:
            progress(total.n, min(consumed / size, 1.0))

    if workers <= 1:
        for lines, consumed in _chunks(path, chunk_lines, csv_cols):
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

            for lines, consumed in _chunks(path, chunk_lines, csv_cols):
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
                                   total.reuse.summary(), policy_result, total.worst.summary())


__all__ = ["audit_file", "default_workers", "NoPasswordColumn"]
