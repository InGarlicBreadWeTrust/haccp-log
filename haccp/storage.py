""":mod:`haccp.storage` -- append-only, tamper-evident JSONL audit store.

Each appended record is one JSON object on one line. The records form a
**SHA-256 hash chain**: every record embeds the hash of the previous record
(``prev_hash``) and its own ``hash``. Because each hash folds in the previous
one, changing any byte of any line changes every subsequent hash, so a single
tampered line breaks the chain from that point on.

Only stdlib ``json`` + ``hashlib`` + ``os`` are used. No DB, no network.

A record looks like::

    {"seq": 0, "ts": "...", "type": "reading", "payload": {...},
     "prev_hash": "<64 hex or genesis>", "hash": "<64 hex>"}
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass

from .models import RECORD_TYPES, make_record

GENESIS = "0" * 64   # the prev_hash of the very first record


def _canonical(record: dict) -> str:
    """Deterministic canonical JSON of everything except the ``hash`` field."""
    body = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def record_hash(record: dict) -> str:
    """SHA-256 hex digest of the record's canonical form (without ``hash``)."""
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


@dataclass
class AuditResult:
    """The outcome of verifying a chain: the first broken link, if any."""
    ok: bool
    broken_seq: int | None = None
    detail: str = ""
    records_verified: int = 0

    def __bool__(self) -> bool:
        return self.ok


class Store:
    """Append-only JSONL store at ``path`` with a SHA-256 hash chain."""

    def __init__(self, path: str):
        self.path = path

    def _ensure_parent(self) -> None:
        parent = os.path.dirname(os.path.abspath(self.path))
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _last_hash(self) -> str:
        """Hash of the most recently appended record (GENESIS if empty)."""
        if not os.path.exists(self.path):
            return GENESIS
        last = ""
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if not last:
            return GENESIS
        try:
            rec = json.loads(last)
            h = rec.get("hash")
        except (json.JSONDecodeError, AttributeError):
            return GENESIS
        return h if isinstance(h, str) else GENESIS

    def _count_lines(self) -> int:
        if not os.path.exists(self.path):
            return 0
        n = 0
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    n += 1
        return n

    def write_entry(self, obj) -> dict:
        """Append one record built from ``obj`` and return the full record.

        ``obj`` may be any model (``Reading`` / ``ChecklistItem`` /
        ``Incident``) or a plain dict. The new record's ``prev_hash`` is
        chained from the last record on disk, then its ``hash`` is computed and
        appended.
        """
        self._ensure_parent()
        seq = self._count_lines()
        prev = self._last_hash()
        from datetime import datetime, timezone
        payload = make_record(obj)
        kind = payload.get("type", "raw")
        rec = {
            "seq": seq,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": kind,
            "payload": payload,
            "prev_hash": prev,
        }
        rec["hash"] = record_hash(rec)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        return rec

    def read_all(self) -> list:
        """Return every record as a list of dicts (parse failures raise)."""
        out = []
        if not os.path.exists(self.path):
            return out
        with open(self.path, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    out.append(json.loads(line))
        return out

    def objects(self):
        """Yield each record re-instantiated to its model class."""
        for rec in self.read_all():
            kind = rec.get("type", "raw")
            cls = RECORD_TYPES.get(kind)
            if cls is None:
                yield rec
                continue
            try:
                yield cls.from_dict(rec)
            except Exception:
                yield rec

    def audit(self) -> AuditResult:
        """Walk the chain and return the first broken link, if any.

        Verifies, per record in order:
            * the JSON parses,
            * the stored ``hash`` equals the recomputed hash,
            * ``prev_hash`` equals the prior record's hash (GENESIS for #0),
            * ``seq`` equals the line index (monotonic, tamper-proof count).
        """
        expected_prev = GENESIS
        if not os.path.exists(self.path):
            return AuditResult(ok=True, records_verified=0)
        with open(self.path, "r", encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError as exc:
                    return AuditResult(
                        ok=False, broken_seq=i,
                        detail="unparseable JSON: %s" % exc,
                        records_verified=i,
                    )
                stored = rec.get("hash")
                copy = {k: v for k, v in rec.items() if k != "hash"}
                if not isinstance(stored, str) or record_hash(copy) != stored:
                    return AuditResult(
                        ok=False, broken_seq=rec.get("seq", i),
                        detail="hash mismatch on seq %r" % rec.get("seq", i),
                        records_verified=i,
                    )
                if rec.get("prev_hash") != expected_prev:
                    return AuditResult(
                        ok=False, broken_seq=rec.get("seq", i),
                        detail="broken prev_hash link at seq %r" % rec.get("seq", i),
                        records_verified=i,
                    )
                seq = rec.get("seq")
                if seq != i:
                    return AuditResult(
                        ok=False, broken_seq=rec.get("seq", i),
                        detail="sequence gap: line %d has seq %r" % (i, seq),
                        records_verified=i,
                    )
                expected_prev = stored
        return AuditResult(ok=True, records_verified=self._count_lines())


def audit(path: str) -> AuditResult:
    """Module-level convenience: audit the store at ``path``."""
    return Store(path).audit()
