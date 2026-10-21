""":mod:`haccp.tt_abuse` -- time-temperature abuse (TTA) detection.

The HACCP danger zone is 5..60 C. Cold-hold food must not stay in that band for
more than two hours (7200 s). A *contiguous excursion* is a maximal run of
back-to-back readings for one cold-chain item that all sit in the danger zone;
its dwell time is the span from the run's first to its last reading. An
excursion is **flagged** when that span *exceeds* 7200 s (strict ``>``, so
exactly 7200 s passes).

Deterministic: readings are sorted by time first. Open boundaries -- the true
start before the first reading and the true end after the last -- contribute
nothing extra; only the available span is counted.

Constants: DANGER_LOW, DANGER_HIGH, COLDHOLD_LIMIT_SECONDS.
Public API: in_danger_zone, status_for, ReadingStatus, Excursion, TTAReport,
detect_excursions.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Reading, parse_when

DANGER_LOW = 5.0
DANGER_HIGH = 60.0
COLDHOLD_LIMIT_SECONDS = 7200


# True when a temperature sits strictly inside the 5..60 C danger zone.
def in_danger_zone(celsius):
    return DANGER_LOW < float(celsius) < DANGER_HIGH


# Return 'in_danger' or 'ok' for a single reading's temperature.
def status_for(reading):
    return "in_danger" if in_danger_zone(reading.celsius) else "ok"


# Per-reading temperature assessment inside a TTAReport.
@dataclass(frozen=True)
class ReadingStatus:
    when: str
    kind: str
    celsius: float
    status: str      # ok | in_danger | exceeded


# A contiguous block of time in the danger zone for one item.
@dataclass(frozen=True)
class Excursion:
    item: str
    start_time: str
    end_time: str
    seconds: float
    max_celsius: float
    flagged: bool


# Per-reading statuses plus the excursions found across the series.
@dataclass(frozen=True)
class TTAReport:
    statuses: tuple
    excursions: tuple

    @property
    def has_flags(self):
        return any(e.flagged for e in self.excursions)

    @property
    def flagged(self):
        return [e for e in self.excursions if e.flagged]


# Detect TTA over an ordered list of readings for one cold-chain item.
#
# Readings are sorted by time first (stable on ties). A maximal contiguous run
# of in-danger readings forms one excursion; its dwell is the span from the run's
# first reading to its last. Flag when the span strictly exceeds
# `seconds_threshold`, so exactly 7200 s is NOT flagged. Open boundaries add no
# span -- only the available span is counted.
def detect_excursions(readings, item="",
                      seconds_threshold=COLDHOLD_LIMIT_SECONDS):
    order = sorted(range(len(readings)),
                   key=lambda i: (parse_when(readings[i].when), i))
    ordered = [readings[i] for i in order]
    dts = [parse_when(r.when) for r in ordered]

    statuses_flag = [False] * len(ordered)
    runs = []
    start_idx = None
    for i, r in enumerate(ordered):
        if status_for(r) == "in_danger":
            if start_idx is None:
                start_idx = i
        elif start_idx is not None:
            runs.append((start_idx, i - 1))
            start_idx = None
    if start_idx is not None:
        runs.append((start_idx, len(ordered) - 1))

    excursions = []
    for a, b in runs:
        seconds = (dts[b] - dts[a]).total_seconds()
        max_c = max(r.celsius for r in ordered[a:b + 1])
        flagged = seconds > seconds_threshold
        excursions.append(Excursion(
            item=item,
            start_time=dts[a].isoformat(),
            end_time=dts[b].isoformat(),
            seconds=seconds,
            max_celsius=max_c,
            flagged=flagged,
        ))
        if flagged:
            for j in range(a, b + 1):
                statuses_flag[j] = True

    statuses = []
    for i, r in enumerate(ordered):
        base = "in_danger" if status_for(r) == "in_danger" else "ok"
        if statuses_flag[i]:
            base = "exceeded"
        statuses.append(ReadingStatus(
            when=r.when,
            kind=r.kind.value,
            celsius=r.celsius,
            status=base,
        ))

    return TTAReport(statuses=tuple(statuses), excursions=tuple(excursions))
