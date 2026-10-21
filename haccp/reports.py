"""
:mod:`haccp.reports` -- deterministic, stdlib-only report writers.

Pure string outputs (no HTML/PDF): CSV exports of readings and of
time-temperature-abuse excursions, plus a shift/summary report giving counts
and per-checklist pass/fail. Everything is deterministic for a given input.

Output paths are written only by the explicit writer functions (a user-supplied
--csv target is a write destination, never a path that is read or trusted).

API: readings_csv, write_readings_csv, tta_csv, write_tta_csv, tta_text,
shift_report, all_report. Output uses csv + io only, plus package modules.
"""
from __future__ import annotations

import csv
import io

from .models import Checklist, Incident, Reading
from .tt_abuse import TTAReport, detect_excursions
from .checks import evaluate


# --- CSV writers ---

def readings_csv(readings) -> str:
    """Serialise readings to CSV (header + one row each, sorted by time)."""
    rows = sorted(readings, key=lambda r: (r.when or ""))
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["when", "kind", "celsius", "operator", "note"])
    for r in rows:
        row = [
            r.when or "",
            r.kind.value,
            r.celsius,
            r.operator or "",
            r.note or "",
        ]
        writer.writerow(row)
    return buf.getvalue()


def write_readings_csv(readings, path):
    """Write a readings CSV to `path` (explicit output target)."""
    with open(path, "w", newline="") as fh:
        fh.write(readings_csv(readings))
    return path


def tta_csv(report: TTAReport) -> str:
    """Serialise excursions to CSV (header + one row each)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["item", "start_time", "end_time", "seconds",
                      "max_celsius", "flagged"])
    for e in report.excursions:
        writer.writerow([
            e.item, e.start_time, e.end_time,
            e.seconds, e.max_celsius, e.flagged,
        ])
    return buf.getvalue()


def write_tta_csv(report: TTAReport, path):
    """Write a TTA CSV to `path` (explicit output target)."""
    with open(path, "w", newline="") as fh:
        fh.write(tta_csv(report))
    return path


# --- text reporters ---

def tta_text(report: TTAReport) -> str:
    """Human-readable TTA report listing per-reading status and excursions."""
    lines = []
    lines.append("Time-Temperature Abuse report")
    lines.append("  excursions detected: %d" % len(report.excursions))
    lines.append("  flagged (>2h in danger zone 5..60C): %d" % len(report.flagged))
    if not report.excursions:
        lines.append("  No excursions -- all readings within their safe ranges.")
    lines.append("")
    lines.append("  per-reading status:")
    for s in report.statuses:
        if s.status == "exceeded":
            tag = "EXCEEDED"
        elif s.status == "in_danger":
            tag = "IN_DANGER"
        else:
            tag = "ok"
        lines.append("       %s  %s  %sC  %s" % (
            s.when, s.kind, s.celsius, tag))
    lines.append("")
    lines.append("  excursions:")
    if not report.excursions:
        lines.append("       (none)")
    for e in report.excursions:
        lines.append("       [%s] %s .. %s  %ds  max %sC  flagged=%s" % (
            e.item, e.start_time, e.end_time,
            e.seconds, e.max_celsius, e.flagged))
    return "\n".join(lines)


def _severity_counts(incidents):
    """Count incidents by severity, deterministically sorted by name."""
    counts = {}
    for inc in incidents:
        key = inc.severity.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def shift_report(readings=None, checklists=None, incidents=None,
                 tta=None, now=None) -> str:
    """Shift/summary: counts, per-checklist pass/fail, TTA flags."""
    readings = readings or []
    checklists = list(checklists or [])
    incidents = incidents or []
    checklists.sort(key=lambda c: (c.when or ""))
    lines = []
    lines.append("=== HACCP shift summary ===")
    lines.append("readings logged:  %d" % len(readings))
    lines.append("checklists run:   %d" % len(checklists))
    lines.append("incidents:         %d" % len(incidents))
    sev = _severity_counts(incidents)
    if sev:
        pairs = ", ".join("%s=%d" % (k, v) for k, v in sorted(sev.items()))
        lines.append("incident severity: %s" % pairs)
    lines.append("")
    lines.append("checklist status (pass = all items done):")
    if not checklists:
        lines.append("       (none)")
    for chk in checklists:
        done = sum(1 for it in chk.items if it.done)
        total = len(chk.items)
        status = "PASS" if (total and done == total) else "FAIL"
        note = "" if total else " (no items)"
        lines.append("       [%s] %s  %d/%d done%s" % (
            status, chk.label, done, total, note))
    if tta is not None:
        lines.append("")
        lines.append("time-temperature abuse: %d excursions, %d flagged" % (
            len(tta.excursions), len(tta.flagged)))
    return "\n".join(lines)


def all_report(readings=None, checklists=None, incidents=None,
               item="item", now=None) -> str:
    """Combined TTA + shift report (concatenated with a blank line)."""
    readings = readings or []
    tta = detect_excursions(readings, item=item)
    part1 = tta_text(tta)
    part2 = shift_report(
        readings=readings, checklists=checklists,
        incidents=incidents, tta=tta, now=now)
    return part1 + "\n\n" + part2
