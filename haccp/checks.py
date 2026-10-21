"""
:mod:`haccp.checks` -- sanitation / cleaning checklist templates + evaluation.

Provides built-in templates for the recurring checks a kitchen must run, and a
deterministic evaluator that, given a Checklist and a reference time, reports
completion and flags overdue items by their recurrence frequency.

An item stays current for frequency_hours after its last completion; overdue
once that window has elapsed (or never logged and required). A required item
that was never logged is always overdue.

API: Template, BUILTIN_TEMPLATES, make_checklist_from, is_overdue,
completed_in_window, CompletionReport, completion_ratio, evaluate, render.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import Checklist, ChecklistItem, parse_when


# --- built-in templates ---
@dataclass(frozen=True)
class Template:
    id: str
    group: str
    description: str
    frequency_hours: float = 4.0
    required: bool = True

    def make_item(self, done=False, done_by="", when=None, freq=None):
        f = self.frequency_hours if freq is None else freq
        return ChecklistItem(
            id=self.id,
            group=self.group,
            description=self.description,
            done=done,
            done_by=done_by,
            when=when,
            frequency=f,
            required=self.required,
        )


BUILTIN_TEMPLATES = [
    Template("fridge_temp", "cold_chain", "Refrigerator temperature check", 4.0),
    Template("freezer_temp", "cold_chain", "Freezer temperature check", 4.0),
    Template("cold_hold", "cold_chain", "Cold-hold food temperature check", 2.0),
    Template("hot_hold", "hot_holding", "Hot-hold food temperature check", 1.0),
    Template("sink_utensils", "sanitation", "Wash sink and utensils", 8.0),
    Template("waste_disposal", "sanitation", "Waste disposal / replace liner", 8.0),
    Template("handwash", "staff_hygiene", "Hand-wash station restock", 4.0),
]


def make_checklist_from(ids=None, when=None):
    """Build a Checklist from built-in template ids (all, if ids is None)."""
    if ids is None:
        ids = [t.id for t in BUILTIN_TEMPLATES]
    items = [t.make_item() for t in BUILTIN_TEMPLATES if t.id in ids]
    return Checklist(
        items=items,
        when=parse_when(when) if when else None,
        template_ids=tuple(ids),
    )


def _parse_or_none(value):
    """Parse a timestamp into a naive datetime, or None if empty/sentinel."""
    if not value:
        return None
    return parse_when(value)


def _as_naive(dt):
    """Normalise a tz-aware or naive datetime to naive (UTC-stripped)."""
    if dt is None:
        return None
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _now_or(dt):
    """Coerce `dt` (None -> now, str -> parsed) to a naive datetime."""
    if dt is None:
        return datetime.now(timezone.utc).replace(tzinfo=None)
    if isinstance(dt, str):
        dt = parse_when(dt)
    return _as_naive(dt)


def is_overdue(item, now=None):
    """Overdue when the frequency window has elapsed since the last completion.

    A required item that was never logged is always overdue; a non-required
    never-logged item is not.
    """
    now = _now_or(now)
    if not item.frequency:
        return False
    last = _parse_or_none(item.when)
    if last is None:
        return item.required or not item.done
    last = _as_naive(last)
    hours = (now - last).total_seconds() / 3600.0
    return hours > item.frequency


def completed_in_window(items, start, now=None):
    """Count done items whose completion timestamp falls within [start, now]."""
    now = _now_or(now)
    start = _as_naive(start)
    n = 0
    for it in items:
        if not it.done:
            continue
        last = _parse_or_none(it.when)
        if last is None:
            continue
        last = _as_naive(last)
        if start <= last <= now:
            n += 1
    return n


@dataclass(frozen=True)
class CompletionReport:
    total: int
    done: int
    overdue_items: tuple = ()
    by_group: dict = field(default_factory=dict)
    all_clear: bool = False


def completion_ratio(report):
    """Fraction of items done (1.0 for an empty checklist)."""
    return report.done / report.total if report.total else 1.0


def render(report):
    """Render a deterministic, human-readable completion summary string."""
    out = ["HACCP checklist completion"]
    pct = 100.0 * completion_ratio(report)
    out.append("  total items: " + str(report.total))
    out.append("  completed:      " + str(report.done))
    out.append("  completion:    " + str(int(pct)) + "%")
    out.append("  overdue:       " + str(len(report.overdue_items)))
    if report.by_group:
        out.append("  by group:")
        for grp in sorted(report.by_group):
            cell = report.by_group[grp]
            out.append(
                "          " + grp + ": " + str(cell["done"]) + "/"
                + str(cell["total"]) + " done"
            )
    if report.overdue_items:
        out.append("  overdue items:")
        for it in report.overdue_items:
            when = it.when or "(never logged)"
            out.append("          - " + it.id + " " + it.description[:40])
    else:
        out.append("  ALL CLEARED -- no overdue items.")
    return "\n".join(out)


def evaluate(checklist, now=None):
    """Completion per group plus overdue items flagged by frequency."""
    items = list(checklist.items)
    total = len(items)
    done = sum(1 for it in items if it.done)
    overdue = tuple(it for it in items if is_overdue(it, now=now))
    by_group = {}
    for it in items:
        cell = by_group.setdefault(it.group, {"done": 0, "total": 0})
        cell["total"] += 1
        if it.done and not is_overdue(it, now=now):
            cell["done"] += 1
    return CompletionReport(
        total=total,
        done=done,
        overdue_items=overdue,
        by_group=by_group,
        all_clear=(len(overdue) == 0),
    )
