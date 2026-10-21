"""haccp -- lightweight, stdlib-only HACCP logging & audit for kitchens.

Pure standard library, no third-party dependencies, all outputs deterministic.

Public surface (re-exported for convenience; the submodules remain the source
of truth):

    core models   : Reading, Checklist, Incident + ReadingKind / Severity
                    parse_when, RECORD_TYPES, make_record
    cold chain    : detect_excursions, in_danger_zone, status_for
                    TTAReport, ReadingStatus, Excursion
                    DANGER_LOW, DANGER_HIGH, COLDHOLD_LIMIT_SECONDS
    checklists    : Template, BUILTIN_TEMPLATES, make_checklist_from
                    is_overdue, completed_in_window
                    CompletionReport, completion_ratio, evaluate, render
    reporting     : readings_csv, tta_csv (write_* variants),
                    tta_text, shift_report, all_report
    storage       : Store, AuditResult, audit, record_hash, GENESIS
                    (SHA-256 hash chain, tamper-evident)
"""
from __future__ import annotations

from . import checks, models, reports, storage, tt_abuse

# --- core models ---
from .models import (
    RECORD_TYPES,
    Severity,
    Reading,
    ReadingKind,
    Checklist,
    ChecklistItem,
    Incident,
    make_record,
    parse_when,
)

# --- time-temperature abuse detection ---
from .tt_abuse import (
    COLDHOLD_LIMIT_SECONDS,
    DANGER_HIGH,
    DANGER_LOW,
    Excursion,
    TTAReport,
    ReadingStatus,
    detect_excursions,
    in_danger_zone,
    status_for,
)

# --- sanitation / cleaning checklists ---
from .checks import (
    BUILTIN_TEMPLATES,
    Template,
    make_checklist_from,
    is_overdue,
    completed_in_window,
    CompletionReport,
    completion_ratio,
    evaluate,
    render,
)

# --- report writers ---
from .reports import (
    all_report,
    readings_csv,
    shift_report,
    tta_csv,
    tta_text,
    write_readings_csv,
    write_tta_csv,
)

# --- tamper-evident storage ---
from .storage import (
    GENESIS,
    AuditResult,
    Store,
    record_hash,
    audit,
)

__all__ = [
    # submodules
    "checks", "models", "reports", "storage", "tt_abuse",
    # core models
    "Reading", "Checklist", "ChecklistItem", "Incident",
    "ReadingKind", "Severity",
    "parse_when", "RECORD_TYPES", "make_record",
     # cold chain
    "DANGER_LOW", "DANGER_HIGH", "COLDHOLD_LIMIT_SECONDS",
    "ReadingStatus", "Excursion", "TTAReport",
    "detect_excursions", "in_danger_zone", "status_for",
     # checklists
    "Template", "BUILTIN_TEMPLATES", "make_checklist_from",
    "is_overdue", "completed_in_window",
    "CompletionReport", "completion_ratio", "evaluate", "render",
     # reporting
    "readings_csv", "write_readings_csv",
    "tta_csv", "write_tta_csv",
    "tta_text", "shift_report", "all_report",
     # storage
    "GENESIS", "Store", "AuditResult", "record_hash", "audit",
]
