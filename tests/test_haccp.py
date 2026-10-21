"""End-to-end tests for the haccp engine.

Pure stdlib, no network, deterministic. Covers:
   * danger-zone classification (strict 5..60C bounds)
   * time-temperature-abuse excursion detection (strict > 7200s flagged)
   * model validation (malformed records rejected on construction)
   * parse_when: ISO-8601 + trailing-Z tolerance
   * SHA-256 hash-chain tamper-evidence (Store + audit)
   * checklist evaluation / overdue detection
   * deterministic report writers
"""
from __future__ import annotations

import json

import haccp
from haccp import (
    Reading,
    ReadingKind,
    Checklist,
    ChecklistItem,
    Incident,
    Severity,
    parse_when,
    in_danger_zone,
    status_for,
    detect_excursions,
    COLDHOLD_LIMIT_SECONDS,
    Store,
    audit,
    record_hash,
    GENESIS,
    make_checklist_from,
    evaluate,
    is_overdue,
    readings_csv,
    tta_csv,
    tta_text,
    shift_report,
    all_report,
)


# --- danger zone (strict 5..60C per module design) ---
def test_danger_zone_bounds_strict():
    assert in_danger_zone(4.0) is False
    assert in_danger_zone(5.0) is False
    assert in_danger_zone(10.0) is True
    assert in_danger_zone(25.0) is True
    assert in_danger_zone(60.0) is False
    assert in_danger_zone(60.1) is False


def test_status_for_single_reading():
    r = Reading(kind="cold_hold", celsius=10.0,
                when="2026-01-01T00:00:00", operator="op")
    assert status_for(r) == "in_danger"
    cold = Reading(kind="fridge", celsius=2.0,
                   when="2026-01-01T00:00:00", operator="op")
    assert status_for(cold) == "ok"


# --- TTA excursion detection ---
def test_excursion_over_two_hours_is_flagged():
    r1 = Reading(kind="cold_hold", celsius=10.0,
                 when="2026-01-01T00:00:00", operator="op")
    r2 = Reading(kind="cold_hold", celsius=12.0,
                 when="2026-01-01T03:00:00", operator="op")
    rep = detect_excursions([r1, r2], item="fridge-1")
    assert len(rep.excursions) == 1
    exc = rep.excursions[0]
    assert exc.seconds == 10800.0
    assert exc.flagged is True
    assert rep.has_flags is True
    assert len(rep.flagged) == 1


def test_excursion_exactly_two_hours_not_flagged():
    r1 = Reading(kind="cold_hold", celsius=10.0,
                 when="2026-01-01T00:00:00", operator="op")
    r2 = Reading(kind="cold_hold", celsius=11.0,
                 when="2026-01-01T02:00:00", operator="op")
    rep = detect_excursions([r1, r2], item="fridge-1")
    assert len(rep.excursions) == 1
    assert rep.excursions[0].seconds == 7200.0
    assert rep.excursions[0].flagged is False
    assert rep.has_flags is False
    assert rep.flagged == []


def test_danger_breaks_run_into_separate_excursions():
    r1 = Reading(kind="cold_hold", celsius=10.0,
                 when="2026-01-01T00:00:00", operator="op")
    r2 = Reading(kind="fridge", celsius=3.0,
                 when="2026-01-01T01:00:00", operator="op")
    r3 = Reading(kind="cold_hold", celsius=11.0,
                 when="2026-01-01T02:00:00", operator="op")
    rep = detect_excursions([r1, r2, r3], item="x")
    assert len(rep.excursions) == 2


def test_no_danger_no_excursion():
    r1 = Reading(kind="fridge", celsius=2.0,
                 when="2026-01-01T00:00:00", operator="op")
    r2 = Reading(kind="fridge", celsius=3.0,
                 when="2026-01-01T05:00:00", operator="op")
    rep = detect_excursions([r1, r2], item="fridge-2")
    assert rep.excursions == ()
    assert rep.has_flags is False


# --- model validation ---
def test_bad_celsius_rejected():
    try:
        Reading(kind="fridge", celsius="hot",
                when="2026-01-01T00:00:00", operator="op")
        assert False, "should have raised"
    except (TypeError, ValueError):
        pass


def test_bad_kind_rejected():
    try:
        Reading(kind="kitchen_sink", celsius=10.0,
                when="2026-01-01T00:00:00", operator="op")
        assert False, "should have raised"
    except ValueError:
        pass


def test_bad_timestamp_rejected():
    try:
        Reading(kind="fridge", celsius=10.0, when="not-a-date",
                operator="op")
        assert False, "should have raised"
    except ValueError:
        pass


def test_celsius_coerced_to_float():
    r = Reading(kind="fridge", celsius=10,
                when="2026-01-01T00:00:00", operator="op")
    assert r.celsius == 10.0
    assert isinstance(r.celsius, float)


# --- parse_when ---
def test_parse_when_tolerates_trailing_z():
    dt = parse_when("2026-03-15T12:30:00Z")
    assert dt.year == 2026
    assert dt.month == 3
    assert dt.day == 15
    assert dt.hour == 12
    assert dt.minute == 30


def test_parse_when_rejects_garbage():
    try:
        parse_when("nope")
        assert False, "should have raised"
    except ValueError:
        pass


# --- SHA-256 hash-chain tamper-evidence ---
def test_store_audit_ok(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    s = Store(path)
    s.write_entry(Reading(kind="fridge", celsius=4.0,
                          when="2026-01-01T00:00:00", operator="op"))
    s.write_entry(Incident(description="cold chain breach",
                           when="2026-01-01T01:00:00",
                           severity=Severity.HIGH,
                           action_taken="discarded"))
    res = s.audit()
    assert res.ok is True
    assert res.records_verified == 2
    assert bool(res) is True


def test_tamper_breaks_chain(tmp_path):
    path = str(tmp_path / "chain.jsonl")
    s = Store(path)
    s.write_entry(Reading(kind="fridge", celsius=4.0,
                          when="2026-01-01T00:00:00", operator="op"))
    s.write_entry(Reading(kind="fridge", celsius=5.0,
                          when="2026-01-01T01:00:00", operator="op"))
    with open(path, "r", encoding="utf-8") as fh:
        lines = [ln for ln in fh if ln.strip()]
    rec = json.loads(lines[0])
    rec["payload"]["celsius"] = 99.0
    lines[0] = json.dumps(rec, ensure_ascii=False)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    res = audit(path)
    assert res.ok is False
    assert res.broken_seq == 0


def test_genesis_and_hash_are_64_hex():
    assert len(GENESIS) == 64 and GENESIS == "0" * 64
    h = record_hash({"seq": 0, "prev_hash": GENESIS})
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


# --- checklist evaluation ---
def test_make_checklist_from_builtin():
    chk = make_checklist_from()
    assert len(chk.items) >= 1
    rep = evaluate(chk, now="2026-01-01T00:00:00")
    assert rep.total == len(chk.items)


def test_is_overdue_required_never_logged():
    it = ChecklistItem(group="sanitation", description="wash sink",
                       id="sink", frequency=8.0,
                       done=False, required=True)
    assert is_overdue(it, now="2026-01-01T10:00:00") is True


def test_is_overdue_within_window():
    it = ChecklistItem(group="sanitation", description="wash sink",
                       id="sink", frequency=8.0,
                       done=True, when="2026-01-01T08:00:00",
                       required=True)
    assert is_overdue(it, now="2026-01-01T10:00:00") is False


def test_is_overdue_past_window():
    it = ChecklistItem(group="sanitation", description="wash sink",
                       id="sink", frequency=4.0,
                       done=True, when="2026-01-01T00:00:00",
                       required=True)
    assert is_overdue(it, now="2026-01-01T05:00:00") is True


# --- report writers are deterministic ---
def test_readings_csv_deterministic():
    rs = [
        Reading(kind="fridge", celsius=4.0,
                when="2026-01-01T00:00:00", operator="op"),
        Reading(kind="fridge", celsius=5.0,
                when="2026-01-01T01:00:00", operator="op"),
    ]
    a = readings_csv(rs)
    b = readings_csv(rs)
    assert a == b
    assert "celsius" in a
    assert "operator" in a


def test_tta_csv_and_text_nonempty():
    rep = detect_excursions([
        Reading(kind="cold_hold", celsius=10.0,
                when="2026-01-01T00:00:00", operator="op"),
        Reading(kind="cold_hold", celsius=12.0,
                when="2026-01-01T03:00:00", operator="op"),
    ], item="fridge-1")
    assert "excursions detected" in tta_text(rep)
    assert "item" in tta_csv(rep)


def test_shift_report_counts():
    chk = make_checklist_from(["fridge_temp"], when="2026-01-01T00:00:00")
    out = shift_report(
        readings=[],
        checklists=[chk],
        incidents=[Incident(
            description="spoiled", when="2026-01-01T00:00:00",
            severity=Severity.MEDIUM)],
    )
    assert "checklists run:" in out
    assert "incidents:" in out


def test_all_report_combines():
    out = all_report(
        readings=[
            Reading(kind="cold_hold", celsius=10.0,
                    when="2026-01-01T00:00:00", operator="op"),
            Reading(kind="cold_hold", celsius=12.0,
                    when="2026-01-01T03:00:00", operator="op")],
        checklists=[],
        incidents=[])
    assert "Time-Temperature Abuse report" in out
    assert "HACCP shift summary" in out
