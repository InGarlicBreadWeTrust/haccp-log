# haccp-log

Local-first, **stdlib-only** HACCP food-safety logging and audit for kitchens.
Zero runtime dependencies, no network — every byte of the audit trail is
deterministic and tamper-evident.

## What it does

`haccp-log` captures the three record types that flow through a HACCP program and
produces the reports a shift lead needs:

* **Cold-chain readings** — temperature observations by station
  (`fridge`, `freezer`, `hot_hold`, `cold_hold`, `ambient`, …).
* **Time-temperature abuse (TTA) detection** — a *contiguous excursion* is a
  maximal run of back-to-back readings sitting inside the 5–60 °C bacterial
  danger zone; it is **flagged** when the dwell time *strictly exceeds* the
  2-hour cold-hold limit (7200 s). Exactly 7200 s is **not** flagged.
* **Sanitation checklists** — built-in templates (fridge temp, hand-wash, cold
  chain, cleaning) evaluated per shift, with overdue detection by recurrence
  window.
* **Incidents** — food-safety events with severity and corrective action.
* **Tamper-evident storage** — an append-only JSONL store where every record
  embeds the SHA-256 hash of the previous record (`prev_hash`) and its own
  `hash`. Change any byte of any line and the chain breaks from that link on.

## Why stdlib-only

A kitchen audit trail must survive a bad Wi-Fi day and must never phone home.
`haccp-log` uses only `dataclasses`, `enum`, `datetime`, `hashlib` and `json` —
nothing to install for production, nothing to leak.

## Layout

```
haccp/
    __init__.py    public surface (re-exports)
    models.py      Reading / Checklist / ChecklistItem / Incident + parse_when
    tt_abuse.py    danger-zone classification & TTA excursion detection
    checks.py      checklist templates, evaluation and overdue detection
    reports.py     deterministic CSV / text report writers
    tests/         23 unit tests (pytest)
```

## Install & use

```bash
pip install .            # or: pip install -e .
pytest -q               # run the suite
```

```python
from haccp import Reading, detect_excursions, shift_report

readings = [
    Reading(kind="cold_hold", celsius=10.0, when="2026-01-01T00:00:00", operator="op"),
    Reading(kind="cold_hold", celsius=12.0, when="2026-01-01T03:00:00", operator="op"),
]
report = detect_excursions(readings, item="fridge-1")
print(report.excursions[0].seconds, report.excursions[0].flagged)  # 10800.0 True
```

Write the audit trail to a tamper-evident store:

```python
from haccp import Store, Incident

store = Store("chain.jsonl")
store.write_entry(Reading(kind="fridge", celsius=4.0,
                          when="2026-01-01T00:00:00", operator="op"))
store.write_entry(Incident(description="cold chain breach",
                           when="2026-01-01T01:00:00",
                           severity="high", action_taken="discarded"))
print(store.audit())       # AuditResult(ok=True, records_verified=2, ...)
```

## License

MIT — see [LICENSE](LICENSE).
