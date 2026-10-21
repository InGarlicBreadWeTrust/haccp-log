"""Data models for HACCP food-safety logging.

Three core record types flow into the auditable store:

* :class:`Reading`       -- a cold-chain temperature observation.
* :class:`ChecklistItem` -- one sanitation / cleaning checklist task.
* :class:`Incident`      -- a food-safety incident with severity + action.

Every model validates on construction (``__post_init__``), so a malformed
reading can never be persisted: a non-numeric temperature, an unknown ``kind``
or a timestamp that is not ISO-8601 raise ``ValueError`` / ``TypeError`` before
a store ever touches it. Fields are coerced defensively (e.g. an int celsius
becomes a float, a string kind becomes the :class:`ReadingKind` enum member).
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from datetime import datetime

_Z = re.compile(r"Z$")


class ReadingKind(str, Enum):
    """Cold-chain station / holding type a temperature reading belongs to."""
    FRIDGE = "fridge"
    FREEZER = "freezer"
    AMBIENT = "ambient"
    HOT_HOLD = "hot_hold"
    COLD_HOLD = "cold_hold"
    AMBIENT_ROOM = "ambient_room"


class Severity(str, Enum):
    """Severity of a food-safety incident."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def parse_when(value: str) -> datetime:
    """Parse an ISO-8601 timestamp string, tolerating a trailing ``Z``.

    Returns the :class:`datetime` (aware when the string carries an offset).
    Raises :class:`ValueError` for empty / non-ISO input. Kept pure and
    stdlib-only so the whole engine stays testable offline.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    text = _Z.sub("+00:00", value.strip())
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(
            "%r is not a valid ISO-8601 timestamp" % value
        ) from exc


def _coerce_kind(kind) -> ReadingKind:
    if isinstance(kind, ReadingKind):
        return kind
    try:
        return ReadingKind(kind)
    except ValueError as exc:
        raise ValueError("unknown reading kind: %r" % (kind,)) from exc


def _coerce_celsius(celsius) -> float:
    if isinstance(celsius, bool) or not isinstance(celsius, (int, float)):
        raise TypeError("celsius must be a number, got: %r" % (type(celsius),))
    return float(celsius)


def _coerce_severity(severity) -> Severity:
    if isinstance(severity, Severity):
        return severity
    try:
        return Severity(severity)
    except ValueError as exc:
        raise ValueError("unknown severity: %r" % (severity,)) from exc


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Reading:
    """A single cold-chain temperature observation."""
    kind: ReadingKind
    celsius: float
    when: str
    operator: str
    note: str = ""

    def __post_init__(self):
        object.__setattr__(self, "kind", _coerce_kind(self.kind))
        object.__setattr__(self, "celsius", _coerce_celsius(self.celsius))
        parse_when(self.when)  # validate only; keep the original string
        if not isinstance(self.operator, str):
            raise TypeError("operator must be a string")
        if not isinstance(self.note, str):
            raise TypeError("note must be a string")

    def to_dict(self) -> dict:
        return {
            "type": "reading",
            "kind": self.kind.value,
            "celsius": self.celsius,
            "when": self.when,
            "operator": self.operator,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Reading":
        raw = d.get("payload", d)
        return cls(
            kind=raw.get("kind", "ambient"),
            celsius=raw.get("celsius", 0.0),
            when=raw.get("when", ""),
            operator=raw.get("operator", ""),
            note=raw.get("note", ""),
        )


# ---------------------------------------------------------------------------
# ChecklistItem
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ChecklistItem:
    """One sanitation / cleaning task inside a checklist group."""
    group: str
    description: str
    id: str = ""
    done_by: str = ""
    when: str = ""
    frequency: float = 4.0        # recurrence window in hours; 0.0 == no constraint
    done: bool = False
    required: bool = True

    def __post_init__(self):
        for name in ("group", "description", "id", "done_by", "when"):
            value = getattr(self, name)
            if not isinstance(value, str):
                object.__setattr__(self, name, str(value) if value else "")
        # frequency is measured in hours (a number); non-numeric / None -> 0.0.
        if isinstance(self.frequency, bool) or not isinstance(
                self.frequency, (int, float)):
            object.__setattr__(self, "frequency", 0.0)
        object.__setattr__(self, "frequency", float(self.frequency))
        object.__setattr__(self, "done", bool(self.done))
        object.__setattr__(self, "required", bool(self.required))

    def to_dict(self) -> dict:
        return {
            "type": "checklist",
            "id": self.id,
            "group": self.group,
            "description": self.description,
            "done_by": self.done_by,
            "when": self.when,
            "frequency": self.frequency,
            "done": self.done,
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ChecklistItem":
        raw = d.get("payload", d)
        return cls(
            group=raw.get("group", ""),
            description=raw.get("description", ""),
            id=raw.get("id", ""),
            done_by=raw.get("done_by", ""),
            when=raw.get("when", ""),
            frequency=raw.get("frequency", 4.0),
            done=bool(raw.get("done", False)),
            required=bool(raw.get("required", True)),
        )


# ---------------------------------------------------------------------------
# Checklist -- an in-memory grouping of ChecklistItems for one shift/session
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Checklist:
    """A named group of checklist items evaluated together at one shift.

    ``items`` holds the :class:`ChecklistItem` members; ``when`` is the shift
    timestamp (ISO-8601 string, may be empty); ``template_ids`` records which
    built-in templates seeded this checklist (empty for ad-hoc lists).
    """
    label: str = "checklist"
    items: tuple = ()
    when: str = ""
    template_ids: tuple = ()

    def __post_init__(self):
        object.__setattr__(self, "label",
            str(self.label) if self.label else "checklist")
        object.__setattr__(self, "when", str(self.when) if self.when else "")
        object.__setattr__(self, "items", tuple(self.items))
        object.__setattr__(self, "template_ids", tuple(self.template_ids))

    @property
    def done_count(self) -> int:
        return sum(1 for it in self.items if it.done)


# ---------------------------------------------------------------------------
# Incident
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Incident:
    """A food-safety incident: what happened, when, how severe, what was done."""
    description: str
    when: str
    severity: Severity = Severity.MEDIUM
    action_taken: str = ""
    operator: str = ""

    def __post_init__(self):
        object.__setattr__(self, "severity", _coerce_severity(self.severity))
        parse_when(self.when)
        if not isinstance(self.description, str):
            raise TypeError("description must be a string")
        if not isinstance(self.action_taken, str):
            raise TypeError("action_taken must be a string")
        if not isinstance(self.operator, str):
            raise TypeError("operator must be a string")

    def to_dict(self) -> dict:
        return {
            "type": "incident",
            "description": self.description,
            "when": self.when,
            "severity": self.severity.value,
            "action_taken": self.action_taken,
            "operator": self.operator,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Incident":
        raw = d.get("payload", d)
        return cls(
            description=raw.get("description", ""),
            when=raw.get("when", ""),
            severity=raw.get("severity", "medium"),
            action_taken=raw.get("action_taken", ""),
            operator=raw.get("operator", ""),
        )


# Discriminator -> (factory class, human label).
RECORD_TYPES = {
    "reading": Reading,
    "checklist": ChecklistItem,
    "incident": Incident,
}


def make_record(obj):
    """Normalise a model to its ``to_dict`` payload dict, or pass through a dict."""
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if isinstance(obj, dict):
        return dict(obj)
    raise TypeError("cannot serialise %r to a record" % (type(obj),))
