"""
Ghost Data Still Exists — Deletion Audit Agent
Entry point: python code/main.py

All file paths are resolved relative to the repository root (the directory
containing AGENTS.md), regardless of where this script is called from.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Late-imported helpers for the end-to-end pipeline (optional at import time)
try:
    from evidence_parser import load_evidence_corpus, EvidenceCorpus
    from state_reconstruction import reconstruct_case_state, AuditStep
except Exception:  # pragma: no cover - keep module importable in minimal envs
    load_evidence_corpus = None  # type: ignore
    EvidenceCorpus = None  # type: ignore
    reconstruct_case_state = None  # type: ignore
    AuditStep = None  # type: ignore

# Reconfigure stdout/stderr to UTF-8 so Japanese/accents print cleanly on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Repository root resolution
# ---------------------------------------------------------------------------

def _find_repo_root() -> Path:
    """Locate the directory holding dataset/ (accepts AGENTS.md when present)."""
    here = Path(__file__).resolve().parent
    candidate = here
    for _ in range(10):
        if (candidate / "AGENTS.md").exists():
            return candidate
        if (candidate / "dataset" / "deletion_requests.csv").exists():
            return candidate
        candidate = candidate.parent
    return here.parent


REPO_ROOT = _find_repo_root()
DATASET_DIR = REPO_ROOT / "dataset"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DeletionRequest:
    case_id: str
    email: str
    requested_at: datetime
    reported_status: str
    reported_at: datetime
    audit_at: datetime
    request_text: str


@dataclass
class UserIdentity:
    user_id: str
    name: str
    current_email: str
    phone: str
    email_hash: str
    updated_at: datetime


@dataclass
class IdentityFingerprint:
    """All known identifiers for a single user, collected from current snapshot
    and audit history. Used for evidence matching."""
    user_id: str
    name: str
    current_email: str
    phone: str
    current_email_hash: str
    # Historical values (email_hash changes in lock-step with email)
    old_emails: list[str] = field(default_factory=list)
    old_email_hashes: list[str] = field(default_factory=list)
    old_phones: list[str] = field(default_factory=list)

    @property
    def all_emails(self) -> list[str]:
        """All emails, current first, then historical."""
        return [self.current_email] + self.old_emails

    @property
    def all_emails_lower(self) -> set[str]:
        return {e.lower() for e in self.all_emails}

    @property
    def all_identifiers(self) -> set[str]:
        """Union of all identifiers, case-preserved, for broad matching."""
        ids: set[str] = set()
        ids.add(self.user_id)
        ids.update(self.all_emails)
        ids.update(self.old_email_hashes)
        ids.add(self.current_email_hash)
        ids.add(self.phone)
        ids.update(self.old_phones)
        # Also add uppercase variants (evidence uses mixed case)
        return ids | {i.upper() for i in ids}


@dataclass
class IdentityResolutionResult:
    """Outcome of resolve_identity()."""
    status: str  # 'found' | 'not_found' | 'ambiguous'
    fingerprint: Optional[IdentityFingerprint] = None
    match_type: str = ""   # 'current_email' | 'historical_email'
    matched_email: str = ""
    message: str = ""
    candidates: list[str] = field(default_factory=list)  # for 'ambiguous'


@dataclass
class EvidenceFile:
    file_id: str
    file_path: Path   # absolute path
    origin: str
    captured_at: datetime


@dataclass
class Datasets:
    deletion_requests: list[DeletionRequest]
    sample_requests: list[DeletionRequest]
    identities: dict[str, UserIdentity]           # user_id -> UserIdentity
    email_to_user_id: dict[str, str]              # lowercase email -> user_id
    audit_log: list[dict]                          # raw rows
    historical_emails: dict[str, list[str]]       # user_id -> [old_email, ...]
    historical_email_hashes: dict[str, list[str]] # user_id -> [old_hash, ...]
    historical_phones: dict[str, list[str]]        # user_id -> [old_phone, ...]
    system_activity: list[dict]
    deletion_rules: list[dict]
    evidence_files: list[EvidenceFile]


# ---------------------------------------------------------------------------
# Module 1: Dataset loading & validation
# ---------------------------------------------------------------------------

def _parse_iso(ts: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp (ending in Z or +00:00) to datetime."""
    ts = ts.strip()
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def _read_csv(path: Path) -> list[dict]:
    """Read a CSV file and return a list of row dicts. Uses the stdlib csv
    module so there is no pandas dependency for core logic."""
    with open(path, encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        return [row for row in reader]


def load_datasets(dataset_dir: Path = DATASET_DIR) -> Datasets:
    """Load and validate all participant-facing CSV files.

    Raises ValueError with a descriptive message if a validation check fails.
    """
    # --- deletion_requests.csv ---
    dr_rows = _read_csv(dataset_dir / "deletion_requests.csv")
    _validate_columns(
        dr_rows,
        {"case_id", "email", "requested_at", "reported_status", "reported_at",
         "audit_at", "request_text"},
        "deletion_requests.csv",
    )
    if len(dr_rows) != 518:
        raise ValueError(
            f"deletion_requests.csv: expected 518 rows, got {len(dr_rows)}"
        )
    deletion_requests = [_parse_deletion_request(r) for r in dr_rows]
    _check_unique_ids([r.case_id for r in deletion_requests], "deletion_requests.csv case_id")

    # --- sample_deletion_requests.csv ---
    sdr_rows = _read_csv(dataset_dir / "sample_deletion_requests.csv")
    _validate_columns(
        sdr_rows,
        {"case_id", "email", "requested_at", "reported_status", "reported_at",
         "audit_at", "request_text"},
        "sample_deletion_requests.csv",
    )
    if len(sdr_rows) != 32:
        raise ValueError(
            f"sample_deletion_requests.csv: expected 32 rows, got {len(sdr_rows)}"
        )
    sample_requests = [_parse_deletion_request(r) for r in sdr_rows]

    # --- user_identities.csv ---
    id_rows = _read_csv(dataset_dir / "user_identities.csv")
    _validate_columns(
        id_rows,
        {"user_id", "name", "email", "phone", "email_hash", "updated_at"},
        "user_identities.csv",
    )
    identities: dict[str, UserIdentity] = {}
    email_to_user_id: dict[str, str] = {}
    for row in id_rows:
        uid = row["user_id"].strip()
        email = row["email"].strip()
        identity = UserIdentity(
            user_id=uid,
            name=row["name"].strip(),
            current_email=email,
            phone=row["phone"].strip(),
            email_hash=row["email_hash"].strip(),
            updated_at=_parse_iso(row["updated_at"]),
        )
        identities[uid] = identity
        email_lower = email.lower()
        if email_lower in email_to_user_id:
            raise ValueError(
                f"user_identities.csv: duplicate email (case-insensitive): {email}"
            )
        email_to_user_id[email_lower] = uid

    # --- user_audit_log.csv ---
    audit_rows = _read_csv(dataset_dir / "user_audit_log.csv")
    _validate_columns(
        audit_rows,
        {"audit_id", "user_id", "event_time", "field_name", "old_value", "new_value"},
        "user_audit_log.csv",
    )
    historical_emails: dict[str, list[str]] = {}
    historical_email_hashes: dict[str, list[str]] = {}
    historical_phones: dict[str, list[str]] = {}
    for row in audit_rows:
        uid = row["user_id"].strip()
        field_name = row["field_name"].strip()
        old_val = row["old_value"].strip()
        if field_name == "email":
            historical_emails.setdefault(uid, []).append(old_val)
        elif field_name == "email_hash":
            historical_email_hashes.setdefault(uid, []).append(old_val)
        elif field_name == "phone":
            historical_phones.setdefault(uid, []).append(old_val)

    # --- system_activity.csv ---
    activity_rows = _read_csv(dataset_dir / "system_activity.csv")
    _validate_columns(
        activity_rows,
        {"activity_id", "event_time", "event_type", "source_system",
         "target_system", "resource_id", "reported_result", "details"},
        "system_activity.csv",
    )

    # --- deletion_rules.csv ---
    rules_rows = _read_csv(dataset_dir / "deletion_rules.csv")
    _validate_columns(
        rules_rows,
        {"rule_id", "data_category", "condition", "required_action"},
        "deletion_rules.csv",
    )
    if len(rules_rows) != 15:
        raise ValueError(
            f"deletion_rules.csv: expected 15 rules, got {len(rules_rows)}"
        )

    # --- evidence_files.csv ---
    ev_rows = _read_csv(dataset_dir / "evidence_files.csv")
    _validate_columns(
        ev_rows,
        {"file_id", "file_path", "origin", "captured_at"},
        "evidence_files.csv",
    )
    evidence_files: list[EvidenceFile] = []
    for row in ev_rows:
        file_id = row["file_id"].strip()
        rel_path = row["file_path"].strip()
        abs_path = dataset_dir / rel_path
        evidence_files.append(EvidenceFile(
            file_id=file_id,
            file_path=abs_path,
            origin=row["origin"].strip(),
            captured_at=_parse_iso(row["captured_at"]),
        ))

    return Datasets(
        deletion_requests=deletion_requests,
        sample_requests=sample_requests,
        identities=identities,
        email_to_user_id=email_to_user_id,
        audit_log=audit_rows,
        historical_emails=historical_emails,
        historical_email_hashes=historical_email_hashes,
        historical_phones=historical_phones,
        system_activity=activity_rows,
        deletion_rules=rules_rows,
        evidence_files=evidence_files,
    )


def _parse_deletion_request(row: dict) -> DeletionRequest:
    return DeletionRequest(
        case_id=row["case_id"].strip(),
        email=row["email"].strip(),
        requested_at=_parse_iso(row["requested_at"]),
        reported_status=row["reported_status"].strip(),
        reported_at=_parse_iso(row["reported_at"]),
        audit_at=_parse_iso(row["audit_at"]),
        request_text=row["request_text"].strip(),
    )


def _validate_columns(rows: list[dict], required: set[str], name: str) -> None:
    if not rows:
        raise ValueError(f"{name}: file is empty (no data rows)")
    actual = set(rows[0].keys())
    missing = required - actual
    if missing:
        raise ValueError(f"{name}: missing columns: {missing}")


def _check_unique_ids(ids: list[str], label: str) -> None:
    seen: set[str] = set()
    for id_ in ids:
        if id_ in seen:
            raise ValueError(f"Duplicate {label}: {id_!r}")
        seen.add(id_)


# ---------------------------------------------------------------------------
# Module 2: Request classification
# ---------------------------------------------------------------------------

# Deletion-intent detection.
#
# A request authorizes deletion only when a positive (non-negated) statement
# asks for the account/profile/records to be deleted, erased, removed, closed,
# purged or wiped. Requests in the dataset also mix in non-deletion intents:
#   - marketing opt-out ("remove me from marketing lists", "stop promotional")
#   - access/export ("download a copy", "send me a copy", "information request")
#   - correction ("correct my surname", "change the email address")
#   - login help ("can't access", "reset the login")
#   - negated deletion ("not asking for deletion", "do not close", "without removing")
# The negation and marketing-scope checks run before the decision so a request
# like "correct it without removing any of my records" is not read as deletion.
#
# Deletion verbs (multilingual):
#   EN: delete, erase, remove, close, purge, wipe
#   ES/PT: eliminar, exclusão, borrar, cerrar, suprimir, apagar, remover
#   FR: suppression, supprimer, effacer, fermer, clôturer
#   JA: 削除, 消去, 抹消
#   KO: 삭제, 제거, 폐쇄, 탈퇴, 지우

_DELETION_VERB_PATTERNS: list[re.Pattern] = [
    # English stems (word-start, no trailing boundary so inflections match)
    re.compile(r'\b(?:delet|eras|remov|clos|purg|wip)', re.I),
    # Spanish / Portuguese stems
    re.compile(r'\b(?:elimin|exclus|exclu|borr|cerrar|suprim|apag)', re.I),
    # French stems
    re.compile(r'\b(?:suppression|supprim|effac|fermer|clotur|clôtur)', re.I),
    # Japanese
    re.compile(r'削除|消去|抹消'),
    # Korean
    re.compile(r'삭제|제거|폐쇄|탈퇴|지우'),
]

# Indirect wording that still authorizes deletion (already-deleted narratives).
_INDIRECT_DELETION_PATTERNS: list[re.Pattern] = [
    re.compile(r'\b(?:gone|absent|wiped)\b', re.I),
    re.compile(r'\b(?:cannot|can.t)\s+(?:identify|be identified)\b', re.I),
    re.compile(r'\b(?:get rid of|take down|clear out|left behind)\b', re.I),
]

# Clauses that mention deletion only to reject it.
_NEGATION_CUE = re.compile(
    r"(?:['’]t\b|\bnot\b|\bnever\b|\bwithout\b|\bno\s+(?:deletion|removal|erasure)\b"
    r"|지\s*마|않|마세요|마십시오)",
    re.I,
)
# "I have not been able to delete my account" is a deletion request, not a refusal.
_NEGATION_EXEMPTION = re.compile(
    r"(?:not\s+(?:yet\s+)?(?:been\s+)?able\s+to|unable\s+to|failed\s+to"
    r"|could\s*n['’]?t|could\s+not|can\s*n['’]?t|cannot|not\s+yet)",
    re.I,
)
_CLAUSE_BOUNDARY = re.compile(r"[.!?;\n]|\bbut\b|\bhowever\b|\bexcept\b", re.I)

# "Remove me from marketing lists" / "stop promotional emails" is an opt-out,
# not a deletion of the account.
_MARKETING_OPT_OUT = re.compile(
    r"\bunsubscrib"
    r"|\bopt[\s-]?out\b"
    r"|\b(?:remove|delete|take|drop)\s+(?:me|my\s+(?:name|email|address|details))\s+from\s+"
    r"(?:[\w'-]+\s+){0,3}(?:marketing|mailing|promotional|newsletter|subscription)"
    r"|\bstop\s+(?:the\s+|all\s+|your\s+)?(?:promotional|marketing|newsletter)\b"
    r"|\b(?:promotional|marketing)\s+(?:e-?mails?|messages?)\b",
    re.I,
)

_NON_DELETION_INTENT: list[re.Pattern] = [
    _MARKETING_OPT_OUT,
    # access / export / copies of data
    re.compile(
        r"\b(?:download|export|portable\s+format|copy\s+of|send\s+me\s+a\s+copy"
        r"|information\s+request|what\s+personal\s+information|right\s+to\s+access"
        r"|access\s+(?:and|to)\s+.*\b(?:data|records|information))\b",
        re.I,
    ),
    # correction / update of profile fields
    re.compile(
        r"\b(?:correct|fix|misspell\w*|out\s+of\s+date|update|change|replace)"
        r"\b.{0,40}\b(?:name|surname|email|address|phone|number|details|profile|login)\b",
        re.I,
    ),
    # login help
    re.compile(r"\b(?:can.?t|cannot|unable\s+to)\s+access\b|\breset(?:ting)?\s+(?:the\s+)?(?:login|password)\b", re.I),
    # explicit keep / continue
    re.compile(
        r"\b(?:keep|leave)\b.{0,40}\b(?:account|profile|records?|history)\b"
        r"|\b(?:continue\s+using|still\s+(?:use|need)\b)",
        re.I,
    ),
]


def _clause_span(text: str, start: int, end: int) -> tuple[int, int]:
    """Return the clause boundaries around text[start:end]."""
    left = 0
    for m in _CLAUSE_BOUNDARY.finditer(text, 0, start):
        left = m.end()
    m = _CLAUSE_BOUNDARY.search(text, end)
    right = m.start() if m else len(text)
    return left, right


def _is_negated(text: str, start: int, end: int) -> bool:
    left, _ = _clause_span(text, start, end)
    clause = text[left:start]
    if _NEGATION_EXEMPTION.search(clause):
        return False
    return bool(_NEGATION_CUE.search(clause))


def classify_request(request_text: str) -> dict:
    """Classify whether the request_text authorizes a deletion.

    Returns a dict with:
        is_deletion: bool
        confidence: 'high' | 'medium' | 'low'
        matched_deletion_signals: list[str]
        matched_non_deletion_signals: list[str]
        notes: str
    """
    text = request_text.strip()

    marketing_spans = [m.span() for m in _MARKETING_OPT_OUT.finditer(text)]

    deletion_hits: list[str] = []
    indirect_hits: list[str] = []
    rejected_hits: list[str] = []

    for pat in _DELETION_VERB_PATTERNS:
        for m in pat.finditer(text):
            start, end = m.span()
            if any(s <= start < e for s, e in marketing_spans):
                continue
            if _is_negated(text, start, end):
                rejected_hits.append(m.group(0))
                continue
            deletion_hits.append(m.group(0))

    for pat in _INDIRECT_DELETION_PATTERNS:
        for m in pat.finditer(text):
            start, end = m.span()
            if any(s <= start < e for s, e in marketing_spans):
                continue
            if _is_negated(text, start, end):
                rejected_hits.append(m.group(0))
                continue
            indirect_hits.append(m.group(0))

    non_deletion_hits: list[str] = []
    for pat in _NON_DELETION_INTENT:
        m = pat.search(text)
        if m:
            non_deletion_hits.append(m.group(0).strip())
    if rejected_hits:
        non_deletion_hits.append("negated deletion: " + ", ".join(rejected_hits))

    if deletion_hits:
        return {
            "is_deletion": True,
            "confidence": "high",
            "matched_deletion_signals": deletion_hits,
            "matched_non_deletion_signals": non_deletion_hits,
            "notes": "Explicit positive deletion instruction.",
        }

    if indirect_hits:
        return {
            "is_deletion": True,
            "confidence": "medium",
            "matched_deletion_signals": indirect_hits,
            "matched_non_deletion_signals": non_deletion_hits,
            "notes": "Deletion confirmed indirectly (state described as already deleted).",
        }

    return {
        "is_deletion": False,
        "confidence": "high" if non_deletion_hits else "low",
        "matched_deletion_signals": [],
        "matched_non_deletion_signals": non_deletion_hits,
        "notes": (
            "No positive deletion instruction; treated as non-deletion."
            if non_deletion_hits
            else "No deletion intent detected; treated as non-deletion. Manual review recommended."
        ),
    }


# ---------------------------------------------------------------------------
# Module 3: Identity resolution
# ---------------------------------------------------------------------------

def resolve_identity(
    email: str,
    datasets: Datasets,
) -> IdentityResolutionResult:
    """Resolve a request email to a user identity fingerprint.

    Strategy:
    1. Direct match: look up email (case-insensitive) in current user_identities.
    2. Historical match: look up email (case-insensitive) in user_audit_log
       old_value where field_name = 'email'.
    3. If both match the same user_id -> use that (consistent result).
    4. If they match different users -> return 'ambiguous' (log & skip).
    5. If no match -> return 'not_found'.

    Decoy protection: we match only complete email addresses (not substrings),
    and we require the match to be in either the current snapshot or the
    historical record — not inferred from similarity.
    """
    email_lower = email.lower()

    # Step 1: direct current-email match
    current_uid = datasets.email_to_user_id.get(email_lower)

    # Step 2: historical email match
    historical_uid: Optional[str] = None
    for row in datasets.audit_log:
        if (
            row["field_name"].strip() == "email"
            and row["old_value"].strip().lower() == email_lower
        ):
            candidate = row["user_id"].strip()
            if historical_uid is not None and historical_uid != candidate:
                # Multiple different users had this as an old email — ambiguous
                return IdentityResolutionResult(
                    status="ambiguous",
                    message=(
                        f"Email '{email}' appears as a historical email for "
                        f"multiple users: {historical_uid!r} and {candidate!r}. "
                        "Cannot resolve safely."
                    ),
                    candidates=[historical_uid, candidate],
                )
            historical_uid = candidate

    # Determine final user_id
    if current_uid and historical_uid and current_uid != historical_uid:
        # Email is current for one user AND historical for a different user
        return IdentityResolutionResult(
            status="ambiguous",
            message=(
                f"Email '{email}' is the current email for {current_uid!r} "
                f"but also a historical email for {historical_uid!r}. "
                "Cannot resolve safely — manual review required."
            ),
            candidates=[current_uid, historical_uid],
        )

    resolved_uid = current_uid or historical_uid
    match_type = (
        "current_email" if current_uid else
        "historical_email" if historical_uid else
        ""
    )

    if resolved_uid is None:
        return IdentityResolutionResult(
            status="not_found",
            message=f"No user found for email '{email}' (current or historical).",
        )

    # Build fingerprint
    identity = datasets.identities[resolved_uid]
    fp = IdentityFingerprint(
        user_id=resolved_uid,
        name=identity.name,
        current_email=identity.current_email,
        phone=identity.phone,
        current_email_hash=identity.email_hash,
        old_emails=datasets.historical_emails.get(resolved_uid, []),
        old_email_hashes=datasets.historical_email_hashes.get(resolved_uid, []),
        old_phones=datasets.historical_phones.get(resolved_uid, []),
    )

    return IdentityResolutionResult(
        status="found",
        fingerprint=fp,
        match_type=match_type,
        matched_email=email,
        message="",
    )


# ---------------------------------------------------------------------------
# Module 4: Temporal evidence filtering
# ---------------------------------------------------------------------------

def filter_evidence(
    audit_at: datetime,
    evidence_files: list[EvidenceFile],
) -> list[EvidenceFile]:
    """Return evidence files captured at or before audit_at (inclusive).

    Both timestamps are expected to be UTC-aware. Raises ValueError if
    either timestamp is naive (no tzinfo).
    """
    if audit_at.tzinfo is None:
        raise ValueError(
            f"audit_at has no timezone info: {audit_at!r}. "
            "All timestamps must be UTC-aware."
        )
    admissible: list[EvidenceFile] = []
    for ev in evidence_files:
        if ev.captured_at.tzinfo is None:
            raise ValueError(
                f"EvidenceFile {ev.file_id} has no timezone info on captured_at."
            )
        if ev.captured_at <= audit_at:
            admissible.append(ev)
    # Sort by captured_at descending so the most recent is first
    admissible.sort(key=lambda e: e.captured_at, reverse=True)
    return admissible


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    print("Ghost Data Still Exists — Deletion Audit Agent")
    print(f"Repository root: {REPO_ROOT}")
    print()

    print("Loading datasets...")
    try:
        datasets = load_datasets()
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"  deletion_requests: {len(datasets.deletion_requests)} cases")
    print(f"  sample_requests:   {len(datasets.sample_requests)} cases")
    print(f"  user_identities:   {len(datasets.identities)} users")
    print(f"  audit_log entries: {len(datasets.audit_log)}")
    print(f"  system_activity:   {len(datasets.system_activity)} events")
    print(f"  deletion_rules:    {len(datasets.deletion_rules)} rules")
    print(f"  evidence_files:    {len(datasets.evidence_files)} files")
    print()

    print("Running identity resolution on sample requests...")
    results: dict[str, IdentityResolutionResult] = {}
    for req in datasets.sample_requests:
        result = resolve_identity(req.email, datasets)
        results[req.case_id] = result
        status_str = result.status.upper()
        if result.fingerprint:
            print(
                f"  {req.case_id}: {status_str} ({result.match_type}) "
                f"-> {result.fingerprint.user_id} ({result.fingerprint.name})"
            )
        else:
            print(f"  {req.case_id}: {status_str} — {result.message}")
    print()

    print("Running request classification on sample requests...")
    for req in datasets.sample_requests:
        clf = classify_request(req.request_text)
        flag = "DELETE" if clf["is_deletion"] else "NOT_APPLICABLE"
        print(
            f"  {req.case_id}: {flag} [{clf['confidence']}] "
            f"signals={clf['matched_deletion_signals'][:2]}"
        )
    print()
    print("Done. Run tests with: python -m pytest code/tests/ -v")


# ---------------------------------------------------------------------------
# End-to-end pipeline (Task 4)
# ---------------------------------------------------------------------------

def _serialize_steps(steps) -> str:
    """Serialize a list of AuditStep (or dicts) into a compact JSON array."""
    out = []
    for s in steps:
        if hasattr(s, "to_dict"):
            out.append(s.to_dict())
        else:
            out.append(s)
    # Ensure step_no renumbered consecutively
    for i, d in enumerate(out, 1):
        d["step_no"] = i
    return json.dumps(out, ensure_ascii=False, separators=(",", ":"))


def audit_request(req, datasets, corpus) -> tuple[str, list, Optional[str]]:
    """Audit one request. Returns (status, steps, failure_reason)."""
    if not classify_request(req.request_text).get("is_deletion", False):
        return "NOT_APPLICABLE", [], None

    fp = resolve_identity(req.email, datasets).fingerprint
    if fp is None:
        # Still a deletion request: claiming NOT_APPLICABLE would assert the
        # person never asked for deletion. Without a resolved identity the
        # compliant state cannot be proven, so report INCOMPLETE.
        return "INCOMPLETE", [], "unresolved_identity"

    try:
        result = reconstruct_case_state(
            case_id=req.case_id,
            audit_at=req.audit_at,
            is_deletion=True,
            user_identifiers=fp.all_identifiers,
            corpus=corpus,
            system_activity=datasets.system_activity,
            require_evidence=True,
            not_before=req.requested_at,
        )
    except Exception as exc:  # pragma: no cover - defensive
        print(f"WARN {req.case_id}: reconstruction failed: {exc}", file=sys.stderr)
        return "INCOMPLETE", [], "reconstruction_error"

    return result.deletion_status, result.steps, None


def run_full_pipeline(dataset_dir=None, output_path=None) -> Path:
    """Run the deletion audit over every evaluation request and write output.csv.

    Returns the path of the written CSV.
    """
    if dataset_dir is None:
        dataset_dir = DATASET_DIR
    dataset_dir = Path(dataset_dir)
    if output_path is None:
        output_path = REPO_ROOT / "output.csv"
    output_path = Path(output_path)

    datasets = load_datasets(dataset_dir)
    corpus = load_evidence_corpus(dataset_dir) if load_evidence_corpus else None

    rows = []
    unresolved = 0
    pipeline_errors = 0
    for req in datasets.deletion_requests:
        status, steps, failure = audit_request(req, datasets, corpus)
        if failure == "unresolved_identity":
            unresolved += 1
        elif failure == "reconstruction_error":
            pipeline_errors += 1

        rows.append((req.case_id, status, _serialize_steps(steps)))

    rows.sort(key=lambda r: r[0])

    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
        writer.writerow(["case_id", "deletion_status", "steps_json"])
        for cid, status, steps_json in rows:
            writer.writerow([cid, status, steps_json])

    if unresolved or pipeline_errors:
        print(
            f"  WARNING: {unresolved} unresolved identities, "
            f"{pipeline_errors} reconstruction errors",
            file=sys.stderr,
        )

    return output_path


def main() -> None:
    print("Ghost Data Still Exists — Deletion Audit Agent")
    print(f"Repository root: {REPO_ROOT}")
    print()

    print("Loading datasets...")
    try:
        datasets = load_datasets()
    except (ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"  deletion_requests: {len(datasets.deletion_requests)} cases")
    print(f"  sample_requests:   {len(datasets.sample_requests)} cases")
    print(f"  user_identities:   {len(datasets.identities)} users")
    print(f"  audit_log entries: {len(datasets.audit_log)}")
    print(f"  system_activity:   {len(datasets.system_activity)} events")
    print(f"  deletion_rules:    {len(datasets.deletion_rules)} rules")
    print(f"  evidence_files:    {len(datasets.evidence_files)} files")
    print()

    print("Running identity resolution on sample requests...")
    results = {}
    for req in datasets.sample_requests:
        result = resolve_identity(req.email, datasets)
        results[req.case_id] = result
        status_str = result.status.upper()
        if result.fingerprint:
            print(
                f"  {req.case_id}: {status_str} ({result.match_type}) "
                f"-> {result.fingerprint.user_id} ({result.fingerprint.name})"
            )
        else:
            print(f"  {req.case_id}: {status_str} — {result.message}")
    print()

    print("Running request classification on sample requests...")
    for req in datasets.sample_requests:
        clf = classify_request(req.request_text)
        flag = "DELETE" if clf["is_deletion"] else "NOT_APPLICABLE"
        print(
            f"  {req.case_id}: {flag} [{clf['confidence']}] "
            f"signals={clf['matched_deletion_signals'][:2]}"
        )
    print()

    print("Generating output.csv for all evaluation cases...")
    out_path = run_full_pipeline()
    print(f"  Written: {out_path}")
    print()
    print("Done. Run tests with: python -m pytest code/tests/ -v")


if __name__ == "__main__":
    main()
