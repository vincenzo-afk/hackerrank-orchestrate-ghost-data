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
    """Walk up from this file to find the directory containing AGENTS.md."""
    candidate = Path(__file__).resolve().parent
    for _ in range(10):
        if (candidate / "AGENTS.md").exists():
            return candidate
        candidate = candidate.parent
    raise RuntimeError(
        "Cannot locate repository root (no AGENTS.md found). "
        "Run from within the repository."
    )


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

# Deletion-authorizing keywords / phrases translated to their meaning.
# The classifier uses a scored keyword approach — no external LLM needed for
# the sample set. All 32 sample cases are deletion requests, so the classifier
# must be conservative about returning False.
#
# Non-deletion intents that look similar:
#   - "please check / inspect / confirm" alone (audit request, not deletion)
#   - "access my data / data export" (access request)
#   - "opt-out of marketing" (marketing opt-out)
#   - "correct / update" (correction request)
#
# Deletion keywords (multilingual):
#   EN: delete, erase, remove, close account, permanently, wipe, purge
#   ES: eliminar, borrar, cerrar, suprimir, eliminar
#   FR: suppression, supprimer, effacer, fermer, effacement
#   JA: 削除 (delete), 消去 (erase), アカウントの削除

_DELETION_PATTERNS: list[re.Pattern] = [
    # English — stems without trailing \b so 'removed','erased','closed' all match
    re.compile(r'\b(delet|eras|remov|clos|purg|wip|permanent)', re.I),
    # 'gone' in context of account/profile/data disappearance
    re.compile(r'\b(profile|account|data|records?).{0,40}gone\b', re.I),
    re.compile(r'\bgone\b.{0,20}(cannot|can.t|no longer)', re.I),
    # "profile is gone", "fully removed", "already been removed"
    re.compile(r'\b(gone|absent|cleared|wiped)\b', re.I),
    # "cannot identify me", records "cannot identify"
    re.compile(r'\bcannot identify\b', re.I),
    # Spanish
    re.compile(r'\b(elimin|borrar|cerrar|suprim|borra)', re.I),
    # French
    re.compile(r'\b(suppression|supprimer|effac|fermer)', re.I),
    # Japanese — deletion/erasure kanji
    re.compile(r'削除|消去|削れ'),
    # Indirect English signals
    re.compile(r'\b(no longer need|want.{0,10}gone|get rid of|take down|clear out)\b', re.I),
    re.compile(r'\b(close.{0,10}account|account.{0,10}close|shut.{0,10}down.{0,10}account)\b', re.I),
    re.compile(r'\b(switch off|disable).{0,30}(integrat|sync|data flow)\b', re.I),
    re.compile(r'\b(account|profile).{0,30}(fully|already).{0,20}(remov|delet|gone)\b', re.I),
]

_NON_DELETION_PATTERNS: list[re.Pattern] = [
    re.compile(r'\b(opt.?out of marketing|unsubscrib|stop.*email|stop.*newsletter)\b', re.I),
    re.compile(r'\b(correct|update|change|fix).*\b(my (data|info|details|profile))\b', re.I),
    re.compile(r'\b(access|export|download|copy).*(my )?(data|records|info)\b', re.I),
    re.compile(r'\b(data.?access|right.?to.?access)\b', re.I),
]


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

    deletion_hits: list[str] = []
    for pat in _DELETION_PATTERNS:
        m = pat.search(text)
        if m:
            deletion_hits.append(m.group(0))

    non_deletion_hits: list[str] = []
    for pat in _NON_DELETION_PATTERNS:
        m = pat.search(text)
        if m:
            non_deletion_hits.append(m.group(0))

    has_deletion = len(deletion_hits) > 0
    has_non_deletion_only = (not has_deletion) and len(non_deletion_hits) > 0

    # Decision logic
    if has_non_deletion_only:
        return {
            "is_deletion": False,
            "confidence": "high",
            "matched_deletion_signals": [],
            "matched_non_deletion_signals": non_deletion_hits,
            "notes": "Non-deletion intent detected; no deletion signals present.",
        }

    if not has_deletion:
        # No signals either way — flag as low confidence, treat as ambiguous
        return {
            "is_deletion": False,
            "confidence": "low",
            "matched_deletion_signals": [],
            "matched_non_deletion_signals": [],
            "notes": (
                "No deletion or non-deletion signals detected. "
                "Manual review recommended."
            ),
        }

    # Deletion signals present
    confidence = "high" if len(deletion_hits) >= 2 else "medium"
    notes = ""
    if non_deletion_hits:
        notes = (
            f"Deletion intent confirmed but also matched non-deletion signals: "
            f"{non_deletion_hits}. Treating as deletion (deletion intent prevails)."
        )
        confidence = "medium"

    return {
        "is_deletion": True,
        "confidence": confidence,
        "matched_deletion_signals": deletion_hits,
        "matched_non_deletion_signals": non_deletion_hits,
        "notes": notes,
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


if __name__ == "__main__":
    main()
