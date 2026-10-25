"""Global resource-ownership linker for Ghost Data Still Exists.

Deleted accounts and anonymized analytics records no longer carry any
identifier, so evidence alone cannot say whose they were.  The deletion
worker, however, names every resource it touched, and its events are emitted
on a fixed cadence around each request's ``reported_at``.  This module learns
that cadence from requests whose resources *are* identifier-linked, then
assigns the remaining worker events to requests with a global one-to-one
minimum-cost matching.

Activity establishes ownership only.  The state of an assigned resource still
comes from admissible readbacks or complete snapshots in the reconstruction
layer; ``reported_status`` and ``reported_result`` are used as matching
features, never as state.

Nothing here reads case ids, sample answers or organizer files.  Every window,
scale and probability is estimated from participant data at run time.
"""

from __future__ import annotations

import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Optional

from evidence_parser import (
    EvidenceCorpus,
    _normalize_system_id,
    _parse_iso,
    strong_identifiers,
)

# Default category of the resource a worker event names, by target system.
SYSTEM_CATEGORY = {
    "account_service": "USER_PROFILE",
    "analytics_platform": "ANALYTICS_PROFILE",
    "search_service": "SEARCH_INDEX_ENTRY",
    "export_service": "USER_EXPORT",
    "identity_service": "ACCOUNT_TOMBSTONE",
    "legal_service": "LEGAL_HOLD_RECORD",
    "integration_service": "DATA_FLOW",
    "backup_service": "BACKUP_ARCHIVE",
    "marketing_platform": "MARKETING_PROFILE",
    "security_service": "SECURITY_AUDIT_LOG",
}

# Proximity of a resource's latest in-window readback to the case audit time.
_PROXIMITY_EDGES_HOURS = (6.0, 24.0, 72.0)

# Workflow notes name their target explicitly; batch events do not.
_WORKFLOW_NOTE = re.compile(r"Target resource:", re.I)
_RESOURCE_TOKEN = re.compile(r"\b[a-z]+(?:_[a-z]+)*_\d+\b")
_STATUS_RESULTS = ("SUCCESS", "PARTIAL", "FAILED")


@dataclass(frozen=True)
class WorkerEvent:
    activity_id: str
    event_time: datetime
    event_type: str
    system_id: str
    resource_id: str
    result: str
    template: str
    family: str


@dataclass(frozen=True)
class ResourceLink:
    """A resource placed in a case's audit scope, and why."""
    system_id: str
    resource_id: str
    category: str
    method: str           # direct | activity | catalog | profile_fallback
    evidence_id: str = ""  # activity_id or catalog activity that established it
    event_time: Optional[datetime] = None
    cost: float = 0.0
    margin: Optional[float] = None


@dataclass
class TimingModel:
    level: str
    median: float
    sigma: float
    low: float
    high: float
    pairs: int
    result_counts: dict = field(default_factory=dict)  # reported_status -> Counter(result)

    def window_contains(self, minutes: float) -> bool:
        return self.low <= minutes <= self.high

    def cost(self, minutes: float, reported_status: str, result: str) -> float:
        z = (minutes - self.median) / self.sigma
        counts = self.result_counts.get(reported_status, Counter())
        outcomes = set(_STATUS_RESULTS) | {result}
        p = (counts.get(result, 0) + 1) / (sum(counts.values()) + len(outcomes))
        return 0.5 * z * z - math.log(p)


@dataclass
class PhaseModel:
    """Sub-minute phase shared by all worker events of one request.

    The worker emits a request's events on a fixed grid, so the time of any
    event modulo ``period`` is predictable from the request's other events
    once the per-type offsets are known.  Everything here is estimated from
    identifier-resolved requests.
    """
    period: int
    offsets: dict[tuple[str, str], float]   # (anchor type, event type) -> seconds
    residual_counts: Counter
    residual_total: int
    score: float

    def residual(self, value: float) -> float:
        half = self.period / 2.0
        return (value + half) % self.period - half

    def cost(self, event_time: float, event_type: str, anchors: list[tuple[str, float]]) -> float:
        """-log(p(residual) / uniform); 0 when the request has no usable anchor."""
        predictions = [
            anchor_time + self.offsets[(anchor_type, event_type)]
            for anchor_type, anchor_time in anchors
            if (anchor_type, event_type) in self.offsets
        ]
        if not predictions:
            return 0.0
        angles = [2 * math.pi * (p % self.period) / self.period for p in predictions]
        mean = math.atan2(sum(map(math.sin, angles)), sum(map(math.cos, angles)))
        predicted = mean / (2 * math.pi) * self.period
        r = round(self.residual(event_time - predicted))
        p = (self.residual_counts.get(r, 0) + 1) / (self.residual_total + self.period)
        return -math.log(p * self.period)


def _phase_type(event: "WorkerEvent") -> str:
    """Template with system names removed: one phase class per worker step."""
    return re.sub(r"\b(from|to) [a-z_]+", r"\1 S", event.template)


def _circular_r(values: list[float], period: int) -> float:
    if not values:
        return 0.0
    angles = [2 * math.pi * (v % period) / period for v in values]
    return math.hypot(sum(map(math.cos, angles)), sum(map(math.sin, angles))) / len(values)


@dataclass
class LinkResult:
    links: dict[str, list[ResourceLink]] = field(default_factory=dict)
    event_owner: dict[str, str] = field(default_factory=dict)  # activity_id -> case_id
    deletion_time: dict[tuple[str, str], datetime] = field(default_factory=dict)
    models: dict[str, TimingModel] = field(default_factory=dict)
    phase: Optional[PhaseModel] = None
    diagnostics: list[str] = field(default_factory=list)
    naming_rule: Optional[str] = None


# ---------------------------------------------------------------------------
# Small numeric helpers
# ---------------------------------------------------------------------------

def _quartiles(values: list[float]) -> tuple[float, float]:
    ordered = sorted(values)
    if len(ordered) < 4:
        return ordered[0], ordered[-1]
    q = statistics.quantiles(ordered, n=4, method="inclusive")
    return q[0], q[2]


def _inliers(values: list[float]) -> list[float]:
    """Tukey's fences (k=1.5) remove pairs linked through stale identifiers."""
    if len(values) < 4:
        return list(values)
    q1, q3 = _quartiles(values)
    iqr = q3 - q1
    return [v for v in values if q1 - 1.5 * iqr <= v <= q3 + 1.5 * iqr]


def _hungarian(cost: list[list[float]]) -> list[int]:
    """Minimum-cost assignment of every row to a distinct column (rows <= cols)."""
    n, m = len(cost), len(cost[0])
    inf = float("inf")
    u, v = [0.0] * (n + 1), [0.0] * (m + 1)
    p, way = [0] * (m + 1), [0] * (m + 1)
    for i in range(1, n + 1):
        p[0], j0 = i, 0
        minv, used = [inf] * (m + 1), [False] * (m + 1)
        while True:
            used[j0] = True
            i0, delta, j1 = p[j0], inf, 0
            for j in range(1, m + 1):
                if used[j]:
                    continue
                cur = cost[i0 - 1][j - 1] - u[i0] - v[j]
                if cur < minv[j]:
                    minv[j], way[j] = cur, j0
                if minv[j] < delta:
                    delta, j1 = minv[j], j
            for j in range(m + 1):
                if used[j]:
                    u[p[j]] += delta
                    v[j] -= delta
                else:
                    minv[j] -= delta
            j0 = j1
            if p[j0] == 0:
                break
        while j0:
            j1 = way[j0]
            p[j0] = p[j1]
            j0 = j1
    assignment = [-1] * n
    for j in range(1, m + 1):
        if p[j]:
            assignment[p[j] - 1] = j - 1
    return assignment


# ---------------------------------------------------------------------------
# Linker
# ---------------------------------------------------------------------------

def _template(details: str) -> str:
    return _RESOURCE_TOKEN.sub("X", details.strip())


def worker_events(activity_rows: Iterable[dict]) -> list[WorkerEvent]:
    events = []
    for row in activity_rows:
        if str(row.get("source_system") or "") != "deletion_worker":
            continue
        resource_id = str(row.get("resource_id") or "").strip()
        if not resource_id:
            continue
        details = str(row.get("details") or "")
        events.append(WorkerEvent(
            activity_id=str(row.get("activity_id") or ""),
            event_time=_parse_iso(str(row.get("event_time") or "")),
            event_type=str(row.get("event_type") or ""),
            system_id=_normalize_system_id(str(row.get("target_system") or "")),
            resource_id=resource_id,
            result=str(row.get("reported_result") or "").strip().upper(),
            template=_template(details),
            family="workflow_note" if _WORKFLOW_NOTE.search(details) else "batch",
        ))
    return events


class ActivityLinker:
    """Learns worker cadence from resolved pairs and assigns the rest.

    ``subjects`` maps case_id -> (request, user_id, strong identifiers).
    ``identifier_owner`` maps every known strong identifier to its user_id.
    """

    def __init__(
        self,
        corpus: EvidenceCorpus,
        activity_rows: list[dict],
        subjects: dict[str, tuple[object, str, set[str]]],
        identifier_owner: dict[str, str],
    ):
        self.corpus = corpus
        self.subjects = subjects
        self.identifier_owner = identifier_owner
        self.events = worker_events(activity_rows)
        self.result = LinkResult()

    # -- ownership -------------------------------------------------------

    def _owners(self, system_id: str, resource_id: str) -> set[str]:
        owners: set[str] = set()
        for rec in self.corpus.records_for(system_id, resource_id):
            for ident in strong_identifiers(rec.identifiers):
                owner = self.identifier_owner.get(ident)
                if owner:
                    owners.add(owner)
        return owners

    def _direct_resources(self) -> dict[str, set[tuple[str, str]]]:
        """Resources whose admissible evidence carries the subject's identifiers."""
        direct: dict[str, set[tuple[str, str]]] = {}
        for case_id, (req, _, ids) in self.subjects.items():
            found = set()
            for rec in self.corpus.records_with_identifiers(ids):
                if rec.observed_within(req.audit_at):
                    found.add((rec.system_id, rec.resource_id))
            direct[case_id] = found
        return direct

    # -- cadence model ---------------------------------------------------

    def _levels(self, event: WorkerEvent) -> list[str]:
        return [
            f"{event.template}|{event.system_id}",
            event.template,
            f"family:{event.family}",
        ]

    def _fit_models(self, resolved: list[tuple[WorkerEvent, str]]) -> None:
        samples: dict[str, list[tuple[float, str, str]]] = defaultdict(list)
        for event, case_id in resolved:
            req = self.subjects[case_id][0]
            minutes = (event.event_time - req.reported_at).total_seconds() / 60.0
            for level in self._levels(event):
                samples[level].append((minutes, req.reported_status, event.result))

        # The spread of the best-supported cadence is the floor for every
        # model, so sparse templates are not given a spuriously tight scale.
        floor = None
        for level, rows in samples.items():
            inl = _inliers([m for m, _, _ in rows])
            if len(inl) >= 20:
                sd = statistics.pstdev(inl)
                floor = sd if floor is None else min(floor, sd)
        floor = max(floor or 1.0, 1.0)

        for level, rows in samples.items():
            minutes = [m for m, _, _ in rows]
            inl = _inliers(minutes)
            lo, hi = min(inl), max(inl)
            pad = hi - lo
            sigma = max(statistics.pstdev(inl) if len(inl) > 1 else 0.0, floor)
            pad = max(pad, sigma)
            counts: dict[str, Counter] = defaultdict(Counter)
            for m, status, result in rows:
                if lo <= m <= hi:
                    counts[status][result] += 1
            self.result.models[level] = TimingModel(
                level=level,
                median=statistics.median(inl),
                sigma=sigma,
                low=lo - pad,
                high=hi + pad,
                pairs=len(inl),
                result_counts=dict(counts),
            )

    def _model_for(self, event: WorkerEvent, minimum_pairs: int = 4) -> Optional[TimingModel]:
        for level in self._levels(event):
            model = self.result.models.get(level)
            if model is not None and model.pairs >= minimum_pairs:
                return model
        return None

    # -- per-request phase -----------------------------------------------

    def _fit_phase(self, case_events: dict[str, list[WorkerEvent]]) -> Optional[PhaseModel]:
        groups = [
            [(_phase_type(e), e.event_time.timestamp()) for e in events]
            for events in case_events.values() if len(events) >= 2
        ]
        if len(groups) < 10:
            return None
        # Burst-mates (same reported_at) give the between-request baseline.
        by_burst: dict[datetime, list[str]] = defaultdict(list)
        for case_id in case_events:
            by_burst[self.subjects[case_id][0].reported_at].append(case_id)

        def within(period: int) -> float:
            diffs: dict[tuple[str, str], list[float]] = defaultdict(list)
            for group in groups:
                for (ta, a), (tb, b) in ((x, y) for x in group for y in group if x is not y):
                    diffs[(ta, tb)].append(b - a)
            weights = [(len(v), _circular_r(v, period)) for v in diffs.values() if len(v) >= 5]
            total = sum(w for w, _ in weights)
            return sum(w * r for w, r in weights) / total if total else 0.0

        def between(period: int) -> float:
            diffs: dict[tuple[str, str], list[float]] = defaultdict(list)
            for cases in by_burst.values():
                for ca in cases:
                    for cb in cases:
                        if ca == cb:
                            continue
                        for ea in case_events[ca]:
                            for eb in case_events[cb]:
                                diffs[(_phase_type(ea), _phase_type(eb))].append(
                                    eb.event_time.timestamp() - ea.event_time.timestamp())
            weights = [(len(v), _circular_r(v, period)) for v in diffs.values() if len(v) >= 5]
            total = sum(w for w, _ in weights)
            return sum(w * r for w, r in weights) / total if total else 0.0

        best = max(range(2, 121), key=lambda p: (round(within(p) - between(p), 6), -p))
        score = within(best) - between(best)
        if score <= 0.5:
            return None

        offsets: dict[tuple[str, str], float] = {}
        diffs: dict[tuple[str, str], list[float]] = defaultdict(list)
        for group in groups:
            for (ta, a) in group:
                for (tb, b) in group:
                    if (ta, a) != (tb, b):
                        diffs[(ta, tb)].append(b - a)
        for key, values in diffs.items():
            if len(values) >= 3 and _circular_r(values, best) >= 0.9:
                angles = [2 * math.pi * (v % best) / best for v in values]
                mean = math.atan2(sum(map(math.sin, angles)), sum(map(math.cos, angles)))
                offsets[key] = mean / (2 * math.pi) * best

        model = PhaseModel(best, offsets, Counter(), 0, score)
        # Leave-one-out residuals on resolved requests give the likelihood.
        for group in groups:
            for i, (event_type, t) in enumerate(group):
                anchors = [g for j, g in enumerate(group) if j != i]
                preds = [a_t + offsets[(a_type, event_type)] for a_type, a_t in anchors
                         if (a_type, event_type) in offsets]
                if not preds:
                    continue
                angles = [2 * math.pi * (p % best) / best for p in preds]
                mean = math.atan2(sum(map(math.sin, angles)), sum(map(math.cos, angles)))
                r = round(model.residual(t - mean / (2 * math.pi) * best))
                model.residual_counts[r] += 1
                model.residual_total += 1
        return model

    # -- audit-time proximity --------------------------------------------

    def _proximity_bucket(self, req, system_id: str, resource_id: str) -> str:
        times = [
            rec.captured_at
            for rec in self.corpus.records_for(system_id, resource_id)
            if rec.observed_within(req.audit_at, req.requested_at)
        ]
        if not times:
            return "none"
        hours = (req.audit_at - max(times)).total_seconds() / 3600.0
        for edge in _PROXIMITY_EDGES_HOURS:
            if hours < edge:
                return f"<{edge:g}h"
        return f">={_PROXIMITY_EDGES_HOURS[-1]:g}h"

    def _fit_proximity(self, resolved: list[tuple[WorkerEvent, str]]) -> dict[str, float]:
        counts = Counter(
            self._proximity_bucket(self.subjects[c][0], e.system_id, e.resource_id)
            for e, c in resolved
        )
        buckets = [f"<{e:g}h" for e in _PROXIMITY_EDGES_HOURS] + [f">={_PROXIMITY_EDGES_HOURS[-1]:g}h", "none"]
        total = sum(counts.values()) + len(buckets)
        return {b: -math.log((counts.get(b, 0) + 1) / total) for b in buckets}

    # -- main ------------------------------------------------------------

    def run(self) -> LinkResult:
        res = self.result
        direct = self._direct_resources()

        # 1. Resolved pairs: worker events on a resource the request is
        #    identifier-linked to.  These train the cadence model.
        by_resource: dict[tuple[str, str], list[str]] = defaultdict(list)
        for case_id, keys in direct.items():
            for key in keys:
                by_resource[key].append(case_id)
        resolved: list[tuple[WorkerEvent, str]] = []
        unresolved: list[WorkerEvent] = []
        for event in self.events:
            cases = by_resource.get((event.system_id, event.resource_id), [])
            if cases:
                for case_id in cases:
                    resolved.append((event, case_id))
            else:
                unresolved.append(event)
        self._fit_models(resolved)
        proximity_cost = self._fit_proximity(
            [(e, c) for e, c in resolved if self._model_for(e) and self._model_for(e).window_contains(
                (e.event_time - self.subjects[c][0].reported_at).total_seconds() / 60.0)]
        )

        # A resolved event claims its resource for the request(s) it is
        # linked to, as long as it falls inside the learned cadence window.
        has_system: dict[str, set[str]] = defaultdict(set)
        case_events: dict[str, list[WorkerEvent]] = defaultdict(list)
        for event, case_id in resolved:
            model = self._model_for(event)
            req = self.subjects[case_id][0]
            minutes = (event.event_time - req.reported_at).total_seconds() / 60.0
            if model is None or not model.window_contains(minutes) or event.event_time > req.audit_at:
                continue
            res.event_owner.setdefault(event.activity_id, case_id)
            has_system[case_id].add(event.system_id)
            case_events[case_id].append(event)
            self._record_deletion(event)
            res.links.setdefault(case_id, []).append(ResourceLink(
                system_id=event.system_id, resource_id=event.resource_id,
                category=SYSTEM_CATEGORY.get(event.system_id, ""), method="direct",
                evidence_id=event.activity_id, event_time=event.event_time,
            ))
        res.phase = self._fit_phase(case_events)

        # 2-3. Assign unresolved events one target system at a time,
        #    accounts first: each request's assigned events become phase
        #    anchors for the systems assigned after it.
        event_by_id = {e.activity_id: e for e in unresolved}
        by_system: dict[str, list[WorkerEvent]] = defaultdict(list)
        for event in unresolved:
            by_system[event.system_id].append(event)
        order = sorted(by_system, key=lambda s: (s != "account_service", s))
        for system_id in order:
            edges: dict[str, dict[str, float]] = defaultdict(dict)
            for event in by_system[system_id]:
                model = self._model_for(event)
                if model is None:
                    res.diagnostics.append(f"{event.activity_id}: no cadence model for template {event.template!r}")
                    continue
                owners = self._owners(event.system_id, event.resource_id)
                for case_id, (req, user_id, _) in self.subjects.items():
                    if event.system_id in has_system[case_id]:
                        continue
                    if event.event_time > req.audit_at:
                        continue
                    minutes = (event.event_time - req.reported_at).total_seconds() / 60.0
                    if not model.window_contains(minutes):
                        continue
                    if owners and user_id not in owners:
                        # The resource's own evidence names someone else.
                        continue
                    cost = model.cost(minutes, req.reported_status, event.result)
                    cost += proximity_cost[self._proximity_bucket(req, event.system_id, event.resource_id)]
                    if res.phase is not None:
                        anchors = [(_phase_type(e), e.event_time.timestamp()) for e in case_events[case_id]]
                        cost += res.phase.cost(event.event_time.timestamp(), _phase_type(event), anchors)
                    edges[event.activity_id][case_id] = cost
            # One-to-one per target system, solved per connected component
            # so independent bursts stay independent.
            for component in self._components(sorted(edges), edges):
                for case_id, event in self._assign_component(component, edges, event_by_id, res):
                    has_system[case_id].add(event.system_id)
                    case_events[case_id].append(event)

        # 4. Catalog links establish ownership for named resources.
        self._apply_catalog_links()
        # 5. Data-derived account fallback, applied only where nothing else
        #    recovered an account for the request.
        self._apply_profile_fallback()
        return res

    def _record_deletion(self, event: WorkerEvent) -> None:
        key = (event.system_id, event.resource_id)
        current = self.result.deletion_time.get(key)
        if current is None or event.event_time > current:
            self.result.deletion_time[key] = event.event_time

    @staticmethod
    def _components(activity_ids: list[str], edges: dict[str, dict[str, float]]) -> list[list[str]]:
        parent: dict[str, str] = {}

        def find(x: str) -> str:
            while parent.setdefault(x, x) != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        for activity_id in activity_ids:
            for case_id in edges[activity_id]:
                parent[find("e:" + activity_id)] = find("c:" + case_id)
        groups: dict[str, list[str]] = defaultdict(list)
        for activity_id in activity_ids:
            groups[find("e:" + activity_id)].append(activity_id)
        return [sorted(g) for _, g in sorted(groups.items())]

    def _assign_component(self, activity_ids, edges, event_by_id, res: LinkResult) -> list:
        events = sorted(activity_ids, key=lambda a: (event_by_id[a].event_time, a))
        cases = sorted({c for a in events for c in edges[a]})
        assigned: list[tuple[str, WorkerEvent]] = []
        if not cases:
            return assigned
        real = [cost for a in events for cost in edges[a].values()]
        forbidden = (max(real) + 1.0) * 1000.0
        unassigned = (max(real) + 1.0) * 100.0
        # Columns: real cases, then one "leave unassigned" slot per event so
        # every event is matched when any admissible case is available.
        matrix = []
        for i, activity_id in enumerate(events):
            row = [edges[activity_id].get(case_id, forbidden) for case_id in cases]
            row += [unassigned if j == i else forbidden for j in range(len(events))]
            matrix.append(row)
        assignment = _hungarian(matrix)
        for i, column in enumerate(assignment):
            activity_id = events[i]
            event = event_by_id[activity_id]
            if column < 0 or column >= len(cases):
                res.diagnostics.append(f"{activity_id}: {event.resource_id} left unassigned")
                continue
            case_id = cases[column]
            cost = edges[activity_id][case_id]
            others = [c for k, c in edges[activity_id].items() if k != case_id]
            margin = (min(others) - cost) if others else None
            if margin is not None and margin < 1e-6:
                res.diagnostics.append(
                    f"{activity_id}: {event.resource_id} -> {case_id} is a tie "
                    f"(margin {margin:.3f}) among {sorted(edges[activity_id])}"
                )
            res.event_owner[activity_id] = case_id
            self._record_deletion(event)
            res.links.setdefault(case_id, []).append(ResourceLink(
                system_id=event.system_id, resource_id=event.resource_id,
                category=SYSTEM_CATEGORY.get(event.system_id, ""), method="activity",
                evidence_id=activity_id, event_time=event.event_time,
                cost=cost, margin=margin,
            ))
            assigned.append((case_id, event))
        return assigned

    def _apply_catalog_links(self) -> None:
        for case_id, (req, user_id, ids) in self.subjects.items():
            for link in self.corpus.catalog_links:
                if link.event_time > req.audit_at or not (link.identifiers & ids):
                    continue
                owners = self._owners(link.system_id, link.resource_id)
                if owners and user_id not in owners:
                    self.result.diagnostics.append(
                        f"{case_id}: catalog link {link.activity_id} rejected; "
                        f"{link.resource_id} evidence names {sorted(owners)}"
                    )
                    continue
                unknown = sorted(
                    ident
                    for rec in self.corpus.records_for(link.system_id, link.resource_id)
                    for ident in strong_identifiers(rec.identifiers)
                    if ident not in ids and ident not in self.identifier_owner
                )
                if unknown:
                    # An unrecognized persona does not override an explicit
                    # catalog link, but the conflict is kept for review.
                    self.result.diagnostics.append(
                        f"{case_id}: catalog link {link.activity_id} kept; {link.resource_id} "
                        f"evidence also shows unrecognized identifiers {unknown}"
                    )
                self.result.links.setdefault(case_id, []).append(ResourceLink(
                    system_id=link.system_id, resource_id=link.resource_id,
                    category="", method="catalog", evidence_id=link.activity_id,
                    event_time=link.event_time,
                ))

    def learn_naming_rule(self) -> Optional[int]:
        """Zero-pad width of account ids whose number equals the user number.

        Learned only from profile rows that show both a user reference and an
        account id; returns None unless the visible pairs are one-to-one and
        every equal-number pair agrees on a single width.
        """
        pairs: set[tuple[str, str]] = set()
        for rec in self.corpus.records:
            if rec.system_id != "account_service" or rec.data_category != "USER_PROFILE":
                continue
            ref = str(rec.details.get("user_id") or rec.details.get("customer_reference") or "").strip().lower()
            if re.fullmatch(r"user_\d+", ref) and re.fullmatch(r"account_\d+", rec.resource_id):
                pairs.add((ref, rec.resource_id))
        users, accounts = Counter(u for u, _ in pairs), Counter(a for _, a in pairs)
        if any(n > 1 for n in users.values()) or any(n > 1 for n in accounts.values()):
            return None
        same = [
            (int(u.split("_")[1]), a.split("_")[1])
            for u, a in pairs if int(u.split("_")[1]) == int(a.split("_")[1])
        ]
        if not same:
            return None
        widths = [
            w for w in range(1, max(len(s) for _, s in same) + 1)
            if all(f"{n:0{w}d}" == s for n, s in same)
        ]
        if not widths:
            return None
        width = max(widths)
        self.result.naming_rule = (
            f"account_{{n:0{width}d}} ({len(same)} of {len(pairs)} visible "
            f"user/account pairs share the number)"
        )
        return width

    def _apply_profile_fallback(self) -> None:
        width = self.learn_naming_rule()
        if width is None:
            return
        claimed = {
            (l.system_id, l.resource_id)
            for links in self.result.links.values() for l in links
        }
        for case_id, (req, user_id, ids) in sorted(self.subjects.items()):
            has_account = any(l.system_id == "account_service" for l in self.result.links.get(case_id, []))
            has_account = has_account or any(
                rec.system_id == "account_service" and rec.data_category == "USER_PROFILE"
                for rec in self.corpus.records_with_identifiers(ids) if rec.observed_within(req.audit_at)
            )
            if has_account:
                continue
            number = re.fullmatch(r"user_(\d+)", user_id)
            if not number:
                continue
            candidate = f"account_{int(number.group(1)):0{width}d}"
            key = ("account_service", candidate)
            owners = self._owners(*key)
            if key in claimed or (owners and user_id not in owners):
                self.result.diagnostics.append(f"{case_id}: fallback {candidate} rejected (owned elsewhere)")
                continue
            self.result.links.setdefault(case_id, []).append(ResourceLink(
                system_id="account_service", resource_id=candidate,
                category="USER_PROFILE", method="profile_fallback",
            ))


def build_identifier_owner(datasets) -> dict[str, str]:
    """Every strong identifier ever held by a known user -> that user."""
    owner: dict[str, str] = {}
    for user_id, identity in datasets.identities.items():
        for value in (user_id, identity.current_email, identity.phone, identity.email_hash):
            for ident in strong_identifiers([value]):
                owner.setdefault(ident, user_id)
    for row in datasets.audit_log:
        user_id = row["user_id"].strip()
        for value in (row["old_value"], row["new_value"]):
            for ident in strong_identifiers([value]):
                owner.setdefault(ident, user_id)
    return owner


def link_resources(requests_with_identity, datasets, corpus: EvidenceCorpus) -> LinkResult:
    """Run the global linker over every authorized request at once.

    ``requests_with_identity`` is an iterable of (request, fingerprint).
    """
    subjects = {}
    for req, fp in requests_with_identity:
        ids = strong_identifiers(fp.all_identifiers)
        subjects[req.case_id] = (req, fp.user_id, ids)
    linker = ActivityLinker(
        corpus, datasets.system_activity, subjects, build_identifier_owner(datasets)
    )
    return linker.run()
