"""Reproducible evaluation for the deletion-audit agent.

Run from the repository root:  python code/evaluation/main.py

It (1) scores the 32 public sample cases against dataset/sample_output.csv
using the challenge's comparison rules, (2) validates the root output.csv
against the output contract with the same validator main.py runs before
writing, and (3) prints linker diagnostics.  Metrics are printed; the
evaluation report quotes the output of this script.

sample_output.csv is read here only, for scoring; production code never
reads it.
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "code"))

from main import (  # noqa: E402
    audit_requests,
    global_links,
    load_datasets,
    validate_output_rows,
)
from evidence_parser import load_evidence_corpus  # noqa: E402

DATASET_DIR = REPO_ROOT / "dataset"
FIELDS = ("step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id")


def score_rows(gold_path: Path, rows: list[tuple[str, str, str]]) -> dict:
    gold = {}
    with open(gold_path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            gold[row["case_id"]] = (row["deletion_status"], json.loads(row["steps_json"]))
    results = {cid: (status, steps) for cid, status, steps in rows}

    status_ok = exact_ok = sequence_ok = 0
    tp = fp = fn = 0
    field_ok = field_total = 0
    mismatches = []
    for cid in sorted(gold):
        g_status, g_steps = gold[cid]
        p_status, p_json = results[cid]
        p_steps = json.loads(p_json)
        same_status = g_status == p_status
        status_ok += same_status

        g_tuples = [tuple(s[k] for k in FIELDS[1:]) for s in g_steps]
        p_tuples = [tuple(s[k] for k in FIELDS[1:]) for s in p_steps]
        g_count, p_count = Counter(g_tuples), Counter(p_tuples)
        hit = sum((g_count & p_count).values())
        tp += hit
        fp += sum(p_count.values()) - hit
        fn += sum(g_count.values()) - hit

        exact = same_status and g_tuples == p_tuples
        exact_ok += exact
        sequence_ok += g_tuples == p_tuples

        for index in range(max(len(g_steps), len(p_steps))):
            for name in FIELDS:
                field_total += 1
                field_ok += (
                    index < len(g_steps)
                    and index < len(p_steps)
                    and g_steps[index][name] == p_steps[index].get(name)
                )
        if not exact:
            missing = sorted((g_count - p_count).elements())
            extra = sorted((p_count - g_count).elements())
            mismatches.append((cid, g_status, p_status, missing, extra))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cases": len(gold),
        "status_correct": status_ok,
        "status_accuracy": status_ok / len(gold),
        "exact_case": exact_ok,
        "sequence_accuracy": sequence_ok / len(gold),
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "field_correct": field_ok, "field_total": field_total,
        "field_accuracy": field_ok / field_total if field_total else 0.0,
        "mismatches": mismatches,
    }


def main() -> int:
    datasets = load_datasets(DATASET_DIR)
    corpus = load_evidence_corpus(DATASET_DIR)
    links = global_links(datasets, corpus)

    sample_rows, sample_diag, sample_scope = audit_requests(datasets.sample_requests, datasets, corpus, links)
    scores = score_rows(DATASET_DIR / "sample_output.csv", sample_rows)
    print("== SAMPLE EVALUATION (32 public cases) ==")
    for key in ("cases", "status_correct", "status_accuracy", "exact_case",
                "sequence_accuracy", "tp", "fp", "fn", "precision", "recall", "f1",
                "field_correct", "field_total", "field_accuracy"):
        print(f"{key}: {scores[key]}")
    print("\nmismatches (case, gold_status, pred_status, missing steps, extra steps):")
    for item in scores["mismatches"]:
        print(" ", item)
    sample_errors = validate_output_rows(
        sample_rows, datasets.sample_requests, datasets, sample_diag, sample_scope
    )
    print("sample contract errors:", len(sample_errors))

    with open(REPO_ROOT / "output.csv", encoding="utf-8") as f:
        written = [(r["case_id"], r["deletion_status"], r["steps_json"]) for r in csv.DictReader(f)]
    fresh, diagnostics, scope = audit_requests(datasets.deletion_requests, datasets, corpus, links)
    errors = validate_output_rows(written, datasets.deletion_requests, datasets, diagnostics, scope)
    steps = [json.loads(s) for _, _, s in written]
    print("\n== FULL OUTPUT VALIDATION (518 cases) ==")
    print("rows:", len(written))
    print("status_counts:", dict(Counter(status for _, status, _ in written)))
    print("total_steps:", sum(len(s) for s in steps))
    print("empty_arrays:", dict(Counter(status for (_, status, _), s in zip(written, steps) if not s)))
    print("matches_fresh_run:", written == fresh)
    print("errors:", len(errors))
    for err in errors[:50]:
        print(" ", err)

    print("\n== LINKER ==")
    methods = Counter(l.method for ls in links.links.values() for l in ls)
    print("links_by_method:", dict(methods))
    if links.phase is not None:
        print(f"phase_model: period={links.phase.period}s score={links.phase.score:.3f} "
              f"offsets={len(links.phase.offsets)} residuals={sorted(links.phase.residual_counts.items())}")
    print("naming_rule:", links.naming_rule)
    ties = [d for d in links.diagnostics if " tie " in d]
    print("low_margin_assignments:", len(ties))
    print("other_diagnostics:", len(links.diagnostics) - len(ties))

    failed = errors or sample_errors or written != fresh
    if failed:
        print("\nNOTE: failures above are reported as-is; they are not masked.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
