#!/usr/bin/env python3
"""Verify ``P_paper`` graph composition against paper Table II/VII.

    python scripts/check_paper_counts.py --graphs data/graphs/P_paper

Hard failures (non-zero exit):

* ``train1`` edges != 5,000, ``train2`` != 2,000, test benign != 5,000;
* a test class count differs from the count the build recorded as feasible;
* any shortfall the build cannot attribute to an exhausted CSV pool;
* ``flow_id`` overlap across train1/train2/test.

Paper counts that no CICFlowMeter CSV row population can supply (Heartbleed,
Infiltration) are reported as ``csv_pool_exhausted`` and do not fail the check:
they are a data-availability finding, not a build bug. Node counts are reported
against paper Table II and never fail, because node ids depend on which exact
rows were drawn.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.cic_graph import (  # noqa: E402
    PAPER_NODES,
    PAPER_TRAIN1,
    PAPER_TRAIN2,
    PAPER_TEST_BENIGN,
    PAPER_TEST_COUNTS,
    PAPER_TEST_TOTAL,
)
from src.graph_builder import load_graph  # noqa: E402

SHORTFALL_TOLERANCE = 0.05


def _check(name: str, actual: int, expected: int, note: str = "") -> tuple[str, int, int, str, bool]:
    ok = actual == expected
    return (name, actual, expected, note or ("" if ok else "MISMATCH"), ok)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/P_paper")
    parser.add_argument("--p", type=int, default=8)
    parser.add_argument("--out", default="results/P_paper_counts.csv")
    args = parser.parse_args(argv)

    root = Path(args.graphs)
    p_dir = root / f"p{args.p}"
    summary_path = root / "summary.json"
    if not p_dir.is_dir():
        parser.error(f"missing graph directory {p_dir}")
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {}
    built = summary.get("graphs", {}).get(f"p{args.p}", {})
    shortfall = summary.get("shortfall", {})

    graphs = {name: load_graph(p_dir / f"{name}.npz") for name in ("train1", "train2", "test")}
    test = graphs["test"]

    rows: list[tuple[str, int, int, str, bool]] = [
        _check("train1_edges", int(graphs["train1"].edge_index.shape[1]), PAPER_TRAIN1),
        _check("train2_edges", int(graphs["train2"].edge_index.shape[1]), PAPER_TRAIN2),
    ]
    benign_test = int((test.y == 0).sum())
    rows.append(_check("test_benign_edges", benign_test, PAPER_TEST_BENIGN))

    counts: dict[str, int] = {}
    for kind in test.attack_type:
        if kind:
            counts[str(kind)] = counts.get(str(kind), 0) + 1

    unattainable: dict[str, int] = {}
    for attack, target in PAPER_TEST_COUNTS.items():
        actual = counts.get(attack, 0)
        if attack in shortfall:
            available = int(shortfall[attack].get("rows_with_packets", actual))
            unattainable[attack] = target - available
            ok = actual == available
            rows.append(
                (
                    f"test_{attack}",
                    actual,
                    target,
                    f"csv_pool_exhausted: only {available} CSV rows with packets "
                    f"({(target - available) / target:.1%} short)",
                    ok,
                )
            )
        else:
            rows.append(_check(f"test_{attack}", actual, target))

    unexpected = sorted(set(counts) - set(PAPER_TEST_COUNTS))
    for attack in unexpected:
        rows.append((f"test_{attack}", counts[attack], 0, "NOT IN PAPER TABLE VII", False))

    feasible_test = PAPER_TEST_BENIGN + sum(
        min(target, int(shortfall[a]["rows_with_packets"])) if a in shortfall else target
        for a, target in PAPER_TEST_COUNTS.items()
    )
    rows.append(
        (
            "test_edges",
            int(test.edge_index.shape[1]),
            feasible_test,
            f"paper Table II total {PAPER_TEST_TOTAL} "
            f"(deficit {PAPER_TEST_TOTAL - feasible_test} from unattainable classes)",
            int(test.edge_index.shape[1]) == feasible_test,
        )
    )
    for name, paper_nodes in PAPER_NODES.items():
        rows.append(
            (
                f"{name}_nodes",
                int(graphs[name].num_nodes),
                paper_nodes,
                "informational: node ids depend on the exact rows drawn",
                True,
            )
        )

    ids = {name: set(int(i) for i in graph.flow_id) for name, graph in graphs.items()}
    overlaps = {
        "train1&train2": len(ids["train1"] & ids["train2"]),
        "train1&test": len(ids["train1"] & ids["test"]),
        "train2&test": len(ids["train2"] & ids["test"]),
    }
    rows.append(
        (
            "flow_id_overlap",
            sum(overlaps.values()),
            0,
            json.dumps(overlaps, sort_keys=True),
            sum(overlaps.values()) == 0,
        )
    )
    benign_train = int(graphs["train1"].y.sum()) + int(graphs["train2"].y.sum())
    rows.append(
        (
            "train_attack_edges",
            benign_train,
            0,
            "train1/train2 must be benign-only",
            benign_train == 0,
        )
    )

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["check", "actual", "expected", "note", "ok"])
        for row in rows:
            writer.writerow([row[0], row[1], row[2], row[3], int(row[4])])

    failed = [row for row in rows if not row[4]]
    for name, actual, expected, note, ok in rows:
        flag = "ok  " if ok else "FAIL"
        print(f"{flag} {name:<34} {actual:>7} (expected {expected}){'  ' + note if note else ''}")
    if unattainable:
        for attack, deficit in sorted(unattainable.items()):
            share = deficit / PAPER_TEST_COUNTS[attack]
            level = "WARN" if share > SHORTFALL_TOLERANCE else "note"
            print(
                f"{level} {attack}: {deficit} of {PAPER_TEST_COUNTS[attack]} paper edges "
                f"unattainable from CICFlowMeter rows ({share:.1%} short)"
            )
    print(f"wrote {out}")
    if failed:
        print(f"FAILED {len(failed)} check(s)", flush=True)
        return 1
    print("all hard checks passed", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
