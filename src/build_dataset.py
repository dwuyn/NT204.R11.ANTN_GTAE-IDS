"""Build train/test graph artifacts for every p (design doc §4.5, T9/T14).

Temporal protocol T (primary): train1/train2 from Monday benign, test from
Tuesday-Friday. Random protocol R is available for the paper-like comparison.

Usage:
    python -m src.build_dataset --p 2 3 4 5 6 7 8
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

import pyarrow.parquet as pq

from src.graph_builder import (
    build_graph,
    load_packets,
    save_graph,
    select_random,
    select_temporal,
)

DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")


def load_labeled(processed: Path, days=DAYS) -> dict[str, list[dict[str, Any]]]:
    flows_by_day = {}
    for day in days:
        rows = pq.read_table(processed / f"flows_{day}_labeled.parquet").to_pylist()
        for row in rows:
            row["day"] = day
        flows_by_day[day] = rows
    return flows_by_day


def _packets_for(
    processed: Path,
    selected: list[Mapping[str, Any]],
    cache: dict[str, dict[int, list[dict[str, Any]]]] | None = None,
) -> dict[int, list[dict[str, Any]]]:
    ids_by_day: dict[str, list[int]] = defaultdict(list)
    for flow in selected:
        ids_by_day[str(flow["day"])].append(int(flow["flow_id"]))
    merged: dict[int, list[dict[str, Any]]] = {}
    for day, ids in ids_by_day.items():
        if cache is not None and day in cache:
            by_flow = cache[day]
            merged.update({fid: by_flow[fid] for fid in ids if fid in by_flow})
        else:
            merged.update(load_packets(processed / f"packets_{day}.parquet", ids))
    return merged


def _summary(name: str, graph) -> dict[str, Any]:
    attack_types: dict[str, int] = {}
    for value in graph.attack_type.tolist():
        if value:
            attack_types[value] = attack_types.get(value, 0) + 1
    return {
        "name": name,
        "edges": int(graph.y.shape[0]),
        "nodes": graph.num_nodes,
        "benign": int((graph.y == 0).sum()),
        "attack": int((graph.y == 1).sum()),
        "attack_types": dict(sorted(attack_types.items())),
    }


def build(
    processed: Path,
    out_dir: Path,
    ps: list[int],
    split: str = "T",
    seed: int = 0,
    train1_n: int = 5000,
    train2_n: int = 2000,
    test_benign_n: int = 5000,
    attack_cap: int = 5000,
    min_packets: int | None = None,
    tag: str | None = None,
) -> dict[str, Any]:
    flows_by_day = load_labeled(processed)
    all_flows = [flow for rows in flows_by_day.values() for flow in rows]
    summary: dict[str, Any] = {}
    base_dir = out_dir / (tag or split)

    for p in ps:
        min_p = p if min_packets is None else min_packets
        if split == "T":
            selection = select_temporal(
                flows_by_day,
                seed=seed,
                train1_n=train1_n,
                train2_n=train2_n,
                test_benign_n=test_benign_n,
                attack_cap=attack_cap,
                min_packets=min_p,
            )
        else:
            selection = select_random(
                all_flows,
                seed=seed,
                train1_n=train1_n,
                train2_n=train2_n,
                test_benign_n=test_benign_n,
                attack_cap=attack_cap,
                min_packets=min_p,
            )

        train_flows = selection.train1 + selection.train2
        train_packets = _packets_for(processed, train_flows)
        train1_graph = build_graph(selection.train1, train_packets, p)
        train2_graph = build_graph(selection.train2, train_packets, p)

        test_packets = _packets_for(processed, selection.test)
        test_graph = build_graph(selection.test, test_packets, p)

        base = base_dir / f"p{p}"
        save_graph(train1_graph, base / "train1.npz")
        save_graph(train2_graph, base / "train2.npz")
        save_graph(test_graph, base / "test.npz")

        summary[f"p{p}"] = {
            "train1": _summary("train1", train1_graph),
            "train2": _summary("train2", train2_graph),
            "test": _summary("test", test_graph),
        }

    (base_dir / "summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed", default="data/processed")
    parser.add_argument("--out", default="data/graphs")
    parser.add_argument("--p", type=int, nargs="+", default=[2, 4, 8])
    parser.add_argument("--split", choices=["T", "R"], default="T")
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--train1", type=int, default=5000)
    parser.add_argument("--train2", type=int, default=2000)
    parser.add_argument("--test-benign", type=int, default=5000)
    parser.add_argument("--attack-cap", type=int, default=5000)
    parser.add_argument(
        "--min-packets",
        type=int,
        default=None,
        help="override the per-p minimum (use 8 for a fixed population across p)",
    )
    parser.add_argument(
        "--tag", default=None, help="output subdirectory instead of the split name"
    )
    args = parser.parse_args(argv)

    summary = build(
        Path(args.processed),
        Path(args.out),
        args.p,
        split=args.split,
        seed=args.seed,
        train1_n=args.train1,
        train2_n=args.train2,
        test_benign_n=args.test_benign,
        attack_cap=args.attack_cap,
        min_packets=args.min_packets,
        tag=args.tag,
    )
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
