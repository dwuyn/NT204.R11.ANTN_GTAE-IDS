"""Build one-day cross-dataset graphs (CIC-IDS2018) for the MAY experiment.

Why a separate builder: ``src/build_dataset.py`` implements protocol T (Monday benign ->
Tuesday-Friday test) over the seven CIC-IDS2017 days. A one-day CIC-IDS2018 day is not
expressible with it, and CIC-IDS2018 ships **per-host captures** that must be merged first.

Layout written (same contract as T, so ``scripts/train_all.py`` and ``src/eval.py`` work
unchanged)::

    data/graphs/2018/p{p}/{train1,train2,test}.npz
    data/graphs/2018/summary.json

Split rule (temporal, leak-free by construction):
  * ``cutoff`` = t_first of the earliest attack flow (or ``--attack-start``), i.e. every
    training flow starts strictly before the first attack in the captures;
  * ``train1`` / ``train2`` = benign flows with ``t_first < cutoff``, sampled without
    replacement (5000 / 2000 by default);
  * ``test`` = benign flows with ``t_first >= cutoff`` (5000) plus attack flows (5000 per
    class; this day has one class, DoS-Hulk).

Flows are renumbered per capture because every capture restarts flow_id at 1; UNCERTAIN
labels (including the closed-port-21 SlowHTTPTest residue) are dropped by ``build_graph``.

Prerequisites (see docs/DATA_ACQUISITION.md)::

    python -m src.parse_pcap --pcap .../UCAP172.31.69.25-part1.pcap --out data/processed/2018 --day f20180216
    python -m src.label --flows data/processed/2018/flows_f20180216.parquet \
        --schedule configs/cicids2018_schedule.yaml --offset-minutes -240 \
        --out data/processed/2018/flows_f20180216_labeled.parquet
    # ... same for the five capPC1-* captures (tags f20180216_c1..c5)

Usage::

    python scripts/build_cross_dataset_graphs.py --ps 2 3 4 5 6 7 8
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import random
import sys
from collections import defaultdict
from typing import Any, Mapping

import pyarrow.parquet as pq

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.graph_builder import BENIGN, ATTACK, build_graph, load_packets, save_graph  # noqa: E402

DEFAULT_TAGS = ["f20180216"] + [f"f20180216_c{i}" for i in range(1, 6)]


def _load_flows(processed: pathlib.Path, tags: list[str]) -> list[dict[str, Any]]:
    """Read labeled flows and give them globally unique ids (per-capture ids collide)."""
    flows: list[dict[str, Any]] = []
    offset = 0
    for tag in tags:
        rows = pq.read_table(processed / f"flows_{tag}_labeled.parquet").to_pylist()
        for row in rows:
            row["day"] = tag
            row["orig_flow_id"] = int(row["flow_id"])
            row["flow_id"] = offset + int(row["flow_id"])
        offset += max((int(r["orig_flow_id"]) for r in rows), default=0) + 1
        flows.extend(rows)
        print(f"  {tag}: {len(rows):8d} flows", flush=True)
    return flows


def _packets_for(
    processed: pathlib.Path, selected: list[Mapping[str, Any]]
) -> dict[int, list[dict[str, Any]]]:
    """Load packets only for the selected flows, keyed by the renumbered flow_id."""
    ids_by_tag: dict[str, list[int]] = defaultdict(list)
    for flow in selected:
        ids_by_tag[str(flow["day"])].append(int(flow["orig_flow_id"]))
    merged: dict[int, list[dict[str, Any]]] = {}
    for tag, ids in ids_by_tag.items():
        by_orig = load_packets(processed / f"packets_{tag}.parquet", ids)
        for flow in selected:
            if str(flow["day"]) != tag:
                continue
            rows = by_orig.get(int(flow["orig_flow_id"]))
            if rows:
                merged[int(flow["flow_id"])] = rows
    return merged


def _summary(name: str, graph) -> dict[str, Any]:
    return {
        "name": name,
        "edges": int(graph.y.shape[0]),
        "nodes": graph.num_nodes,
        "benign": int((graph.y == 0).sum()),
        "attack": int((graph.y == 1).sum()),
        "attack_types": {
            t: int((graph.attack_type == t).sum())
            for t in sorted(set(graph.attack_type.tolist())) if t
        },
        "day_edges": {
            d: int((graph.day == d).sum())
            for d in sorted(set(graph.day.tolist())) if d
        },
    }


def build(
    processed: pathlib.Path,
    out_dir: pathlib.Path,
    ps: list[int],
    tags: list[str],
    seed: int = 0,
    train1_n: int = 5000,
    train2_n: int = 2000,
    test_benign_n: int = 5000,
    attack_cap: int = 5000,
    attack_start: float | None = None,
    train_tags: list[str] | None = None,
    test_benign_tags: list[str] | None = None,
) -> dict[str, Any]:
    print(f"loading {len(tags)} captures from {processed}", flush=True)
    flows = _load_flows(processed, tags)
    attacks = [f for f in flows if int(f["label"]) == ATTACK]
    if not attacks:
        raise SystemExit("no attack flows labeled; check the schedule and --offset-minutes")
    cross_day = bool(train_tags and test_benign_tags)
    if cross_day:
        # cross-day protocol: train on the benign day(s), test on *another* benign day plus
        # the attack windows; no cutoff is needed because the days are disjoint by construction.
        cutoff = float("nan")
        train_set = set(train_tags or [])
        test_benign_set = set(test_benign_tags or [])
        missing = (train_set | test_benign_set) - set(tags)
        if missing:
            raise SystemExit(f"tag(s) not loaded: {sorted(missing)}")
    else:
        cutoff = float(attack_start) if attack_start is not None else min(float(f["t_first"]) for f in attacks)

    rng = random.Random(seed)
    summary: dict[str, Any] = {
        "protocol": "cross_dataset_day",
        "processed": str(processed),
        "tags": tags,
        "seed": seed,
        "split_mode": "cross_day" if cross_day else "cutoff",
        "train_tags": list(train_tags or []),
        "test_benign_tags": list(test_benign_tags or []),
        "cutoff_epoch": None if cross_day else cutoff,
        "cutoff_utc": None if cross_day else dt.datetime.utcfromtimestamp(cutoff).isoformat() + "Z",
        "flows_total": len(flows),
        "benign_total": sum(1 for f in flows if int(f["label"]) == BENIGN),
        "attack_total": len(attacks),
        "uncertain_total": sum(1 for f in flows if int(f["label"]) == -1),
        "attack_types_total": {
            t: sum(1 for f in attacks if f.get("attack_type") == t)
            for t in sorted({str(f.get("attack_type")) for f in attacks})
        },
        "splits": {},
    }

    for p in ps:
        eligible = [f for f in flows if int(f["label"]) in (BENIGN, ATTACK)
                    and int(f.get("n_pkts_total", 0)) >= p]
        if cross_day:
            train_pool = [f for f in eligible if int(f["label"]) == BENIGN and str(f["day"]) in train_set]
            test_benign_pool = [f for f in eligible if int(f["label"]) == BENIGN and str(f["day"]) in test_benign_set]
        else:
            train_pool = [f for f in eligible if int(f["label"]) == BENIGN and float(f["t_first"]) < cutoff]
            test_benign_pool = [f for f in eligible if int(f["label"]) == BENIGN and float(f["t_first"]) >= cutoff]
        attack_pool = [f for f in eligible if int(f["label"]) == ATTACK]
        need = train1_n + train2_n
        if len(train_pool) < need:
            raise SystemExit(f"p={p}: benign training pool too small: {len(train_pool)} < {need}")

        rng.shuffle(train_pool)
        train1 = train_pool[:train1_n]
        train2 = train_pool[train1_n:train1_n + train2_n]
        rng.shuffle(test_benign_pool)
        # cap the attack budget *per class*: a single overwhelming class (PortScan has 426k
        # flows in ACI) must not crowd the other classes out of the test set.
        attack_groups: dict[str, list[Mapping[str, Any]]] = {}
        for flow in attack_pool:
            attack_groups.setdefault(str(flow.get("attack_type") or "unknown"), []).append(flow)
        test = list(test_benign_pool[:test_benign_n])
        for name in sorted(attack_groups):
            rng.shuffle(attack_groups[name])
            test.extend(attack_groups[name][:attack_cap])

        packets = _packets_for(processed, train1 + train2 + test)
        base = out_dir / f"p{p}"
        graphs = {
            "train1": build_graph(train1, packets, p),
            "train2": build_graph(train2, packets, p),
            "test": build_graph(test, packets, p),
        }
        for name, graph in graphs.items():
            save_graph(graph, base / f"{name}.npz")
        summary["splits"][f"p{p}"] = {
            "pools": {
                "train_benign": len(train_pool),
                "test_benign": len(test_benign_pool),
                "attack": len(attack_pool),
                "attack_by_class": {k: len(v) for k, v in sorted(attack_groups.items())},
            },
            "graphs": {name: _summary(name, graph) for name, graph in graphs.items()},
        }
        print(f"p={p}: " + ", ".join(
            f"{name}={int(g.y.shape[0])} edges ({int((g.y == 1).sum())} attack)"
            for name, g in graphs.items()), flush=True)

    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"wrote {out_dir}/summary.json")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--processed", default="data/processed/2018")
    parser.add_argument("--out", default="data/graphs/2018")
    parser.add_argument("--tags", nargs="+", default=DEFAULT_TAGS)
    parser.add_argument("--ps", nargs="+", type=int, default=list(range(2, 9)))
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--train1", type=int, default=5000)
    parser.add_argument("--train2", type=int, default=2000)
    parser.add_argument("--test-benign", type=int, default=5000)
    parser.add_argument("--attack-cap", type=int, default=5000)
    parser.add_argument(
        "--attack-start",
        default=None,
        help="optional ISO-8601 UTC cutoff; default = t_first of the earliest attack flow",
    )
    parser.add_argument(
        "--train-tags",
        nargs="+",
        default=None,
        help="cross-day mode: tags whose benign flows form the training pool",
    )
    parser.add_argument(
        "--test-benign-tags",
        nargs="+",
        default=None,
        help="cross-day mode: tags whose benign flows form the test benign pool",
    )
    args = parser.parse_args(argv)

    attack_start = None
    if args.attack_start:
        text = args.attack_start.replace("Z", "+00:00")
        attack_start = dt.datetime.fromisoformat(text).replace(tzinfo=dt.timezone.utc).timestamp()

    build(
        pathlib.Path(args.processed),
        pathlib.Path(args.out),
        args.ps,
        list(args.tags),
        seed=args.seed,
        train1_n=args.train1,
        train2_n=args.train2,
        test_benign_n=args.test_benign,
        attack_cap=args.attack_cap,
        attack_start=attack_start,
        train_tags=args.train_tags,
        test_benign_tags=args.test_benign_tags,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
