#!/usr/bin/env python3
"""Build `T_engelen` p8 graphs: our graphs with the Engelen labels applied (L4).

Two changes only, both driven by `data/processed/engelen_label_map.parquet`:

* training (`train1`/`train2`, benign-only): drop edges whose flow the Engelen
  labelling calls anything other than BENIGN — a benign-only set that contains
  attack flows would train the autoencoder on attacks;
* test: replace `y`/`attack_type` where a flow is mapped (`X - Attempted` counts
  as an attack). Unmapped flows keep our labels.

    python scripts/build_engelen_graphs.py --p 8
    python scripts/train_all.py --graphs data/graphs/T_engelen --out experiments/T_engelen \
        --ps 8 --seeds 0 1 2 --epochs 100 --patience 100 --device cpu
    python -m src.eval --models experiments/T_engelen --graphs data/graphs/T_engelen \
        --out results/engelen_retrain --ps 8 --seeds 0 1 2 --device cpu
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.cic_graph import BENIGN_LABEL, normalize_label  # noqa: E402
from src.graph_builder import GraphArrays, load_graph, save_graph  # noqa: E402

SPLITS = ("train1", "train2", "test")


def load_map() -> dict[tuple[str, int], tuple[str, bool]]:
    path = REPO_ROOT / "data/processed/engelen_label_map.parquet"
    if not path.exists():
        raise FileNotFoundError(path)
    rows = pq.read_table(
        path, columns=["day", "flow_id", "engelen_label", "engelen_attempted"]
    ).to_pylist()
    return {
        (row["day"], int(row["flow_id"])): (row["engelen_label"], bool(row["engelen_attempted"]))
        for row in rows
        if row["engelen_label"] is not None
    }


def subset(graph: GraphArrays, keep: np.ndarray) -> GraphArrays:
    return GraphArrays(
        edge_index=graph.edge_index[:, keep],
        edge_attr=graph.edge_attr[keep],
        y=graph.y[keep],
        flow_id=graph.flow_id[keep],
        attack_type=graph.attack_type[keep],
        day=graph.day[keep],
        num_nodes=graph.num_nodes,
        p=graph.p,
    )


def build(src: Path, dst: Path, p: int) -> dict:
    label_map = load_map()
    summary = {"source": str(src), "p": p, "splits": {}}
    for split in SPLITS:
        graph = load_graph(src / f"p{p}" / f"{split}.npz")
        days = graph.day.tolist()
        flows = graph.flow_id.tolist()
        hits = [label_map.get((str(day), int(flow))) for day, flow in zip(days, flows)]

        if split == "test":
            y = graph.y.astype(np.int8).copy()
            attack_type = np.array(graph.attack_type, dtype=graph.attack_type.dtype)
            flipped = {"attack_to_benign": 0, "benign_to_attack": 0, "mapped": 0}
            for i, hit in enumerate(hits):
                if hit is None:
                    continue
                flipped["mapped"] += 1
                label, _attempted = hit
                is_attack = normalize_label(label) != BENIGN_LABEL
                if int(y[i]) == 1 and not is_attack:
                    flipped["attack_to_benign"] += 1
                elif int(y[i]) == 0 and is_attack:
                    flipped["benign_to_attack"] += 1
                y[i] = 1 if is_attack else 0
                attack_type[i] = "" if not is_attack else normalize_label(label)
            out = GraphArrays(
                edge_index=graph.edge_index,
                edge_attr=graph.edge_attr,
                y=y,
                flow_id=graph.flow_id,
                attack_type=attack_type,
                day=graph.day,
                num_nodes=graph.num_nodes,
                p=graph.p,
            )
            summary["splits"][split] = {
                "edges_in": int(graph.y.size),
                "edges_out": int(y.size),
                "attack_edges_out": int(y.sum()),
                **flipped,
            }
        else:
            drop = np.array(
                [
                    hit is not None and normalize_label(hit[0]) != BENIGN_LABEL
                    for hit in hits
                ],
                dtype=bool,
            )
            keep = ~drop
            out = subset(graph, keep)
            summary["splits"][split] = {
                "edges_in": int(graph.y.size),
                "edges_out": int(out.y.size),
                "dropped": int(drop.sum()),
            }
        save_graph(out, dst / f"p{p}" / f"{split}.npz")
        print(f"[engelen-graphs] {split}: {summary['splits'][split]}", flush=True)
    dst.mkdir(parents=True, exist_ok=True)
    (dst / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[engelen-graphs] wrote {dst}", flush=True)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--out", default="data/graphs/T_engelen")
    parser.add_argument("--p", type=int, nargs="+", default=[8])
    args = parser.parse_args(argv)
    for p in args.p:
        build(REPO_ROOT / args.graphs, REPO_ROOT / args.out, p)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
