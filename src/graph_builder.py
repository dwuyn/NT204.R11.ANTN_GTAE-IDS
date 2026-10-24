"""Build PyG-ready graph arrays from labeled flows and encoded packets (T9).

Output is a plain ``.npz`` so preprocessing can run locally without PyTorch;
the Kaggle notebook converts it to ``torch_geometric.data.Data``:

    edge_index [2, E] int32   one directed entry per flow (use to_undirected)
    edge_attr  [E, 50p] float32
    y          [E] int8       0 benign, 1 attack
    flow_id    [E] int64
    attack_type[E] <U...      empty string for benign
    num_nodes  scalar int64
    p          scalar int64

Nodes are ``(ip, port)`` endpoints mapped to contiguous ids; IPs/ports never
enter ``edge_attr``.
"""

from __future__ import annotations

import argparse
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pyarrow as pa
import pyarrow.compute as pc
import pyarrow.parquet as pq

from src.label import ATTACK, BENIGN
from src.packet_encoder import encode_edge


@dataclass(frozen=True)
class GraphArrays:
    edge_index: np.ndarray
    edge_attr: np.ndarray
    y: np.ndarray
    flow_id: np.ndarray
    attack_type: np.ndarray
    day: np.ndarray
    num_nodes: int
    p: int


def sample_flows(
    flows: Sequence[Mapping[str, Any]],
    n: int,
    seed: int = 0,
    label: int | None = None,
    attack_type: str | None = None,
    exclude: Iterable[int] = (),
) -> list[Mapping[str, Any]]:
    """Sample at most ``n`` flows deterministically, excluding given flow ids."""
    excluded = set(exclude)
    pool = [
        flow
        for flow in flows
        if int(flow["flow_id"]) not in excluded
        and (label is None or int(flow["label"]) == label)
        and (attack_type is None or flow.get("attack_type") == attack_type)
    ]
    rng = random.Random(seed)
    if len(pool) <= n:
        return pool
    return rng.sample(pool, n)


def load_packets(
    path: str | Path, flow_ids: Iterable[int]
) -> dict[int, list[dict[str, Any]]]:
    """Load only the packet rows belonging to ``flow_ids``."""
    wanted = list(flow_ids)
    if not wanted:
        return {}
    table = pq.read_table(path)
    mask = pc.is_in(table["flow_id"], value_set=pa.array(wanted, type=pa.int64()))
    rows = table.filter(mask).to_pylist()
    by_flow: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        by_flow.setdefault(int(row["flow_id"]), []).append(row)
    return by_flow


@dataclass(frozen=True)
class SplitSelection:
    train1: list[Mapping[str, Any]]
    train2: list[Mapping[str, Any]]
    test: list[Mapping[str, Any]]


def _eligible(flow: Mapping[str, Any], min_packets: int) -> bool:
    return (
        int(flow["label"]) in (BENIGN, ATTACK)
        and int(flow.get("n_pkts_total", 0)) >= min_packets
    )


def _sample(pool: Sequence[Mapping[str, Any]], n: int, rng: random.Random):
    return rng.sample(list(pool), min(n, len(pool)))


def _sample_test(
    pool: Sequence[Mapping[str, Any]],
    benign_n: int,
    attack_cap: int,
    rng: random.Random,
) -> list[Mapping[str, Any]]:
    benign = [f for f in pool if int(f["label"]) == BENIGN]
    attacks: dict[str, list[Mapping[str, Any]]] = {}
    for flow in pool:
        if int(flow["label"]) == ATTACK:
            attacks.setdefault(str(flow.get("attack_type") or "unknown"), []).append(flow)
    selected = _sample(benign, benign_n, rng)
    for rows in attacks.values():
        selected.extend(_sample(rows, attack_cap, rng))
    return selected


def select_temporal(
    flows_by_day: Mapping[str, Sequence[Mapping[str, Any]]],
    seed: int = 0,
    train1_n: int = 5000,
    train2_n: int = 2000,
    test_benign_n: int = 5000,
    attack_cap: int = 5000,
    min_packets: int = 1,
) -> SplitSelection:
    """Protocol T: train on Monday benign, test on later days (design doc §4.5)."""
    train_pool = [
        flow
        for flow in flows_by_day.get("monday", ())
        if _eligible(flow, min_packets) and int(flow["label"]) == BENIGN
    ]
    if len(train_pool) < train1_n + train2_n:
        raise ValueError(
            f"Monday benign pool too small: {len(train_pool)} < {train1_n + train2_n}"
        )
    rng = random.Random(seed)
    rng.shuffle(train_pool)
    train1 = train_pool[:train1_n]
    train2 = train_pool[train1_n : train1_n + train2_n]

    test_pool = [
        flow
        for day, rows in flows_by_day.items()
        if day != "monday"
        for flow in rows
        if _eligible(flow, min_packets)
    ]
    test = _sample_test(test_pool, test_benign_n, attack_cap, rng)
    return SplitSelection(train1=train1, train2=train2, test=test)


def select_random(
    flows: Sequence[Mapping[str, Any]],
    seed: int = 0,
    train1_n: int = 5000,
    train2_n: int = 2000,
    test_benign_n: int = 5000,
    attack_cap: int = 5000,
    min_packets: int = 1,
) -> SplitSelection:
    """Protocol R: flow-level random split across all days (paper-like)."""
    eligible = [flow for flow in flows if _eligible(flow, min_packets)]
    benign = [flow for flow in eligible if int(flow["label"]) == BENIGN]
    if len(benign) < train1_n + train2_n + test_benign_n:
        raise ValueError(
            f"benign pool too small: {len(benign)} < "
            f"{train1_n + train2_n + test_benign_n}"
        )
    rng = random.Random(seed)
    rng.shuffle(benign)
    train1 = benign[:train1_n]
    train2 = benign[train1_n : train1_n + train2_n]
    held_out = benign[train1_n + train2_n :]
    test = _sample(held_out, test_benign_n, rng)
    for attack_type in sorted(
        {str(f.get("attack_type") or "unknown") for f in eligible if int(f["label"]) == ATTACK}
    ):
        rows = [
            f for f in eligible if int(f["label"]) == ATTACK and str(f.get("attack_type") or "unknown") == attack_type
        ]
        test.extend(_sample(rows, attack_cap, rng))
    return SplitSelection(train1=train1, train2=train2, test=test)


def build_graph(
    flows: Sequence[Mapping[str, Any]],
    packets_by_flow: Mapping[int, Sequence[Mapping[str, Any]]],
    p: int,
) -> GraphArrays:
    """Encode selected flows into edge arrays; UNCERTAIN/short flows are dropped."""
    if not 1 <= p <= 8:
        raise ValueError(f"p must be in 1..8 (paper scope), got {p}")
    node_ids: dict[tuple[str, int], int] = {}
    edge_index: list[tuple[int, int]] = []
    edge_attrs: list[np.ndarray] = []
    ys: list[int] = []
    flow_ids: list[int] = []
    attack_types: list[str] = []
    days: list[str] = []

    for flow in flows:
        label = int(flow["label"])
        if label not in (BENIGN, ATTACK):
            continue
        rows = sorted(packets_by_flow.get(int(flow["flow_id"]), ()), key=lambda r: r["pkt_idx"])
        if len(rows) < p:
            continue

        kept = [(row["kept25"], int(row["dir"])) for row in rows[:p]]
        edge_attrs.append(encode_edge(kept, p))

        src = (str(flow["src_ip"]), int(flow["src_port"]))
        dst = (str(flow["dst_ip"]), int(flow["dst_port"]))
        for endpoint in (src, dst):
            if endpoint not in node_ids:
                node_ids[endpoint] = len(node_ids)
        edge_index.append((node_ids[src], node_ids[dst]))

        ys.append(label)
        flow_ids.append(int(flow["flow_id"]))
        attack_types.append(str(flow.get("attack_type") or ""))
        days.append(str(flow.get("day") or ""))

    return GraphArrays(
        edge_index=np.asarray(edge_index, dtype=np.int32).reshape(-1, 2).T,
        edge_attr=np.asarray(edge_attrs, dtype=np.float32).reshape(-1, 50 * p),
        y=np.asarray(ys, dtype=np.int8),
        flow_id=np.asarray(flow_ids, dtype=np.int64),
        attack_type=np.asarray(attack_types, dtype=str),
        day=np.asarray(days, dtype=str),
        num_nodes=len(node_ids),
        p=p,
    )


def save_graph(graph: GraphArrays, path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(
        path,
        edge_index=graph.edge_index,
        edge_attr=graph.edge_attr,
        y=graph.y,
        flow_id=graph.flow_id,
        attack_type=graph.attack_type,
        day=graph.day,
        num_nodes=np.int64(graph.num_nodes),
        p=np.int64(graph.p),
    )


def load_graph(path: str | Path) -> GraphArrays:
    with np.load(path, allow_pickle=False) as data:
        return GraphArrays(
            edge_index=data["edge_index"],
            edge_attr=data["edge_attr"],
            y=data["y"],
            flow_id=data["flow_id"],
            attack_type=data["attack_type"],
            day=data["day"],
            num_nodes=int(data["num_nodes"]),
            p=int(data["p"]),
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flows", required=True, help="labeled flows parquet")
    parser.add_argument("--packets", required=True, help="packets parquet")
    parser.add_argument("--p", type=int, required=True)
    parser.add_argument("--benign", type=int, default=5000)
    parser.add_argument("--attack-cap", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    flows = pq.read_table(args.flows).to_pylist()
    selected = _sample_test(
        [f for f in flows if int(f["n_pkts_total"]) >= args.p],
        args.benign,
        args.attack_cap,
        random.Random(args.seed),
    )
    packets = load_packets(args.packets, [f["flow_id"] for f in selected])
    graph = build_graph(selected, packets, args.p)

    save_graph(graph, args.out)
    summary = {
        "out": args.out,
        "p": graph.p,
        "edges": int(graph.y.shape[0]),
        "benign": int((graph.y == BENIGN).sum()),
        "attack": int((graph.y == ATTACK).sum()),
        "nodes": graph.num_nodes,
        "attack_types": {
            str(t): int((graph.attack_type == t).sum())
            for t in sorted(set(graph.attack_type.tolist()) - {""})
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
