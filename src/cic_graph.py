"""Paper-faithful ``P_paper`` graph construction from CICFlowMeter CSV rows.

The clean protocol ``T``/``T_fixed`` builds flows with ``src.parse_pcap``
(idle timeout 120 s, first 8 packets, ``>= p`` matched packets). That is the
correct reading of the paper's prose but it does not reproduce the paper's
test graph: at ``p = 8`` the paper (Table II/VII) reports 33,228 test edges
(40,744 nodes) and per-class counts such as PortScan 6,451 and Heartbleed
1,468, while ``T`` yields 30,907 edges with PortScan 204 and Heartbleed 1.

``P_paper`` instead treats the CICFlowMeter CSV rows as the flow definitions,
which is the only public artefact consistent with the paper's per-class edge
counts, and picks the exact per-class test counts from paper Table VII. Flows
with fewer than ``p`` matched pcap packets are zero padded instead of dropped,
because PortScan/heartbeat-style flows rarely carry 8 packets and the paper
still counts 6,451 of them.

Everything here is numpy-only; it reuses

* ``scripts.repro_cic_flows.load_flows`` (CSV timestamp AM/PM fix),
  ``_match`` (5-tuple + time-window row matching) and ``src.parse_pcap._open_reader``;
* ``src.packet_encoder.strip_headers``/``normalize``/``pack_direction``;
* ``src.graph_builder.GraphArrays``/``save_graph``.
"""

from __future__ import annotations

import json
import math
import random
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from src.graph_builder import GraphArrays, save_graph
from src.packet_encoder import BLOCK_DIM, normalize, pack_direction, strip_headers
from src.parse_pcap import _open_reader

REPO_ROOT = Path(__file__).resolve().parents[1]
CSV_DIR = REPO_ROOT / "data/raw/GeneratedLabelledFlows/TrafficLabelling"

BENIGN_LABEL = "BENIGN"

# Paper Table VII (test set, p = 8). Sum = 28,228 attack edges.
PAPER_TEST_COUNTS: dict[str, int] = {
    "DoS GoldenEye": 6090,
    "Heartbleed": 1468,
    "DoS Slowhttptest": 964,
    "DoS Slowloris": 1002,
    "DoS Hulk": 5000,
    "PortScan": 6451,
    "DDoS": 5000,
    "Infiltration": 1764,
    "Web Attack - Brute Force": 140,
    "SSH-Patator": 175,
    "FTP-Patator": 174,
}
PAPER_TEST_BENIGN = 5000
PAPER_TRAIN1 = 5000
PAPER_TRAIN2 = 2000
PAPER_BENIGN_ROWS = PAPER_TRAIN1 + PAPER_TRAIN2 + PAPER_TEST_BENIGN
PAPER_TEST_TOTAL = PAPER_TEST_BENIGN + sum(PAPER_TEST_COUNTS.values())  # 33,228
PAPER_NODES = {"train1": 7023, "train2": 3106, "test": 40744}

# Paper Table II: (nodes, edges) per split and p. Node ids depend on which exact CSV rows
# are drawn, so node counts are reported and never asserted; edge counts are the contract.
PAPER_TABLE_II: dict[int, dict[str, tuple[int, int]]] = {
    2: {"train1": (7160, 5000), "train2": (3736, 2000), "test": (44767, 38984)},
    3: {"train1": (7144, 5000), "train2": (3351, 2000), "test": (46285, 37971)},
    4: {"train1": (7135, 5000), "train2": (3145, 2000), "test": (45008, 36964)},
    5: {"train1": (7135, 5000), "train2": (3143, 2000), "test": (44118, 36093)},
    6: {"train1": (7129, 5000), "train2": (3136, 2000), "test": (43417, 35482)},
    7: {"train1": (7112, 5000), "train2": (3126, 2000), "test": (41643, 33974)},
    8: {"train1": (7023, 5000), "train2": (3106, 2000), "test": (40744, 33228)},
}

# Paper Table VII does not list these, so they never enter P_paper's test set.
# Paper Table VII: per-class TPR (%) at p = 8, the paper's own operating point.
PAPER_TABLE_VII_TPR: dict[str, float] = {
    "DoS GoldenEye": 99.08,
    "Heartbleed": 99.52,
    "DoS Slowhttptest": 99.79,
    "DoS Slowloris": 99.60,
    "DoS Hulk": 98.74,
    "PortScan": 98.50,
    "DDoS": 99.34,
    "Infiltration": 99.83,
    "Web Attack - Brute Force": 99.29,
    "SSH-Patator": 98.86,
    "FTP-Patator": 98.85,
}

PAPER_EXCLUDED_LABELS = (
    "Bot",
    "Web Attack - XSS",
    "Web Attack - Sql Injection",
)

PAPER_CSV_FILES: dict[str, tuple[str, ...]] = {
    "monday": ("Monday-WorkingHours.pcap_ISCX.csv",),
    "tuesday": ("Tuesday-WorkingHours.pcap_ISCX.csv",),
    "wednesday": ("Wednesday-workingHours.pcap_ISCX.csv",),
    "thursday": (
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
    ),
    "friday": (
        "Friday-WorkingHours-Morning.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
    ),
}
PAPER_PCAPS: dict[str, str] = {
    "monday": "data/raw/Monday-WorkingHours.pcap",
    "tuesday": "data/raw/Tuesday-WorkingHours.pcap",
    "wednesday": "data/raw/Wednesday-workingHours.pcap",
    "thursday": "data/raw/Thursday-WorkingHours.pcap",
    "friday": "data/raw/Friday-WorkingHours.pcap",
}

# A row is only useful if its pcap packets can be matched; the pool is capped
# at a multiple of the needed count so building does not need ~1e6 row dicts.
POOL_FACTOR = 2.0
POOL_MIN_HEADROOM = 200


def normalize_label(raw: str) -> str:
    """Map a raw CICFlowMeter label to the paper Table VII spelling."""
    text = " ".join(raw.replace("\ufffd", "-").split())
    if text in ("Infilteration", "Infiltration"):
        return "Infiltration"
    if text.startswith("Web Attack") and "Brute" in text:
        return "Web Attack - Brute Force"
    if text in ("DoS slowloris", "DoS Slowloris"):
        return "DoS Slowloris"
    if text in ("DoS Slowhttptest", "DoS SlowHTTPTest"):
        return "DoS Slowhttptest"
    return text


@dataclass(frozen=True)
class PaperSplit:
    """Rows chosen for ``P_paper``; ``shortfall`` records unattainable classes."""

    train1: list[dict[str, Any]]
    train2: list[dict[str, Any]]
    test: list[dict[str, Any]]
    shortfall: dict[str, dict[str, int]] = field(default_factory=dict)


def _pool_cap(
    day: str, label: str, factor: float = POOL_FACTOR, headroom: int = POOL_MIN_HEADROOM
) -> int:
    if label == BENIGN_LABEL:
        # Only Friday benign rows are used (the authors' code splits Friday).
        if day != "friday":
            return 0
        target = PAPER_BENIGN_ROWS
    elif label in PAPER_TEST_COUNTS:
        target = PAPER_TEST_COUNTS[label]
    else:
        return 0
    return int(math.ceil(factor * target)) + headroom


def load_paper_rows(
    csv_dir: str | Path | None = None,
    seed: int = 0,
    pool_factor: float = POOL_FACTOR,
    min_headroom: int = POOL_MIN_HEADROOM,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any]]:
    """Reservoir-sample the CSV rows ``P_paper`` can draw on, per day.

    Every CSV row of a needed label is a candidate; because the whole CSV set
    holds ~1e6 such rows, candidates are reservoir-sampled down to
    ``pool_factor * target + min_headroom`` per (day, label) with a seeded RNG,
    which keeps the selection deterministic and independent of CSV row order
    beyond that sampling.

    Returns ``(rows_by_day, stats)``; each row carries ``row_id``, ``day``,
    ``label`` (normalized), ``src``/``dst`` ``(ip, port)``, ``start``/``end``.
    """
    from scripts.repro_cic_flows import load_flows

    csv_root = Path(csv_dir) if csv_dir is not None else CSV_DIR
    rng = random.Random(seed)
    rows_by_day: dict[str, list[dict[str, Any]]] = {}
    reservoirs: dict[tuple[str, str], list[dict[str, Any]]] = {}
    seen: dict[tuple[str, str], int] = {}
    next_id = 0

    for day, filenames in PAPER_CSV_FILES.items():
        for filename in filenames:
            path = csv_root / filename
            if not path.exists():
                raise FileNotFoundError(path)
            flows_by_key = load_flows(str(path), label_filter=None)
            for key, flows in flows_by_key.items():
                for flow in flows:
                    label = normalize_label(flow["label"])
                    cap = _pool_cap(day, label, pool_factor, min_headroom)
                    if cap <= 0:
                        continue
                    slot = (day, label)
                    count = seen.get(slot, 0) + 1
                    seen[slot] = count
                    row = {
                        "row_id": next_id,
                        "day": day,
                        "label": label,
                        "src": flow["src"],
                        "dst": flow["dst"],
                        "start": flow["start"],
                        "end": flow["end"],
                    }
                    next_id += 1
                    reservoir = reservoirs.setdefault(slot, [])
                    if len(reservoir) < cap:
                        reservoir.append(row)
                    else:
                        j = rng.randrange(count)
                        if j < cap:
                            reservoir[j] = row
            del flows_by_key

    stats: dict[str, Any] = {"pools": {}}
    for (day, label), rows in sorted(reservoirs.items()):
        rows.sort(key=lambda r: r["row_id"])
        rows_by_day.setdefault(day, []).extend(rows)
        stats["pools"][f"{day}/{label}"] = {
            "csv_rows_seen": seen[(day, label)],
            "pool_rows": len(rows),
        }
    return rows_by_day, stats


def _index_by_key(rows: Iterable[dict[str, Any]]) -> tuple[dict, dict]:
    """Bucket rows by canonical 5-tuple and remember sorted start times."""
    by_key: dict[tuple, list[dict[str, Any]]] = {}
    for row in rows:
        key = (row["src"][0], row["src"][1], row["dst"][0], row["dst"][1])
        by_key.setdefault(key, []).append(row)
    starts: dict[tuple, list[float]] = {}
    for key, bucket in by_key.items():
        bucket.sort(key=lambda r: r["start"])
        starts[key] = [r["start"] for r in bucket]
    return by_key, starts


def collect_paper_packets(
    rows_by_day: Mapping[str, Sequence[dict[str, Any]]],
    pcap_paths: Mapping[str, str | Path] | None = None,
    p: int = 8,
) -> tuple[dict[int, list[tuple[bytes, int]]], dict[str, Any]]:
    """Assign up to ``p`` pcap packets to each candidate CSV row.

    A packet belongs to a row when its 5-tuple matches either orientation and
    its timestamp falls in the row's window (``scripts.repro_cic_flows._match``).
    Direction 0 means the packet travels row ``src`` -> ``dst``.
    """
    import dpkt

    from scripts.repro_cic_flows import _match

    if p < 1:
        raise ValueError(f"p must be >= 1, got {p}")
    paths = dict(PAPER_PCAPS) if pcap_paths is None else dict(pcap_paths)
    packets_by_row: dict[int, list[tuple[bytes, int]]] = {}
    stats: dict[str, Any] = {"days": {}}

    for day, rows in sorted(rows_by_day.items()):
        if not rows:
            continue
        pcap = Path(paths[day])
        if not pcap.is_absolute():
            pcap = REPO_ROOT / pcap
        if not pcap.exists():
            raise FileNotFoundError(pcap)
        by_key, starts = _index_by_key(rows)
        day_stats = {"pcap": str(pcap), "packets_read": 0, "tcp_packets": 0, "matched": 0}
        with open(pcap, "rb") as fh:
            reader = _open_reader(fh)
            for ts, buf in reader:
                day_stats["packets_read"] += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not isinstance(ip, dpkt.ip.IP) or ip.p != dpkt.ip.IP_PROTO_TCP:
                        continue
                    tcp = ip.data
                    if not isinstance(tcp, dpkt.tcp.TCP):
                        continue
                except Exception:
                    continue
                day_stats["tcp_packets"] += 1
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                key = (src, tcp.sport, dst, tcp.dport)
                rev = (dst, tcp.dport, src, tcp.sport)
                row = None
                direction = 0
                if key in by_key:
                    row = _match(by_key[key], starts[key], ts)
                if row is None and rev in by_key:
                    row = _match(by_key[rev], starts[rev], ts)
                    direction = 1
                if row is None:
                    continue
                rid = int(row["row_id"])
                kept = packets_by_row.get(rid)
                if kept is not None and len(kept) >= p:
                    continue
                raw = bytes(ip)
                ihl, thl = ip.hl * 4, tcp.off * 4
                if thl < 20 or len(raw) < ihl + thl:
                    continue
                packets_by_row.setdefault(rid, []).append(
                    (strip_headers(raw[: ihl + thl]), direction)
                )
                day_stats["matched"] += 1
        day_stats["candidate_rows"] = sum(len(v) for v in by_key.values())
        day_stats["rows_with_packets"] = sum(
            1
            for bucket in by_key.values()
            for row in bucket
            if int(row["row_id"]) in packets_by_row
        )
        print(
            f"[cic_graph] {day}: {day_stats['packets_read']} packets, "
            f"{day_stats['tcp_packets']} tcp, {day_stats['matched']} matched, "
            f"{day_stats['rows_with_packets']}/{day_stats['candidate_rows']} rows with packets",
            flush=True,
        )
        stats["days"][day] = day_stats
    return packets_by_row, stats


def encode_edge_padded(
    packets: Sequence[tuple[bytes, int]], p: int
) -> np.ndarray:
    """(50 * p,) edge feature from the first ``p`` packets; missing slots stay zero."""
    if p < 1:
        raise ValueError(f"p must be >= 1, got {p}")
    if not packets:
        raise ValueError("flow has no packets to encode")
    out = np.zeros(BLOCK_DIM * p, dtype=np.float32)
    for i, (kept, direction) in enumerate(packets[:p]):
        out[i * BLOCK_DIM : (i + 1) * BLOCK_DIM] = pack_direction(
            normalize(kept), direction
        )
    return out


def select_paper_split(
    rows_by_day: Mapping[str, Sequence[dict[str, Any]]],
    packets_by_row: Mapping[int, Sequence[tuple[bytes, int]]],
    seed: int = 0,
) -> PaperSplit:
    """Pick paper Table VII counts from rows that actually have packets."""
    usable = [
        row
        for rows in rows_by_day.values()
        for row in rows
        if packets_by_row.get(int(row["row_id"]))
    ]
    benign = [
        row
        for row in usable
        if row["label"] == BENIGN_LABEL and row["day"] == "friday"
    ]
    if len(benign) < PAPER_BENIGN_ROWS:
        raise ValueError(
            f"Friday benign pool with packets too small: {len(benign)} < {PAPER_BENIGN_ROWS}"
        )
    rng = random.Random(seed)
    rng.shuffle(benign)
    train1 = benign[:PAPER_TRAIN1]
    train2 = benign[PAPER_TRAIN1 : PAPER_TRAIN1 + PAPER_TRAIN2]
    test_benign = benign[PAPER_TRAIN1 + PAPER_TRAIN2 : PAPER_BENIGN_ROWS]

    test = list(test_benign)
    shortfall: dict[str, dict[str, int]] = {}
    for i, (attack, target) in enumerate(PAPER_TEST_COUNTS.items()):
        pool = [row for row in usable if row["label"] == attack]
        random.Random(seed + 1 + i).shuffle(pool)
        selected = pool[:target]
        test.extend(selected)
        entry = {
            "paper_target": target,
            "rows_with_packets": len(pool),
            "selected": len(selected),
        }
        if len(selected) < target:
            entry["unattainable"] = 1
            shortfall[attack] = entry
    if shortfall:
        missing = ", ".join(
            f"{name} {info['selected']}/{info['paper_target']}"
            for name, info in shortfall.items()
        )
        print(f"[cic_graph] unattainable paper counts: {missing}", flush=True)
    return PaperSplit(train1=train1, train2=train2, test=test, shortfall=shortfall)


def build_graph_rows(
    rows: Sequence[dict[str, Any]],
    packets_by_row: Mapping[int, Sequence[tuple[bytes, int]]],
    p: int,
) -> GraphArrays:
    """Encode rows into ``GraphArrays``; rows without packets are dropped."""
    if not 1 <= p <= 8:
        raise ValueError(f"p must be in 1..8 (paper scope), got {p}")
    node_ids: dict[tuple[str, int], int] = {}
    edge_index: list[tuple[int, int]] = []
    edge_attrs: list[np.ndarray] = []
    ys: list[int] = []
    flow_ids: list[int] = []
    attack_types: list[str] = []
    days: list[str] = []

    for row in rows:
        packets = packets_by_row.get(int(row["row_id"]))
        if not packets:
            continue
        endpoints = []
        for endpoint in (row["src"], row["dst"]):
            key = (str(endpoint[0]), int(endpoint[1]))
            if key not in node_ids:
                node_ids[key] = len(node_ids)
            endpoints.append(node_ids[key])
        edge_index.append((endpoints[0], endpoints[1]))
        edge_attrs.append(encode_edge_padded(packets, p))
        benign = row["label"] == BENIGN_LABEL
        ys.append(0 if benign else 1)
        flow_ids.append(int(row["row_id"]))
        attack_types.append("" if benign else str(row["label"]))
        days.append(str(row["day"]))

    if not edge_index:
        raise ValueError("no rows with packets; graph would be empty")
    return GraphArrays(
        edge_index=np.asarray(edge_index, dtype=np.int32).reshape(-1, 2).T,
        edge_attr=np.asarray(edge_attrs, dtype=np.float32).reshape(-1, BLOCK_DIM * p),
        y=np.asarray(ys, dtype=np.int8),
        flow_id=np.asarray(flow_ids, dtype=np.int64),
        attack_type=np.asarray(attack_types, dtype=str),
        day=np.asarray(days, dtype=str),
        num_nodes=len(node_ids),
        p=p,
    )


def _padding_stats(
    rows: Sequence[dict[str, Any]],
    packets_by_row: Mapping[int, Sequence[tuple[bytes, int]]],
    p: int,
) -> dict[str, Any]:
    counts = np.asarray(
        [len(packets_by_row[int(r["row_id"])]) for r in rows if packets_by_row.get(int(r["row_id"]))],
        dtype=np.int64,
    )
    if counts.size == 0:
        return {"edges": 0}
    return {
        "edges": int(counts.size),
        "packets_min": int(counts.min()),
        "packets_median": float(np.median(counts)),
        "packets_mean": float(counts.mean()),
        "padded_edges": int((counts < p).sum()),
        "padded_fraction": float((counts < p).mean()),
    }


def build_paper_graphs(
    out_dir: str | Path,
    ps: Sequence[int] = (8,),
    seed: int = 0,
    csv_dir: str | Path | None = None,
    pcap_paths: Mapping[str, str | Path] | None = None,
) -> dict[str, Any]:
    """Build ``P_paper`` train1/train2/test graphs for every ``p`` in ``ps``."""
    if not ps:
        raise ValueError("ps must not be empty")
    max_p = max(ps)
    if not 1 <= max_p <= 8 or any(not 1 <= p <= max_p for p in ps):
        raise ValueError(f"ps must be within 1..8, got {ps}")

    rows_by_day, row_stats = load_paper_rows(csv_dir=csv_dir, seed=seed)
    packets_by_row, packet_stats = collect_paper_packets(
        rows_by_day, pcap_paths=pcap_paths, p=max_p
    )
    split = select_paper_split(rows_by_day, packets_by_row, seed=seed)

    out_root = Path(out_dir)
    summary: dict[str, Any] = {
        "split": "P_paper",
        "seed": seed,
        "paper_targets": {
            "train1": PAPER_TRAIN1,
            "train2": PAPER_TRAIN2,
            "test": PAPER_TEST_TOTAL,
            "test_benign": PAPER_TEST_BENIGN,
            "test_attacks": dict(PAPER_TEST_COUNTS),
            "nodes": dict(PAPER_NODES),
        },
        "rows": row_stats,
        "packets": packet_stats,
        "shortfall": split.shortfall,
        "graphs": {},
    }
    for p in ps:
        p_dir = out_root / f"p{p}"
        p_summary: dict[str, Any] = {}
        for name, rows in (
            ("train1", split.train1),
            ("train2", split.train2),
            ("test", split.test),
        ):
            graph = build_graph_rows(rows, packets_by_row, p)
            path = p_dir / f"{name}.npz"
            save_graph(graph, path)
            p_summary[name] = {
                "edges": int(graph.edge_index.shape[1]),
                "nodes": int(graph.num_nodes),
                "positives": int((graph.y == 1).sum()),
                "padding": _padding_stats(rows, packets_by_row, p),
            }
        counts: dict[str, int] = {}
        for kind in graph.attack_type:
            if kind:
                counts[str(kind)] = counts.get(str(kind), 0) + 1
        p_summary["test_attack_counts"] = counts
        summary["graphs"][f"p{p}"] = p_summary
        print(
            f"[cic_graph] p={p}: train1={p_summary['train1']['edges']} "
            f"train2={p_summary['train2']['edges']} test={p_summary['test']['edges']} "
            f"nodes={p_summary['test']['nodes']}",
            flush=True,
        )

    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


if __name__ == "__main__":
    raise SystemExit("use scripts/build_paper_graphs.py")
