"""Tests for the one-day cross-dataset graph builder (CIC-IDS2018 protocol)."""

from __future__ import annotations

import pathlib

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq

from scripts.build_cross_dataset_graphs import build
from src.graph_builder import load_graph

FLOW_SCHEMA = pa.schema([
    ("flow_id", pa.int64()),
    ("src_ip", pa.string()),
    ("src_port", pa.int64()),
    ("dst_ip", pa.string()),
    ("dst_port", pa.int64()),
    ("t_first", pa.float64()),
    ("t_last", pa.float64()),
    ("n_pkts_total", pa.int64()),
    ("label", pa.int8()),
    ("attack_type", pa.string()),
])

PACKET_SCHEMA = pa.schema([
    ("flow_id", pa.int64()),
    ("pkt_idx", pa.int64()),
    ("ts", pa.float64()),
    ("dir", pa.int8()),
    ("kept25", pa.binary()),
])


def _write_capture(root: pathlib.Path, tag: str, flows: list[dict]) -> None:
    """Write one capture; a flow's stored packets = min(n_pkts_total, 8), as in parse_pcap."""
    packets = []
    for flow in flows:
        for idx in range(1, min(flow["n_pkts_total"], 8) + 1):
            packets.append({
                "flow_id": flow["flow_id"],
                "pkt_idx": idx,
                "ts": flow["t_first"] + 0.1 * idx,
                "dir": idx % 2,
                "kept25": bytes([flow["flow_id"] % 256]) * 25,
            })
    pq.write_table(pa.Table.from_pylist(flows, schema=FLOW_SCHEMA), root / f"flows_{tag}_labeled.parquet")
    pq.write_table(pa.Table.from_pylist(packets, schema=PACKET_SCHEMA), root / f"packets_{tag}.parquet")


def _flow(flow_id: int, t_first: float, label: int, attack: str | None = None, n: int = 8) -> dict:
    return {
        "flow_id": flow_id,
        "src_ip": "10.0.0.1",
        "src_port": 1000 + flow_id,
        "dst_ip": "10.0.0.2",
        "dst_port": 80,
        "t_first": t_first,
        "t_last": t_first + 1.0,
        "n_pkts_total": n,
        "label": label,
        "attack_type": attack,
    }


def test_split_is_temporal_and_graphs_are_disjoint(tmp_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    # capture "a" (ids 0..3, all benign) and capture "b" (ids 4..9). Capture b holds the
    # only post-cutoff benign flow (id 5 -> renumbered 9) and the two attacks.
    _write_capture(processed, "a", [_flow(i, t_first=100.0 + i, label=0) for i in range(4)])
    _write_capture(processed, "b", [
        _flow(0, t_first=200.0, label=0),                      # pre-cutoff benign
        _flow(1, t_first=210.0, label=0),                      # pre-cutoff benign
        _flow(2, t_first=300.0, label=1, attack="DoS-Hulk"),   # earliest attack
        _flow(3, t_first=301.0, label=1, attack="DoS-Hulk"),
        _flow(4, t_first=302.0, label=-1),                     # UNCERTAIN, must vanish
        _flow(5, t_first=400.0, label=0),                      # post-cutoff benign
    ])

    out = tmp_path / "graphs"
    summary = build(
        processed,
        out,
        ps=[2],
        tags=["a", "b"],
        seed=0,
        train1_n=2,
        train2_n=1,
        test_benign_n=1,
        attack_cap=1,
    )

    assert summary["cutoff_epoch"] == 300.0
    assert summary["attack_types_total"] == {"DoS-Hulk": 2}

    train1 = load_graph(out / "p2" / "train1.npz")
    train2 = load_graph(out / "p2" / "train2.npz")
    pre_cutoff_ids = {0, 1, 2, 3, 4, 5}          # capture a + b's two pre-cutoff benign flows
    for graph in (train1, train2):
        assert graph.y.tolist() == [0] * int(graph.y.shape[0])
        assert set(int(fid) for fid in graph.flow_id) <= pre_cutoff_ids

    test = load_graph(out / "p2" / "test.npz")
    assert int(test.y.sum()) == 1
    assert test.attack_type.tolist().count("DoS-Hulk") == 1
    assert int((test.y == 0).sum()) == 1
    # the benign test edge is capture b's post-cutoff flow (renumbered 4 + 5 = 9)
    assert test.flow_id[test.y == 0].tolist() == [9]
    assert test.edge_attr.shape[1] == 100        # 50 * p
    assert np.isfinite(test.edge_attr).all()

    ids = np.concatenate([train1.flow_id, train2.flow_id, test.flow_id])
    assert len(set(ids.tolist())) == ids.size


def test_flows_shorter_than_p_are_dropped(tmp_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    _write_capture(processed, "a", [_flow(i, t_first=100.0 + i, label=0) for i in range(4)])
    _write_capture(processed, "b", [
        _flow(0, t_first=400.0, label=0),                      # post-cutoff benign, 8 packets
        _flow(1, t_first=300.0, label=1, attack="DoS-Hulk", n=8),
        _flow(2, t_first=301.0, label=1, attack="DoS-Hulk", n=2),   # too short for p=8
    ])

    out = tmp_path / "graphs"
    summary = build(
        processed, out, ps=[2, 8], tags=["a", "b"], seed=0,
        train1_n=2, train2_n=1, test_benign_n=1, attack_cap=2,
    )
    p2 = summary["splits"]["p2"]["graphs"]["test"]
    p8 = summary["splits"]["p8"]["graphs"]["test"]
    assert p2["edges"] == 3 and p2["attack"] == 2
    assert p8["edges"] == 2 and p8["attack"] == 1


def test_cross_day_mode_uses_explicit_tags(tmp_path):
    processed = tmp_path / "processed"
    processed.mkdir()
    _write_capture(processed, "b1", [_flow(i, t_first=100.0 + i, label=0) for i in range(4)])
    _write_capture(processed, "b2", [
        _flow(0, t_first=100.0, label=0),
        _flow(1, t_first=101.0, label=0),
        _flow(2, t_first=200.0, label=1, attack="DoS-Slowloris"),
    ])

    out = tmp_path / "graphs"
    summary = build(
        processed, out, ps=[2], tags=["b1", "b2"], seed=0,
        train1_n=2, train2_n=1, test_benign_n=1, attack_cap=1,
        train_tags=["b1"], test_benign_tags=["b2"],
    )
    assert summary["split_mode"] == "cross_day"
    assert summary["cutoff_epoch"] is None

    # b1 ids are 0..3; b2 ids are renumbered 4..6
    train = load_graph(out / "p2" / "train1.npz")
    assert set(int(f) for f in train.flow_id) <= {0, 1, 2, 3}
    test = load_graph(out / "p2" / "test.npz")
    assert int(test.y.sum()) == 1
    assert int((test.y == 0).sum()) == 1
    assert all(int(f) >= 4 for f in test.flow_id[test.y == 0])
