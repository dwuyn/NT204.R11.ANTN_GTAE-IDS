"""Tests for graph assembly (no PyG/torch required)."""

from __future__ import annotations

import numpy as np
import pytest

from src.graph_builder import (
    build_graph,
    load_graph,
    sample_flows,
    save_graph,
    select_random,
    select_temporal,
)


def _flow(flow_id, src, dst, label, attack=None, n=3):
    return {
        "flow_id": flow_id,
        "src_ip": src[0],
        "src_port": src[1],
        "dst_ip": dst[0],
        "dst_port": dst[1],
        "label": label,
        "attack_type": attack,
        "n_pkts_total": n,
    }


def _packets(flow_id, dirs, value):
    return [
        {"flow_id": flow_id, "pkt_idx": i + 1, "dir": d, "kept25": bytes([value]) * 25}
        for i, d in enumerate(dirs)
    ]


def test_build_graph_shapes_and_semantics():
    flows = [
        _flow(0, ("10.0.0.1", 1234), ("10.0.0.2", 80), 0),
        _flow(1, ("10.0.0.3", 5555), ("10.0.0.2", 80), 1, "DoS Hulk", n=2),
        _flow(2, ("10.0.0.4", 6666), ("10.0.0.2", 80), -1),
        _flow(3, ("10.0.0.5", 7777), ("10.0.0.2", 80), 0, n=1),
    ]
    packets = {
        0: _packets(0, [0, 1], 10),
        1: _packets(1, [0, 0], 20),
        2: _packets(2, [0, 1], 30),
        3: _packets(3, [0], 40),
    }
    graph = build_graph(flows, packets, p=2)

    assert graph.edge_attr.shape == (2, 100)
    assert graph.edge_index.shape == (2, 2)
    assert graph.num_nodes == 3
    assert graph.y.tolist() == [0, 1]
    assert graph.attack_type.tolist() == ["", "DoS Hulk"]
    assert graph.flow_id.tolist() == [0, 1]
    assert graph.edge_index.tolist() == [[0, 2], [1, 1]]

    # Flow 0: fwd packet in the first half of block 1, bwd packet in block 2.
    np.testing.assert_allclose(graph.edge_attr[0, :25], 10 / 255)
    assert np.all(graph.edge_attr[0, 25:75] == 0)
    np.testing.assert_allclose(graph.edge_attr[0, 75:], 10 / 255)


def test_save_load_roundtrip(tmp_path):
    flows = [_flow(0, ("10.0.0.1", 1), ("10.0.0.2", 2), 1, "PortScan")]
    packets = {0: _packets(0, [0, 1], 7)}
    graph = build_graph(flows, packets, p=2)

    path = tmp_path / "graph.npz"
    save_graph(graph, path)
    loaded = load_graph(path)

    assert loaded.p == 2 and loaded.num_nodes == graph.num_nodes
    np.testing.assert_array_equal(loaded.edge_index, graph.edge_index)
    np.testing.assert_array_equal(loaded.edge_attr, graph.edge_attr)
    assert loaded.attack_type.tolist() == ["PortScan"]


def test_sample_flows_is_deterministic_and_excludes():
    flows = [_flow(i, ("10.0.0.1", i), ("10.0.0.2", 80), 0) for i in range(50)]
    a = sample_flows(flows, 10, seed=0)
    b = sample_flows(flows, 10, seed=0)
    assert [f["flow_id"] for f in a] == [f["flow_id"] for f in b]

    exclude = {f["flow_id"] for f in a[:5]}
    c = sample_flows(flows, 50, seed=0, exclude=exclude)
    assert not (exclude & {f["flow_id"] for f in c})
    assert len(c) == 45


def test_sample_flows_filters_attack_type():
    flows = [
        _flow(0, ("10.0.0.1", 1), ("10.0.0.2", 80), 1, "DoS Hulk"),
        _flow(1, ("10.0.0.1", 2), ("10.0.0.2", 80), 1, "PortScan"),
    ]
    picked = sample_flows(flows, 10, attack_type="PortScan")
    assert [f["flow_id"] for f in picked] == [1]


def test_build_graph_rejects_invalid_p():
    with pytest.raises(ValueError):
        build_graph([], {}, p=0)


def _day_flow(flow_id, day, label, attack=None, n=3):
    flow = _flow(flow_id, ("10.0.0.1", flow_id), ("10.0.0.2", 80), label, attack, n=n)
    flow["day"] = day
    return flow


def test_select_temporal_keeps_monday_for_training():
    flows_by_day = {
        "monday": [_day_flow(i, "monday", 0) for i in range(800)],
        "tuesday": [_day_flow(1000 + i, "tuesday", 0) for i in range(100)]
        + [_day_flow(2000 + i, "tuesday", 1, "DoS Hulk") for i in range(100)]
        + [_day_flow(3000 + i, "tuesday", 1, "PortScan") for i in range(50)],
    }
    split = select_temporal(
        flows_by_day,
        seed=1,
        train1_n=100,
        train2_n=50,
        test_benign_n=30,
        attack_cap=20,
    )
    assert len(split.train1) == 100 and len(split.train2) == 50
    assert {f["day"] for f in split.train1 + split.train2} == {"monday"}
    assert {f["label"] for f in split.train1 + split.train2} == {0}
    assert not ({f["flow_id"] for f in split.train1} & {f["flow_id"] for f in split.train2})

    attacks = [f for f in split.test if f["label"] == 1]
    assert sum(f["attack_type"] == "DoS Hulk" for f in attacks) == 20
    assert sum(f["attack_type"] == "PortScan" for f in attacks) == 20
    assert sum(f["label"] == 0 for f in split.test) == 30


def test_select_temporal_filters_short_flows_and_raises():
    flows_by_day = {
        "monday": [_day_flow(i, "monday", 0, n=2) for i in range(100)],
        "tuesday": [],
    }
    with pytest.raises(ValueError):
        select_temporal(flows_by_day, train1_n=60, train2_n=20, min_packets=5)


def test_select_random_is_flow_disjoint():
    flows = [_day_flow(i, "monday" if i % 2 else "tuesday", 0) for i in range(1000)]
    flows += [_day_flow(2000 + i, "tuesday", 1, "DDoS") for i in range(100)]
    split = select_random(
        flows, seed=0, train1_n=100, train2_n=50, test_benign_n=100, attack_cap=10
    )
    train_ids = {f["flow_id"] for f in split.train1 + split.train2}
    test_ids = {f["flow_id"] for f in split.test}
    assert not (train_ids & test_ids)
    assert len(split.test) == 100 + 10
    assert {f["label"] for f in split.train1 + split.train2} == {0}
