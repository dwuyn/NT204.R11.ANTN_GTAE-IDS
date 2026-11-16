"""Tests for the rolling-window graph used by the online latency harness."""

from __future__ import annotations

import numpy as np
import torch

from src.model_gtae import GTAE
from src.streaming import WindowGraph, embed_rows


def flow(flow_id, t, src=("10.0.0.1", 5000), dst=("10.0.0.2", 80), packets=8):
    stamps = [(t - 0.01 * i, b"\x11" * 25, 0) for i in range(packets)]
    return {
        "flow_id": flow_id,
        "src_ip": src[0],
        "src_port": src[1],
        "dst_ip": dst[0],
        "dst_port": dst[1],
        "t_first": t - 0.01 * packets,
        "t_last": t,
        "n_pkts_total": packets,
        "start_with_syn": True,
        "end_reason": "eof",
        "packets": stamps,
    }


def test_add_returns_last_row_and_arrays_track_edges():
    graph = WindowGraph(window=120.0)
    assert graph.num_nodes == 0
    for i in range(3):
        row = graph.add(flow(i, float(i), dst=(f"10.0.0.{i + 2}", 80)), 2)
        assert row == graph.num_edges - 1
    edge_index, edge_attr = graph.arrays(2)
    assert edge_index.shape == (2, 3) and edge_index.dtype == np.int32
    assert edge_attr.shape == (3, 100) and edge_attr.dtype == np.float32


def test_node_ids_are_monotone_and_never_pruned():
    graph = WindowGraph(window=10.0)
    graph.add(flow(0, 0.0), 8)
    nodes = graph.num_nodes
    assert nodes == 2
    graph.expire(1000.0)
    assert graph.num_edges == 0
    assert graph.num_nodes == nodes
    graph.add(flow(1, 1000.0, dst=("10.0.0.9", 80)), 8)
    assert graph.num_nodes == nodes + 1
    edge_index, _ = graph.arrays(8)
    # dead nodes keep their ids (monotone mapping) but are no longer endpoints
    assert set(edge_index.ravel().tolist()) == {0, 2}


def test_expire_drops_only_edges_outside_the_window():
    graph = WindowGraph(window=120.0)
    graph.add(flow(0, 0.0), 8)
    graph.add(flow(1, 60.0), 8)
    assert graph.expire(100.0) == 0  # 0.0 is still inside [−20, 100]
    assert graph.expire(200.0) == 2  # both outside [80, 200]
    assert graph.num_edges == 0
    edge_index, edge_attr = graph.arrays(8)
    assert edge_index.shape == (2, 0) and edge_attr.shape == (0, 400)


def test_padding_for_short_flows_is_zero():
    graph = WindowGraph(window=120.0)
    graph.add(flow(0, 1.0, packets=2), 4)
    _, edge_attr = graph.arrays(4)
    assert edge_attr.shape == (1, 200)
    assert not edge_attr[0, 100:].any()  # only two packets were seen


def test_compaction_keeps_arrays_consistent_with_num_edges():
    graph = WindowGraph(window=5.0)
    for i in range(3000):
        graph.expire(float(i))
        graph.add(flow(i, float(i), dst=("10.1.0.1", 80)), 2)
        if i % 250 == 0:
            edge_index, edge_attr = graph.arrays(2)
            assert edge_index.shape[1] == graph.num_edges == edge_attr.shape[0]
    assert graph._size <= 2 * graph.num_edges + 1024  # dead rows are reclaimed


def test_embed_rows_shape_and_pe_cost():
    graph = WindowGraph(window=120.0)
    for i in range(4):
        graph.add(flow(i, 1.0 + 0.1 * i, dst=(f"10.0.0.{i + 2}", 80)), 2)
    edge_index, edge_attr = graph.arrays(2)
    model = GTAE(2).eval()
    timings: dict[str, float] = {}
    z = embed_rows(model, edge_index, edge_attr, use_pe=True, seed=0, timings=timings)
    assert z.shape == (4, 8)
    assert set(timings) == {"line", "pe", "forward"}
    assert timings["pe"] > 0.0
    no_pe = embed_rows(model, edge_index, edge_attr, use_pe=False, seed=0)
    assert no_pe.shape == (4, 8)


def test_p_is_fixed_per_graph():
    graph = WindowGraph(window=120.0)
    graph.add(flow(0, 0.0), 2)
    try:
        graph.arrays(4)
    except ValueError as exc:
        assert "p=2" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("expected ValueError for a different p")
    assert torch.isfinite(torch.zeros(1)).all()
