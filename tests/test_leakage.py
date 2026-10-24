"""Leakage tests: label/feature separation and split disjointness."""

from __future__ import annotations

import socket
import struct

import numpy as np

from src.graph_builder import build_graph, select_temporal
from src.packet_encoder import DIR_BWD, DIR_FWD, encode_edge, strip_headers

FIG3_IP = bytes.fromhex("450001c7c50040004006deaac0a80a32c0a80a03")
FIG3_TCP = bytes.fromhex("db2c0cc46a70fd5c3630dfa980180179d0aa0000")


def _mutated_ip(src: str, dst: str) -> bytes:
    ip = bytearray(FIG3_IP)
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    return bytes(ip)


def _mutated_tcp(sport: int, dport: int) -> bytes:
    tcp = bytearray(FIG3_TCP)
    struct.pack_into("!HH", tcp, 0, sport, dport)
    return bytes(tcp)


def test_features_ignore_addresses_and_ports():
    # Checksums are deliberately not recomputed: this checks the *direct* leak
    # only. The documented indirect checksum dependency is tested in
    # tests/test_encoder.py.
    base = strip_headers(FIG3_IP + FIG3_TCP)
    mutated = strip_headers(_mutated_ip("203.0.113.7", "198.51.100.9") + _mutated_tcp(45000, 443))
    assert mutated == base

    x = encode_edge([(base, DIR_FWD), (base, DIR_BWD)], p=2)
    y = encode_edge([(mutated, DIR_FWD), (mutated, DIR_BWD)], p=2)
    np.testing.assert_array_equal(x, y)


def _flow(flow_id, src, dst, label, attack=None, n=3, day="monday"):
    return {
        "flow_id": flow_id,
        "src_ip": src[0],
        "src_port": src[1],
        "dst_ip": dst[0],
        "dst_port": dst[1],
        "label": label,
        "attack_type": attack,
        "n_pkts_total": n,
        "day": day,
    }


def _packets(flow_id, dirs):
    kept = strip_headers(FIG3_IP + FIG3_TCP)
    return [
        {"flow_id": flow_id, "pkt_idx": i + 1, "dir": d, "kept25": kept}
        for i, d in enumerate(dirs)
    ]


def test_graph_ignores_endpoint_identity():
    flows = [
        _flow(0, ("10.0.0.1", 1111), ("10.0.0.2", 80), 0),
        _flow(1, ("192.168.1.9", 5555), ("172.16.0.3", 22), 1, "PortScan"),
    ]
    packets = {0: _packets(0, [DIR_FWD, DIR_BWD]), 1: _packets(1, [DIR_FWD, DIR_BWD])}
    graph = build_graph(flows, packets, p=2)

    assert graph.edge_attr.shape == (2, 100)
    np.testing.assert_array_equal(graph.edge_attr[0], graph.edge_attr[1])
    assert graph.y.tolist() == [0, 1]


def test_uncertain_and_short_flows_never_enter_graph():
    flows = [
        _flow(0, ("10.0.0.1", 1), ("10.0.0.2", 2), -1, n=3),
        _flow(1, ("10.0.0.1", 3), ("10.0.0.2", 4), 0, n=1),
    ]
    packets = {0: _packets(0, [DIR_FWD, DIR_BWD]), 1: _packets(1, [DIR_FWD])}
    graph = build_graph(flows, packets, p=2)
    assert graph.y.shape[0] == 0
    assert graph.edge_attr.shape == (0, 100)


def test_temporal_split_is_disjoint_and_benign_in_train():
    flows_by_day = {
        "monday": [_flow(i, ("10.0.0.1", i), ("10.0.0.2", 80), 0) for i in range(20)],
        "tuesday": [_flow(100 + i, ("10.0.0.1", i), ("10.0.0.2", 80), 0, day="tuesday") for i in range(10)]
        + [
            _flow(200 + i, ("10.0.0.9", i), ("10.0.0.2", 80), 1, "PortScan", day="tuesday")
            for i in range(10)
        ],
    }
    split = select_temporal(
        flows_by_day, seed=0, train1_n=5, train2_n=3, test_benign_n=5, attack_cap=5, min_packets=2
    )
    train_ids = {f["flow_id"] for f in split.train1 + split.train2}
    test_ids = {f["flow_id"] for f in split.test}
    assert not (train_ids & test_ids)
    assert {f["day"] for f in split.train1 + split.train2} == {"monday"}
    assert {f["label"] for f in split.train1 + split.train2} == {0}
    assert {f["day"] for f in split.test} == {"tuesday"}
    assert sum(f["label"] == 1 for f in split.test) == 5
