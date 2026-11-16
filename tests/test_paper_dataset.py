"""P_paper construction invariants: padding, paper counts, split disjointness."""

from __future__ import annotations

import numpy as np

from src.cic_graph import (
    PAPER_TEST_COUNTS,
    build_graph_rows,
    encode_edge_padded,
    normalize_label,
    select_paper_split,
)
from src.packet_encoder import BLOCK_DIM, encode_edge


def _packets(n: int, start: int = 0) -> list[tuple[bytes, int]]:
    return [(bytes([(start + i) % 256] * 25), i % 2) for i in range(n)]


def _row(row_id: int, day: str, label: str) -> dict:
    return {
        "row_id": row_id,
        "day": day,
        "label": label,
        "src": (f"10.0.0.{row_id % 251}", 1024 + row_id % 1000),
        "dst": ("10.0.1.1", 80),
        "start": 1.0e9 + row_id,
        "end": 1.0e9 + row_id + 60.0,
    }


def test_encode_edge_padded_zero_fills_short_flows() -> None:
    packets = _packets(2, start=7)
    padded = encode_edge_padded(packets, 4)
    assert padded.shape == (4 * BLOCK_DIM,)
    assert padded.dtype == np.float32
    np.testing.assert_allclose(padded[: 2 * BLOCK_DIM], encode_edge(packets, 2))
    np.testing.assert_allclose(padded[2 * BLOCK_DIM :], 0.0)


def test_normalize_label_maps_csv_spellings() -> None:
    assert normalize_label("Web Attack \ufffd Brute Force") == "Web Attack - Brute Force"
    assert normalize_label("DoS slowloris") == "DoS Slowloris"
    assert normalize_label("Infilteration") == "Infiltration"
    assert normalize_label("  BENIGN ") == "BENIGN"


def _population() -> tuple[dict[str, list[dict]], dict[int, list[tuple[bytes, int]]]]:
    rows: dict[str, list[dict]] = {"friday": []}
    packets: dict[int, list[tuple[bytes, int]]] = {}
    next_id = 0
    for _ in range(12000 + 25):  # arrives with surplus so the split is a sample
        rows["friday"].append(_row(next_id, "friday", "BENIGN"))
        packets[next_id] = _packets(8)
        next_id += 1
    for attack, target in PAPER_TEST_COUNTS.items():
        day = "wednesday"
        rows.setdefault(day, [])
        for _ in range(target + 5):
            rows[day].append(_row(next_id, day, attack))
            packets[next_id] = _packets(8)
            next_id += 1
    return rows, packets


def test_paper_test_counts_exact() -> None:
    rows, packets = _population()
    split = select_paper_split(rows, packets, seed=0)
    assert not split.shortfall
    assert (len(split.train1), len(split.train2)) == (5000, 2000)
    counts: dict[str, int] = {}
    for row in split.test:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    assert counts.pop("BENIGN") == 5000
    assert counts == PAPER_TEST_COUNTS


def test_paper_split_disjoint() -> None:
    rows, packets = _population()
    split = select_paper_split(rows, packets, seed=0)
    ids = [{r["row_id"] for r in part} for part in (split.train1, split.train2, split.test)]
    assert not (ids[0] & ids[1])
    assert not (ids[0] & ids[2])
    assert not (ids[1] & ids[2])
    assert {r["label"] for r in split.train1 + split.train2} == {"BENIGN"}


def test_shortfall_recorded_when_csv_pool_is_short() -> None:
    rows, packets = _population()
    scarce = "Heartbleed"
    rows["wednesday"] = [r for r in rows["wednesday"] if r["label"] != scarce] + [
        _row(999_000 + i, "wednesday", scarce) for i in range(3)
    ]
    for i in range(3):
        packets[999_000 + i] = _packets(8)
    split = select_paper_split(rows, packets, seed=0)
    assert split.shortfall[scarce]["selected"] == 3
    assert split.shortfall[scarce]["paper_target"] == PAPER_TEST_COUNTS[scarce]
    scarce_test = [r for r in split.test if r["label"] == scarce]
    assert len(scarce_test) == 3


def test_build_graph_rows_pads_and_keeps_endpoints() -> None:
    rows = [_row(0, "friday", "BENIGN"), _row(1, "wednesday", "DDoS")]
    packets = {0: _packets(2, start=1), 1: _packets(3, start=9)}
    graph = build_graph_rows(rows, packets, p=4)
    assert graph.edge_attr.shape == (2, 4 * BLOCK_DIM)
    assert graph.edge_index.shape == (2, 2)
    assert graph.y.tolist() == [0, 1]
    assert graph.attack_type.tolist() == ["", "DDoS"]
    assert graph.day.tolist() == ["friday", "wednesday"]
    assert graph.flow_id.tolist() == [0, 1]
    assert graph.p == 4
    np.testing.assert_allclose(graph.edge_attr[0, 2 * BLOCK_DIM :], 0.0)
    np.testing.assert_allclose(graph.edge_attr[1, : 3 * BLOCK_DIM], encode_edge(packets[1], 3))
    np.testing.assert_allclose(graph.edge_attr[1, 3 * BLOCK_DIM :], 0.0)
    # (10.0.1.1, 80) is shared: 2 distinct sources + 1 shared destination.
    assert graph.num_nodes == 3


def test_build_graph_rows_drops_rows_without_packets() -> None:
    rows = [_row(0, "friday", "BENIGN"), _row(1, "friday", "BENIGN")]
    graph = build_graph_rows(rows, {1: _packets(8)}, p=2)
    assert graph.edge_index.shape[1] == 1
    assert graph.flow_id.tolist() == [1]
