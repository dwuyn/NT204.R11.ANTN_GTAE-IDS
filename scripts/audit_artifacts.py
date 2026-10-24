"""End-to-end audit of the GTAE-IDS artifacts produced so far."""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import numpy as np
import pyarrow.parquet as pq

from src.graph_builder import encode_edge, load_graph, load_packets
from src.label import load_schedule, qa_summary
from src.model_gtae import ARCH, GTAE

ROOT = REPO_ROOT
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")

failures: list[str] = []
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        failures.append(message)
        print(f"FAIL  {message}")


def main() -> int:
    # ---------- raw data ----------
    for name, min_size in [
        ("Monday-WorkingHours.pcap", 10 * 2**30),
        ("Tuesday-WorkingHours.pcap", 10 * 2**30),
        ("Wednesday-workingHours.pcap", 12 * 2**30),
        ("Thursday-WorkingHours.pcap", 7 * 2**30),
        ("Friday-WorkingHours.pcap", 7 * 2**30),
        ("GeneratedLabelledFlows.zip", 200 * 2**20),
    ]:
        path = ROOT / "data/raw" / name
        check(path.exists() and path.stat().st_size >= min_size, f"raw file {name}")

    # ---------- parse summaries + labeled tables ----------
    flows_by_day = {}
    packets_by_day = {}
    packet_rows = {}
    for day in DAYS:
        summary = json.loads((ROOT / f"data/processed/parse_summary_{day}.json").read_text())
        packets_table = pq.read_table(ROOT / f"data/processed/packets_{day}.parquet")
        flows_table = pq.read_table(ROOT / f"data/processed/flows_{day}_labeled.parquet")
        packets = packets_table.to_pylist()
        flows = flows_table.to_pylist()
        flows_by_day[day] = flows
        packet_rows[day] = packets

        check(summary["packets_written"] == len(packets), f"{day}: packet row count")
        check(summary["flows_written"] == len(flows), f"{day}: flow row count")

        flow_ids = {int(f["flow_id"]) for f in flows}
        check(all(int(p["flow_id"]) in flow_ids for p in packets), f"{day}: packet->flow fk")
        check(all(p["pkt_idx"] in range(1, 9) for p in packets), f"{day}: pkt_idx 1..8")
        check(all(len(p["kept25"]) == 25 for p in packets), f"{day}: kept25 length")
        check(all(p["dir"] in (0, 1) for p in packets), f"{day}: dir 0/1")

        by_flow = {}
        for packet in packets:
            by_flow.setdefault(int(packet["flow_id"]), []).append(packet)
        bad_counts = 0
        for flow in flows:
            stored = len(by_flow.get(int(flow["flow_id"]), ()))
            if stored != min(8, int(flow["n_pkts_total"])):
                bad_counts += 1
        check(bad_counts == 0, f"{day}: stored packets == min(8,n_pkts_total)")

        check(all(f["label"] in (-1, 0, 1) for f in flows), f"{day}: label domain")
        check(
            all((f["label"] != 1) or bool(f["attack_type"]) for f in flows),
            f"{day}: attack label has attack_type",
        )
        check(
            all((f["label"] != 0) or not f["attack_type"] for f in flows),
            f"{day}: benign label has no attack_type",
        )
        check(
            all(bool(f["start_with_syn"]) or f["label"] == -1 for f in flows),
            f"{day}: no-SYN flows are UNCERTAIN",
        )
        check(
            all(f["end_reason"] in ("idle_timeout", "reopened", "eof") for f in flows),
            f"{day}: end_reason domain",
        )

        qa = json.loads((ROOT / f"reports/qa_labeling_{day}.json").read_text())
        recomputed = qa_summary(flows)
        check(qa == recomputed, f"{day}: QA report matches labeled table")

        cc = json.loads((ROOT / f"reports/crosscheck_{day}.json").read_text())
        check(
            cc["matched"] + cc["unmatched"] + cc["skipped_uncertain"] == cc["flows"],
            f"{day}: crosscheck row accounting",
        )
        check(sum(cc["confusion"].values()) == cc["matched"], f"{day}: confusion sum")
        if cc["matched"]:
            expected = (
                cc["confusion"]["tn"] + cc["confusion"]["tp"]
            ) / cc["matched"]
            check(abs(expected - cc["agreement"]) < 1e-9, f"{day}: agreement formula")

    # ---------- schedule ----------
    schedule = load_schedule(ROOT / "configs/cicids2017_schedule.yaml")
    check(len(schedule.windows) >= 18, "schedule window count")
    check(all(w.end >= w.start for w in schedule.windows), "schedule window ordering")
    check(not any(w.victim_cidrs for w in schedule.windows), "lateral CIDR window removed")
    check(
        not any(w.attack == "Infiltration" and w.attacker_ips == {"192.168.10.8"} for w in schedule.windows),
        "no lateral Infiltration entry",
    )
    config = (ROOT / "configs/data.yaml").read_text()
    check("utc_offset_minutes: -180" in config, "calibrated offset in config")
    check("csv_time_tolerance_s: 120" in config, "CSV tolerance in config")

    # ---------- graphs ----------
    flow_lookup = {
        (day, int(flow["flow_id"])): flow
        for day, flows in flows_by_day.items()
        for flow in flows
    }
    graph_summary = json.loads((ROOT / "data/graphs/T/summary.json").read_text())

    for p in (2, 4, 8):
        graphs = {
            name: load_graph(ROOT / f"data/graphs/T/p{p}/{name}.npz")
            for name in ("train1", "train2", "test")
        }
        for name, graph in graphs.items():
            n_edges = graph.y.shape[0]
            check(graph.edge_attr.shape == (n_edges, 50 * p), f"p{p} {name}: edge_attr shape")
            check(graph.edge_index.shape == (2, n_edges), f"p{p} {name}: edge_index shape")
            check(np.isfinite(graph.edge_attr).all(), f"p{p} {name}: finite features")
            check((graph.edge_attr >= 0).all() and (graph.edge_attr <= 1).all(), f"p{p} {name}: feature range")
            check(set(np.unique(graph.y)) <= {0, 1}, f"p{p} {name}: y domain")
            check(graph.edge_index.min() >= 0, f"p{p} {name}: node ids >= 0")
            check(int(graph.edge_index.max()) + 1 == graph.num_nodes, f"p{p} {name}: num_nodes")
            check(len(graph.day) == n_edges, f"p{p} {name}: day length")
            check(all(graph.day), f"p{p} {name}: day non-empty")
            check(
                all(bool(t) == (int(y) == 1) for t, y in zip(graph.attack_type, graph.y)),
                f"p{p} {name}: attack_type iff attack",
            )
            pairs = list(zip(graph.day.tolist(), graph.flow_id.tolist()))
            check(len(pairs) == len(set(pairs)), f"p{p} {name}: (day,flow_id) unique")

            # Flow lookup, labels, packet counts, node mapping, edge features.
            node_map: dict[tuple[str, int], int] = {}
            edges = list(zip(graph.edge_index[0].tolist(), graph.edge_index[1].tolist()))
            bad_feature = 0
            bad_node = 0
            missing = 0
            for idx, (day, fid) in enumerate(pairs):
                flow = flow_lookup.get((day, int(fid)))
                if flow is None:
                    missing += 1
                    continue
                if int(flow["label"]) != int(graph.y[idx]):
                    bad_node += 1
                if str(flow.get("attack_type") or "") != str(graph.attack_type[idx]):
                    bad_node += 1
                if int(flow["n_pkts_total"]) < p:
                    bad_node += 1
                src = (str(flow["src_ip"]), int(flow["src_port"]))
                dst = (str(flow["dst_ip"]), int(flow["dst_port"]))
                for endpoint in (src, dst):
                    if endpoint not in node_map:
                        node_map[endpoint] = len(node_map)
                if edges[idx] != (node_map[src], node_map[dst]):
                    bad_node += 1
            check(missing == 0, f"p{p} {name}: all flows exist")
            check(bad_node == 0, f"p{p} {name}: labels/node mapping")
            check(len(node_map) == graph.num_nodes, f"p{p} {name}: node map size")

            # Re-encode first p packets for every edge (strongest check).
            ids_by_day: dict[str, list[int]] = {}
            for day, fid in pairs:
                ids_by_day.setdefault(day, []).append(int(fid))
            packets = {}
            for day, ids in ids_by_day.items():
                packets.update(load_packets(ROOT / f"data/processed/packets_{day}.parquet", ids))
            for idx, (day, fid) in enumerate(pairs):
                rows = sorted(packets[int(fid)], key=lambda r: r["pkt_idx"])[:p]
                expected = encode_edge([(r["kept25"], int(r["dir"])) for r in rows], p)
                if not np.array_equal(expected, graph.edge_attr[idx]):
                    bad_feature += 1
            check(bad_feature == 0, f"p{p} {name}: edge features match packets")

        train_pairs = set(zip(graphs["train1"].day.tolist(), graphs["train1"].flow_id.tolist()))
        train2_pairs = set(zip(graphs["train2"].day.tolist(), graphs["train2"].flow_id.tolist()))
        test_pairs = set(zip(graphs["test"].day.tolist(), graphs["test"].flow_id.tolist()))
        check(not (train_pairs & train2_pairs), f"p{p}: train1/train2 disjoint")
        check(not (train_pairs & test_pairs), f"p{p}: train1/test disjoint")
        check(not (train2_pairs & test_pairs), f"p{p}: train2/test disjoint")
        check(set(graphs["train1"].y.tolist()) == {0}, f"p{p}: train1 all benign")
        check(set(graphs["train2"].y.tolist()) == {0}, f"p{p}: train2 all benign")
        check(set(graphs["train1"].day.tolist()) == {"monday"}, f"p{p}: train1 Monday")
        check(set(graphs["train2"].day.tolist()) == {"monday"}, f"p{p}: train2 Monday")
        check("monday" not in set(graphs["test"].day.tolist()), f"p{p}: test excludes Monday")
        check(graphs["train1"].y.shape[0] == 5000, f"p{p}: train1 size")
        check(graphs["train2"].y.shape[0] == 2000, f"p{p}: train2 size")
        summary = graph_summary[f"p{p}"]
        check(summary["train1"]["edges"] == 5000, f"p{p}: summary train1")
        check(summary["test"]["edges"] == graphs["test"].y.shape[0], f"p{p}: summary test")
        attack_counts = Counter(
            t for t, y in zip(graphs["test"].attack_type.tolist(), graphs["test"].y.tolist()) if y == 1
        )
        check(
            all(count <= 5000 for count in attack_counts.values()),
            f"p{p}: attack cap respected",
        )
        check(
            sum(1 for y in graphs["test"].y.tolist() if y == 0) == 5000,
            f"p{p}: 5000 benign test edges",
        )

    # ---------- all p artifacts (light) ----------
    for p in (2, 3, 4, 5, 6, 7, 8):
        for name in ("train1", "train2", "test"):
            graph = load_graph(ROOT / f"data/graphs/T/p{p}/{name}.npz")
            check(graph.edge_attr.shape[1] == 50 * p, f"p{p} {name}: feature dim")
            check(len(set(zip(graph.day.tolist(), graph.flow_id.tolist()))) == len(graph.y), f"p{p} {name}: unique ids")

    # ---------- protocol R (lighter: same builder is fully checked on T) ----------
    for p in (2, 4, 8):
        graphs = {
            name: load_graph(ROOT / f"data/graphs/R/p{p}/{name}.npz")
            for name in ("train1", "train2", "test")
        }
        for name, graph in graphs.items():
            check(graph.edge_attr.shape[1] == 50 * p, f"R p{p} {name}: feature dim")
            check(set(np.unique(graph.y)) <= {0, 1}, f"R p{p} {name}: y domain")
            check(all(graph.day), f"R p{p} {name}: day non-empty")
        train1 = set(zip(graphs["train1"].day.tolist(), graphs["train1"].flow_id.tolist()))
        train2 = set(zip(graphs["train2"].day.tolist(), graphs["train2"].flow_id.tolist()))
        test = set(zip(graphs["test"].day.tolist(), graphs["test"].flow_id.tolist()))
        check(not (train1 & train2), f"R p{p}: train splits disjoint")
        check(not (train1 & test), f"R p{p}: train1/test disjoint")
        check(not (train2 & test), f"R p{p}: train2/test disjoint")
        check(set(graphs["train1"].y.tolist()) == {0}, f"R p{p}: train1 benign")
        check(set(graphs["train2"].y.tolist()) == {0}, f"R p{p}: train2 benign")
        check((graphs["test"].y == 1).any(), f"R p{p}: test has attacks")
        check(graphs["train1"].y.shape[0] == 5000, f"R p{p}: train1 size")
        check(graphs["train2"].y.shape[0] == 2000, f"R p{p}: train2 size")

    # ---------- fixed population (same flows for every p, >= 8 packets) ----------
    for name in ("train1", "train2", "test"):
        reference = None
        for p in (2, 3, 4, 5, 6, 7, 8):
            graph = load_graph(ROOT / f"data/graphs/T_fixed/p{p}/{name}.npz")
            ids = list(zip(graph.day.tolist(), graph.flow_id.tolist()))
            if reference is None:
                reference = ids
            check(ids == reference, f"T_fixed {name} p{p}: identical flow set")
            short = sum(
                1 for day, fid in ids if int(flow_lookup[(day, fid)]["n_pkts_total"]) < 8
            )
            check(short == 0, f"T_fixed {name} p{p}: all flows >= 8 packets")

    # ---------- model ----------
    check(sorted(ARCH) == [2, 3, 4, 5, 6, 7, 8], "ARCH covers p=2..8")
    for p in ARCH:
        model = GTAE(p)
        check(len(model.layers) == ARCH[p]["layers"], f"p{p}: encoder layers")
        check(model.in_dim == 50 * p, f"p{p}: input dim")

    # ---------- deterministic rebuild ----------
    from src.build_dataset import build as build_dataset

    rebuild_dir = Path("/tmp/gtae_audit_rebuild")
    build_dataset(ROOT / "data/processed", rebuild_dir, [2, 4, 8], seed=0)
    for p in (2, 4, 8):
        for name in ("train1", "train2", "test"):
            expected = load_graph(ROOT / f"data/graphs/T/p{p}/{name}.npz")
            rebuilt = load_graph(rebuild_dir / "T" / f"p{p}" / f"{name}.npz")
            same = (
                np.array_equal(expected.edge_index, rebuilt.edge_index)
                and np.array_equal(expected.edge_attr, rebuilt.edge_attr)
                and np.array_equal(expected.y, rebuilt.y)
                and np.array_equal(expected.flow_id, rebuilt.flow_id)
                and np.array_equal(expected.attack_type, rebuilt.attack_type)
                and np.array_equal(expected.day, rebuilt.day)
                and expected.num_nodes == rebuilt.num_nodes
            )
            check(same, f"p{p} {name}: deterministic rebuild matches")

    print(f"\n{checks - len(failures)}/{checks} checks passed")
    if failures:
        print(f"{len(failures)} FAILURES")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
