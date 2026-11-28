#!/usr/bin/env python3
"""Recompute the report's headline numbers from the measurement CSVs.

Every check maps one published claim to a number recomputed from a committed
artefact under ``results/``. The run fails (exit 1) on any mismatch, so a
stale table or an edited number cannot pass silently.

    .venv/bin/python scripts/verify_report_numbers.py
"""

from __future__ import annotations

import csv
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILURES: list[str] = []
CHECKS = 0


def _rows(rel: str) -> list[dict]:
    with (ROOT / rel).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _mean(rows: list[dict], key: str) -> float:
    return st.mean(float(row[key]) for row in rows)


def _select(rows: list[dict], **filters: str) -> list[dict]:
    return [row for row in rows if all(row.get(k) == v for k, v in filters.items())]


def check(claim: str, got: float, expected: float, tol: float = 0.0051) -> None:
    global CHECKS
    CHECKS += 1
    if abs(got - expected) > tol:
        FAILURES.append(f"{claim}: got {got:.6f}, report {expected:.6f} (tol {tol})")


def summary_csv(rel: str, p: int = 8, **filters: str) -> list[dict]:
    return _select(_rows(rel), p=str(p), **filters)


def main() -> int:
    # M1 (Table 4.1) and seed spread.
    m1 = summary_csv("results/M1_summary.csv", detector="tie")
    check("M1 TPR", _mean(m1, "tpr"), 0.041842)
    check("M1 FPR", _mean(m1, "fpr"), 0.027867)
    check("M1 AUROC", _mean(m1, "auroc"), 0.593738)
    check("M1 TPR@1%", _mean(m1, "tpr_at_fpr_1pct"), 0.036489)
    check("M1 AUROC std", st.stdev(float(r["auroc"]) for r in m1), 0.105648, 0.002)

    for name, rel, tpr, fpr, auroc in [
        ("B0", "results/B0_summary.csv", 0.0050, 0.0122, 0.698),
        ("B1", "results/B1_summary.csv", 0.0629, 0.0229, 0.595),
        ("B2", "results/B2/M1_summary.csv", 0.0978, 0.0181, 0.689),
    ]:
        rows = summary_csv(rel, rule="ensemble_tie" if name != "B2" else None)
        if name == "B2":
            rows = summary_csv(rel, detector="tie")
        check(f"{name} TPR", _mean(rows, "tpr"), tpr, 0.001)
        check(f"{name} FPR", _mean(rows, "fpr"), fpr, 0.001)
        check(f"{name} AUROC", _mean(rows, "auroc"), auroc, 0.002)
    check("B0 TPR@1%", _mean(summary_csv("results/B0_summary.csv", rule="ensemble_tie"), "tpr_at_fpr"), 0.0213, 0.001)
    check("B1 TPR@1%", _mean(summary_csv("results/B1_summary.csv", rule="ensemble_tie"), "tpr_at_fpr"), 0.0695, 0.001)
    check("B2 TPR@1%", _mean(summary_csv("results/B2/M1_summary.csv", detector="tie"), "tpr_at_fpr_1pct"), 0.1130, 0.002)

    a2 = summary_csv("results/A2_no_pe.csv", detector="tie")
    check("A2 TPR", _mean(a2, "tpr"), 0.0636, 0.001)
    check("A2 FPR", _mean(a2, "fpr"), 0.0123, 0.001)
    check("A2 AUROC", _mean(a2, "auroc"), 0.682, 0.002)
    check("A2 TPR@1%", _mean(a2, "tpr_at_fpr_1pct"), 0.1246, 0.002)

    a3 = _select(_rows("results/A3_recon.csv"), p="8")
    check("A3 TPR", _mean(a3, "tpr"), 0.0601, 0.001)
    check("A3 FPR", _mean(a3, "fpr"), 0.0207, 0.001)
    check("A3 AUROC", _mean(a3, "auroc"), 0.649, 0.002)

    a5 = summary_csv("results/A5_hygiene.csv", detector="tie")
    check("A5 TPR", _mean(a5, "tpr"), 0.0283, 0.001)
    check("A5 AUROC", _mean(a5, "auroc"), 0.675, 0.002)
    check("A5 TPR@1%", _mean(a5, "tpr_at_fpr_1pct"), 0.0377, 0.002)

    # P1 full grid.
    p1 = _rows("results/P1_summary.csv")
    for alpha, tpr, fpr in [("0.05", 0.0895, 0.0364), ("0.1", 0.1411, 0.0578)]:
        rows = _select(p1, alpha=alpha, method="bonferroni")
        check(f"P1 a={alpha} TPR", _mean(rows, "tpr"), tpr, 0.001)
        check(f"P1 a={alpha} FPR", _mean(rows, "fpr"), fpr, 0.001)
    check("P1 AUROC", _mean(_select(p1, method="bonferroni"), "auroc"), 0.662, 0.003)

    # A+B.
    for rel, a05, f05, a10, f10 in [
        ("results/P1_p248/P1_summary.csv", 0.1213, 0.0517, 0.1940, 0.0753),
        ("results/P1_egsage/P1_summary.csv", 0.1449, 0.0476, 0.1852, 0.0693),
    ]:
        rows = _rows(rel)
        check(f"{rel} a=.05 TPR", _mean(_select(rows, alpha="0.05", method="bonferroni"), "tpr"), a05, 0.001)
        check(f"{rel} a=.05 FPR", _mean(_select(rows, alpha="0.05", method="bonferroni"), "fpr"), f05, 0.001)
        check(f"{rel} a=.10 TPR", _mean(_select(rows, alpha="0.1", method="bonferroni"), "tpr"), a10, 0.001)
        check(f"{rel} a=.10 FPR", _mean(_select(rows, alpha="0.1", method="bonferroni"), "fpr"), f10, 0.001)

    # Matched-FPR comparisons.
    m1_rows = _select(_rows("results/paper_parity/T_p8_selected.csv"), detector_or_rule="tie")
    check("M1 TPR@test-FPR 1%", _mean(m1_rows, "tpr_at_test_fpr_1pct"), 0.0279, 0.001)
    for rel, rule, tpr, auroc in [
        ("results/paper_parity/T_p8_selected.csv", "tie", 0.1154, 0.594),
        ("results/paper_parity/p8_selected.csv", "or", 0.0325, 0.478),
        ("results/feature_input/B2_p8/T_p8_selected.csv", "tie", 0.1627, 0.689),
        ("results/feature_input/A2_p8/T_p8_selected.csv", "tie", 0.2034, 0.682),
    ]:
        rows = _select(_rows(rel), detector_or_rule=rule)
        check(f"{rel} TPR@6.56", _mean(rows, "tpr_at_test_fpr_6.56pct"), tpr, 0.001)
        check(f"{rel} AUROC", _mean(rows, "auroc"), auroc, 0.002)
    for rel, rule, tpr in [
        ("results/feature_input/B2_p8/T_p8_selected.csv", "tie", 0.0640),
        ("results/feature_input/A2_p8/T_p8_selected.csv", "tie", 0.0622),
    ]:
        rows = _select(_rows(rel), detector_or_rule=rule)
        check(f"{rel} TPR@1%", _mean(rows, "tpr_at_test_fpr_1pct"), tpr, 0.001)

    # Table VII per-class, P_paper OR at the selected contamination.
    selected = _select(_rows("results/paper_parity/p8_selected.csv"), detector_or_rule="or")
    per_class = _rows("results/paper_parity/p8_per_class.csv")
    chosen = {(r["seed"], float(r["contamination"])) for r in selected}
    by_class: dict[str, list[float]] = {}
    for row in per_class:
        if row["detector_or_rule"] != "or":
            continue
        if (row["seed"], float(row["contamination"])) not in chosen:
            continue
        by_class.setdefault(row["attack_type"], []).append(float(row["tpr"]))
    expected_classes = {
        "DDoS": 0.0923, "DoS GoldenEye": 0.0765, "DoS Hulk": 0.0757,
        "DoS Slowhttptest": 0.0643, "DoS Slowloris": 0.0855, "FTP-Patator": 0.0632,
        "Heartbleed": 0.3333, "Infiltration": 0.0098, "PortScan": 0.2856,
        "SSH-Patator": 0.0552, "Web Attack - Brute Force": 0.0571,
    }
    for cls, expected in expected_classes.items():
        check(f"P_paper {cls}", st.mean(by_class[cls]), expected, 0.001)

    # Protocol tables and counts.
    paper = json.loads((ROOT / "data/graphs/P_paper/summary.json").read_text())["graphs"]["p8"]
    counts = paper["test"]
    attacks = paper["test_attack_counts"]
    check("P_paper test edges", counts["edges"], 30041, 0)
    check("P_paper test nodes", counts["nodes"], 22328, 0)
    check("P_paper benign", counts["edges"] - counts["positives"], 5000, 0)
    check("P_paper PortScan", attacks["PortScan"], 6451, 0)
    check("P_paper Heartbleed", attacks["Heartbleed"], 11, 0)
    check("P_paper Infiltration", attacks["Infiltration"], 34, 0)

    # Cross-dataset.
    for rel, tpr, fpr, auroc in [
        ("results/2018/M1_summary.csv", 0.0599, 0.0152, 0.764),
        ("results/aci/M1_summary.csv", 0.0169, 0.0111, 0.536),
    ]:
        rows = summary_csv(rel, detector="tie")
        check(f"{rel} TPR", _mean(rows, "tpr"), tpr, 0.001)
        check(f"{rel} FPR", _mean(rows, "fpr"), fpr, 0.001)
        check(f"{rel} AUROC", _mean(rows, "auroc"), auroc, 0.002)

    # Direction artifact and exact Table VI reproduction.
    leak = _rows("results/direction_leak.csv")
    for protocol, benign_ens, fwd_attack in [("P_paper", 0.1766, 1.0), ("T", 0.2018, 1.0)]:
        rows = [r for r in leak if r["protocol"] == protocol]
        benign = next(r for r in rows if r["class"] == "Benign")
        check(f"{protocol} artifact benign ensemble", float(benign["ensemble"]), benign_ens, 0.001)
        check(f"{protocol} artifact benign fwd", float(benign["fwd_nonempty"]), 0.0, 0.001)
        attacks = [float(r["fwd_nonempty"]) for r in rows if r["class"] != "Benign"]
        check(f"{protocol} artifact attack fwd", st.mean(attacks), fwd_attack, 0.001)
    votes = _rows("results/direction_leak_votes.csv")
    for protocol, seed, fpr, tpr in [("P_paper", "0", 0.0550, 0.9904), ("T", "0", 0.0666, 0.9922)]:
        row = next(r for r in votes if r["protocol"] == protocol and r["seed"] == seed and r["min_votes"] == "3")
        check(f"{protocol} votes>=3 FPR", float(row["fpr"]), fpr, 0.001)
        check(f"{protocol} votes>=3 TPR", float(row["tpr"]), tpr, 0.001)

    # Supervised bound.
    sup = _rows("results/supervised_bound.csv")
    same_raw = _select(sup, scenario="same_day", features="raw")
    cross_raw = _select(sup, scenario="cross_day", features="raw")
    cross_z = _select(sup, scenario="cross_day", features="z")
    check("RF same-day raw AUROC", _mean(same_raw, "auroc"), 0.999, 0.001)
    check("RF same-day raw TPR@6.56", _mean(same_raw, "tpr_at_test_fpr_6.56pct"), 0.999, 0.001)
    check("RF cross-day raw AUROC", _mean(cross_raw, "auroc"), 0.544, 0.005)
    check("RF cross-day raw TPR@6.56", _mean(cross_raw, "tpr_at_test_fpr_6.56pct"), 0.035, 0.003)
    check("RF cross-day z AUROC min", min(float(r["auroc"]) for r in cross_z), 0.636, 0.003)
    check("RF cross-day z AUROC max", max(float(r["auroc"]) for r in cross_z), 0.747, 0.003)

    # Latency.
    latency = json.loads((ROOT / "results/latency_summary.json").read_text())["modes"]["no_pe"]
    check("latency flows", latency["n_flows"], 349256, 0)
    check("latency us/packet", latency["us_packet"], 15272.22, 1.0)
    check("latency detect flows/s", latency["detection_throughput_flows_s"], 8.2, 0.1)

    # Engelen L1.
    composition = _rows("results/engelen_composition.csv")
    by_label = {r["label"]: int(r["engelen_effective"]) for r in composition}
    check("Engelen Heartbleed", by_label.get("Heartbleed", -1), 11, 0)
    check("Engelen Infiltration", by_label.get("Infiltration", -1), 32, 0)


    # 7-seed p-curve (report section 4.2).
    seven = _rows("results/M1_summary.csv") + _rows("results/probe_extra_seeds/M1_summary.csv")
    for p, tpr, auroc in [(2, 0.0299, 0.499), (3, 0.0731, 0.494), (4, 0.0929, 0.597),
                          (5, 0.0882, 0.680), (6, 0.0921, 0.774), (7, 0.0443, 0.709),
                          (8, 0.0763, 0.663)]:
        rows = [r for r in seven if r["p"] == str(p) and r["detector"] == "tie"]
        check(f"7-seed p={p} TPR", _mean(rows, "tpr"), tpr, 0.001)
        check(f"7-seed p={p} AUROC", _mean(rows, "auroc"), auroc, 0.003)

    # F3 per-class-only graphs.
    pcg = _select(_rows("results/per_class_graphs.csv"), p="8")
    for cls, class_tpr, mixed_tpr in [("PortScan", 0.0, 0.0632), ("DoS Hulk", 0.0007, 0.0015),
                                      ("Infiltration", 0.0098, 0.0), ("DoS Slowloris", 0.0010, 0.0067)]:
        rows = [r for r in pcg if r["attack_type"] == cls]
        check(f"F3 {cls} class graph", _mean(rows, "tpr_class_graph"), class_tpr, 0.001)
        check(f"F3 {cls} mixed graph", _mean(rows, "tpr_mixed_graph"), mixed_tpr, 0.001)

    # F7 label shift.
    f7 = {
        r["metric"]: float(r["value"])
        for r in _rows("results/label_shift_f7.csv")
        if r["metric"] != "day"
    }
    check("F7 skipped packets", f7["packets_skipped_by_bug"], 269201, 0)
    check("F7 mislabelled packets", f7["packets_mislabelled"], 80848, 0)
    check("F7 attack precision", f7["attack_label_precision"], 0.117692, 0.001)
    check("F7 attack recall", f7["attack_label_recall"], 0.148184, 0.001)
    check("F7 flows touched", f7["flows_touched"], 15893, 0)

    # Latency stage table.
    stages = json.loads((ROOT / "results/latency_summary.json").read_text())["modes"]["no_pe"]["stages_us"]
    for stage, expected in [("graph", 115.1), ("line", 72389.1), ("pe", 0.3),
                            ("forward", 13298.5), ("detector", 36344.5)]:
        check(f"latency stage {stage}", stages[stage]["mean"], expected, 0.5)
    check("latency total", json.loads((ROOT / "results/latency_summary.json").read_text())
          ["modes"]["no_pe"]["us_total"]["mean"], 122177.8, 1.0)

    # P1 APD / early-exit (full 7-step run).
    for alpha, apd, early in [("0.05", 7.75, 0.0770), ("0.1", 7.56, 0.1322)]:
        rows = _select(p1, alpha=alpha, method="bonferroni")
        check(f"P1 a={alpha} APD", _mean(rows, "mean_p_attack"), apd, 0.02)
        check(f"P1 a={alpha} early", _mean(rows, "early_exit_rate_attack"), early, 0.002)

    # ACI per-class p=8 (Table IX comparison) from the run JSONs.
    for cls, expected in [("PortScan", 0.0266), ("DoS-Slowloris", 0.0176),
                          ("DictionaryBruteForce", 0.0066)]:
        values = [
            json.loads((ROOT / f"results/aci/M1_p8_seed{seed}.json").read_text())
            ["ensembles"]["tie"]["per_class_tpr"][cls]["tpr"]
            for seed in range(3)
        ]
        check(f"ACI {cls}", st.mean(values), expected, 0.001)


    # Feature-input runs and the published-checkpoint probe.
    for rel, tpr, auroc in [
        ("results/feature_input/P_paper_recon/p8_selected.csv", 0.0493, 0.452),
        ("results/feature_input/T_raw/T_p8_selected.csv", 0.1878, 0.698),
    ]:
        rows = _select(_rows(rel), detector_or_rule="tie")
        check(f"{rel} TPR@6.56", _mean(rows, "tpr_at_test_fpr_6.56pct"), tpr, 0.001)
        check(f"{rel} AUROC", _mean(rows, "auroc"), auroc, 0.002)

    checkpoint = json.loads((ROOT / "results/forensics/authors_checkpoint_p8.json").read_text())
    pp = checkpoint["protocols"]["P_paper"]
    check("authors checkpoint P_paper benign", pp["benign"]["ensemble"], 0.1946, 0.001)
    check("authors checkpoint min class", min(v["ensemble"] for v in pp["classes"].values()), 0.0286, 0.001)
    check("authors checkpoint max class", max(v["ensemble"] for v in pp["classes"].values()), 0.8182, 0.001)


    # Pooled wait/delay (flow-level) and per-class p95.
    pooled = _rows("results/wait_p_pooled.csv")
    for p, benign, attack, attack_p95 in [
        (2, 0.033, 0.000, 1.00), (4, 0.040, 0.002, 1.00),
        (6, 0.085, 0.053, 1.84), (8, 0.102, 0.056, 1.86),
    ]:
        b = next(r for r in pooled if r["p"] == str(p) and r["group"] == "benign" and not r["attack_type"])
        a = next(r for r in pooled if r["p"] == str(p) and r["group"] == "attack" and not r["attack_type"])
        check(f"wait benign p={p}", float(b["median_delay_s"]), benign, 0.002)
        check(f"wait attack p={p}", float(a["median_delay_s"]), attack, 0.002)
        check(f"wait attack p={p} p95", float(a["p95_delay_s"]), attack_p95, 0.01)
    for cls, median, p95 in [("DoS Hulk", 0.147, 1.19), ("DDoS", 0.597, 1.82),
                             ("DoS GoldenEye", 6.271, 12.52), ("DoS slowloris", 3.002, 46.53),
                             ("DoS Slowhttptest", 63.126, 218.46)]:
        row = next(r for r in pooled if r["p"] == "8" and r["attack_type"] == cls)
        check(f"wait {cls} median", float(row["median_delay_s"]), median, 0.01)
        check(f"wait {cls} p95", float(row["p95_delay_s"]), p95, 0.05)


    # P4a (IP nodes) and the pre-registered gate.
    p4a = _select(_rows("results/P4a/M1_summary.csv"), p="8", detector="tie")
    check("P4a AUROC", _mean(p4a, "auroc"), 0.536, 0.002)
    check("P4a TPR", _mean(p4a, "tpr"), 0.0262, 0.001)
    p4a_matched = _select(_rows("results/feature_input/P4a_p8/T_p8_selected.csv"), detector_or_rule="tie")
    check("P4a TPR@6.56", _mean(p4a_matched, "tpr_at_test_fpr_6.56pct"), 0.1299, 0.001)
    check("P4a TPR@1%", _mean(p4a_matched, "tpr_at_test_fpr_1pct"), 0.0005, 0.001)

    if FAILURES:
        print(f"FAILED {len(FAILURES)}/{CHECKS} checks")
        for failure in FAILURES:
            print(" -", failure)
        return 1
    print(f"OK: {CHECKS} report-number checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
