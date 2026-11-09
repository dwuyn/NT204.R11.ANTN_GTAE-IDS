#!/usr/bin/env python3
"""Interactive terminal demo for GTAE-IDS with Proposal P1 (Early-Exit).

Simulates a real-time sequential stream of network flows across packet budget p=2..8.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

import numpy as np
import torch

from src.calibrate import calibrate_and_fuse
from src.detectors import build_detectors, fit_detectors, predict_detectors
from src.early_exit import run_early_exit
from src.embed import embed_graph, load_model
from src.graph_builder import load_graph


def format_row(cols: list[str], widths: list[int]) -> str:
    return " | ".join(c.ljust(w)[:w] for c, w in zip(cols, widths))


def run_demo(n_samples: int = 40, alpha: float = 0.05, seed: int = 0):
    print("=" * 78)
    print("  GTAE-IDS + PROPOSAL P1: REAL-TIME SEQUENTIAL INTRUSION DETECTION DEMO")
    print("=" * 78)
    print(f"[*] Configuration: alpha = {alpha} (conformal target FPR), sample_size = {n_samples}")
    print("[*] Loading GTAE models and fixed-population evaluation graphs (T_fixed)...")

    device = torch.device("cpu")
    fixed_dir = Path("data/graphs/T_fixed")
    exp_dir = Path("experiments/T")

    # Sample equal mix of benign and attack flows
    test_p8 = load_graph(fixed_dir / "p8" / "test.npz")
    benign_indices = np.where(test_p8.y == 0)[0]
    attack_indices = np.where(test_p8.y == 1)[0]

    rng = np.random.default_rng(seed)
    n_half = n_samples // 2
    sel_ben = rng.choice(benign_indices, size=n_half, replace=False)
    sel_att = rng.choice(attack_indices, size=n_half, replace=False)
    selected_indices = np.concatenate([sel_ben, sel_att])
    rng.shuffle(selected_indices)

    y_true = test_p8.y[selected_indices].astype(int)
    flow_ids = test_p8.flow_id[selected_indices]
    attack_types = test_p8.attack_type[selected_indices]

    scores_by_p = {}
    calib_scores_by_p = {}

    ps = [2, 3, 4, 5, 6, 7, 8]
    print("[*] Encoding graph snapshots across sequential packet budgets p=2..8:")
    for p in ps:
        model_path = exp_dir / f"p{p}" / f"seed{seed}" / "model.pt"
        train2 = load_graph(fixed_dir / f"p{p}" / "train2.npz")
        test = load_graph(fixed_dir / f"p{p}" / "test.npz")

        model, checkpoint = load_model(model_path, device)
        use_pe = bool(checkpoint.get("use_pe", True))

        z_train = embed_graph(model, train2, device, k_max=32, use_pe=use_pe, seed=seed)
        z_test = embed_graph(model, test, device, k_max=32, use_pe=use_pe, seed=seed)

        # 20% calibration split
        n_calib = int(len(z_train) * 0.2)
        z_fit = z_train[n_calib:]
        z_calib = z_train[:n_calib]

        detectors = build_detectors(contamination=0.01, seed=seed)
        fit_detectors(detectors, z_fit)

        _, scores_test = predict_detectors(detectors, z_test[selected_indices])
        _, scores_calib = predict_detectors(detectors, z_calib)

        scores_by_p[p] = scores_test
        calib_scores_by_p[p] = scores_calib
        print(f"    - p = {p}: GTAE encoding & calibration ready")

    print("\n[*] Streaming flows through sequential detector (simulating packet arrivals)...")
    time.sleep(0.5)

    headers = ["Flow ID", "Actual Class", "Attack Name", "Decision", "Exit At", "P-Value", "Alert"]
    widths = [8, 12, 22, 10, 8, 8, 7]
    print("\n" + format_row(headers, widths))
    print("-" * 88)

    # Run early exit
    res = run_early_exit(scores_by_p, calib_scores_by_p, y_true, alpha=alpha, ps=ps)

    for i in range(len(selected_indices)):
        fid = str(flow_ids[i])
        actual = "BENIGN" if y_true[i] == 0 else "ATTACK"
        att_name = str(attack_types[i])
        pred = "ALERT" if res.y_pred[i] == 1 else "NORMAL"
        exit_p = f"p={res.p_decision[i]}"
        pval = f"{res.fused_pvalues[res.p_decision[i]][i]:.4f}"
        status = "[!]" if res.y_pred[i] == 1 else "[OK]"

        # Color highlight
        row_str = format_row([fid, actual, att_name, pred, exit_p, pval, status], widths)
        print(row_str)
        time.sleep(0.04)

    print("-" * 88)
    print("\n" + "=" * 78)
    print("  DEMO PERFORMANCE SUMMARY")
    print("=" * 78)
    print(f"  Total evaluated flows:        {len(y_true)} (Benign: {int((y_true==0).sum())}, Attack: {int((y_true==1).sum())})")
    print(f"  Empirical True Positive Rate: {res.tpr * 100:.2f}%")
    print(f"  Empirical False Positive Rate:{res.fpr * 100:.2f}% (Target: <= {alpha*100:.1f}%)")
    print(f"  Average Packets to Decision (Attack): {res.mean_p_attack:.2f} packets (vs baseline 8.00)")
    print(f"  Average Packets to Decision (Benign): {res.mean_p_benign:.2f} packets")
    print(f"  Early Detection Rate for Attacks:     {res.early_exit_rate_attack * 100:.1f}% stopped before p=8")
    saved_packets_pct = max(0.0, (8.0 - res.mean_p_attack) / 8.0 * 100)
    print(f"  Latency reduction:                    {saved_packets_pct:.1f}% packet-wait time saved")
    print("=" * 78)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run GTAE-IDS Early-Exit Demo")
    parser.add_argument("--samples", type=int, default=30, help="Number of demo flows")
    parser.add_argument("--alpha", type=float, default=0.05, help="Target FPR budget")
    parser.add_argument("--seed", type=int, default=0, help="Random seed")
    args = parser.parse_args()

    run_demo(n_samples=args.samples, alpha=args.alpha, seed=args.seed)
