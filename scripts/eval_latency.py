#!/usr/bin/env python3
"""Online latency harness: end-to-end pcap replay and early-exit cost.

Two modes, one script.

``--mode stream`` replays a pcap flow by flow and times the full online path
(window graph update, line graph, optional PE, encoder forward, detectors) per
flow. "Real-time" is defined as per-flow wall clock from flow close to alert
(docs/DECISIONS.md §4). Two checkpoints define the two reported modes: the
no-PE model (headline) and the PE model (secondary, pays the PE cost).

    python scripts/eval_latency.py --mode stream --pcap data/raw/Friday-WorkingHours.pcap \
        --day friday --graphs data/graphs/T --models experiments/T_noPE --p 8 --seed 0 \
        --window 120 --max-flows 0 --out results --device cpu

``--mode early-exit`` measures what the sequential decision actually costs:
per-step encoder forward time on the real test matrix, summed up to the
measured decision step.

Writes ``results/latency.csv`` (append), ``results/latency_summary.json``
(merged), ``results/early_exit_timing.csv`` and ``reports/latency.md``.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from array import array
from pathlib import Path
from typing import Any

import numpy as np
import pyarrow.parquet as pq
import torch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.detectors import (  # noqa: E402
    DETECTOR_NAMES,
    build_detectors,
    fit_detectors,
    metrics,
    predict_detectors,
    rank_normalize,
    vote,
)
from src.early_exit import run_early_exit  # noqa: E402
from src.embed import embed_graph, load_model  # noqa: E402
from src.graph_builder import load_graph  # noqa: E402
from src.line_graph import build_line_graph  # noqa: E402
from src.parse_pcap import iter_flows  # noqa: E402
from src.pe import PE_DIM, edge_pe, laplacian_pe  # noqa: E402
from src.streaming import WindowGraph, embed_rows  # noqa: E402

STAGES = ("graph", "line", "pe", "forward", "detector")
PERCENTILES = (50, 95, 99)
CSV_FIELDS = [
    "mode",
    "p",
    "seed",
    "flow_id",
    "t_last",
    "window_edges",
    "label",
    "attack_type",
    *[f"us_{stage}" for stage in STAGES],
    "us_total",
    *[f"score_{name}" for name in DETECTOR_NAMES],
]


def label_map(day: str) -> dict[int, tuple[int, str]]:
    path = REPO_ROOT / f"data/processed/flows_{day}_labeled.parquet"
    if not path.exists():
        raise FileNotFoundError(path)
    table = pq.read_table(path, columns=["flow_id", "label", "attack_type"])
    return {
        int(row["flow_id"]): (int(row["label"]), str(row["attack_type"] or ""))
        for row in table.to_pylist()
    }


def fit_online_detectors(
    model_path: Path,
    graphs_dir: Path,
    p: int,
    seed: int,
    device: torch.device,
    contamination: float = 0.01,
    calibration_fraction: float = 0.2,
    k_max: int = 32,
) -> tuple[torch.nn.Module, bool, dict[str, Any], dict[str, np.ndarray]]:
    """Fit detectors on the 80% split of train2 (same rule as `src.eval`)."""
    if not model_path.exists():
        raise FileNotFoundError(model_path)
    train2_path = graphs_dir / f"p{p}" / "train2.npz"
    if not train2_path.exists():
        raise FileNotFoundError(train2_path)
    model, checkpoint = load_model(model_path, device)
    use_pe = bool(checkpoint.get("use_pe", True))
    z_train = embed_graph(
        model, load_graph(train2_path), device, k_max=k_max, use_pe=use_pe, seed=seed
    )
    rng = np.random.default_rng(seed)
    permutation = rng.permutation(len(z_train))
    n_calib = max(1, int(len(z_train) * calibration_fraction))
    calibration_idx = permutation[:n_calib]
    fit_idx = permutation[n_calib:]
    detectors = build_detectors(contamination=contamination, seed=seed)
    fit_detectors(detectors, z_train[fit_idx])
    calib_scores = predict_detectors(detectors, z_train[calibration_idx])[1]
    return model, use_pe, detectors, calib_scores


def score_detectors(
    detectors: dict[str, Any], x: np.ndarray
) -> dict[str, float]:
    """Anomaly scores for one embedding row, one ``decision_function`` per detector.

    ``pyod``'s ``predict`` re-traverses the trees that ``decision_function``
    already traversed; the online path only needs the score, and the binary
    decision is reconstructed later as ``score > threshold_`` (identical to
    ``predict``).
    """
    return {name: float(model.decision_function(x)[0]) for name, model in detectors.items()}


def _quantiles(values: np.ndarray, digits: int = 2) -> dict[str, float]:
    if values.size == 0:
        return {f"p{pct}": 0.0 for pct in PERCENTILES}
    return {
        f"p{pct}": round(float(np.percentile(values, pct)), digits)
        for pct in PERCENTILES
    }


def stream_mode(
    pcap: Path,
    day: str,
    graphs_dir: Path,
    model_path: Path,
    p: int,
    seed: int,
    window: float,
    max_flows: int,
    sample_every: int,
    out_dir: Path,
    device: torch.device,
) -> dict[str, Any]:
    if not pcap.exists():
        raise FileNotFoundError(pcap)
    labels = label_map(day)
    model, use_pe, detectors, calib_scores = fit_online_detectors(
        model_path, graphs_dir, p, seed, device
    )
    mode = "window_pe" if use_pe else "no_pe"

    graph = WindowGraph(window=window)
    us = {stage: array("d") for stage in STAGES}
    us_total = array("d")
    scores = {name: array("d") for name in DETECTOR_NAMES}
    ys = array("i")
    valid = array("b")
    behind_flags = array("b")
    window_edges = array("l")
    replayed = 0
    measured = 0
    stale = 0
    unlabelled = 0
    uncertain = 0
    watermark = float("-inf")
    started = time.perf_counter()

    out_csv = out_dir / "latency.csv"
    out_dir.mkdir(parents=True, exist_ok=True)
    fresh = not out_csv.exists()
    with open(out_csv, "a", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_FIELDS, lineterminator="\n")
        if fresh:
            writer.writeheader()

        for flow in iter_flows(pcap):
            replayed += 1
            t_last = float(flow["t_last"])
            # Logical clock: a flow is scored at its own last packet, so the
            # watermark (max seen) defines the window. Flows closed late by the
            # capture boundary carry an old t_last and are already outside it.
            watermark = max(watermark, t_last)
            behind = t_last < watermark - window
            if sample_every > 1 and replayed % sample_every:
                graph.expire(watermark)
                graph.add(flow, p)  # keep the window state exact, skip the cost
                continue

            t0 = time.perf_counter()
            graph.expire(watermark)
            # A flow is always scored against its own window: if its last packet
            # already fell behind the watermark (idle-timeout / capture-boundary
            # closure), it is still added here and dropped by the next expire.
            row = graph.add(flow, p)
            edge_index, edge_attr = graph.arrays(p)
            mark = time.perf_counter()

            timings: dict[str, float] = {}
            z = embed_rows(model, edge_index, edge_attr, use_pe, seed, timings)
            mark_forward_end = time.perf_counter()

            detector_scores = score_detectors(detectors, z[row : row + 1])
            spent = time.perf_counter() - t0
            forward_end = mark_forward_end - t0

            record: dict[str, Any] = {
                "mode": mode,
                "p": p,
                "seed": seed,
                "flow_id": int(flow["flow_id"]),
                "t_last": round(t_last, 6),
                "window_edges": len(graph),
            }
            label = labels.get(int(flow["flow_id"]))
            if label is None:
                unlabelled += 1
                record["label"] = ""
                record["attack_type"] = ""
                valid.append(0)
            elif label[0] not in (0, 1):
                uncertain += 1
                record["label"] = label[0]
                record["attack_type"] = label[1]
                valid.append(0)
            else:
                record["label"] = label[0]
                record["attack_type"] = label[1]
                ys.append(label[0])
                valid.append(1)
            record.update(
                {
                    "us_graph": round(1e6 * (mark - t0), 2),
                    "us_line": round(1e6 * timings["line"], 2),
                    "us_pe": round(1e6 * timings["pe"], 2),
                    "us_forward": round(1e6 * timings["forward"], 2),
                    "us_detector": round(1e6 * (spent - forward_end), 2),
                    "us_total": round(1e6 * spent, 2),
                }
            )
            for name in DETECTOR_NAMES:
                record[f"score_{name}"] = round(detector_scores[name], 6)
            writer.writerow(record)

            us["graph"].append(record["us_graph"])
            us["line"].append(record["us_line"])
            us["pe"].append(record["us_pe"])
            us["forward"].append(record["us_forward"])
            us["detector"].append(record["us_detector"])
            us_total.append(record["us_total"])
            window_edges.append(len(graph))
            if behind:
                stale += 1
            behind_flags.append(1 if behind else 0)
            for name in DETECTOR_NAMES:
                scores[name].append(detector_scores[name])
            measured += 1
            if max_flows and measured >= max_flows:
                break

    elapsed = time.perf_counter() - started
    if measured == 0:
        raise SystemExit("no flows replayed")

    mask = np.asarray(valid, dtype=bool)
    detector_scores_arr = {
        name: np.asarray(scores[name], dtype=np.float64)[mask] for name in DETECTOR_NAMES
    }
    y = np.asarray(ys, dtype=np.int8)
    predictions = {
        name: (detector_scores_arr[name] > float(detectors[name].threshold_)).astype(np.int8)
        for name in DETECTOR_NAMES
    }
    mean_total = float(np.mean(us_total))
    totals = np.asarray(us_total, dtype=np.float64)
    fresh_mask = np.asarray(behind_flags, dtype=bool) == 0
    summary: dict[str, Any] = {
        "mode": mode,
        "p": p,
        "seed": seed,
        "pcap": str(pcap.relative_to(REPO_ROOT)) if pcap.is_relative_to(REPO_ROOT) else str(pcap),
        "window_s": window,
        "use_pe": use_pe,
        "n_flows": replayed,
        "n_measured": measured,
        "sample_every": sample_every,
        "stale_flows": stale,
        "max_flows_cap": max_flows,
        "unlabelled": unlabelled,
        "uncertain": uncertain,
        "labelled": int(y.size),
        "metrics_valid": bool(y.size) and (unlabelled + uncertain) / measured <= 0.10,
        "wall_s": round(elapsed, 1),
        "throughput_flows_s": round(replayed / elapsed, 1),
        "detection_throughput_flows_s": round(1e6 / mean_total, 1) if mean_total else None,
        "detection_throughput_fresh_flows_s": (
            round(1e6 / float(totals[fresh_mask].mean()), 1) if fresh_mask.any() else None
        ),
        "us_packet_basis": f"{p} packets/flow",
        "window_edges_mean": round(float(np.mean(edges_arr := np.asarray(window_edges))), 1),
        "window_edges_p95": round(float(np.percentile(edges_arr, 95)), 1),
        "us_packet": round(mean_total / p, 2),
        "stages_us": {
            stage: {
                "mean": round(float(np.mean(us[stage])), 2),
                **_quantiles(np.asarray(us[stage])),
            }
            for stage in STAGES
        },
        "us_total": {"mean": round(mean_total, 2), **_quantiles(totals)},
        "us_total_fresh": {
            "n": int(fresh_mask.sum()),
            "mean": round(float(totals[fresh_mask].mean()), 2) if fresh_mask.any() else 0.0,
            **_quantiles(totals[fresh_mask]),
        },
        "us_total_stale": {
            "n": int((~fresh_mask).sum()),
            "mean": round(float(totals[~fresh_mask].mean()), 2) if (~fresh_mask).any() else 0.0,
            **_quantiles(totals[~fresh_mask]),
        },
    }
    if y.size and len(np.unique(y)) > 1:
        fused = np.mean(
            [rank_normalize(detector_scores_arr[name]) for name in DETECTOR_NAMES], axis=0
        )
        fused_calib = np.mean(
            [rank_normalize(calib_scores[name]) for name in DETECTOR_NAMES], axis=0
        )
        summary["streaming_metrics"] = {
            name: metrics(
                y,
                predictions[name],
                detector_scores_arr[name],
                calibration_scores=calib_scores[name],
            )
            for name in DETECTOR_NAMES
        }
        for rule in ("strict", "tie"):
            summary["streaming_metrics"][f"ensemble_{rule}"] = metrics(
                y, vote(predictions, rule), fused, calibration_scores=fused_calib
            )
    else:
        summary["streaming_metrics"] = {}

    if (unlabelled + uncertain) / measured > 0.10:
        print(
            f"[latency] WARNING {unlabelled} unlabelled + {uncertain} UNCERTAIN of "
            f"{measured} measured flows; "
            "streaming metrics are not comparable",
            flush=True,
        )
    print(
        f"[latency] {mode}: {replayed} flows replayed, {measured} measured in {elapsed:.1f}s "
        f"(mean {summary['us_total']['mean']:.1f} us/flow, p95 "
        f"{summary['us_total']['p95']:.1f} us/flow, {stale} stale)",
        flush=True,
    )
    return summary


def _step_costs(
    model: torch.nn.Module,
    edge_attr: np.ndarray,
    edge_index: np.ndarray,
    num_nodes: int,
    use_pe: bool,
    seed: int,
    batch: int = 4096,
) -> tuple[float, float]:
    """Mean and p95 per-edge forward cost (seconds) on the real test matrix.

    The encoder is timed in batches of ``batch`` edges; the line graph is
    restricted to edges inside a batch (a slice cannot index rows outside it),
    which is the same neighbourhood density the full graph has.
    """
    line = build_line_graph(edge_index, num_nodes, max_neighbors=32, seed=seed)
    pe_t = None
    if use_pe:
        node_pe = laplacian_pe(edge_index, num_nodes, k=PE_DIM, seed=seed)
        pe_t = torch.from_numpy(edge_pe(node_pe, edge_index))
    x = torch.from_numpy(edge_attr)
    slices = [
        (start, min(start + batch, x.size(0))) for start in range(0, x.size(0), batch)
    ]
    args_list = [
        (
            x[start:stop],
            _sub_line(line, start, stop - start),
            pe_t[start:stop] if pe_t is not None else None,
        )
        for start, stop in slices
    ]
    with torch.no_grad():
        model.encode(*args_list[0])  # warm up thread pool / allocator
        costs: list[float] = []
        for args in args_list:
            t0 = time.perf_counter()
            model.encode(*args)
            costs.append(time.perf_counter() - t0)
    weights = np.asarray([stop - start for start, stop in slices], dtype=np.float64)
    per_edge = np.asarray(costs, dtype=np.float64) / weights
    mean = float((per_edge * weights).sum() / weights.sum())
    order = np.argsort(per_edge)
    cumulative = np.cumsum(weights[order]) / weights.sum()
    p95 = float(per_edge[order][min(np.searchsorted(cumulative, 0.95), len(order) - 1)])
    return mean, p95


def _sub_line(line: np.ndarray, start: int, count: int) -> torch.Tensor:
    """Line-graph slice for edges ``[start, start+count)`` (self-loops kept)."""
    src, dst = line[0], line[1]
    mask = (
        (src >= start) & (src < start + count) & (dst >= start) & (dst < start + count)
    )
    sub = line[:, mask].copy()
    sub[0] -= start
    sub[1] -= start
    return torch.as_tensor(sub, dtype=torch.long)


def early_exit_mode(
    graphs_dir: Path,
    models_dir: Path,
    alphas: list[float],
    seeds: list[int],
    out_dir: Path,
    device: torch.device,
    ps: tuple[int, ...] = (2, 3, 4, 5, 6, 7, 8),
    method: str = "bonferroni",
) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for seed in seeds:
        scores_by_p: dict[int, dict[str, np.ndarray]] = {}
        calib_by_p: dict[int, dict[str, np.ndarray]] = {}
        step_mean: dict[int, float] = {}
        step_p95: dict[int, float] = {}
        y_true: np.ndarray | None = None
        for p in ps:
            model_path = models_dir / f"p{p}" / f"seed{seed}" / "model.pt"
            if not model_path.exists():
                raise FileNotFoundError(model_path)
            train2 = load_graph(graphs_dir / f"p{p}" / "train2.npz")
            test = load_graph(graphs_dir / f"p{p}" / "test.npz")
            if y_true is not None and test.y.size != y_true.size:
                raise ValueError(
                    f"test population differs across p ({test.y.size} at p={p} vs "
                    f"{y_true.size}); early exit needs a fixed population — use "
                    "--graphs data/graphs/T_fixed"
                )
            model, checkpoint = load_model(model_path, device)
            use_pe = bool(checkpoint.get("use_pe", True))
            z_train = embed_graph(model, train2, device, use_pe=use_pe, seed=seed)
            z_test = embed_graph(model, test, device, use_pe=use_pe, seed=seed)
            rng = np.random.default_rng(seed)
            permutation = rng.permutation(len(z_train))
            n_calib = max(1, int(len(z_train) * 0.2))
            calibration_idx = permutation[:n_calib]
            fit_idx = permutation[n_calib:]
            detectors = build_detectors(contamination=0.01, seed=seed)
            fit_detectors(detectors, z_train[fit_idx])
            scores_by_p[p] = predict_detectors(detectors, z_test)[1]
            calib_by_p[p] = predict_detectors(detectors, z_train[calibration_idx])[1]
            step_mean[p], step_p95[p] = _step_costs(
                model, test.edge_attr, test.edge_index, test.num_nodes, use_pe, seed
            )
            y_true = test.y.astype(np.int8)
            print(
                f"[latency] early-exit seed={seed} p={p} step {1e6 * step_mean[p]:.1f} us/flow",
                flush=True,
            )

        assert y_true is not None
        for alpha in alphas:
            result = run_early_exit(
                scores_by_p, calib_by_p, y_true, alpha=alpha, method=method, ps=ps
            )
            cost_ps = np.array([step_mean[p] for p in ps], dtype=np.float64)
            cumulative = np.concatenate([[0.0], np.cumsum(cost_ps)])
            # A flow decided at ps[k] paid for k+1 forward passes.
            step_index = np.searchsorted(np.asarray(ps), result.p_decision)
            per_flow = cumulative[step_index + 1]
            rows.append(
                {
                    "alpha": alpha,
                    "seed": seed,
                    "method": method,
                    "p_decision_median": float(np.median(result.p_decision)),
                    "p_decision_mean": round(float(np.mean(result.p_decision)), 3),
                    "us_per_flow_mean": round(1e6 * float(per_flow.mean()), 1),
                    "us_per_flow_p95": round(1e6 * float(np.percentile(per_flow, 95)), 1),
                    "early_exit_rate_attack": round(result.early_exit_rate_attack, 4),
                    "tpr": round(result.tpr, 4),
                    "fpr": round(result.fpr, 4),
                }
            )

    out_csv = out_dir / "early_exit_timing.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"[latency] wrote {out_csv} ({len(rows)} rows)", flush=True)
    return {"rows": rows}


def _fmt_us(value: float) -> str:
    return f"{value:,.1f}"


def write_report(summary_path: Path, report_path: Path) -> None:
    data = json.loads(summary_path.read_text(encoding="utf-8"))
    modes: dict[str, Any] = data.get("modes", {})
    lines = [
        "# Online latency (sinh tự động)",
        "",
        "**Nguồn:** `results/latency_summary.json` (+ `results/latency.csv`, "
        "`results/early_exit_timing.csv`). Chạy lại bằng "
        "`python scripts/eval_latency.py --mode stream ...`.",
        "",
        "**Định nghĩa (docs/DECISIONS.md §4):** \"real-time\" = wall clock per flow "
        "từ lúc flow đóng đến lúc có alert, trên replay pcap thật. Stage: `graph` "
        "(expire + add + dựng edge matrix), `line` (line graph), `pe` (Laplacian PE, "
        "0 khi no-PE), `forward` (encoder), `detector` (4 detector trên 1 embedding).",
        "",
    ]
    if modes:
        lines += [
            "## 1. Replay end-to-end",
            "",
            "Mỗi flow trong pcap đều được parse và đưa vào cửa sổ; chi phí end-to-end "
            "chỉ được đo trên mỗi flow thứ `K` (`sample_every`) vì dựng lại transformer "
            "trên toàn cửa sổ cho từng flow là bất khả thi về thời gian (xem mục 5).",
            "",
            "| mode | p | seed | flows replayed | K | flows đo | stale | cửa sổ (s) | edges/flow (mean/p95) | wall (s) | flows/s replay | flows/s detect | µs/packet | metrics_valid |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|",
        ]
        for mode in modes.values():
            lines.append(
                f"| {mode['mode']} | {mode['p']} | {mode['seed']} | {mode['n_flows']:,} | "
                f"{mode['sample_every']} | {mode['n_measured']:,} | {mode.get('stale_flows', 0):,} | "
                f"{mode['window_s']:g} | {mode['window_edges_mean']:,.1f} / "
                f"{mode.get('window_edges_p95', 0):,.1f} | {mode['wall_s']:,.0f} | "
                f"{mode['throughput_flows_s']:,.1f} | "
                f"{mode.get('detection_throughput_flows_s') or 0:,.1f} | {mode['us_packet']:g} | "
                f"{'yes' if mode['metrics_valid'] else 'no'} |"
            )
        lines += [
            "",
            "## 2. Stage latency (µs/flow)",
            "",
            "| mode | stage | mean | p50 | p95 | p99 |",
            "|---|---|---:|---:|---:|---:|",
        ]
        for mode in modes.values():
            for stage, stats in mode["stages_us"].items():
                lines.append(
                    f"| {mode['mode']} | {stage} | {_fmt_us(stats['mean'])} | "
                    f"{_fmt_us(stats['p50'])} | {_fmt_us(stats['p95'])} | {_fmt_us(stats['p99'])} |"
                )
            total = mode["us_total"]
            lines.append(
                f"| {mode['mode']} | **total** | **{_fmt_us(total['mean'])}** | "
                f"{_fmt_us(total['p50'])} | {_fmt_us(total['p95'])} | {_fmt_us(total['p99'])} |"
            )
        lines += [
            "",
            "**Stale vs fresh (quan trọng cho cách đọc):** một flow được chấm tại "
            "`t_last` của chính nó; nếu `t_last` đã lùi quá cửa sổ so với mốc thời gian "
            "lớn nhất đã thấy (`watermark`), nó là flow đóng do hết capture (hoặc idle "
            "timeout) và cửa sổ của nó không còn chứa bản thân nó. Tách hai nhóm này ra:",
            "",
            "| mode | nhóm | n | mean | p50 | p95 | p99 |",
            "|---|---|---:|---:|---:|---:|---:|",
        ]
        for mode in modes.values():
            for label, key in (("fresh", "us_total_fresh"), ("stale", "us_total_stale")):
                group = mode.get(key) or {}
                if not group:
                    continue
                lines.append(
                    f"| {mode['mode']} | {label} | {group['n']:,} | {_fmt_us(group['mean'])} | "
                    f"{_fmt_us(group['p50'])} | {_fmt_us(group['p95'])} | {_fmt_us(group['p99'])} |"
                )
        lines += [""]
        lines += [
            "",
            "## 3. Streaming vs offline",
            "",
            "| mode | rule | streaming TPR | streaming FPR | streaming AUROC | offline T TPR (p8, 3 seed mean) | offline FPR |",
            "|---|---|---:|---:|---:|---|---:|",
        ]
        offline = _offline_reference()
        for mode in modes.values():
            for rule in ("ensemble_tie", "ensemble_strict"):
                m = mode.get("streaming_metrics", {}).get(rule)
                if not m:
                    continue
                auroc = f"{m['auroc']:.3f}" if m.get("auroc") is not None else "n/a"
                lines.append(
                    f"| {mode['mode']} | {rule.replace('ensemble_', '')} | "
                    f"{100 * (m['tpr'] or 0):.2f}% | {100 * (m['fpr'] or 0):.2f}% | "
                    f"{auroc} | {offline['tpr']} | {offline['fpr']} |"
                )
        if modes:
            lines += [
                "",
                "**Đọc bảng này:** streaming metrics KHÔNG phải phép đo offline, vì ba "
                "lý do phải đọc cùng nhau:",
                "",
                "1. **Quần thể khác.** Streaming chỉ replay thứ Sáu; offline `T` là "
                "test Thứ Ba–Thứ Sáu. Tỷ lệ tấn công và thành phần lớp khác nhau.",
                "2. **Đồ thị khác.** Mỗi flow được chấm trên cửa sổ trượt của nó, không "
                "phải trên đồ thị tĩnh của split; embedding khác M1 theo thiết kế.",
                "3. **Không hiệu chỉnh lại ngưỡng.** 4 detector được fit trên embedding "
                "`train2` offline và áp nguyên ngưỡng (`threshold_`) lên embedding "
                "cửa sổ. Vì vậy cột TPR/FPR đo *khả năng chuyển ngưỡng*, không phải "
                "năng lực tối đa; **AUROC là cột thông tin** vì nó bất biến với ngưỡng.",
                "",
                "Kết luận cần kiểm tra: streaming còn giữ thứ hạng (AUROC không sụp về "
                "0.5) thì biểu diễn cửa sổ vẫn dùng được, ngay cả khi ngưỡng phải "
                "hiệu chỉnh lại trên dữ liệu cửa sổ.",
                "",
            ]
    exit_rows = data.get("early_exit", {}).get("rows", [])
    if exit_rows:
        lines += [
            "## 4. Early-exit (P1) cost",
            "",
            "Chi phí mỗi flow = tổng forward cost của các bước p đã dùng trước khi ra "
            "quyết định (`EarlyExitResult.p_decision`). Forward cost mỗi bước đo bằng "
            "batch 4096 trên ma trận edge test thật, không phải suy ra từ APD.",
            "",
            "| alpha | seed | method | p_decision median | p_decision mean | µs/flow mean | µs/flow p95 | early-exit rate (attack) | TPR | FPR |",
            "|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|",
        ]
        for row in exit_rows:
            lines.append(
                f"| {row['alpha']} | {row['seed']} | {row['method']} | "
                f"{row['p_decision_median']:g} | {row['p_decision_mean']:g} | "
                f"{_fmt_us(row['us_per_flow_mean'])} | {_fmt_us(row['us_per_flow_p95'])} | "
                f"{100 * row['early_exit_rate_attack']:.2f}% | {100 * row['tpr']:.2f}% | "
                f"{100 * row['fpr']:.2f}% |"
            )
        lines += [
            "",
            "Chi phí này chỉ gồm encoder forward; detector và cửa sổ đồ thị là hằng số "
            "theo p nên không đổi giữa các bước.",
            "",
            "**Chia tách calibration:** mode này dùng đúng split của `src.eval` "
            "(`calibration_fraction = 0.2` → `n_calib = 400`), nên sàn Bonferroni "
            "`4/401 ≈ 0.00998` lớn hơn `α/K = 0.05/7 ≈ 0.00714`: ở α = 0.05 **không thể** "
            "alert, và bảng dưới đúng là 0. P1 công bố (`results/P1_summary.csv`) dùng "
            "`calibration_fraction = 0.4` (800 flow) — đọc TPR/FPR ở đây là của split "
            "0.2, còn cột thời gian là thứ cần lấy từ bảng này.",
            "",
        ]
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[latency] wrote {report_path}", flush=True)


def _offline_reference() -> dict[str, str]:
    """Mean offline `T` p8 ensemble-tie numbers, for the side-by-side table."""
    path = REPO_ROOT / "results/M1_summary.csv"
    if not path.exists():
        return {"tpr": "n/a", "fpr": "n/a"}
    with open(path, encoding="utf-8") as fh:
        rows = [
            row
            for row in csv.DictReader(fh)
            if row.get("p") == "8" and row.get("model") == "ensemble" and row.get("detector") == "tie"
        ]
    if not rows:
        return {"tpr": "n/a", "fpr": "n/a"}
    tpr = 100 * sum(float(row["tpr"]) for row in rows) / len(rows)
    fpr = 100 * sum(float(row["fpr"]) for row in rows) / len(rows)
    return {"tpr": f"**{tpr:.2f}%**", "fpr": f"**{fpr:.2f}%**"}


def merge_json(
    path: Path, key: str, payload: Any, section: str | None = "modes"
) -> None:
    """Merge ``payload`` so runs never overwrite each other.

    ``section="modes"`` puts the payload under ``modes[key]`` (one entry per
    replay configuration); ``section=None`` writes ``key`` at the top level.
    """
    data: dict[str, Any] = {}
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
    if section is None:
        data[key] = payload
    else:
        data.setdefault(section, {})[key] = payload
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", default="stream", choices=["stream", "early-exit"])
    parser.add_argument("--pcap", default="data/raw/Friday-WorkingHours.pcap")
    parser.add_argument("--day", default="friday")
    parser.add_argument("--graphs", default="data/graphs/T")
    parser.add_argument("--models", default="experiments/T")
    parser.add_argument("--p", type=int, default=8)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--alpha", type=float, nargs="+", default=[0.05, 0.10])
    parser.add_argument("--window", type=float, default=120.0)
    parser.add_argument("--threads", type=int, default=None, help="torch intra-op threads")
    parser.add_argument(
        "--max-flows", type=int, default=0, help="stop after N measured flows (0 = no cap)"
    )
    parser.add_argument(
        "--sample-every",
        type=int,
        default=1,
        help="replay every flow, but time only every K-th one (1 = time all)",
    )
    parser.add_argument("--out", default="results")
    parser.add_argument("--device", default="cpu", choices=["auto", "cpu", "cuda"])
    args = parser.parse_args(argv)

    if args.threads:
        torch.set_num_threads(args.threads)
    device = torch.device(
        "cuda" if args.device == "auto" and torch.cuda.is_available() else
        ("cpu" if args.device == "auto" else args.device)
    )
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary_path = out_dir / "latency_summary.json"
    report_path = REPO_ROOT / "reports/latency.md"

    if args.mode == "stream":
        summary = stream_mode(
            REPO_ROOT / args.pcap,
            args.day,
            REPO_ROOT / args.graphs,
            REPO_ROOT / args.models / f"p{args.p}/seed{args.seed}" / "model.pt",
            args.p,
            args.seed,
            args.window,
            args.max_flows,
            args.sample_every,
            out_dir,
            device,
        )
        merge_json(summary_path, summary["mode"], summary)
    else:
        payload = early_exit_mode(
            REPO_ROOT / args.graphs,
            REPO_ROOT / args.models,
            args.alpha,
            args.seeds,
            out_dir,
            device,
        )
        merge_json(summary_path, "early_exit", {"rows": payload["rows"]}, section=None)

    write_report(summary_path, report_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
