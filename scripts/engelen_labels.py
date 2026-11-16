#!/usr/bin/env python3
"""Engelen et al. (WTMC 2021) label audit: composition, matching, re-scoring.

The Engelen relabelling is an independent CICFlowMeter-style pass over the same
2017 traffic, with `- Attempted` variants for sessions that were started but did
not complete. Four levels (docs/DECISIONS.md §5), `X - Attempted` counts as an
attack:

  --compose      L1: composition of our `P_paper` test set vs paper Table VII vs
                 the Engelen labels.
  --map          L2: match Engelen rows onto our flows by 5-tuple + timestamp,
                 then write the label map and a per-day confusion table.
  --relabel-eval L3: re-score the trained p8 models with Engelen labels.

    python scripts/engelen_labels.py --compose
    python scripts/engelen_labels.py --map
    python scripts/engelen_labels.py --relabel-eval --device cpu
"""

from __future__ import annotations

import argparse
import bisect
import collections
import csv
import json
import sys
import time
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pyarrow as pa
import pyarrow.parquet as pq
import torch

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.cic_graph import (  # noqa: E402
    BENIGN_LABEL,
    PAPER_TEST_BENIGN,
    PAPER_TEST_COUNTS,
    normalize_label,
)
from src.detectors import (  # noqa: E402
    DETECTOR_NAMES,
    build_detectors,
    fit_detectors,
    metrics,
    predict_detectors,
    rank_normalize,
    vote,
)
from src.embed import embed_graph, load_model  # noqa: E402
from src.graph_builder import load_graph  # noqa: E402
from src.parse_pcap import _flow_key  # noqa: E402

ENGELEN_DIR = REPO_ROOT / "data/raw/engelen"
PROCESSED = REPO_ROOT / "data/processed"
RESULTS = REPO_ROOT / "results"
ATTEMPTED_SUFFIX = "- Attempted"
MATCH_WINDOW_S = 60.0
OFFSET_SAMPLE_STRIDE = 137

# Our day name -> (Engelen csv, capture date used only for reporting)
DAYS: dict[str, tuple[str, date]] = {
    "monday": ("Monday-WorkingHours.csv", date(2017, 7, 3)),
    "tuesday": ("Tuesday-WorkingHours.csv", date(2017, 7, 4)),
    "wednesday": ("Wednesday-WorkingHours.csv", date(2017, 7, 5)),
    "thursday": ("Thursday-WorkingHours.csv", date(2017, 7, 6)),
    "friday": ("Friday-WorkingHours.csv", date(2017, 7, 7)),
}

COLUMNS = {
    "src_ip": "Src IP",
    "src_port": "Src Port",
    "dst_ip": "Dst IP",
    "dst_port": "Dst Port",
    "timestamp": "Timestamp",
    "label": "Label",
}


def parse_timestamp(raw: str) -> float:
    """``dd/mm/yyyy hh:mm:ss AM/PM`` -> epoch seconds, naive clock treated as UTC.

    Engelen timestamps are in their capture machine's local clock; the offset to
    our UTC pcap epochs is estimated from the data, not assumed.
    """
    for fmt in ("%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %H:%M:%S"):
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            continue
    raise ValueError(f"unparsable timestamp: {raw!r}")


def split_attempted(raw: str) -> tuple[str, bool]:
    """Return ``(label, attempted)``; ``X - Attempted`` carries attempted=True."""
    text = " ".join(raw.split())
    if text.endswith(ATTEMPTED_SUFFIX):
        return text[: -len(ATTEMPTED_SUFFIX)].strip(), True
    return text, False


def engelen_rows(day: str):
    """Yield ``(raw_label, key, epoch)`` for one day's Engelen CSV."""
    filename, _ = DAYS[day]
    path = ENGELEN_DIR / filename
    if not path.exists():
        raise FileNotFoundError(path)
    with open(path, newline="", encoding="utf-8", errors="replace") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        index = {name: header.index(col) for name, col in COLUMNS.items()}
        for row in reader:
            try:
                key = _flow_key(
                    row[index["src_ip"]].strip(),
                    int(row[index["src_port"]]),
                    row[index["dst_ip"]].strip(),
                    int(row[index["dst_port"]]),
                )
                stamp = parse_timestamp(row[index["timestamp"]])
            except (ValueError, IndexError):
                continue
            yield row[index["label"]], key, stamp


def load_day_flows(day: str) -> list[dict[str, Any]]:
    path = PROCESSED / f"flows_{day}_labeled.parquet"
    if not path.exists():
        raise FileNotFoundError(path)
    cols = ["flow_id", "src_ip", "src_port", "dst_ip", "dst_port", "t_first", "label", "attack_type"]
    return pq.read_table(path, columns=cols).to_pylist()


def our_index(flows: list[dict[str, Any]]) -> dict[tuple, list[tuple[float, int]]]:
    index: dict[tuple, list[tuple[float, int]]] = collections.defaultdict(list)
    for flow in flows:
        key = _flow_key(
            str(flow["src_ip"]),
            int(flow["src_port"]),
            str(flow["dst_ip"]),
            int(flow["dst_port"]),
        )
        index[key].append((float(flow["t_first"]), int(flow["flow_id"])))
    for bucket in index.values():
        bucket.sort()
    return index


def estimate_offset(day: str, index: dict[tuple, list[tuple[float, int]]]) -> float:
    """Modal ``engelen_epoch - our_t_first`` (1 s bins) over a strided sample.

    The two clocks are not the same timezone (CIC's own schedule needed a
    -180 min calibration), so the shift is measured, not assumed.
    """
    deltas: list[float] = []
    for i, (_, key, stamp) in enumerate(engelen_rows(day)):
        if i % OFFSET_SAMPLE_STRIDE:
            continue
        bucket = index.get(key)
        if not bucket:
            continue
        deltas.extend(stamp - t_first for t_first, _ in bucket[:5])
    if not deltas:
        return 0.0
    counts = collections.Counter(round(delta) for delta in deltas)
    return float(counts.most_common(1)[0][0])


def match_day(day: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Match Engelen rows onto our flows; return (per-flow rows, engelen rows used)."""
    flows = load_day_flows(day)
    index = our_index(flows)
    if not index:
        return [], []
    offset = estimate_offset(day, index)
    print(f"[engelen] {day}: offset {offset:+.1f}s vs pcap epoch", flush=True)

    used: set[int] = set()
    matched: dict[int, tuple[str, bool, float]] = {}
    started = time.perf_counter()
    for raw_label, key, stamp in engelen_rows(day):
        label, attempted = split_attempted(raw_label)
        bucket = index.get(key)
        if not bucket:
            continue
        target = stamp - offset
        lo = bisect.bisect_left(bucket, (target - MATCH_WINDOW_S, -1))
        hi = bisect.bisect_right(bucket, (target + MATCH_WINDOW_S, 1 << 62))
        best: tuple[float, int] | None = None
        for t_first, flow_id in bucket[lo:hi]:
            if flow_id in used:
                continue
            delta = abs(t_first - target)
            if best is None or delta < best[0]:
                best = (delta, flow_id)
        if best is None:
            continue
        used.add(best[1])
        matched[best[1]] = (label, attempted, best[0])
    print(
        f"[engelen] {day}: {len(flows)} our flows, {len(matched)} matched "
        f"({100 * len(matched) / len(flows):.1f}%) in {time.perf_counter() - started:.0f}s",
        flush=True,
    )

    rows = []
    for flow in flows:
        hit = matched.get(int(flow["flow_id"]))
        rows.append(
            {
                "day": day,
                "flow_id": int(flow["flow_id"]),
                "ours_label": int(flow["label"]),
                "ours_attack_type": str(flow["attack_type"] or ""),
                "engelen_label": hit[0] if hit else None,
                "engelen_attempted": bool(hit[1]) if hit else None,
                "match_dt": round(hit[2], 3) if hit else None,
            }
        )
    summary = {
        "day": day,
        "flows": len(flows),
        "mapped": len(matched),
        "match_rate": len(matched) / len(flows) if flows else 0.0,
        "offset_s": round(offset, 1),
        "rows": rows,
    }
    return rows, summary


def engelen_attack(label: str, attempted: bool) -> int:
    """``Attempted`` counts as an attack (docs/DECISIONS.md §5)."""
    del attempted
    return 0 if normalize_label(label) == BENIGN_LABEL else 1


def confusion_row(summary: dict[str, Any]) -> dict[str, Any]:
    rows = summary["rows"]
    mapped = [row for row in rows if row["engelen_label"] is not None]
    ours_attack_benign = 0
    ours_benign_attack = 0
    agree = 0
    for row in mapped:
        ours = 1 if row["ours_label"] == 1 else 0
        theirs = engelen_attack(row["engelen_label"], row["engelen_attempted"])
        if ours == theirs:
            agree += 1
        elif ours == 1:
            ours_attack_benign += 1
        else:
            ours_benign_attack += 1
    return {
        "day": summary["day"],
        "flows": summary["flows"],
        "mapped": summary["mapped"],
        "match_rate": round(summary["match_rate"], 4),
        "offset_s": summary["offset_s"],
        "agreement": round(agree / len(mapped), 4) if mapped else 0.0,
        "ours_attack_engelen_benign": ours_attack_benign,
        "ours_benign_engelen_attack": ours_benign_attack,
        "uncertain_ours": sum(1 for row in rows if row["ours_label"] == -1),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def compose() -> int:
    built = collections.Counter()
    graph_path = REPO_ROOT / "data/graphs/P_paper/p8/test.npz"
    if graph_path.exists():
        with np.load(graph_path, allow_pickle=False) as data:
            labels = data["attack_type"]
            ys = data["y"]
        for label, y in zip(labels.tolist(), ys.tolist()):
            built[BENIGN_LABEL if int(y) == 0 else normalize_label(str(label))] += 1
    else:
        raise FileNotFoundError(graph_path)

    effective: collections.Counter[str] = collections.Counter()
    attempted: collections.Counter[str] = collections.Counter()
    for day in DAYS:
        for raw_label, _, _ in engelen_rows(day):
            label, is_attempted = split_attempted(raw_label)
            normalised = normalize_label(label)
            (attempted if is_attempted else effective)[normalised] += 1

    labels = list(PAPER_TEST_COUNTS) + [BENIGN_LABEL]
    extra = sorted((set(effective) | set(attempted)) - set(labels))
    rows = []
    for label in labels + extra:
        paper = PAPER_TEST_BENIGN if label == BENIGN_LABEL else PAPER_TEST_COUNTS.get(label, 0)
        rows.append(
            {
                "label": label,
                "engelen_effective": effective.get(label, 0),
                "engelen_attempted": attempted.get(label, 0),
                "paper_table_vii": paper,
                "ppaper_built": built.get(label, 0),
            }
        )
    rows.sort(key=lambda row: -row["engelen_effective"])
    write_csv(RESULTS / "engelen_composition.csv", rows)
    print(f"[engelen] wrote {len(rows)} composition rows", flush=True)
    for row in rows:
        print(
            f"  {row['label']:<28s} engelen {row['engelen_effective']:>7d} "
            f"(+{row['engelen_attempted']} attempted)  paper {row['paper_table_vii']:>6d}  "
            f"built {row['ppaper_built']:>6d}",
            flush=True,
        )
    return 0


def map_labels() -> int:
    all_rows: list[dict[str, Any]] = []
    summaries: list[dict[str, Any]] = []
    for day in DAYS:
        rows, summary = match_day(day)
        if not rows:
            continue
        all_rows.extend(rows)
        summaries.append(summary)

    if not all_rows:
        raise SystemExit("no Engelen row matched any flow")

    table = pa.table(
        {
            "day": pa.array([row["day"] for row in all_rows], pa.string()),
            "flow_id": pa.array([row["flow_id"] for row in all_rows], pa.int64()),
            "ours_label": pa.array([row["ours_label"] for row in all_rows], pa.int8()),
            "ours_attack_type": pa.array([row["ours_attack_type"] for row in all_rows], pa.string()),
            "engelen_label": pa.array([row["engelen_label"] for row in all_rows], pa.string()),
            "engelen_attempted": pa.array(
                [row["engelen_attempted"] for row in all_rows], pa.bool_()
            ),
            "match_dt": pa.array([row["match_dt"] for row in all_rows], pa.float64()),
        }
    )
    PROCESSED.mkdir(parents=True, exist_ok=True)
    pq.write_table(table, PROCESSED / "engelen_label_map.parquet")

    rows = [confusion_row(summary) for summary in summaries]
    write_csv(RESULTS / "engelen_confusion.csv", rows)
    for row in rows:
        print(
            f"[engelen] {row['day']:<10s} match {100 * row['match_rate']:.1f}%  "
            f"agreement {100 * row['agreement']:.1f}%  "
            f"ours-attack/theirs-benign {row['ours_attack_engelen_benign']}  "
            f"ours-benign/theirs-attack {row['ours_benign_engelen_attack']}",
            flush=True,
        )
    summary_path = RESULTS / "engelen_confusion.json"
    summary_path.write_text(
        json.dumps(
            [{k: v for k, v in row.items()} for row in rows], indent=2
        ),
        encoding="utf-8",
    )
    return 0


def load_label_map() -> dict[tuple[str, int], tuple[str, bool]]:
    path = PROCESSED / "engelen_label_map.parquet"
    if not path.exists():
        raise FileNotFoundError(path)
    rows = pq.read_table(
        path, columns=["day", "flow_id", "engelen_label", "engelen_attempted"]
    ).to_pylist()
    return {
        (row["day"], int(row["flow_id"])): (row["engelen_label"], bool(row["engelen_attempted"]))
        for row in rows
        if row["engelen_label"] is not None
    }


def reliable_flag() -> bool:
    path = RESULTS / "engelen_confusion.csv"
    if not path.exists():
        raise FileNotFoundError(path)
    with open(path, encoding="utf-8") as fh:
        rates = [float(row["match_rate"]) for row in csv.DictReader(fh)]
    return bool(rates) and min(rates) >= 0.85


def relabel_eval(seeds: list[int], device: torch.device, p: int = 8) -> int:
    label_map = load_label_map()
    reliable = reliable_flag()
    graphs_dir = REPO_ROOT / "data/graphs/T"
    train2 = load_graph(graphs_dir / f"p{p}" / "train2.npz")
    test = load_graph(graphs_dir / f"p{p}" / "test.npz")
    engelen_y = test.y.astype(np.int8).copy()
    mapped_in_test = 0
    for i, (day, flow) in enumerate(zip(test.day.tolist(), test.flow_id.tolist())):
        hit = label_map.get((str(day), int(flow)))
        if hit is None:
            continue  # unmapped flow keeps OUR label
        mapped_in_test += 1
        engelen_y[i] = 0 if normalize_label(hit[0]) == BENIGN_LABEL else 1
    print(
        f"[engelen] test edges {test.y.size}, mapped {mapped_in_test} "
        f"({100 * mapped_in_test / test.y.size:.1f}%), reliable={reliable}",
        flush=True,
    )

    rows: list[dict[str, Any]] = []
    for seed in seeds:
        model_path = REPO_ROOT / f"experiments/T/p{p}/seed{seed}/model.pt"
        if not model_path.exists():
            raise FileNotFoundError(model_path)
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
        predictions, scores = predict_detectors(detectors, z_test)
        calib_scores = predict_detectors(detectors, z_train[calibration_idx])[1]
        fused = np.mean(
            [rank_normalize(scores[name]) for name in DETECTOR_NAMES], axis=0
        )
        fused_calib = np.mean(
            [rank_normalize(calib_scores[name]) for name in DETECTOR_NAMES], axis=0
        )

        def add(model_name: str, rule: str, y_pred: np.ndarray, score: np.ndarray, calib: np.ndarray) -> None:
            m = metrics(engelen_y, y_pred, score, calibration_scores=calib)
            rows.append(
                {
                    "model": model_name,
                    "rule": rule,
                    "seed": seed,
                    "tpr": m["tpr"],
                    "fpr": m["fpr"],
                    "auroc": m["auroc"],
                    "tpr_at_fpr_1pct": m["tpr_at_fpr"],
                    "reliable": reliable,
                }
            )

        for name in DETECTOR_NAMES:
            add(name, "score", predictions[name], scores[name], calib_scores[name])
        for rule in ("strict", "tie"):
            add("ensemble", rule, vote(predictions, rule), fused, fused_calib)

    write_csv(RESULTS / "engelen_relabel_metrics.csv", rows)
    print(f"[engelen] wrote {len(rows)} relabelled metric rows", flush=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--compose", action="store_true", help="L1 composition")
    parser.add_argument("--map", action="store_true", help="L2 matching + confusion")
    parser.add_argument("--relabel-eval", action="store_true", help="L3 re-scoring")
    parser.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    parser.add_argument("--p", type=int, default=8)
    parser.add_argument("--device", default="cpu", choices=["auto", "cpu", "cuda"])
    args = parser.parse_args(argv)
    if not (args.compose or args.map or args.relabel_eval):
        parser.error("choose at least one of --compose/--map/--relabel-eval")

    device = torch.device(args.device)
    status = 0
    if args.compose:
        status |= compose()
    if args.map:
        status |= map_labels()
    if args.relabel_eval:
        status |= relabel_eval(args.seeds, device, args.p)
    return status


if __name__ == "__main__":
    raise SystemExit(main())
