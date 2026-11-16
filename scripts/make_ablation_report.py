#!/usr/bin/env python3
"""Consolidate baseline and ablation measurements into one table/report.

Reads committed CSVs and writes:
  - results/ablation.csv
  - reports/ablation.md

Supported inputs:
  - results/M1_summary.csv          (p=2,4,8; ensemble tie)
  - results/B0_summary.csv          (p=8; ensemble_tie)
  - results/B1_summary.csv          (p=8; ensemble_tie)
  - results/A3_recon.csv            (reconstruction-error ablation)

Optional future inputs (ignored if absent):
  - results/noPE/M1_summary.csv    (A2 no-PE; also written to results/A2_no_pe.csv)
  - results/B2/M1_summary.csv      (B2 E-GraphSAGE-AE)
  - results/A5_hygiene.csv
"""

from __future__ import annotations

import csv
import json
import statistics as stats
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS = REPO_ROOT / "results"
OUT_CSV = RESULTS / "ablation.csv"
OUT_MD = REPO_ROOT / "reports" / "ablation.md"

METRICS = ("tpr", "fpr", "auroc", "tpr_at_fpr", "fpr_at_threshold")


def group_detector_rows(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    """Per-detector p8 rows, grouped so a multi-seed mean can be taken."""
    grouped: dict[str, list[dict[str, str]]] = {}
    for row in normalize_rows(rows):
        if row.get("p") != "8" or row.get("model") != "detector":
            continue
        grouped.setdefault(row["detector"], []).append(row)
    return grouped


def read_fit_notes() -> list[tuple[str, str, dict]]:
    """Collect `detector_fit_notes` recorded by `src.eval` for the ablation runs."""
    notes: list[tuple[str, str, dict]] = []
    for pattern in ("A5/A5_p8_seed*.json", "engelen_retrain/M1_p8_seed*.json"):
        for path in sorted(RESULTS.glob(pattern)):
            payload = json.loads(path.read_text(encoding="utf-8"))
            for name, note in (payload.get("detector_fit_notes") or {}).items():
                notes.append((path.stem, name, note))
    return notes


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def mean(rows: list[dict[str, str]], field: str) -> float:
    values = [float(row[field]) for row in rows if row.get(field) not in (None, "")]
    return stats.mean(values) if values else float("nan")


def normalize_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    """Accept both `tpr_at_fpr` and `tpr_at_fpr_1pct` schemas."""
    for row in rows:
        if row.get("tpr_at_fpr") in (None, "") and row.get("tpr_at_fpr_1pct") not in (None, ""):
            row["tpr_at_fpr"] = row["tpr_at_fpr_1pct"]
        if row.get("fpr_at_threshold") in (None, ""):
            row["fpr_at_threshold"] = ""
    return rows


def pm(rows: list[dict[str, str]], field: str) -> str:
    values = [float(row[field]) for row in rows if row.get(field) not in (None, "")]
    if not values:
        return "—"
    if len(values) == 1:
        return f"{100.0 * values[0]:.2f}%"
    return f"{100.0 * stats.mean(values):.2f}% ± {100.0 * stats.stdev(values):.2f}%"


def fprm(rows: list[dict[str, str]], field: str) -> str:
    values = [float(row[field]) for row in rows if row.get(field) not in (None, "")]
    if not values:
        return "—"
    return f"{100.0 * stats.mean(values):.2f}%"


def auroc(rows: list[dict[str, str]]) -> str:
    values = [float(row["auroc"]) for row in rows if row.get("auroc") not in (None, "")]
    if not values:
        return "—"
    return f"{stats.mean(values):.3f}"


def group_by_p(rows: list[dict[str, str]]) -> dict[int, list[dict[str, str]]]:
    groups: dict[int, list[dict[str, str]]] = {}
    for row in rows:
        groups.setdefault(int(float(row["p"])), []).append(row)
    return groups


def select_ensemble(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    if not rows:
        return rows
    if "model" in rows[0] and "detector" in rows[0]:
        return [
            row
            for row in rows
            if row.get("model") == "ensemble" and row.get("detector") == "tie"
        ]
    if "rule" in rows[0]:
        return [row for row in rows if row.get("rule") == "ensemble_tie"]
    return rows


def main() -> int:
    m1_rows = normalize_rows(
        [
            row
            for row in read_csv(RESULTS / "M1_summary.csv")
            if row.get("model") == "ensemble" and row.get("detector") == "tie"
        ]
    )
    a3_rows = normalize_rows(read_csv(RESULTS / "A3_recon.csv"))

    m1 = group_by_p(m1_rows)
    a3 = group_by_p(a3_rows)

    records: list[dict] = []
    for experiment, groups in (("M1", m1), ("A3_recon", a3)):
        for p in sorted(groups):
            rows = groups[p]
            records.append(
                {
                    "experiment": experiment,
                    "p": p,
                    "n_seeds": len(rows),
                    "model": "ensemble" if experiment == "M1" else "A3_recon_mse",
                    "rule": "tie" if experiment == "M1" else "threshold_99pct",
                    "tpr": mean(rows, "tpr"),
                    "fpr": mean(rows, "fpr"),
                    "auroc": mean(rows, "auroc"),
                    "tpr_at_fpr": mean(rows, "tpr_at_fpr"),
                    "fpr_at_threshold": mean(rows, "fpr_at_threshold"),
                }
            )

    for name, path, model in (
        ("B0", RESULTS / "B0_summary.csv", "B0_raw_vector"),
        ("B1", RESULTS / "B1_summary.csv", "B1_MLPAE"),
    ):
        rows = normalize_rows(
            [
                row
                for row in read_csv(path)
                if row.get("p") == "8" and row.get("rule") == "ensemble_tie"
            ]
        )
        if rows:
            records.append(
                {
                    "experiment": name,
                    "p": 8,
                    "n_seeds": len(rows),
                    "model": model,
                    "rule": "ensemble_tie",
                    "tpr": mean(rows, "tpr"),
                    "fpr": mean(rows, "fpr"),
                    "auroc": mean(rows, "auroc"),
                    "tpr_at_fpr": mean(rows, "tpr_at_fpr"),
                    "fpr_at_threshold": mean(rows, "fpr_at_threshold"),
                }
            )

    # Optional future ablation outputs.
    for name, filename, model in (
        ("A2_noPE", "noPE/M1_summary.csv", "GTAE_no_pe"),
        ("B2", "B2/M1_summary.csv", "E-GraphSAGE-AE"),
        ("A5_hygiene", "A5_hygiene.csv", "GTAE_hygiene"),
    ):
        rows = select_ensemble(normalize_rows(read_csv(RESULTS / filename)))
        if not rows:
            continue
        if name == "A2_noPE":
            with open(RESULTS / "A2_no_pe.csv", "w", newline="", encoding="utf-8") as fh:
                writer = csv.DictWriter(fh, fieldnames=list(rows[0]), lineterminator="\n")
                writer.writeheader()
                writer.writerows(rows)
        for p, group in group_by_p(rows).items():
            records.append(
                {
                    "experiment": name,
                    "p": p,
                    "n_seeds": len(group),
                    "model": model,
                    "rule": "ensemble_tie",
                    "tpr": mean(group, "tpr"),
                    "fpr": mean(group, "fpr"),
                    "auroc": mean(group, "auroc"),
                    "tpr_at_fpr": mean(group, "tpr_at_fpr"),
                    "fpr_at_threshold": mean(group, "fpr_at_threshold"),
                }
            )

    fieldnames = [
        "experiment", "p", "n_seeds", "model", "rule",
        "tpr", "fpr", "auroc", "tpr_at_fpr", "fpr_at_threshold",
    ]
    with open(OUT_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(records)

    lines = [
        "# Ablation và baseline (sinh tự động)",
        "",
        "**Nguồn:** `results/M1_summary.csv`, `results/B0_summary.csv`, "
        "`results/B1_summary.csv`, `results/A3_recon.csv`, "
        "`results/noPE/M1_summary.csv` (A2 no-PE), `results/B2/M1_summary.csv` "
        "(B2 E-GraphSAGE-AE), `results/A5_hygiene.csv` (A5 hygiene).",
        "",
        "**Quy ước:** TPR/FPR là mean theo seed. `A3_recon` dùng ngưỡng "
        "99th percentile của reconstruction error trên `train2`; cột "
        "`FPR@threshold` là FPR thực trên test tại ngưỡng đó, không phải FPR=1%.",
        "",
        "## 1. M1 vs A3 reconstruction-error",
        "",
        "| p | M1 TPR | M1 FPR | M1 AUROC | A3 TPR | A3 FPR | A3 AUROC | ΔTPR (A3−M1) |",
        "|---:|---|---:|---:|---|---:|---:|---:|",
    ]
    for p in sorted(set(m1) | set(a3)):
        m1_rows_p = m1.get(p, [])
        a3_rows_p = a3.get(p, [])
        delta = "—"
        if m1_rows_p and a3_rows_p:
            delta = f"{100.0 * (mean(a3_rows_p, 'tpr') - mean(m1_rows_p, 'tpr')):+.2f} pp"
        lines.append(
            f"| {p} | {pm(m1_rows_p, 'tpr')} | {fprm(m1_rows_p, 'fpr')} | "
            f"{auroc(m1_rows_p)} | {pm(a3_rows_p, 'tpr')} | "
            f"{fprm(a3_rows_p, 'fpr')} | {auroc(a3_rows_p)} | {delta} |"
        )

    lines += [
        "",
        "## 2. Baseline p=8",
        "",
        "| Experiment | TPR | FPR | AUROC | TPR@calib-threshold | FPR@threshold |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for record in records:
        if record["experiment"] not in ("B0", "B1", "M1", "A3_recon", "A2_noPE", "B2", "A5_hygiene"):
            continue
        if record["p"] != 8:
            continue
        lines.append(
            f"| {record['experiment']} | {100.0 * record['tpr']:.2f}% | "
            f"{100.0 * record['fpr']:.2f}% | {record['auroc']:.3f} | "
            f"{100.0 * record['tpr_at_fpr']:.2f}% | "
            f"{100.0 * record['fpr_at_threshold']:.2f}% |"
        )

    lines += [
        "",
        "## 3. A5 header-hygiene: per-detector",
        "",
        "A5 zeroes TTL + IP/TCP checksums (5 of the 25 kept bytes) and retrains; the "
        "ensemble row alone is not enough to read it, because one detector can lose "
        "its histogram resolution and drag the vote with it.",
        "",
        "| detector | M1 AUROC (p8) | A5 AUROC (p8) | ΔAUROC | M1 TPR@FPR=1% | A5 TPR@FPR=1% |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    a5_detector = group_detector_rows(read_csv(RESULTS / "A5_hygiene.csv"))
    m1_detector = group_detector_rows(read_csv(RESULTS / "M1_summary.csv"))
    for name in ("IForest", "OCSVM", "HBOS", "INNE"):
        a5, m1_d = a5_detector.get(name), m1_detector.get(name)
        if not a5 or not m1_d:
            continue
        lines.append(
            f"| {name} | {mean(m1_d, 'auroc'):.3f} | {mean(a5, 'auroc'):.3f} | "
            f"{mean(a5, 'auroc') - mean(m1_d, 'auroc'):+.3f} | "
            f"{100.0 * mean(m1_d, 'tpr_at_fpr'):.2f}% | "
            f"{100.0 * mean(a5, 'tpr_at_fpr'):.2f}% |"
        )
    fit_notes = read_fit_notes()
    if fit_notes:
        lines += [
            "",
            "**Cảnh báo đo lường:** HBOS chia mỗi chiều embedding thành histogram "
            "`n_bins` khoảng đều; embedding sau khi mask header (A5) có nhiều chiều chỉ "
            "còn 3–6 giá trị float32 phân biệt nên `n_bins=20` không dựng được "
            "histogram (numpy từ chối). `src.detectors.fit_detectors` vì thế tự hạ số "
            "bin (và bỏ chiều không chia được), ghi lại trong `detector_fit_notes` của "
            "từng run. Hàng HBOS và ensemble của các run đó KHÔNG so sánh trực tiếp "
            "được với M1 về cấu hình detector; đọc IForest/OCSVM/INNE cho kết luận "
            "hygiene, và đọc bảng n_bins dưới đây trước khi so ensemble.",
            "",
            "| run | detector | n_bins | lý do |",
            "|---|---|---:|---|",
        ]
        for run, name, note in fit_notes:
            lines.append(f"| {run} | {name} | {note['n_bins']} | {note['reason']} |")

    lines += [
        "",
        "## 4. Đọc kết quả",
        "",
        "- A3 là detector chỉ dùng reconstruction MSE; không fit PyOD.",
        "- So sánh phải cùng p/seed và cùng operating point; `FPR@threshold` "
        "khác nhau nên không được chỉ so TPR.",
        "- Nếu A3 vượt M1 ở cùng FPR, đó là bằng chứng đồ thị/decoder có tín hiệu; "
        "nếu không, ghi nhận trung thực.",
        "",
        "```bash",
        "python scripts/eval_recon_ablation.py --graphs data/graphs/T --models experiments/T --ps 2 4 8 --seeds 0 1 2",
        "python scripts/make_ablation_report.py",
        "```",
        "",
    ]
    OUT_MD.parent.mkdir(parents=True, exist_ok=True)
    OUT_MD.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT_CSV} ({len(records)} rows)")
    print(f"wrote {OUT_MD}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
