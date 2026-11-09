#!/usr/bin/env python3
"""Generate reports/P1.md from the measurement CSVs.

Reads:
  - results/P1_summary.csv
  - results/P1_meta.json   (optional; written by eval_baselines_p1.py)
  - results/M1_summary.csv
  - results/B0_summary.csv (optional)
  - results/B1_summary.csv (optional)

The report is deliberately generated: Markdown tables must not be edited by
hand. Re-run this script after any P1 evaluation.
"""

from __future__ import annotations

import csv
import json
import statistics as stats
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS = REPO_ROOT / "results"
OUT = REPO_ROOT / "reports" / "P1.md"

P1_FIELDS = ("seed", "alpha", "method", "tpr", "fpr", "mean_p_attack", "mean_p_benign", "mean_p_total", "early_exit_rate_attack")


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise FileNotFoundError(path)
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def mean(values: list[float]) -> float:
    return stats.mean(values) if values else float("nan")


def std(values: list[float]) -> float:
    return stats.stdev(values) if len(values) > 1 else 0.0


def pct(value: float) -> str:
    return f"{100.0 * value:.2f}%"


def pm(values: list[float]) -> str:
    if not values:
        return "—"
    if len(values) == 1:
        return f"{100.0 * values[0]:.2f}%"
    return f"{100.0 * mean(values):.2f}% ± {100.0 * std(values):.2f}%"


def num_pm(values: list[float]) -> str:
    if not values:
        return "—"
    if len(values) == 1:
        return f"{values[0]:.2f}"
    return f"{mean(values):.2f} ± {std(values):.2f}"


def metric_rows(rows: list[dict[str, str]], field: str) -> list[float]:
    return [float(row[field]) for row in rows if field in row and row[field] not in ("", None)]


def m1_reference() -> dict[str, float]:
    rows = [
        row
        for row in read_csv(RESULTS / "M1_summary.csv")
        if row["p"] == "8" and row["model"] == "ensemble" and row["detector"] == "tie"
    ]
    if not rows:
        raise ValueError("M1_summary.csv has no p=8 ensemble/tie rows")
    return {
        "tpr": mean(metric_rows(rows, "tpr")),
        "fpr": mean(metric_rows(rows, "fpr")),
        "auroc": mean(metric_rows(rows, "auroc")),
        "tpr_at_fpr_1pct": mean(metric_rows(rows, "tpr_at_fpr_1pct")),
    }


def baseline_reference(name: str) -> dict[str, float] | None:
    path = RESULTS / f"{name}_summary.csv"
    if not path.exists():
        return None
    rows = [row for row in read_csv(path) if row["p"] == "8" and row["rule"] == "ensemble_tie"]
    if not rows:
        return None
    return {
        "tpr": mean(metric_rows(rows, "tpr")),
        "fpr": mean(metric_rows(rows, "fpr")),
        "auroc": mean(metric_rows(rows, "auroc")),
        "tpr_at_fpr_1pct": mean(metric_rows(rows, "tpr_at_fpr")),
    }


def load_meta() -> dict:
    path = RESULTS / "P1_meta.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    p1_rows = read_csv(RESULTS / "P1_summary.csv")
    if not p1_rows:
        raise ValueError("P1_summary.csv is empty")
    meta = load_meta()
    m1 = m1_reference()
    b0 = baseline_reference("B0")
    b1 = baseline_reference("B1")

    groups: dict[tuple[float, str], list[dict[str, str]]] = {}
    for row in p1_rows:
        key = (float(row["alpha"]), row["method"])
        groups.setdefault(key, []).append(row)

    calibration_fraction = meta.get("calibration_fraction")
    n_calib = meta.get("n_calib")
    ps = meta.get("ps", [2, 3, 4, 5, 6, 7, 8])
    k_steps = len(ps)
    if isinstance(n_calib, int) and n_calib > 0:
        min_fused_p = 4.0 / (n_calib + 1.0)
    else:
        min_fused_p = float("nan")

    lines: list[str] = []
    lines.append("# P1 — Conformal Calibration & Sequential Early-Exit")
    lines.append("")
    lines.append("**Trạng thái:** tài liệu sinh tự động từ `results/P1_summary.csv`; không sửa tay.")
    lines.append("")
    lines.append("**Nguồn số liệu:** `results/P1_summary.csv`, `results/P1_meta.json`, `results/M1_summary.csv`.")
    lines.append("")
    lines.append("**Thiết lập:** protocol `T_fixed` (30.907 flow test), p = 2..8, "
                 f"{len(meta.get('seeds', [])) or 'nhiều'} seed.")
    lines.append("")
    if calibration_fraction is not None:
        lines.append(
            f"**Calibration:** {calibration_fraction:.0%} của `train2` "
            f"(n_calib = {n_calib}); phần còn lại dùng để fit 4 detector."
        )
    lines.append("")
    lines.append("## 1. Kết quả trung bình theo α và fusion")
    lines.append("")
    lines.append("| α | Fusion | TPR | FPR | APD attack | APD benign | Early-exit attack | AUROC | TPR@FPR=1% |")
    lines.append("|---|---|---:|---:|---:|---:|---:|---:|---:|")
    for (alpha, method) in sorted(groups, key=lambda item: (item[0], item[1] != "bonferroni", item[1])):
        rows = groups[(alpha, method)]
        lines.append(
            f"| {alpha:g} | {method} | {pm(metric_rows(rows, 'tpr'))} | "
            f"{pm(metric_rows(rows, 'fpr'))} | {num_pm(metric_rows(rows, 'mean_p_attack'))} | "
            f"{num_pm(metric_rows(rows, 'mean_p_benign'))} | "
            f"{pm(metric_rows(rows, 'early_exit_rate_attack'))} | "
            f"{num_pm(metric_rows(rows, 'auroc'))} | "
            f"{pm(metric_rows(rows, 'tpr_at_fpr_1pct'))} |"
        )
    lines.append("")
    lines.append("## 2. So sánh với M1 và baseline (p = 8)")
    lines.append("")
    lines.append("| Phương pháp | TPR | FPR | AUROC | TPR@FPR=1% |")
    lines.append("|---|---:|---:|---:|---:|")
    lines.append(
        f"| M1 GTAE, ensemble tie | {pct(m1['tpr'])} | {pct(m1['fpr'])} | "
        f"{m1['auroc']:.3f} | {pct(m1['tpr_at_fpr_1pct'])} |"
    )
    for label, ref in (("B0 raw vector, ensemble tie", b0), ("B1 MLP-AE, ensemble tie", b1)):
        if ref is not None:
            lines.append(
                f"| {label} | {pct(ref['tpr'])} | {pct(ref['fpr'])} | "
                f"{ref['auroc']:.3f} | {pct(ref['tpr_at_fpr_1pct'])} |"
            )
    lines.append("")
    lines.append("## 3. Đối chiếu tiêu chí P1")
    lines.append("")
    lines.append("Tiêu chí trong `docs/GTAE-IDS_Research_docs.md` §6: FPR ≤ α + 1 điểm %, "
                 "APD attack < 8, TPR ≥ M1 p=8 − 1 điểm; TPR@FPR=1% phải được đo.")
    lines.append("")
    lines.append("| α | Fusion | FPR ≤ α+1? | APD < 8? | TPR ≥ M1−1? | TPR@FPR1 > M1? | Ghi chú |")
    lines.append("|---|---|---:|---:|---:|---:|---|")
    for (alpha, method) in sorted(groups, key=lambda item: (item[0], item[1] != "bonferroni", item[1])):
        rows = groups[(alpha, method)]
        fpr = mean(metric_rows(rows, "fpr"))
        tpr = mean(metric_rows(rows, "tpr"))
        apd = mean(metric_rows(rows, "mean_p_attack"))
        tpr_at_fpr_values = metric_rows(rows, "tpr_at_fpr_1pct")
        tpr_at_fpr_1pct = mean(tpr_at_fpr_values)
        fpr_ok = "có" if fpr <= alpha + 0.01 else "**không**"
        apd_ok = "có" if apd < 8.0 else "**không**"
        tpr_ok = "có" if tpr >= m1["tpr"] - 0.01 else "**không**"
        rank_ok = (
            "có" if tpr_at_fpr_1pct > m1["tpr_at_fpr_1pct"]
            else "**không**" if tpr_at_fpr_values else "—"
        )
        note = ""
        if method == "bonferroni" and isinstance(n_calib, int):
            alpha_p = alpha / k_steps
            if min_fused_p > alpha_p:
                note = (
                    f"Không thể alert: min fused p = {min_fused_p:.6f} > "
                    f"α/{k_steps} = {alpha_p:.6f}"
                )
        if method == "fisher":
            note = "Fisher giả định p-value độc lập; không có bảo đảm FPR"
        lines.append(
            f"| {alpha:g} | {method} | {fpr_ok} | {apd_ok} | {tpr_ok} | {rank_ok} | {note} |"
        )
    lines.append("")
    lines.append("## 4. Diễn giải")
    lines.append("")
    lines.append("- **Bonferroni** là test hợp lệ theo conformal nếu calibration và benign test "
                 "exchangeable; đây là cấu hình dùng được cho claim kiểm soát FPR.")
    lines.append("- **Fisher** không còn đúng phân phối χ² khi 4 detector tương quan; kết quả "
                 "Fisher chỉ nên đọc như exploratory, không dùng để claim FPR ≤ α.")
    lines.append("- **Calibration floor:** với n_calib hữu hạn, p-value nhỏ nhất là "
                 "1/(n_calib+1); Bonferroni×4 có sàn 4/(n_calib+1). Nếu sàn này lớn hơn α/K "
                 "thì cấu hình đó không thể alert, bất kể score.")
    lines.append("- **APD** là số gói trung bình đến quyết định; mức giảm so với 8 gói được tính "
                 "trực tiếp từ cột `mean_p_attack`.")
    lines.append("- **TPR@FPR=1%** dùng score `1 − min_p` (p-value gộp nhỏ nhất qua các p), "
                 "nên là metric xếp hạng độc lập với α.")
    lines.append("")
    lines.append("## 5. Tệp sinh")
    lines.append("")
    lines.append("```bash")
    lines.append("python scripts/make_p1_report.py")
    lines.append("```")
    lines.append("")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
