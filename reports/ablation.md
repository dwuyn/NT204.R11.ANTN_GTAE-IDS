# Ablation và baseline (sinh tự động)

**Nguồn:** `results/M1_summary.csv`, `results/B0_summary.csv`, `results/B1_summary.csv`, `results/A3_recon.csv`.

**Quy ước:** TPR/FPR là mean theo seed. `A3_recon` dùng ngưỡng 99th percentile của reconstruction error trên `train2`; cột `FPR@threshold` là FPR thực trên test tại ngưỡng đó, không phải FPR=1%.

## 1. M1 vs A3 reconstruction-error

| p | M1 TPR | M1 FPR | M1 AUROC | A3 TPR | A3 FPR | A3 AUROC | ΔTPR (A3−M1) |
|---:|---|---:|---:|---|---:|---:|---:|
| 2 | 8.58% ± 8.50% | 5.90% | 0.551 | 4.58% ± 1.70% | 3.71% | 0.436 | -4.00 pp |
| 3 | 7.26% ± 6.77% | 3.45% | 0.571 | — | — | — | — |
| 4 | 11.70% ± 2.03% | 3.62% | 0.625 | 7.40% ± 1.22% | 1.73% | 0.543 | -4.30 pp |
| 5 | 8.83% ± 10.73% | 2.87% | 0.712 | — | — | — | — |
| 6 | 6.49% ± 4.10% | 2.92% | 0.794 | — | — | — | — |
| 7 | 13.53% ± 5.89% | 3.13% | 0.811 | — | — | — | — |
| 8 | 11.36% ± 8.48% | 2.47% | 0.668 | 23.65% ± 4.18% | 4.17% | 0.676 | +12.29 pp |

## 2. Baseline p=8

| Experiment | TPR | FPR | AUROC | TPR@calib-threshold | FPR@threshold |
|---|---:|---:|---:|---:|---:|
| M1 | 11.36% | 2.47% | 0.668 | 9.64% | 1.93% |
| A3_recon | 23.65% | 4.17% | 0.676 | 23.65% | 4.17% |
| B0 | 0.50% | 1.22% | 0.698 | 2.13% | 1.58% |
| B1 | 6.29% | 2.29% | 0.595 | 6.95% | 2.52% |

## 3. Đọc kết quả

- A3 là detector chỉ dùng reconstruction MSE; không fit PyOD.
- So sánh phải cùng p/seed và cùng operating point; `FPR@threshold` khác nhau nên không được chỉ so TPR.
- Nếu A3 vượt M1 ở cùng FPR, đó là bằng chứng đồ thị/decoder có tín hiệu; nếu không, ghi nhận trung thực.

```bash
python scripts/eval_recon_ablation.py --graphs data/graphs/T --models experiments/T --ps 2 4 8 --seeds 0 1 2
python scripts/make_ablation_report.py
```
