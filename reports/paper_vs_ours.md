# Bảng đối chiếu: Paper vs Baseline vs GTAE-IDS vs P1

**Cập nhật:** 2026-11-10
**Đồ án:** NT204.R11.ANTN — Nhóm B — Tái hiện & Cải tiến GTAE-IDS
**Paper:** Ghadermazi et al., *GTAE-IDS*, IEEE TIFS 20:4026–4041, 2025.

---

## 1. Bảng so sánh tổng hợp các phương pháp (p = 8)

| Phương pháp | Loại mô hình | Phân chia dữ liệu | Luật quyết định | TPR | FPR | AUROC | Ghi chú |
|---|---|---|---|---:|---:|---:|---|
| **Paper Table VI** | Graph Transformer AE | Random / Same-day | Majority vote | **99,04%** | **6,56%** | — | Ghép TPR Ensemble với FPR OCSVM |
| **Official Repo Code** | Disconnected Linear AE | Friday 70/30 | Union (votes $\ge 1$) | **98,74%** | **13,12%** | — | Code tác giả `Final_Results_8pkt` |
| **B0: Raw Vector** | PyOD Detectors (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **0,50%** | **1,22%** | **0,698** | Ensemble tie yếu; detector INNE đạt 10,21% @ 2,45% |
| **B1: MLP-AE** | Dense AE (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **6,29%** | **2,29%** | **0,595** | AE chuẩn nén 400d → 64d |
| **M1: GTAE-IDS (Ours)** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **11,5%** | **2,5%** | **0,67** | Tái hiện sạch đúng mô tả paper |
| **M1 (Official Rules)** | Graph Transformer AE | Friday same-day | Union (votes $\ge 1$) | *chưa lưu artifact* | — | — | Không dùng làm kết luận |
| **P1: Bonferroni α=0,05** | GTAE + Conformal Fusion | Temporal T (Sạch) | $\pi_{\text{fused}} \le \alpha_p$ | **16,49%** | **3,67%** | **0,652** | TPR@FPR=1% = 0%; Fisher 47,58/18,07 không kiểm soát FPR |
| **Upper Bound (Supervised RF)** | Random Forest | Cross-day (Tue/Wed → Thu/Fri) | Ngưỡng xác suất | **18,1%** | **6,7%** | **0,92** | Giới hạn trên phân loại giám sát |
| **Upper Bound (Same-session RF)** | Random Forest | Same-session (Random) | Ngưỡng xác suất | **99,4%** | **6,1%** | **0,97** | Rò rỉ nhận diện phiên/ngày |

---

## 2. Kết quả Proposal P1 (Conformal Calibration & Early Exit)

Proposal P1 giải quyết 3 hạn chế thực tế của GTAE-IDS:
1. Chuẩn hóa điểm bất thường thành **conformal p-value**; Bonferroni kiểm soát FPR theo lý thuyết, Fisher chỉ exploratory khi detector tương quan.
2. Cơ chế **Early-Exit**: dừng kiểm tra ngay khi p-value $\le \alpha_p$, không cần chờ đủ 8 gói tin.
3. Đo lường chỉ số **Average Packets to Decision (APD)** và độ trôi phân phối thời gian (temporal drift).

*Bảng kết quả trung bình 3 seed trên tập kiểm thử chuẩn T_fixed (30.907 flow), calibration 40% = 800 flow:*

| $\alpha$ mục tiêu | Phương pháp Fusion | TPR thực đo | FPR thực đo | APD Tấn công (gói) | APD Bình thường (gói) | Tỉ lệ dừng sớm (Attack) | AUROC | TPR@FPR=1% |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0,01 | Bonferroni | 0,00% | 0,00% | 8,00 pkts | 8,00 pkts | 0,00% | 0,652 | 0,00% |
| 0,05 | Bonferroni | **16,49%** | **3,67%** | 7,57 pkts | 7,89 pkts | 15,23% | 0,652 | 0,00% |
| 0,10 | Bonferroni | **23,07%** | **6,13%** | 7,34 pkts | 7,79 pkts | 21,75% | 0,652 | 0,00% |
| 0,01 | Fisher | 39,65% | 11,55% | 6,43 pkts | 7,44 pkts | 39,44% | 0,641 | 5,14% |
| 0,05 | Fisher | **47,58%** | **18,07%** | **5,90 pkts** | 7,14 pkts | **47,39%** | 0,641 | 5,14% |
| 0,10 | Fisher | 51,32% | 22,91% | 5,72 pkts | 6,93 pkts | 51,08% | 0,641 | 5,14% |

**Nhận xét:**
- Với **Bonferroni ($\alpha = 0,05$)**, FPR thực đo **3,67%** ($\le 5\%$) và TPR **16,49%**, cao hơn M1 (11,54% @ 2,52%) ở vùng FPR tương đương. Ở $\alpha=0,10$, TPR **23,07%** @ FPR **6,13%**.
- Với **Bonferroni ($\alpha = 0,01$)**, TPR/FPR đều 0 vì sàn p-value $4/801 = 0,004994 > 0,01/7$; cấu hình này không thể alert với 800 calibration flow.
- Với **Fisher**, TPR tăng lên **39,65–51,32%** nhưng FPR **11,55–22,91%**, vượt xa $\alpha$ do 4 detector tương quan. Fisher chỉ nên đọc như exploratory, không dùng để claim kiểm soát FPR.
- **Giới hạn:** tại FPR=1%, Bonferroni đạt TPR 0% và Fisher 5,14%, đều thấp hơn M1 (9,42%). P1 chưa vượt M1 ở vùng FPR thấp; đóng góp là operating point có kiểm soát FPR và phân tích trade-off.
- **Early-exit:** Bonferroni $\alpha=0,05$ phát hiện sớm **15,23%** attack, APD **7,57 gói**; $\alpha=0,10$ phát hiện sớm **21,75%**, APD **7,34 gói**. Fisher giảm APD mạnh hơn (5,90 gói) nhưng FPR quá cao.
