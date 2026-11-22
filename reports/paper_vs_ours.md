# Bảng đối chiếu: Paper vs Baseline vs GTAE-IDS vs P1

> Số liệu đồng bộ với `results/*.csv` (retrain 2026-11-16). Mean ± std theo seed: [`seed_stats.md`](seed_stats.md). Đối chiếu paper ↔ code ↔ CSV của tác giả: [`../docs/REPRO_AUDIT.md`](../docs/REPRO_AUDIT.md) §5.

**Cập nhật:** 2026-11-22
**Đồ án:** NT204.R11.ANTN — Nhóm B — Tái hiện & Cải tiến GTAE-IDS
**Paper:** Ghadermazi et al., *GTAE-IDS*, IEEE TIFS 20:4026–4041, 2025.

---

## 1. Bảng so sánh tổng hợp các phương pháp (p = 8)

| Phương pháp | Loại mô hình | Phân chia dữ liệu | Luật quyết định | TPR | FPR | AUROC | Ghi chú |
|---|---|---|---|---:|---:|---:|---|
| **Paper Table VI** | Graph Transformer AE | Snapshot (code: Friday 70/30) | "Majority vote" (code: OR) | **99,04%** | **6,56%** | — | FPR Ensemble công bố; OCSVM 4,03% (Table VI) |
| **CSV công khai của tác giả** | Notebook `GTAE_8pkt` (không chạy được như công bố) | Friday 70/30, mỗi lớp 1 đồ thị | Union (votes $\ge 1$) | 98,5–99,8% (theo lớp, = Table VII) | **13,12%** | — | `Final_Results_8pkt_Anomaly_Detection_2017.csv`; FPR ≠ 6,56% của paper |
| **B0: Raw Vector** | PyOD Detectors (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **0,50%** | **1,22%** | **0,698** | Ensemble tie yếu; detector INNE đạt 10,21% @ 2,45% |
| **B1: MLP-AE** | Dense AE (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **6,29%** | **2,29%** | **0,595** | AE chuẩn nén 400d → 64d |
| **M1: GTAE-IDS (Ours)** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **4,18 ± 4,30%** | **2,79 ± 1,40%** | **0,594 ± 0,106** | Tái hiện đúng mô tả paper; phương sai seed lớn |
| **M1 (Official Rules)** | Graph Transformer AE | Friday same-day | Union (votes $\ge 1$) | *chưa lưu artifact* | — | — | Không dùng làm kết luận |
| **P_paper: M1 + Union (luật code)** | Graph Transformer AE | Friday CSV-row, test = paper Table VII | Union (votes $\ge 1$) | **3,25%** @ FPR 6,56% matched | **6,56%** | **0,478** | Dựng đúng Table VII: 30.041/33.228 edge; Heartbleed/Infiltration thiếu CSV; TPR@1% 1,39% |
| **P_paper: M1 + INNE** | Graph Transformer AE + INNE | Friday CSV-row, test = paper Table VII | Detector đơn | **8,31%** @ FPR 6,56% matched | **6,56%** | **0,590** | Detector tốt nhất trên `P_paper`; TPR@1% = 4,12% |
| **T sạch @ cùng điểm vận hành** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie | **11,54%** @ FPR 6,56% matched | **6,56%** | **0,594** | Đo bằng cùng pipeline `eval_paper_parity.py` |
| **P1: Bonferroni α=0,05** | GTAE + Conformal Fusion | Temporal T (Sạch) | $\pi_{\text{fused}} \le \alpha_p$ | **8,95%** | **3,64%** | **0,662** | TPR@FPR=1% = 0%; Fisher 47,53/18,86 không kiểm soát FPR |
| **A3: Reconstruction error** | GTAE decoder MSE | Temporal T (Sạch) | Threshold 99th pct | **6,01%** | **2,07%** | **0,649** | Cao hơn M1 ở cả p nhưng p=2/4 kèm FPR 6,31/3,51% |
| **A2: No LapPE** (Đề xuất A) | GTAE without PE | Temporal T (Sạch) | Ensemble tie | **6,36%** | **1,23%** | **0,682 ± 0,003** | AUROC ổn định theo seed; TPR@1% 12,46% |
| **B2: E-GraphSAGE-AE** (Đề xuất A) | Mean aggregation, cùng độ sâu/rộng | Temporal T (Sạch) | Ensemble tie | **9,78%** | **1,81%** | **0,689 ± 0,021** | Attention không cần thiết; TPR@1% 11,30% |
| **A5: Header hygiene** | GTAE, bỏ TTL + 2 checksum | Temporal T (Sạch) | Ensemble tie | **2,83%** | **2,33%** | **0,675** | Train lại 3 seed; TPR@1% **3,77%** ≥ M1 3,65%, AUROC 0,594 → 0,675 ⇒ không phải shortcut định danh |
| **Upper Bound (Supervised RF)** | Random Forest | Cross-day (Tue/Wed → Thu/Fri) | Ngưỡng xác suất | **18,1%** | **6,7%** | **0,92** | Giới hạn trên phân loại giám sát |
| **Upper Bound (Same-session RF)** | Random Forest | Same-session (Random) | Ngưỡng xác suất | **99,4%** | **6,1%** | **0,97** | Rò rỉ nhận diện phiên/ngày |

*Ghi chú phương pháp:* các dòng **M1/Ours** dùng ngưỡng riêng của detector ở contamination 0,01 (FPR thực 2,79%). Các dòng **@ FPR 6,56% matched** đặt ngưỡng sao cho FPR thực trên benign test đúng bằng 6,56% — cùng định nghĩa với paper — và grid contamination `[0,001; 0,01; 0,04; 0,05; 0,1]`. Cột FPR ở các dòng `P_paper`/`T sạch` là ngưỡng matched với FPR Ensemble công bố trong Table VI (6,56%), không phải FPR của một detector cụ thể. Số đo: `results/paper_parity/`, chi tiết: [`paper_parity.md`](paper_parity.md).

---

## 2. Kết quả Proposal P1 (Conformal Calibration & Early Exit)

Proposal P1 giải quyết 3 hạn chế thực tế của GTAE-IDS:
1. Chuẩn hóa điểm bất thường thành **conformal p-value**; Bonferroni kiểm soát FPR theo lý thuyết, Fisher chỉ exploratory khi detector tương quan.
2. Cơ chế **Early-Exit**: dừng kiểm tra ngay khi p-value $\le \alpha_p$, không cần chờ đủ 8 gói tin.
3. Đo lường chỉ số **Average Packets to Decision (APD)** và độ trôi phân phối thời gian (temporal drift).

*Bảng kết quả trung bình 3 seed trên tập kiểm thử chuẩn T_fixed (30.907 flow), calibration 40% = 800 flow. Chi tiết sinh tự động: [`P1.md`](P1.md).*

| $\alpha$ mục tiêu | Phương pháp Fusion | TPR thực đo | FPR thực đo | APD Tấn công (gói) | APD Bình thường (gói) | Tỉ lệ dừng sớm (Attack) | AUROC | TPR@FPR=1% |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| 0,01 | Bonferroni | 0,00% | 0,00% | 8,00 pkts | 8,00 pkts | 0,00% | 0,66 | 0,00% |
| 0,05 | Bonferroni | **8,95%** | **3,64%** | 7,75 pkts | 7,91 pkts | 7,70% | 0,66 | 0,00% |
| 0,10 | Bonferroni | **14,11%** | **5,78%** | 7,56 pkts | 7,84 pkts | 13,22% | 0,66 | 0,00% |
| 0,01 | Fisher | 42,46% | 13,57% | 6,44 pkts | 7,41 pkts | 41,57% | 0,64 | 2,77% |
| 0,05 | Fisher | **47,53%** | **18,86%** | **6,24 pkts** | 7,23 pkts | **46,98%** | 0,64 | 2,77% |
| 0,10 | Fisher | 49,33% | 22,96% | 6,16 pkts | 7,08 pkts | 48,58% | 0,64 | 2,77% |

**Nhận xét:**
- Với **Bonferroni ($\alpha = 0,05$)**, FPR thực đo **3,64%** ($\le 5\%$) và TPR **8,95%**, cao hơn M1 (4,18% @ 2,79%) ở vùng FPR tương đương. Ở $\alpha=0,10$, TPR **14,11%** @ FPR **5,78%**.
- Với **Bonferroni ($\alpha = 0,01$)**, TPR/FPR đều 0 vì sàn p-value $4/801 = 0,004994 > 0,01/7$; cấu hình này không thể alert với 800 calibration flow.
- Với **Fisher**, TPR tăng lên **42,46–49,33%** nhưng FPR **13,57–22,96%**, vượt xa $\alpha$ do 4 detector tương quan. Fisher chỉ nên đọc như exploratory, không dùng để claim kiểm soát FPR.
- **Giới hạn:** tại FPR=1%, Bonferroni đạt TPR 0% và Fisher 2,77%, đều thấp hơn M1 (3,65%). P1 chưa vượt M1 ở vùng FPR thấp; đóng góp là operating point có kiểm soát FPR và phân tích trade-off.
- **Early-exit:** Bonferroni $\alpha=0,05$ phát hiện sớm **7,70%** attack, APD **7,75 gói**; $\alpha=0,10$ phát hiện sớm **13,22%**, APD **7,56 gói**. Fisher giảm APD mạnh hơn (6,24 gói) nhưng FPR quá cao.
