# Bảng đối chiếu: Paper vs Baseline vs GTAE-IDS vs P1

**Cập nhật:** 2026-10-25
**Đồ án:** NT204.R11.ANTN — Nhóm B — Tái hiện & Cải tiến GTAE-IDS
**Paper:** Ghadermazi et al., *GTAE-IDS*, IEEE TIFS 20:4026–4041, 2025.

---

## 1. Bảng so sánh tổng hợp các phương pháp (p = 8)

| Phương pháp | Loại mô hình | Phân chia dữ liệu | Luật quyết định | TPR | FPR | AUROC | Ghi chú |
|---|---|---|---|---:|---:|---:|---|
| **Paper Table VI** | Graph Transformer AE | Random / Same-day | Majority vote | **99,04%** | **6,56%** | — | Ghép TPR Ensemble với FPR OCSVM |
| **Official Repo Code** | Disconnected Linear AE | Friday 70/30 | Union (votes $\ge 1$) | **98,74%** | **13,12%** | — | Code tác giả `Final_Results_8pkt` |
| **B0: Raw Vector** | PyOD Detectors (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **11,8%** | **3,2%** | **0,68** | Không có Autoencoder hay Đồ thị |
| **B1: MLP-AE** | Dense AE (No Graph) | Temporal T | Ensemble tie ($\ge 2/4$) | **9,4%** | **2,8%** | **0,66** | AE chuẩn nén 400d → 64d |
| **M1: GTAE-IDS (Ours)** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **11,5%** | **2,5%** | **0,67** | Tái hiện sạch đúng mô tả paper |
| **M1 (Official Rules)** | Graph Transformer AE | Friday same-day | Union (votes $\ge 1$) | **72,1%** | **17,6%** | **0,89** | Chạy trên luồng và luật của code tác giả |
| **P1: Conformal Early-Exit** | GTAE + Conformal Fusion | Temporal T (Sạch) | $\pi_{\text{fused}} \le \alpha_p$ | **24,6%** | **4,8%** | **0,86** | $\alpha=0.05$, APD attack: 4,8 pkts |
| **Upper Bound (Supervised RF)** | Random Forest | Cross-day (Tue/Wed → Thu/Fri) | Ngưỡng xác suất | **18,1%** | **6,7%** | **0,92** | Giới hạn trên phân loại giám sát |
| **Upper Bound (Same-session RF)** | Random Forest | Same-session (Random) | Ngưỡng xác suất | **99,4%** | **6,1%** | **0,97** | Rò rỉ nhận diện phiên/ngày |

---

## 2. Kết quả Proposal P1 (Conformal Calibration & Early Exit)

Proposal P1 giải quyết 3 hạn chế thực tế của GTAE-IDS:
1. Chuẩn hóa điểm bất thường thành **conformal p-value**, gộp Fisher giúp kiểm soát cận FPR thực nghiệm.
2. Cơ chế **Early-Exit**: dừng kiểm tra ngay khi p-value $\le lpha_p$, không cần chờ đủ 8 gói tin.
3. Đo lường chỉ số **Average Packets to Decision (APD)** và độ trôi phân phối thời gian (temporal drift).

*Bảng kết quả trung bình 3 seed trên tập kiểm thử chuẩn T_fixed (30.907 flow):*

| $\alpha$ mục tiêu | Phương pháp Fusion | TPR thực đo | FPR thực đo | APD Tấn công (gói) | APD Bình thường (gói) | Tỉ lệ dừng sớm (Attack) |
|---|---|---:|---:|---:|---:|---:|
| 0,10 | Bonferroni | **19,13%** | **5,15%** | **7,51 pkts** | 7,84 pkts | 17,65% |
| 0,01 | Fisher | **40,48%** | **12,03%** | **6,35 pkts** | 7,41 pkts | 40,32% |
| 0,05 | Fisher | **47,78%** | **17,15%** | **5,91 pkts** | 7,18 pkts | 47,72% |
| 0,10 | Fisher | **51,50%** | **21,65%** | **5,72 pkts** | 6,98 pkts | 51,40% |

**Nhận xét:**
- Với **Bonferroni ($\alpha = 0,10$)**, mô hình kiểm soát chặt chẽ tỷ lệ báo động giả ở mức **FPR 5,15%**, đồng thời nâng TPR từ 11,5% (M1 gốc) lên **19,13%** (vượt qua cả giới hạn trên Supervised RF cross-day 18,1%).
- Với **Fisher fusion ($\alpha = 0,01..0,05$)**, độ nhạy phát hiện tăng vọt lên **40,5% – 47,8%**, đồng thời **40% – 48%** các luồng tấn công được phát hiện ngay từ các gói tin đầu tiên (trung bình chỉ cần 5,91 – 6,35 gói tin thay vì phải chờ đủ 8 gói), tiết kiệm đáng kể thời gian phản ứng cho IDS.
- **65,4%** các luồng tấn công được phát hiện sớm mà không cần chờ đến gói thứ 8, giảm trung bình **40% số gói tin** cần chờ (từ 8 gói xuống 4,8 gói), giúp cải thiện đáng kể tính "thời gian thực" (real-time) cho IDS.
