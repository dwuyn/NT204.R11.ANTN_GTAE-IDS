# NT204.R11.ANTN — Tái hiện, Phản biện và Cải tiến GTAE-IDS (Nhóm B)

Đồ án môn học **Nghiên cứu Hệ thống Phát hiện & Ngăn ngừa Xâm nhập** (NT204.R11.ANTN) — Khoa Mạng máy tính & Truyền thông, Trường Đại học Công nghệ Thông tin, ĐHQG-HCM.

**Bài báo nghiên cứu (Paper neo):**
> J. Ghadermazi, S. Hore, A. Shah, N. D. Bastian, *"GTAE-IDS: Graph Transformer-Based Autoencoder Framework for Real-Time Network Intrusion Detection,"* **IEEE Transactions on Information Forensics and Security (TIFS)**, vol. 20, pp. 4026–4041, 2025. DOI: `10.1109/TIFS.2025.3557741`.

---

## 1. Tóm tắt Đóng góp & Phát hiện Nghiên cứu

1. **Tái hiện độc lập nghiêm ngặt:** Xây dựng lại toàn bộ pipeline kỹ thuật xử lý dữ liệu từ 51 GB file pcap thô (CIC-IDS2017), mã hóa 25 byte IP/TCP header, xây dựng đồ thị Line-Graph Attention, huấn luyện 21 mô hình GTAE trên GPU T4, kiểm thử với **81 bài unit/integration test** và **428 bài kiểm tra chéo artifact** không rò rỉ dữ liệu.
2. **Phát hiện phản biện học thuật đối với bài báo gốc:**
   - Kết quả công bố của bài báo (**TPR 99,04% ở FPR 6,56%**) **không thể tái lập trong môi trường IDS thời gian thực, không rò rỉ dữ liệu** (kết quả tái hiện sạch Protocol T đạt TPR 11,5% ở FPR 2,5%).
   - Mổ xẻ trực tiếp mã nguồn mở chính thức của tác giả (`jalalgh7/graph-representation-learning-for-NIDS` và `jalalgh7/robust-and-real-time-NIDS`), nhóm phát hiện **4 nguyên nhân kỹ thuật cốt lõi**:
     1. *Lỗi lệch nhãn gói tin (Label Row-Shift):* Thiếu nhánh `else` trong vòng lặp tiền xử lý khiến cột nhãn bị trượt hàng, gán nhãn tấn công cho lưu lượng bình thường đầu ngày.
     2. *Lỗi ngắt kết nối Transformer Encoder:* Trong `GraphAutoencoder.forward()`, biến `edge_features` bị bỏ qua và `features` thô được truyền thẳng vào decoder, biến mô hình thực tế thành một tầng tuyến tính `Linear(400, 400)`.
     3. *Sai lệch phân chia dữ liệu:* Tác giả huấn luyện và kiểm thử trên cùng ngày thứ Sáu (Friday 70/30 split) thay vì phân chia thời gian xuyên suốt tuần.
     4. *Luật bầu chọn OR và ghép chỉ số:* Tác giả sử dụng luật hợp logic (OR, `votes >= 1`), làm FPR trên Benign tăng lên **13,12%**, nhưng lại trích dẫn ghép TPR của Ensemble với FPR của riêng OCSVM (6,56%).
3. **Đề xuất cải tiến P1 (Calibrated Conformal Early-Exit):**
   - Ứng dụng Conformal Prediction để chuẩn hóa điểm số bất thường, kiểm soát chặt chẽ FPR thực nghiệm ($\le \alpha$).
   - Cơ chế phát hiện sớm tuần tự (Sequential Early-Exit): cho phép báo động ngay từ $p=2..7$ gói tin, giúp phát hiện sớm **65,4%** các cuộc tấn công và tiết kiệm **40% thời gian chờ gói tin**.

---

## 2. Bảng Đối chiếu Kết quả Thực nghiệm (p = 8)

| Phương pháp | Loại mô hình | Giao thức dữ liệu | Luật bầu chọn | TPR | FPR | AUROC |
|---|---|---|---|---:|---:|---:|
| **Paper Table VI** | GTAE-IDS | Random / Same-day | Majority vote | **99,04%** | **6,56%** | — |
| **Official Repo Code** | Disconnected Linear AE | Friday 70/30 | Union (votes $\ge 1$) | **98,74%** | **13,12%** | — |
| **B0: Raw Vector** | PyOD Detectors (Không đồ thị) | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **11,8%** | **3,2%** | **0,68** |
| **B1: MLP-AE** | Dense AE (Không đồ thị) | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **9,4%** | **2,8%** | **0,66** |
| **M1: GTAE-IDS (Ours)** | Graph Transformer AE | Temporal T (Sạch) | Ensemble tie ($\ge 2/4$) | **11,5%** | **2,5%** | **0,67** |
| **P1: Conformal Early-Exit** | GTAE + Conformal Fusion | Temporal T (Sạch) | $\pi_{\text{fused}} \le \alpha_p$ | **24,6%** | **4,8%** | **0,86** |
| **Supervised RF (Upper Bound)** | Random Forest | Cross-day (Tue/Wed $\to$ Thu/Fri) | Ngưỡng xác suất | **18,1%** | **6,7%** | **0,92** |
| **Supervised RF (Same-day)** | Random Forest | Same-session (Cùng ngày) | Ngưỡng xác suất | **99,4%** | **6,1%** | **0,97** |

---

## 3. Cấu trúc Thư mục Dự án

```
ids-proj/
├── configs/               # Cấu hình dữ liệu và lịch trình tấn công CIC-IDS2017
├── data/
│   ├── raw/               # 5 file pcap + CSV (không commit)
│   ├── processed/         # Parquet gói tin và luồng đã gán nhãn
│   └── graphs/            # Đồ thị PyG cho Protocol T, R và T_fixed (p=2..8)
├── demo/
│   ├── run_demo.py        # Demo tương tác dòng lệnh thời gian thực
│   └── run_demo.sh        # Script 1 lệnh khởi chạy demo
├── docs/
│   ├── GTAE-IDS_Research_docs.md  # Tài liệu kỹ thuật chi tiết
│   ├── REPRO_AUDIT.md     # Báo cáo rà soát và mổ xẻ mã nguồn gốc
│   └── WORK_PLAN.md       # Kế hoạch công việc và nhật ký tiến độ
├── experiments/           # 21 mô hình checkpoint GTAE đã huấn luyện
├── reports/
│   ├── report.md          # Báo cáo nghiên cứu tổng kết đồ án
│   ├── slides.md          # Slide thuyết trình Marp (14 slide)
│   ├── paper_vs_ours.md   # Báo cáo so sánh đối chứng chi tiết
│   └── qa_labeling.md     # Báo cáo kiểm định chất lượng nhãn
├── results/               # Kết quả thực nghiệm CSV/JSON
├── scripts/
│   ├── eval_baselines_p1.py # Đánh giá B0, B1 và P1
│   ├── train_all.py       # Huấn luyện toàn bộ mô hình (hỗ trợ resume)
│   └── audit_artifacts.py # Kiểm toán tự động 428 tiêu chí dữ liệu
├── src/                   # Mã nguồn chính của pipeline GTAE-IDS và P1
└── tests/                 # 81 bài kiểm thử tự động pytest
```

---

## 4. Hướng dẫn Tái Chạy Thực nghiệm

### 4.1 Cài đặt môi trường
Yêu cầu Python 3.10+ và card GPU (CUDA 11.8+ khuyến nghị cho huấn luyện nhanh):
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4.2 Chạy kiểm thử tự động (81 tests)
```bash
pytest -v
```

### 4.3 Đúng 1 lệnh Huấn luyện (Train GTAE Model)
```bash
# Huấn luyện GTAE p=8 (mặc định GPU nếu khả dụng, fallback CPU):
python -m src.train_gtae --p 8 --graphs data/graphs/T --out experiments/T/p8/seed0 --epochs 100 --seed 0
```

### 4.4 Đúng 1 lệnh Đánh giá (Evaluate Models & Baselines)
```bash
# Đánh giá toàn bộ 21 model GTAE, Baselines B0/B1 và P1 Early-Exit:
python scripts/eval_baselines_p1.py
```

### 4.5 Chạy Demo 5 phút
```bash
./demo/run_demo.sh
```
