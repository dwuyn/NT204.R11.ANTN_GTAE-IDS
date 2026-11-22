# NT204.R11.ANTN — Tái hiện, Phản biện và Cải tiến GTAE-IDS (Nhóm B)

> Số liệu trong README được đồng bộ với các CSV đo trong `results/` (retrain 2026-11-16, đo bổ sung tới 2026-11-21). Mean ± std: [`reports/seed_stats.md`](reports/seed_stats.md) (sinh bởi `scripts/make_seed_stats.py`); M1 dùng 7 seed cho đường cong p, baseline/P1 dùng 3 seed. Báo cáo đầy đủ: [`reports/report.md`](reports/report.md).

Đồ án môn học **Nghiên cứu Hệ thống Phát hiện & Ngăn ngừa Xâm nhập** (NT204.R11.ANTN) — Khoa Mạng máy tính & Truyền thông, Trường Đại học Công nghệ Thông tin, ĐHQG-HCM.

**Bài báo nghiên cứu (paper neo):**
> J. Ghadermazi, S. Hore, A. Shah, N. D. Bastian, *"GTAE-IDS: Graph Transformer-Based Autoencoder Framework for Real-Time Network Intrusion Detection,"* **IEEE Transactions on Information Forensics and Security (TIFS)**, vol. 20, pp. 4026–4041, 2025. DOI: `10.1109/TIFS.2025.3557741`.

---

## 1. Tóm tắt đóng góp

| Yêu cầu đề tài | Đóng góp | Tài liệu |
|---|---|---|
| Tìm hiểu vấn đề và phương pháp | Phân tích bài báo; liệt kê các điểm bài báo không mô tả nhưng ảnh hưởng tới tái lập | `reports/report.md` Ch.1–2, `docs/GTAE-IDS_Research_docs.md` |
| Thực hiện lại và đánh giá | Pipeline từ 51 GB pcap; 21 mô hình; **132 test** + 428 kiểm tra artefact; 4 protocol (`T`, `T_fixed`, `R`, `P_paper`); CIC-IDS2018, ACI-IoT-2023; đo độ trễ end-to-end | Ch.3–4 |
| Phân tích, so sánh với bài liên quan | Đối chiếu bài báo ↔ code ↔ CSV của tác giả; baseline cùng protocol (B0, B1, B2 E-GraphSAGE, A2, A3, A5); đối chiếu từng tuyên bố của bài báo | Ch.5–6, `docs/REPRO_AUDIT.md`, `reports/related_work.md` |
| Đề xuất cải tiến | (A) encoder mean aggregation / bỏ LapPE; (B) P1 conformal fusion + early-exit | Ch.7, `reports/P1.md` |

### Phát hiện chính
1. **Không tái lập được 99,04% TPR @ 6,56% FPR.**
   - Protocol `T` (train Monday benign, test Tue–Fri): TPR **4,18 ± 4,30%** @ FPR **2,79 ± 1,40%**, AUROC **0,594 ± 0,106**.
   - `P_paper` (đúng thành phần test của Table II/VII, đúng luật OR của code tác giả): **3,25%** TPR tại cùng FPR 6,56%.
2. **Mâu thuẫn kiểm chứng được giữa bài báo, code và CSV của tác giả** (`docs/REPRO_AUDIT.md` §5):
   - Table VII trùng khớp từng chữ số với luật **OR** (`votes >= 1`), trong khi bài báo mô tả *majority voting*.
   - FPR Ensemble công bố **6,56%**, nhưng CSV công khai ghi **13,12%**.
   - Mỗi lớp tấn công được test trên **một đồ thị riêng**; benign train/test cùng lấy từ **Friday** (bài báo không nêu ngày).
   - Detector chạy trên **output của decoder**, không phải bottleneck.
   - Lớp `GraphAutoencoder` công bố không nối encoder vào decoder và **không chạy được** như hiện có, nên notebook không phản ánh code đã sinh ra kết quả.
3. **Baseline cùng protocol:**
   - Mean aggregation (E-GraphSAGE-AE) đạt AUROC **0,689 ± 0,021**; vector header thô đạt **0,698**. Cả hai đều cao hơn GTAE, nên attention và ngữ cảnh đồ thị không phải nguồn tín hiệu.
   - Xoá TTL và checksum không làm giảm AUROC (0,675), nên mô hình không dựa vào shortcut định danh.
4. **"Real-time" không đạt ở mức triển khai:** 122 ms/flow end-to-end, xử lý 8,2 flow/s trong khi lưu lượng đến là 12,1 flow/s.
5. **Đề xuất cải tiến:**
   - **(A)** Bỏ LapPE hoặc dùng mean aggregation: AUROC tăng lên 0,68–0,69, độ lệch chuẩn giữa seed giảm 5–35 lần, TPR @ ngưỡng FPR=1% tăng từ 3,65% lên 11–12%.
   - **(B)** P1 conformal early-exit: Bonferroni giữ FPR thực đo ≤ α (3,64% @ α=0,05; 5,78% @ α=0,10). Tuy nhiên TPR tăng ít, và tại FPR=1% không vượt M1.

---

## 2. Bảng kết quả (p = 8, mean 3 seed)

| Phương pháp | Mô hình | Dữ liệu | Luật quyết định | TPR | FPR | AUROC |
|---|---|---|---|---:|---:|---:|
| **Paper Table VI** | GTAE-IDS | Snapshot (code: Friday 70/30) | "Majority" (code: OR) | **99,04%** | **6,56%** | — |
| **CSV công khai của tác giả** | notebook `GTAE_8pkt` | Friday 70/30, mỗi lớp 1 đồ thị | OR (votes ≥ 1) | 98,5–99,8% (theo lớp) | **13,12%** | — |
| **M1: GTAE tái hiện** | Graph Transformer AE | Protocol T | Ensemble tie (≥ 2/4) | **4,18 ± 4,30%** | **2,79 ± 1,40%** | **0,594 ± 0,106** |
| P_paper: M1 + OR | Graph Transformer AE | Friday, test = Table VII | OR @ FPR 6,56% matched | **3,25%** | 6,56% | 0,478 |
| P_paper: M1 + INNE | Graph Transformer AE | Friday, test = Table VII | INNE @ FPR 6,56% matched | 8,31% | 6,56% | 0,590 |
| B0: vector thô | Không đồ thị | Protocol T | Ensemble tie | 0,50% | 1,22% | 0,698 |
| B1: MLP-AE | Không đồ thị | Protocol T | Ensemble tie | 6,29% | 2,29% | 0,595 |
| **A – B2: E-GraphSAGE-AE** | Mean aggregation | Protocol T | Ensemble tie | **9,78%** | **1,81%** | **0,689 ± 0,021** |
| **A – A2: bỏ LapPE** | GTAE không PE | Protocol T | Ensemble tie | 6,36% | **1,23%** | **0,682 ± 0,003** |
| **B – P1: Bonferroni α=0,05** | GTAE + conformal | T_fixed | $\pi_{\text{fused}} \le \alpha/7$ | **8,95%** | **3,64%** | 0,662 |
| Supervised RF (cận trên) | Random Forest | Tue/Wed → Thu/Fri | Ngưỡng xác suất | 18,1% | 6,7% | 0,92 |
| Supervised RF (cùng phiên) | Random Forest | Cùng ngày | Ngưỡng xác suất | 99,4% | 6,1% | 0,97 |

*Lưu ý: mỗi dòng dùng ngưỡng riêng nên FPR khác nhau; so sánh tại cùng FPR xem `reports/seed_stats.md` (cột TPR @ ngưỡng FPR=1%) và `reports/paper_parity.md` (FPR 6,56% matched). P1 Bonferroni có TPR @ FPR=1% bằng 0%, thấp hơn M1 (3,65%).*

---

## 3. Cấu trúc Thư mục Dự án

```
ids-proj/
├── configs/               # Cấu hình dữ liệu và lịch trình tấn công CIC-IDS2017
├── data/
│   ├── raw/               # 5 file pcap + CSV (không commit)
│   ├── processed/         # Parquet gói tin và luồng đã gán nhãn
│   └── graphs/            # Đồ thị NumPy cho Protocol T, R và T_fixed (p=2..8)
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
│   ├── slides.md          # Slide thuyết trình Marp (16 slide)
│   ├── paper_vs_ours.md   # Báo cáo so sánh đối chứng chi tiết
│   ├── P1.md              # Báo cáo P1 sinh tự động từ CSV
│   ├── seed_stats.md      # Mean ± std theo seed, sinh tự động từ CSV
│   ├── related_work.md    # So sánh với các bài liên quan (có ghi nguồn số liệu)
│   └── qa_labeling.md     # Báo cáo kiểm định chất lượng nhãn
├── results/               # Kết quả thực nghiệm CSV/JSON
├── scripts/
│   ├── eval_baselines_p1.py # Đánh giá B0, B1 và P1
│   ├── make_p1_report.py  # Sinh reports/P1.md từ CSV
│   ├── make_seed_stats.py # Sinh reports/seed_stats.md (mean ± std 3 seed) từ CSV
│   ├── train_all.py       # Huấn luyện toàn bộ mô hình (hỗ trợ resume)
│   └── audit_artifacts.py # Kiểm toán tự động 428 tiêu chí dữ liệu
├── src/                   # Mã nguồn chính của pipeline GTAE-IDS và P1
├── tests/                 # 132 bài kiểm thử tự động pytest
└── requirements.txt       # Dependency pins cho Python 3.11
```

---

## 4. Hướng dẫn Tái Chạy Thực nghiệm

### 4.1 Cài đặt môi trường
Yêu cầu Python 3.11. Repo có `requirements.txt`; local venv dùng wheel CPU, còn Kaggle/GPU cài wheel CUDA tương ứng:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4.2 Chạy kiểm thử tự động (132 tests)
```bash
pytest -q
```

### 4.3 Đúng 1 lệnh Huấn luyện (Train GTAE Model)
```bash
# Huấn luyện GTAE p=8 (mặc định GPU nếu khả dụng, fallback CPU):
python -m src.train_gtae --p 8 --graphs data/graphs/T --out experiments/T/p8/seed0 --epochs 100 --seed 0
```

### 4.4 Đánh giá model và baseline (Evaluate Models & Baselines)
```bash
# Đánh giá 21 model GTAE:
python -m src.eval --models experiments/T --graphs data/graphs/T \
  --out results --ps 2 3 4 5 6 7 8 --seeds 0 1 2

# B0/B1/P1 (cần checkpoints + data/graphs/T_fixed):
PYTHONPATH=. python scripts/eval_baselines_p1.py

# Sinh lại báo cáo P1 từ CSV:
python scripts/make_p1_report.py

# Bảng mean ± std theo seed (chỉ cần results/, không cần data/):
python scripts/make_seed_stats.py

# Đề xuất A + B: P1 trên encoder E-GraphSAGE (B2), cần experiments/T_egsage:
PYTHONPATH=. python scripts/eval_baselines_p1.py --p1-only \
  --models experiments/T_egsage --p1-ps 2 4 8 --results results/P1_egsage
```

### 4.5 Chạy Demo 5 phút
```bash
./demo/run_demo.sh
```
