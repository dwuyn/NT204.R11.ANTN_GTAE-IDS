---
marp: true
theme: default
paginate: true
header: "NT204.R11 — Đồ án Nghiên cứu GTAE-IDS — Nhóm B"
footer: "Trường Đại học Công nghệ Thông tin — ĐHQG-HCM"
---

<!-- CẢNH BÁO: số liệu của lần chạy trước retrain 2026-11-16. Nguồn chuẩn: results/*.csv, docs/DECISIONS.md, reports/ablation.md, reports/P1.md, reports/latency.md. T p8 ensemble-tie: TPR 4,18% @ FPR 2,79%, AUROC 0,594; matched FPR 6,56%: T 11,54%, P_paper 3,25%. -->

<style>
@import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&family=Inter:wght@400;600;700&display=swap');

:root {
  --color-background: #0d1117;
  --color-foreground: #c9d1d9;
  --color-heading: #58a6ff;
  --color-accent: #7ee787;
  --color-warning: #f2cc60;
  --color-danger: #ff7b72;
  --color-code-bg: #161b22;
  --color-border: #30363d;
  --font-default: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
  --font-code: 'Fira Code', Consolas, monospace;
}

section {
  background-color: var(--color-background);
  color: var(--color-foreground);
  font-family: var(--font-default);
  box-sizing: border-box;
  border-left: 5px solid var(--color-accent);
  position: relative;
  line-height: 1.5;
  font-size: 20px;
  padding: 48px 56px;
}

h1, h2, h3 {
  font-weight: 700;
  color: var(--color-heading);
  font-family: var(--font-code);
  margin-top: 0;
}

h1 {
  font-size: 38px;
  line-height: 1.3;
}

h1::before {
  content: '# ';
  color: var(--color-accent);
}

h2 {
  font-size: 30px;
  margin-bottom: 24px;
  padding-bottom: 8px;
  border-bottom: 2px solid var(--color-border);
}

h2::before {
  content: '## ';
  color: var(--color-accent);
}

h3 {
  font-size: 22px;
  color: var(--color-warning);
  margin-top: 16px;
  margin-bottom: 8px;
}

ul, ol {
  padding-left: 28px;
  margin-top: 8px;
  margin-bottom: 8px;
}

li {
  margin-bottom: 8px;
}

li::marker {
  color: var(--color-accent);
}

table {
  width: 100%;
  border-collapse: collapse;
  font-size: 15px;
  margin-top: 12px;
  margin-bottom: 12px;
}

th, td {
  border: 1px solid var(--color-border);
  padding: 8px 12px;
  text-align: left;
}

th {
  background-color: #161b22;
  color: var(--color-heading);
  font-weight: 600;
}

tr:nth-child(even) {
  background-color: #131820;
}

code {
  background-color: var(--color-code-bg);
  color: var(--color-accent);
  padding: 2px 6px;
  border-radius: 4px;
  font-family: var(--font-code);
  font-size: 0.88em;
}

strong {
  color: #fff;
  font-weight: 700;
}

.badge-danger {
  background-color: rgba(255, 123, 114, 0.2);
  color: var(--color-danger);
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 600;
}

.badge-success {
  background-color: rgba(126, 231, 135, 0.2);
  color: var(--color-accent);
  padding: 2px 8px;
  border-radius: 4px;
  font-weight: 600;
}

section.lead {
  border-left: 6px solid var(--color-heading);
  display: flex;
  flex-direction: column;
  justify-content: center;
}

section.lead h1 {
  font-size: 44px;
  color: #fff;
  margin-bottom: 16px;
}

section.lead p {
  font-size: 20px;
  color: var(--color-foreground);
  font-family: var(--font-code);
}
</style>

<!-- _class: lead -->

# GTAE-IDS: TÁI HIỆN, PHẢN BIỆN VÀ CẢI TIẾN
### Đồ án môn học Nghiên cứu NIDS (NT204.R11.ANTN)

**Nhóm thực hiện:** Nhóm B  
**Paper neo:** Ghadermazi et al., *IEEE TIFS 2025* (DOI: `10.1109/TIFS.2025.3557741`)  
**Giảng viên hướng dẫn:** Bộ môn An toàn Thông tin  

---

## 1. Bài toán NIDS & Động cơ Nghiên cứu

- **Hạn chế NIDS theo luật (Signature-based):** Bất lực trước tấn công zero-day và mã độc biến thể mới.
- **Hạn chế NIDS thống kê luồng (Statistical Flow-based):**
  - Trích xuất 80+ đặc trưng sau khi luồng kết thúc $\implies$ **Độ trễ quá lớn** (không thể ngăn chặn inline).
- **Mục tiêu của GTAE-IDS (Ghadermazi et al., 2025):**
  - **Phát hiện sớm (Early Detection):** Chỉ dùng $p$ gói tin đầu tiên ($p=2 \dots 8$) của luồng mạng.
  - **Học không giám sát (Unsupervised Graph Transformer Autoencoder):** Tận dụng cấu trúc liên kết đồ thị luồng mạng kết hợp Autoencoder để nhận diện bất thường không cần nhãn.
  - **Tuyên bố của paper:** Đạt **TPR 99,04%** ở mức **FPR 6,56%**.

---

## 2. Kiến trúc & Ý tưởng GTAE-IDS

```
   Raw PCAP (Gói tin TCP/IPv4)
       │
       ▼
 [Packet Truncation] ──> Cắt 25 byte Header (9B IP + 16B TCP)
       │
       ▼
[Directional Padding] ─> Ghép fwd/bwd 50 chiều x p gói = 50p vector
       │
       ▼
  [Line-Graph G] ─────> Nút = (IP, Port), Cạnh = Luồng giao tiếp
       │
       ▼
 [Graph Transformer] ──> Line-Graph Self-Attention + Laplacian PE
       │
       ▼
  [Embeddings Z] ─────> Không gian nhúng tiềm ẩn
       │
       ▼
 [Ensemble PyOD] ─────> OCSVM + IForest + HBOS + INNE ("Majority Vote" — code thực tế: OR)
```

---

## 3. Biểu diễn Gói tin & Hướng (Fig. 3 & Fig. 4)

- **Cắt xén 25 byte Header (Fig. 3):**
  - **IP Header (9 bytes):** Total Length (2B), Identification (2B), Flags + Fragment Offset (2B), Protocol (1B), Options (2B). Bỏ IP nguồn/đích, TTL, Checksum.
  - **TCP Header (16 bytes):** Sequence Number (4B), Acknowledgment (4B), Data Offset + Flags (2B), Window Size (2B), Options (4B). Bỏ Port, Checksum.
  - Chuẩn hóa: $\text{byte} / 255.0 \in [0.0, 1.0]$.
- **Mã hóa hướng truyền thông (Fig. 4):**
  - Mỗi bước $k$ dùng 50 chiều:
    - **Chiều thuận (fwd):** `[25 bytes Header, 25 zeros]`
    - **Chiều nghịch (bwd):** `[25 zeros, 25 bytes Header]`
  - Luồng $p$ gói tin $\implies$ Vector đặc trưng có kích thước $50 \times p$ chiều ($p=8 \implies 400$ chiều).

---

## 4. Line-Graph Transformer & Bộ Dò Bất thường

- **Line Graph Transformation:**
  - Cạnh đồ thị gốc $G$ (luồng mạng) trở thành đỉnh của $\mathcal{L}(G)$.
  - Tự chú ý đa đầu tính toán trực tiếp giữa các luồng có chung nút mạng:
    $$\text{Attn}(e_i, e_j) = \text{Softmax}\left(\frac{Q(e_i) K(e_j)^T}{\sqrt{d}}\right) V(e_j)$$
  - **Laplacian Positional Encoding:** Nhúng vector riêng $k=8$ chiều bổ sung vị trí topo đồ thị.
- **Tập hợp 4 thuật toán phát hiện bất thường (PyOD):**
  - **OCSVM** (RBF kernel, contamination 0,01)
  - **Isolation Forest** (150 cây)
  - **HBOS** (20 bins histogram)
  - **INNE** (100 isolation hyper-spheres)
  - **Bầu chọn đa số ("Majority Vote" — code thực tế: OR):** Cảnh báo nếu $\ge 3/4$ hoặc $\ge 2/4$ bộ dò báo động.

---

## 5. Kết quả Tái hiện (Protocol T, mean ± std 3 seed)

- **Hạ tầng:** 51 GB pcap CIC-IDS2017 thô, **132 pytest pass**, 428 kiểm tra artefact, 21 mô hình (7 giá trị $p$ × 3 seed).
- **Protocol T:** train benign Monday, test Tue–Fri (lựa chọn của nhóm để đo khi phân phối trôi theo thời gian).

| $p$ | TPR (Ours) | FPR (Ours) | AUROC | Paper Table VI |
|---:|---:|---:|---:|---:|
| 2 | 3,30 ± 1,70% | 2,89% | 0,505 | 84,47% |
| 4 | 8,56 ± 2,64% | 2,94% | 0,578 | 94,72% |
| 6 | 14,93 ± 10,87% | 2,29% | **0,835** | 98,44% |
| **8** | <span class="badge-danger">**4,18 ± 4,30%**</span> | **2,79%** | **0,594 ± 0,106** | <span class="badge-success">**99,04% (FPR 6,56%)**</span> |

- **Không tái lập được**, kể cả trong `P_paper` (đúng test Table VII + luật OR của code): **3,25%** @ FPR 6,56%.
- **Tự đánh giá:** AUROC theo seed 0,495–0,705; đường cong theo $p$ **không** đơn điệu như paper.

---

## 6. Đối chiếu Bài báo ↔ Code ↔ CSV của Tác giả

Repo: `jalalgh7/graph-representation-learning-for-NIDS` (+ `robust-and-real-time-NIDS` cho trích xuất gói tin)

| # | Phát hiện | Kiểm chứng |
|---|---|---|
| F1 | Table VII **trùng từng chữ số** với luật **OR** (`votes >= 1`); paper ghi *majority voting* | ✔ |
| F2 | FPR Ensemble công bố **6,56%** ≠ CSV công khai **13,12%** | ✔ |
| F3 | Mỗi lớp tấn công test trên **một đồ thị riêng**: topo tự lộ nhãn | ✔ cơ chế |
| F4 | Benign train/test cùng **Friday 70/30** (paper không nêu ngày) | ✔ |
| F5 | Detector chạy trên **output decoder**, không phải bottleneck | ✔ |
| F6 | `GraphAutoencoder` không nối encoder và **không chạy được** như công bố | ✔ code |
| F7 | Nhãn gói tin **trượt hàng** (thiếu `else` + `dropna`) | ✔ cơ chế, chưa định lượng |

$\implies$ Nhóm chỉ khẳng định **mâu thuẫn kiểm tra được**, không suy diễn mô hình thật là gì.

---

## 7. Chi tiết F1 + F2: Luật Ensemble & Điểm Vận hành

**Paper (tr. 4033):** *"we introduce a majority voting ensemble classifier"*

**Code (`GTAE_8pkt.ipynb`, cell 60):**
```python
votes = np.sum([prediction == 1 for prediction in combined_predictions], axis=0)
anomalies_ensemble = (votes >= 1).astype(int)   # OR, không phải đa số
```

| p = 8 | OCSVM | IF | HBOS | INNE | **Ensemble** |
|---|---:|---:|---:|---:|---:|
| FPR trong **paper** (Table VI) | 4,03 | 4,93 | 4,96 | 4,99 | **6,56** |
| FPR trong **CSV tác giả** | 8,06 | 9,86 | 9,92 | 9,98 | <span class="badge-danger">**13,12**</span> |

- TPR theo lớp ở Table VII = cột Ensemble (OR) của CSV, **khớp tuyệt đối**.
- Không thể tái tạo điểm vận hành 99,04% / 6,56% từ artefact công khai.

---

## 8. Chi tiết F3–F6: Thiết lập Đánh giá & Notebook

- **F3 – mỗi lớp một đồ thị:** `create_graph_from_df(test_df)` gọi riêng cho từng lớp. Đồ thị DoS có hub cực lớn, khác hẳn topo benign.
- **F4 – cùng ngày:** train `Friday_benign_train_70%`, test `Friday_benign_test_30%`. Paper chỉ nói *"snapshot at arbitrary timestamp t"*, nên đây là **điểm yếu phương pháp**, không phải mâu thuẫn.
- **F5 + F6 – notebook (cell 24):**
```python
self.transformer_encoder = nn.TransformerEncoder(nn.GraphTransformerLayer(...))  # không tồn tại trong torch.nn
def forward(self, g, features):
    edge_features = self.transformer_encoder(features)
    return self.decoder(features)          # edge_features không được dùng
```
  `execution_count` lộn xộn (cell 24 = 42, cell 41 = 40, cell 60 = 136) $\implies$ **notebook không phản ánh code đã sinh ra kết quả**.

---

## 9. So sánh với Nghiên cứu Liên quan (cùng protocol, p = 8)

| Phương pháp | Đại diện | AUROC (mean ± std) | TPR @ ngưỡng FPR=1% |
|---|---|---:|---:|
| M1 GTAE (attention + LapPE) | GTAE-IDS [1] | 0,594 ± 0,106 | 3,65% |
| **B2 E-GraphSAGE-AE** (mean agg.) | E-GraphSAGE [6], Anomal-E [8] | **0,689 ± 0,021** | **11,30%** |
| B1 MLP-AE (không đồ thị) | AE kiểu Kitsune [11] | 0,595 ± 0,005 | 6,95% |
| B0 vector header thô | PBCNN/nPrint, bản unsupervised | 0,698 ± 0,004 | 2,13% |
| A5 bỏ TTL + checksum | kiểm tra shortcut | 0,675 ± 0,042 | 3,77% |

| Tuyên bố của paper | Số đo | Kết luận |
|---|---|---|
| Attention cạnh–cạnh là cốt lõi | Mean aggregation tốt hơn | ✘ |
| Ngữ cảnh đồ thị giúp phát hiện | B0 không đồ thị ≥ M1 | ✘ |
| Không dùng shortcut định danh | A5 AUROC tăng | ✔ |
| Real-time 1,28 µs/gói | 15.272 µs/gói end-to-end; 8,2 < 12,1 flow/s | ✘ |
| > 98% trên 2018 / ACI | 5,99% / 1,69% khi test có benign | ✘ |

---

## 10. Ưu / Nhược điểm của GTAE-IDS

**Ưu điểm**
- Duy nhất kết hợp **packet-level + đồ thị + không giám sát** trong nhóm bài liên quan.
- Không cần nhãn tấn công; đặc trưng không chứa IP/port, không phụ thuộc TTL/checksum (A5).
- Khung quyết định theo $p$ gói, nền tảng cho phát hiện sớm.

**Nhược điểm (có số đo)**
- Embedding tách kém khi phân phối trôi theo thời gian (AUROC ~0,6) và **bất ổn theo seed**.
- Attention + LapPE không đóng góp, còn tăng phương sai.
- Đồ thị cửa sổ phải dựng lại line graph: **122 ms/flow**, không đạt thời gian thực.
- Phiếu cứng 4 detector: không kiểm soát được FPR.
- Đánh giá trong paper: test toàn tấn công, mỗi lớp một đồ thị, benign cùng ngày.

---

## 11. Đề xuất A (Tầng Biểu diễn): Encoder Gọn hơn

**Chẩn đoán:** điểm nghẽn nằm ở embedding, attention và LapPE không giúp ích.
**Đề xuất:** thay attention bằng **mean aggregation** và/hoặc **bỏ LapPE**.

| p = 8, protocol T | M1 (gốc) | Bỏ LapPE | Mean aggregation |
|---|---:|---:|---:|
| AUROC | 0,594 ± 0,106 | **0,682 ± 0,003** | **0,689 ± 0,021** |
| TPR @ ngưỡng FPR=1% | 3,65% | **12,46%** | **11,30%** |
| TPR / FPR (tie) | 4,18% / 2,79% | 6,36% / **1,23%** | **9,78%** / 1,81% |
| std AUROC giữa seed | 0,106 | **÷35** | **÷5** |

- AUROC +0,09, TPR ở FPR thấp gấp ~3 lần, ổn định hơn nhiều; mean aggregation còn **rẻ hơn** attention.
- **Giới hạn:** AUROC ~0,69 vẫn chưa đủ để triển khai.

---

## 12. Đề xuất B (Tầng Quyết định): P1 Conformal Early-Exit

1. **Conformal p-value** trên tập calibration benign $\mathcal{C}$ (800 flow):
   $$\pi_m(x) = \frac{1 + \sum_{c \in \mathcal{C}} \mathbb{I}(s_m(c) \ge s_m(x))}{1 + |\mathcal{C}|}$$
2. **Hợp nhất Bonferroni:** $\pi_{\text{fused}} = \min(1, 4\min_m \pi_m)$. FPR $\le \alpha$ khi exchangeable, **không** cần detector độc lập. *(Fisher giả định độc lập, nên chỉ dùng để thăm dò.)*
3. **Early-exit tuần tự** $p = 2..8$, ngân sách $\alpha_p = \alpha/7$: báo động ngay khi $\pi_{\text{fused},p} \le \alpha_p$.

| α | Fusion | TPR | FPR thực đo | Số gói TB (attack) |
|---|---|---:|---:|---:|
| 0,05 | **Bonferroni** | **8,95 ± 3,72%** | **3,64%** (≤ 5%) | 7,75 |
| 0,10 | **Bonferroni** | **14,11 ± 2,11%** | **5,78%** (≤ 10%) | 7,56 |
| 0,05 | Fisher (thăm dò) | 47,53% | 18,86% (> α) | 6,24 |

- **Đạt:** giữ FPR ≤ α trên benign **khác ngày** với calibration, điều phiếu cứng không làm được.
- **Chưa đạt:** AUROC chỉ 0,594 → 0,662; tại FPR=1% Bonferroni có TPR 0% (< M1 3,65%); dừng sớm ít.
- **Bước tiếp theo:** P1 trên encoder của Đề xuất A (đã có lệnh chạy, `--models experiments/T_egsage`).

---

## 13. Minh họa Chương trình Demo (5 Phút)

- **Script chạy tự động:** `./demo/run_demo.sh` (cần checkpoint + `data/graphs/T_fixed`).
  - Phát lại các luồng của tập test; mỗi luồng đi qua P1 early-exit từ $p=2$ đến $p=8$.

```
Flow ID  | Actual Class | Attack Name            | Decision   | Exit At | P-Value | Alert
---------|--------------|------------------------|------------|---------|---------|------
104821   | ATTACK       | DoS Hulk               | ALERT      | p=4     | 0.0012  | [!]
104822   | BENIGN       | no_attack_window       | NORMAL     | p=8     | 0.4521  | [OK]
104823   | ATTACK       | DoS Hulk               | NORMAL     | p=8     | 0.3170  | [OK]   <- tấn công bị bỏ sót
```
- *Bảng trên minh họa **định dạng** output. Trên toàn tập test, P1 Bonferroni α=0,05 chỉ phát hiện 8,95% tấn công (§12); phần lớn tấn công **không** bị chặn.*

---

## 14. Kết luận & Hạn chế

1. **Tìm hiểu & tái hiện:** pipeline đầy đủ từ pcap, đúng Table III/V và Fig. 3/4; 132 test, 428 kiểm tra artefact. Con số 99,04% @ 6,56% **không tái lập được** (`T`: 4,18%; `P_paper`: 3,25%).
2. **Đối chiếu & so sánh:** 7 mâu thuẫn có trích dẫn giữa paper, code và CSV; baseline cùng protocol cho thấy attention, LapPE và đồ thị không phải nguồn tín hiệu; claim real-time không đạt.
3. **Đề xuất:** (A) encoder gọn hơn: AUROC +0,09, ổn định hơn; (B) conformal early-exit: FPR ≤ α nhưng TPR tăng ít.
4. **Hạn chế:** 3 seed; số của bài liên quan (trừ B2) là nguồn thứ cấp; chưa định lượng F3 và F7; chưa chạy A + B kết hợp.

---

<!-- _class: lead -->

# CẢM ƠN THẦY CÔ VÀ CÁC BẠN ĐÃ LẮNG NGHE!

### Q & A

**Mã nguồn đồ án:** `github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS_Nhom8`  
**Liên hệ nhóm:** Nhóm B — Lớp An toàn Thông tin Khóa 2021
