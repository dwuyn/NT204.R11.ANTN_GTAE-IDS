---
marp: true
theme: default
paginate: true
header: "NT204.R11 — Đồ án Nghiên cứu GTAE-IDS — Nhóm B"
footer: "Trường Đại học Công nghệ Thông tin — ĐHQG-HCM"
---

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
 [Ensemble PyOD] ─────> OCSVM + IForest + HBOS + INNE (Majority Vote)
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
  - **OCSVM** (RBF kernel, $\nu=0.05$)
  - **Isolation Forest** (150 cây)
  - **HBOS** (20 bins histogram)
  - **INNE** (100 isolation hyper-spheres)
  - **Bầu chọn đa số (Majority Vote):** Cảnh báo nếu $\ge 3/4$ hoặc $\ge 2/4$ bộ dò báo động.

---

## 5. Kết quả Tái hiện Sạch & Mâu thuẫn Thực nghiệm

- **Hạ tầng kiểm thử nghiêm ngặt:**
  - 51 GB pcap CIC-IDS2017 thô, 81 pytest pass, 428 checks audit artifact.
  - Đã huấn luyện **21 mô hình GTAE** (7 giá trị $p \times 3$ seed) trên Kaggle GPU T4.
- **Kết quả Protocol T (Temporal sạch: Train Monday, Test Tue–Fri):**

| $p$ | TPR Tái hiện (Ours) | FPR Tái hiện (Ours) | AUROC | Paper Table VI |
|---:|---:|---:|---:|---:|
| 2 | 8,5% | 5,8% | 0,55 | — |
| 4 | 11,4% | 3,7% | 0,63 | — |
| 6 | 6,9% | 2,9% | 0,83 | — |
| **8** | <span class="badge-danger">**11,5%**</span> | **2,5%** | **0,67** | <span class="badge-success">**99,04% (FPR 6,56%)**</span> |

$\implies$ **Khoảng cách khổng lồ:** Mô hình sạch không thể tách biệt tấn công chưa từng gặp ở FPR thấp!

---

## 6. Mổ xẻ Mã nguồn gốc Tác giả (Official Code Audit)

Nhóm đã tìm và phân tích trực tiếp mã nguồn gốc do chính tác giả công bố:
- Repo mô hình: `jalalgh7/graph-representation-learning-for-NIDS`
- Repo tiền xử lý: `jalalgh7/robust-and-real-time-NIDS`

### Phát hiện 4 nguyên nhân cốt lõi dẫn đến sai lệch:
1. **Lỗi lệch nhãn gói tin (Label Row-Shift):** Do thiếu nhánh `else` trong vòng lặp gán nhãn.
2. **Lỗi ngắt kết nối Transformer Encoder:** Transformer bị bỏ qua, không nối vào Decoder!
3. **Phân chia dữ liệu cùng ngày (Same-day Friday split):** Không dùng Protocol T sạch.
4. **Luật bầu chọn hợp logic (OR) & Ghép chỉ số:** Bầu chọn $\ge 1$ và ghép FPR của OCSVM.

---

## 7. Chi tiết Sai sót 1 & 2 trong Code Tác giả

### 1. Lỗi lệch nhãn gói tin (`Tuesday_Packet_Level_Data.ipynb`):
```python
if float(epoch_time) >= ftp_start and float(epoch_time) <= ftp_end:
    if source_ip == '172.16.0.1' and dst_ip == '192.168.10.50':
        dict_d_labels[packets] = 6
    # THIẾU NHÁNH ELSE! -> Gói tin bình thường nền không được gán key!
# DataFrame dropna() làm cột nhãn bị trượt hàng, gán nhãn tấn công cho gói duyệt web đầu ngày!
```

### 2. Transformer Encoder bị bỏ qua (`GTAE_8pkt.ipynb` Cell 24):
```python
def forward(self, g, features):
    edge_features = self.transformer_encoder(features)
    decoded_features = self.decoder(features)  # TRUYỀN FEATURES THÔ VÀO DECODER!
    return decoded_features
```
$\implies$ Mô hình thật trong code chỉ là một tầng `nn.Linear(400, 400)` tái tạo `features`. Graph Transformer hoàn toàn không nhận gradient!

---

## 8. Chi tiết Sai sót 3 & 4: Data Split & Ghép nối Chỉ số

### 3. Phân chia dữ liệu sai lệch (Same-Day Split):
- Paper khẳng định train Monday Benign, test trên các ngày sau.
- Trong code thực tế: Train trên **Friday Benign 70%**, test trên **Friday Benign 30%** và các đồ thị tấn công riêng biệt $\implies$ Rò rỉ phân phối môi trường mạng cùng phiên.

### 4. Luật Bầu chọn OR & Ghép nối chỉ số:
- Code thực tế: `anomalies_ensemble = (votes >= 1).astype(int)` (Luật OR: chỉ cần 1 bộ dò báo động).
- Trong file `Final_Results_8pkt_Anomaly_Detection_2017.csv` của tác giả:
  - Benign FPR của Ensemble: <span class="badge-danger">**13,12%**</span> (không phải 6,56%).
  - Benign FPR của riêng OCSVM: **8,06%** (hoặc 6,49% ở file comparative).
- **Paper đã lấy TPR của Ensemble ($\ge 1$, đạt 99,04%) ghép với FPR của riêng OCSVM (6,56%)!**

---

## 9. Đề xuất Cải tiến P1: Calibrated Early-Exit GTAE

Nhằm khắc phục triệt để các hạn chế đo lường và tính thời gian thực, nhóm đề xuất **P1**:

1. **Hiệu chuẩn Conformal P-Value (Tránh bùng nổ FPR):**
   - Chuyển đổi điểm số bất thường sang conformal p-value trên tập calibration lành tính $\mathcal{C}$:
     $$\pi_m(x) = \frac{1 + \sum_{c \in \mathcal{C}} \mathbb{I}(s_m(c) \ge s_m(x))}{1 + |\mathcal{C}|}$$
   - Hợp nhất bằng kiểm định Fisher: $T = -2 \sum_{m=1}^4 \ln(\pi_m) \sim \chi^2(8) \implies$ Bảo đảm $\text{FPR} \le \alpha$.
2. **Cơ chế Dừng Sớm theo chuỗi gói tin (Sequential Early-Exit):**
   - Kiểm tra tuần tự tại $p = 2, 3, \dots, 8$ với ngân sách $\alpha_p = \alpha / 7$.
   - **Báo động ngay lập tức** khi $\pi_{\text{fused}, p} \le \alpha_p$ (dừng thu thập, gán `p_decision = p`).
   - Đến $p=8$ không vi phạm $\implies$ Kết luận Benign.

---

## 10. Kết quả Thực nghiệm của P1 (Early-Exit)

*Đánh giá trên quần thể cố định T_fixed (30.907 luồng, trung bình 3 seed, calibration 40% = 800 flow):*

| $\alpha$ mục tiêu | Phương pháp | TPR thực đo | FPR thực đo | APD Tấn công | APD Bình thường | Tỉ lệ dừng sớm |
|---|---|---:|---:|---:|---:|---:|
| **0,01** | Fisher | 39,65% | 11,55% | 6,43 pkts | 7,44 pkts | 39,44% |
| **0,05** | Fisher | **47,58%** | **18,07%** | **5,90 pkts** | 7,14 pkts | **47,39%** |
| **0,10** | Fisher | 51,32% | 22,91% | 5,72 pkts | 6,93 pkts | 51,08% |
| **0,01** | Bonferroni | 0,00% | 0,00% | 8,00 pkts | 8,00 pkts | 0,00% |
| **0,05** | Bonferroni | **16,49%** | **3,67%** | 7,57 pkts | 7,89 pkts | 15,23% |
| **0,10** | Bonferroni | **23,07%** | **6,13%** | 7,34 pkts | 7,79 pkts | 21,75% |

### Điểm nhấn quan trọng:
- **Bonferroni kiểm soát FPR:** $\alpha=0,05$ đạt FPR **3,67%** và TPR **16,49%**; $\alpha=0,10$ đạt FPR **6,13%** và TPR **23,07%**.
- **Fisher không kiểm soát FPR:** TPR 47,6% nhưng FPR **18,07%** do 4 detector tương quan; chỉ dùng làm exploratory.
- **TPR@FPR=1%:** Bonferroni 0%, Fisher 5,14%, đều thấp hơn M1 (9,42%) — P1 chưa thắng ở vùng FPR thấp.
- **Early-exit:** Bonferroni $\alpha=0,05$ giảm APD tấn công xuống **7,57 gói**; $\alpha=0,10$ xuống **7,34 gói**.

---

## 11. Bảng Đối chiếu Kết quả Đa Phương diện (p = 8)

| Phương pháp | Loại mô hình | Dữ liệu & Giao thức | TPR | FPR | AUROC |
|---|---|---|---:|---:|---:|
| **Paper Table VI** | GTAE-IDS | Random / Same-day | **99,04%** | **6,56%** | — |
| **Official Repo Code** | Disconnected Linear AE | Friday 70/30 (OR vote) | **98,74%** | **13,12%** | — |
| **B0: Raw Vector** | PyOD Detectors (No Graph) | Temporal T (Sạch) | **0,50%** | **1,22%** | **0,698** |
| **B1: MLP-AE** | Dense AE (No Graph) | Temporal T (Sạch) | **6,29%** | **2,29%** | **0,595** |
| **M1: GTAE-IDS (Ours)** | Graph Transformer AE | Temporal T (Sạch) | **11,5%** | **2,5%** | **0,67** |
| **P1: Bonferroni α=0,05** | GTAE + Conformal Fusion | Temporal T (Sạch) | **16,49%** | **3,67%** | **0,652** |
| **Supervised RF (Upper Bound)** | Random Forest | Cross-day (Tue/Wed $\to$ Thu/Fri) | **18,1%** | **6,7%** | **0,92** |
| **Supervised RF (Same-day)** | Random Forest | Same-session (Cùng ngày) | **99,4%** | **6,1%** | **0,97** |

*B0 ensemble tie rất thấp; B0 + INNE đạt 10,21% @ 2,45% — cần so cùng detector/FPR. P1 Bonferroni α=0,05 có TPR@FPR=1% = 0%, thấp hơn M1 (9,42%).*

---

## 12. Minh họa Chương trình Demo (5 Phút)

- **Script chạy tự động:** `./demo/run_demo.sh`
  - Mô phỏng luồng giao thông mạng streaming thời gian thực.
  - Áp dụng mô hình GTAE-IDS kết hợp cơ chế P1 Early-Exit.

```
Flow ID  | Actual Class | Attack Name            | Decision   | Exit At | P-Value | Alert
---------|--------------|------------------------|------------|---------|---------|------
104821   | ATTACK       | DoS Hulk               | ALERT      | p=4     | 0.0012  | [!]
104822   | BENIGN       | no_attack_window       | NORMAL     | p=8     | 0.4521  | [OK]
104823   | ATTACK       | PortScan               | ALERT      | p=3     | 0.0004  | [!]
104824   | BENIGN       | no_attack_window       | NORMAL     | p=8     | 0.8190  | [OK]
104825   | ATTACK       | FTP-Patator            | ALERT      | p=2     | 0.0001  | [!]
```
- **Kết quả trực quan:** Tấn công PortScan/FTP được chặn ngay tại $p=2, 3$; lưu lượng lành tính chạy hết 8 gói tin mà không kích hoạt báo động giả.

---

## 13. Đóng góp Học thuật & Giá trị Đồ án

1. **Tính trung thực & Phản biện học thuật sâu sắc:**
   - Không dừng lại ở việc báo cáo kết quả tái hiện âm tính, nhóm đã đào sâu và phát hiện **4 sai sót kỹ thuật** trong mã nguồn mở của bài báo IEEE TIFS 2025.
   - Làm sáng tỏ nghịch lý: mô hình One-class Autoencoder học đặc trưng header không thể đạt 99% TPR xuyên ngày nếu không rò rỉ phân phối.
2. **Kỹ thuật phần mềm chuẩn mực:**
   - Xây dựng hoàn chỉnh pipeline từ pcap thô (51 GB) đến phân tích đồ thị; 82 bài unit/integration test; kiểm toán 428 tiêu chí artifact.
3. **Đóng góp giải pháp mới (P1):**
   - Đưa ra khung Conformal Prediction + Sequential Early-Exit; Bonferroni α=0,05 kiểm soát FPR (3,67%), TPR 16,49%, APD 7,57 gói (giảm 5,4%). Fisher giảm APD còn 5,90 gói nhưng FPR 18,07% nên chỉ là exploratory; tại FPR=1%, P1 chưa vượt M1.

---

<!-- _class: lead -->

# CẢM ƠN THẦY CÔ VÀ CÁC BẠN ĐÃ LẮNG NGHE!

### Q & A

**Mã nguồn đồ án:** `github.com/dwuyn/NT204.R11.ANTN_GTAE-IDS_Nhom8`  
**Liên hệ nhóm:** Nhóm B — Lớp An toàn Thông tin Khóa 2021
