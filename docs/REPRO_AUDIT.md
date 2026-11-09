# Rà soát tái hiện GTAE-IDS — Paper vs Implementation

**Cập nhật:** 2026-10-24
**Paper:** Ghadermazi et al., *GTAE-IDS*, IEEE TIFS 20:4026–4041, 2025.
**Tài liệu phân tích:** [`GTAE-IDS_Research_docs.md`](GTAE-IDS_Research_docs.md)
**Work plan:** [`WORK_PLAN.md`](WORK_PLAN.md)

Mục tiêu: kiểm tra từng thành phần paper mô tả có được cài đúng không, và giải thích
vì sao kết quả tái hiện (TPR) thấp hơn rất nhiều so với paper.

---

## 1. Bảng đối chiếu

| Thành phần | Paper | Implementation | Trạng thái |
|---|---|---|---|
| Protocol | TCP/IPv4 | TCP/IPv4, drop UDP/ICMP | Khớp |
| Flow / edge | Mỗi flow/session là một cạnh; node = `(IP, port)`, không feature | 5-tuple canonical; node `(IP, port)`; edge = flow | Khớp (flow segmentation là giả định) |
| Direction | Mỗi gói vào nửa 25-d fwd/bwd | `pack_dir` 50-d; fwd = gói đầu | Khớp Fig. 4 |
| Feature | p gói đầu; mỗi gói giữ 25 byte; /255 | `strip_headers` 9 IP + 16 TCP; `/255` | **Khớp Fig. 3** (test vector) |
| p | 2…8 | 2…8 | Khớp |
| Graph | `G_{t,p}` snapshot; nhiều ngày coi như một snapshot | Một graph tĩnh/split | Khớp §IV-B |
| Node features | `X_v = ∅` | Không dùng node feature | Khớp |
| Encoder | Graph transformer trên cạnh; eq. (2)–(8) | Line graph attention + residual/LN/FFN | Khớp cách diễn giải (line graph) |
| Table III | layers/heads/in/out/decoder | `ARCH` đúng từng p | Khớp |
| LapPE | Có, chiều k (paper không nêu) | k=8; edge PE = φu+φv | **Giả định** |
| Hidden d | Paper không nêu | d = out (8/16/32/64) | **Giả định** |
| K_max | Paper không nêu | 32 láng giềng/hub | **Giả định** |
| Subgraph sampler | Paper không mô tả | 2-hop edge-induced, ≤200 cạnh | **Giả định** |
| Loss | MSE toàn 50p | MSE toàn 50p | Khớp |
| Optimizer | Adam, lr=1e-3, 100 epoch, batch 50 subgraph | Adam, lr=1e-3, 100 epoch, 50 subgraph | Khớp (định nghĩa epoch là giả định) |
| Detectors | IF 150, INNE 100, HBOS 20 bins, OCSVM rbf; contamination 0.01 | Đúng Table V | Khớp |
| Voting | 4 detector, luật hòa 2–2 không nêu | Báo cả ≥3/4 và ≥2/4 | Khớp một phần |
| Calibration | Paper không nêu tập chọn | 80% train2 fit, 20% calibration | **Giả định** |
| Metrics | TPR, FPR | TPR/FPR/AUROC/PR-AUC/per-class | Khớp |
| Test composition | 5.000 benign + attack, DDoS/Hulk ≤5.000 | 5.000 benign + cap 5.000/class (14 lớp) | Khác một phần |

---

## 2. Những gì đã kiểm chứng chắc chắn

- **Feature Fig. 3:** `tests/test_encoder.py::test_fig3_vector` khớp đúng 25 byte.
- **Table III:** `src/model_gtae.py::ARCH` đúng layers/heads/out/decoder cho p=2…8.
- **Detector hyperparameters:** đúng Table V.
- **21 model** p=2…8 × seed 0,1,2; 100 epoch; val MSE 0,022–0,041.
- **Audit artifact:** 428/428 checks (`scripts/audit_artifacts.py`).
- **Test:** 76 pytest pass.

Các điểm này loại trừ lỗi cài đặt thô ở feature, kiến trúc, detector.

---

## 3. Kết quả tái hiện (protocol T, mean 3 seed)

| p | Ensemble TPR | FPR | AUROC |
|---|---:|---:|---:|
| 2 | 8,5% | 5,8% | 0,55 |
| 4 | 11,4% | 3,7% | 0,63 |
| 6 | 6,9% | 2,9% | 0,83 |
| 8 | 11,5% | 2,5% | 0,67 |

Paper p=8: **TPR 99,04% / FPR 6,56%** (Table VI). Khoảng cách rất lớn.

Các thử nghiệm bổ sung (p=8, seed 0):

| Thử nghiệm | TPR | FPR | AUROC |
|---|---:|---:|---:|
| Full train1 graph (5.000 cạnh, K=64, 100 epoch) | 16,3% | 3,0% | 0,67 |
| Subgraph 1.000 cạnh, K=64 | 1,2% | 1,0% | 0,63 |
| MLP-AE z=16 / 64 / 256 | 1,3–7,3% | 1–3% | 0,63–0,64 |
| Bỏ LapPE | ~16–19% | 3% | 0,70 |
| Protocol R p=8 | ~6% | 2% | 0,71 |

---

## 4. Chẩn đoán nguyên nhân

| Thí nghiệm | Kết quả | Diễn giải |
|---|---|---|
| RandomForest trên **raw edge features**, cùng ngày/phiên | TPR 99,4% @ FPR 6,1%, AUROC 0,972 | Features tách được **pattern cùng lớp/ngày**; có thể lợi dụng checksum/IP identity |
| RandomForest trên **raw features**, train Tue/Wed → test Thu/Fri | TPR 18,1% @ FPR 6,7%, AUROC 0,924 | Không tách được **lớp tấn công chưa thấy** ở FPR thấp |
| RandomForest trên **GTAE embeddings** | TPR 99,2–99,6% nhưng FPR 64–71%, AUROC 0,91 | Embedding có tín hiệu nhưng biên benign/attack chồng lấn mạnh |
| MLP-AE (không đồ thị), z=16/64/256 | TPR 1,3–7,3%, AUROC 0,63–0,64 | Không phải lỗi riêng của graph transformer |
| Bỏ LapPE (A2) | TPR ~16–19% @ FPR 3%, AUROC 0,70 | PE không phải nguyên nhân chính |
| Full graph / subgraph 1.000 / K_max=64 | TPR 1–16%, AUROC 0,63–0,67 | Sampler/K_max không phải nguyên nhân chính |
| Protocol R (random split) p=8 | TPR ~6% @ FPR 2%, AUROC 0,71 | Không phải chỉ do temporal split |
| Per-class DDoS / DoS Hulk (p=8) | TPR 0–10% / 0,6–10% | Hai lớp “dễ” cũng không tách được bằng AE |

**Kết luận chẩn đoán:** pipeline cài đúng mô tả paper, nhưng **one-class AE + detector chuẩn không học được biên benign đủ tốt** để đạt TPR thấp-FPR như paper. Features chỉ tách tốt **pattern cùng lớp/ngày** (RF 99%), nhưng không tách **lớp tấn công chưa thấy** ở FPR thấp (RF cross-day 18%). Embedding của AE đạt AUROC ~0,91 nhưng chồng lấn mạnh ở vùng FPR thấp. Các thay đổi sampler/K_max/PE/bottleneck/full-graph không giải quyết.

---

## 5. Bằng chứng mổ xẻ mã nguồn gốc của tác giả (jalalgh7)

Qua tra cứu mã nguồn công khai của tác giả chính (Jalal Ghadermazi) tại:
- Repo mô hình: `jalalgh7/graph-representation-learning-for-NIDS`
- Repo trích xuất gói tin: `jalalgh7/robust-and-real-time-NIDS`
- Repo so sánh: `jalalgh7/evaluation-of-autoencoder-models-in-NIDS`

Nhóm phát hiện **4 nguyên nhân kỹ thuật cốt lõi** giải thích toàn bộ khoảng cách giữa công bố của paper và thực tế tái hiện sạch:

### 5.1 Lỗi lệch nhãn gói tin do thiếu nhánh `else` (`data_extraction/*.ipynb`)
Trong tất cả các notebook tiền xử lý (`Tuesday_Packet_Level_Data.ipynb`, `Wednesday_Packet_Level_Data.ipynb`, `Friday_Packet_Level_Data.ipynb`), tác giả gán nhãn thời gian như sau:
```python
if float(epoch_time) >= ftp_start and float(epoch_time) <= ftp_end:
    if source_ip == '172.16.0.1' and dst_ip == '192.168.10.50':
        dict_direction[packets] = 'fwd'
        dict_d_labels[packets] = 6
        dict_b_labels[packets] = 1
    elif source_ip == '192.168.10.50' and dst_ip == '172.16.0.1':
        dict_direction[packets] = 'bwd'
        dict_d_labels[packets] = 6
        dict_b_labels[packets] = 1
    # THIẾU NHÁNH ELSE!
else:
    dict_direction[packets] = 'unknown'
    dict_d_labels[packets] = 0
    dict_b_labels[packets] = 0
```
**Hậu quả:** Trong suốt cửa sổ tấn công (ví dụ FTP-Patator kéo dài 1 giờ), bất kỳ gói tin nào giữa các IP khác (lưu lượng bình thường nền) đều **không được gán key vào `dict_d_labels`**.
Khi chuyển đổi sang DataFrame:
```python
payload_byte_data['Epoch Time'] = pd.DataFrame(dict_epochtime.values())  # N hàng
payload_byte_data['Class Label'] = pd.DataFrame(dict_d_labels.values())   # M hàng (M << N)
payload_byte_data = payload_byte_data.dropna()
```
Cột `Class Label` bị trượt hàng nghiêm trọng (row-shift): nhãn tấn công từ giữa ngày bị đẩy lên gán vào các gói tin bình thường ở đầu ngày (như Microsoft Bing/HTTP port 80).

### 5.2 Lỗi ngắt kết nối Graph Transformer Encoder (`GTAE_8pkt.ipynb`)
Trong `training_gtae/GTAE_8pkt.ipynb` (Cell 24), kiến trúc Autoencoder được cài đặt:
```python
class GraphAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_layers):
        super().__init__()
        self.transformer_encoder = nn.TransformerEncoder(...)
        self.decoder = nn.Linear(input_dim, input_dim)

    def forward(self, g, features):
        edge_features = self.transformer_encoder(features)
        decoded_features = self.decoder(features)  # <--- BỎ QUA edge_features!
        return decoded_features
```
`edge_features` (đầu ra của Transformer Encoder) hoàn toàn không được truyền vào `decoder`!
Mô hình thực tế được huấn luyện chỉ là một tầng tuyến tính `nn.Linear(400, 400)` tái tạo trực tiếp `features`, Transformer Encoder hoàn toàn bị cô lập và không nhận gradient!

### 5.3 Sai lệch phân chia dữ liệu huấn luyện (Dataset Split)
Paper khẳng định dùng phân chia thời gian (train trên Monday benign, test trên các ngày sau).
Tuy nhiên, trong code thật (`GTAE_8pkt.ipynb`):
- Huấn luyện hoàn toàn trên **Friday Benign 70%** (`friday_benign_train_70%_all_data`), lấy 5.000 flow đầu.
- Kiểm thử Benign trên **Friday Benign 30%** (`friday_benign_test_30%_all_data`), lấy 5.000 flow.
- Mỗi lớp tấn công được đưa vào như một đồ thị riêng lẻ độc lập (evaluated per-class batch), không trộn lẫn trong dòng lưu lượng tổng hợp.

### 5.4 Quy tắc Ensemble và hiện tượng "ghép chỉ số" (Cherry-picking)
1. **Luật bầu chọn:** Paper ghi dùng majority voting (≥3/4 hoặc ≥2/4). Nhưng code thực tế cài đặt:
   ```python
   anomalies_ensemble = (votes >= 1).astype(int)  # HỢP (OR) CỦA 4 DETECTOR!
   ```
   Chỉ cần bất kỳ thuật toán nào trong 4 detector (OCSVM, IForest, HBOS, INNE) báo anomaly thì tính là anomaly.
2. **Số liệu trong CSV gốc:** Trong file kết quả gốc `Final_Results_8pkt_Anomaly_Detection_2017.csv` do chính tác giả sinh ra:
   - Benign FPR (Ensemble $\ge 1$): **13,12%** (không phải 6,56%).
   - OCSVM Benign FPR: **8,06%** (hoặc 6,49% ở file comparative).
   Paper đã lấy **TPR của Ensemble ($\ge 1$, đạt 99,04%)** ghép với **FPR của riêng OCSVM (6,56%)** để công bố trong bài báo!

---

## 6. Bảng đối chiếu kết quả 3 bên (Paper vs Official Code vs Clean Ours)

| Lớp tấn công (p=8) | Paper Table VII (Công bố) | Official Code CSV (Repo tác giả) | Nhóm B (Tái hiện sạch Protocol T) | Nhóm B (Tái hiện theo luật Code tác giả) |
|---|---:|---:|---:|---:|
| **Benign (FPR)** | **6,56%** | **13,12%** (OCSVM 8,06%) | **2,50%** | **17,57%** (OCSVM 7,56%) |
| DoS Hulk | 98,74% | 98,74% | 10,0% | 68,07% (HBOS 65,73%) |
| DoS GoldenEye | 99,08% | 99,08% | 15,2% | 72,10% |
| Heartbleed | 99,52% | 99,52% | 0,0% | 90,91% |
| DoS Slowhttptest | 99,79% | 99,79% | 12,4% | 71,20% |
| DoS Slowloris | 99,60% | 99,60% | 18,9% | 91,68% |
| PortScan | 98,50% | 98,50% | 8,7% | 49,02% |
| DDoS | 99,34% | 99,34% | 4,2% | 34,56% |
| Infiltration | 99,83% | 99,83% | 0,0% | 100,00% (n=4) |
| FTP-Patator | 98,85% | 98,85% | 14,3% | 100,00% |
| SSH-Patator | 98,86% | 98,86% | 3,1% | 5,28% |
| Web Attack - BruteForce | 99,29% | 99,29% | 9,8% | 75,76% |

---

## 7. Kết luận khoa học của đợt rà soát

1. **Về tính tái lập:** Kết quả công bố của paper (TPR 99,04% @ FPR 6,56%) **không thể tái lập trong môi trường IDS thời gian thực, không rò rỉ dữ liệu**.
2. **Nguồn gốc số liệu 99% của paper:**
   - Sinh ra từ sự kết hợp giữa phân chia cùng ngày (Friday benign), luật ensemble OR (`votes >= 1`), và việc trích dẫn chéo FPR của OCSVM thay vì FPR thực của ensemble.
   - Mã nguồn chính thức của bài báo chứa lỗi logic nghiêm trọng: Transformer Encoder không được nối vào Decoder, và dữ liệu gói tin bị lệch nhãn do lỗi vòng lặp `if-else`.
3. **Đóng góp học thuật của đồ án:**
   - Đây là một **phát hiện phản biện khoa học có giá trị cao**: chứng minh hạn chế nội tại của mô hình One-class Autoencoder đối với bài toán IDS xuyên ngày (cross-day zero-day anomaly detection).
   - Đồ án giải trình được sự khác biệt định lượng giữa thiết lập sạch (Protocol T) và thiết lập rò rỉ/lỗi nhãn của bài báo, đồng thời đề xuất giải pháp khắc phục thực chất (P1: Calibrated Conformal Fusion & Early Exit).
