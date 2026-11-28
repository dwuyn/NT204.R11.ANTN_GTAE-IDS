# Rà soát tái hiện GTAE-IDS — Paper vs Implementation

**Cập nhật:** 2026-11-29 (§5.7–§5.9 bổ sung sau khi chạy checkpoint công bố và tái tạo artifact hướng gói tin)
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
- **Test:** 132 pytest pass (`pytest -q`).

Các điểm này loại trừ lỗi cài đặt thô ở feature, kiến trúc, detector.

---

## 3. Kết quả tái hiện (protocol T, mean 3 seed)

| p | Ensemble TPR | FPR | AUROC |
|---|---:|---:|---:|
| 2 | 3,30% | 2,89% | 0,505 |
| 4 | 8,56% | 2,94% | 0,578 |
| 6 | 14,93% | 2,29% | 0,835 |
| 8 | 4,18% | 2,79% | 0,594 |

Paper p=8: **TPR 99,04% / FPR 6,56%** (Table VI). Khoảng cách rất lớn.

Các thử nghiệm bổ sung (p=8, seed 0; đo trong lần chạy trước retrain 2026-11-16 — artefact của các biến thể full-graph/R đã bị xoá):

| Thử nghiệm | TPR | FPR | AUROC |
|---|---:|---:|---:|
| Full train1 graph (5.000 cạnh, K=64, 100 epoch) | 16,3% | 3,0% | 0,67 |
| Subgraph 1.000 cạnh, K=64 | 1,2% | 1,0% | 0,63 |
| MLP-AE z=16 / 64 / 256 | 1,3–7,3% | 1–3% | 0,63–0,64 |
| Bỏ LapPE | 6,36% | 1,23% | 0,682 |
| Protocol R p=8 | ~6% | 2% | 0,71 |

---

## 4. Chẩn đoán nguyên nhân

| Thí nghiệm | Kết quả | Diễn giải |
|---|---|---|
| RandomForest trên **raw edge features**, cùng ngày/phiên | TPR 99,4% @ FPR 6,1%, AUROC 0,972 | Features tách được **pattern cùng lớp/ngày**; có thể lợi dụng checksum/IP identity |
| RandomForest trên **raw features**, train Tue/Wed → test Thu/Fri | TPR 18,1% @ FPR 6,7%, AUROC 0,924 | Không tách được **lớp tấn công chưa thấy** ở FPR thấp |
| RandomForest trên **GTAE embeddings** | TPR 99,2–99,6% nhưng FPR 64–71%, AUROC 0,91 | Embedding có tín hiệu nhưng biên benign/attack chồng lấn mạnh |
| MLP-AE (không đồ thị), z=16/64/256 | TPR 1,3–7,3%, AUROC 0,63–0,64 | Không phải lỗi riêng của graph transformer |
| Bỏ LapPE (A2) | TPR 6,36% @ FPR 1,23%, AUROC 0,682 | PE không phải nguyên nhân chính |
| Full graph / subgraph 1.000 / K_max=64 | TPR 1–16%, AUROC 0,63–0,67 | Sampler/K_max không phải nguyên nhân chính |
| Protocol R (random split) p=8 | TPR ~6% @ FPR 2%, AUROC 0,71 | Không phải chỉ do temporal split |
| Per-class DDoS / DoS Hulk (p=8) | TPR 0–10% / 0,6–10% | Hai lớp “dễ” cũng không tách được bằng AE |

**Kết luận chẩn đoán:** pipeline cài đúng mô tả paper, nhưng **one-class AE + detector chuẩn không học được biên benign đủ tốt** để đạt TPR thấp-FPR như paper. Features chỉ tách tốt **pattern cùng lớp/ngày** (RF 99%), nhưng không tách **lớp tấn công chưa thấy** ở FPR thấp (RF cross-day 18%). Embedding của AE đạt AUROC ~0,91 nhưng chồng lấn mạnh ở vùng FPR thấp. Các thay đổi sampler/K_max/PE/bottleneck/full-graph không giải quyết.

---


## 5. Đối chiếu bài báo với mã nguồn công khai của tác giả

Nguồn kiểm tra:
- Bài báo: `docs/GTAE-IDS_...Intrusion_Detection.pdf` (Table VI tr. 4035, Table VII tr. 4036, §III-B tr. 4033, §IV-B tr. 4034).
- Repo mô hình: `jalalgh7/graph-representation-learning-for-NIDS` (`training_gtae/GTAE_8pkt.ipynb`, `graph_generation/*.ipynb`, `results/*.csv`).
- Repo trích xuất gói tin: `jalalgh7/robust-and-real-time-NIDS` (`data_extraction/*_Packet_Level_Data.ipynb`). Repo này thuộc một bài CNN khác của cùng tác giả, nhưng `graph_generation/Tuesday_data_preparation_gnn_all_ftp_patator.ipynb` (cell 4) đọc trực tiếp `Tuesday_Packet_Level_Data.pkl` do nó sinh ra, nên lỗi ở đây ảnh hưởng tới dữ liệu của GTAE.

**Nguyên tắc trình bày:** mỗi phát hiện ghi rõ *đã kiểm chứng tới đâu*. Chúng tôi tách bạch (a) điều bài báo viết, (b) điều code làm, (c) điều chưa chứng minh được.

### 5.0 Tóm tắt mức độ kiểm chứng

| # | Phát hiện | Mức độ | Ảnh hưởng tới con số 99% |
|---|---|---|---|
| F1 | Table VII khớp **từng số** với luật OR (`votes >= 1`), trong khi bài báo mô tả *majority voting* | **Đã kiểm chứng** | Trực tiếp: OR luôn cho TPR ≥ mọi detector đơn |
| F2 | FPR Ensemble trong bài báo (6,56%) ≠ FPR Ensemble trong CSV công khai (13,12%) | **Đã kiểm chứng** | Trực tiếp: điểm vận hành công bố không khớp artefact |
| F3 | Mỗi lớp tấn công được dựng thành **một đồ thị riêng**, không trộn với benign (dùng cho **Table VII**) | **Đã kiểm chứng và đã định lượng** | Table VII: đồ thị chỉ-attack khác hẳn benign, nhưng trên dữ liệu nhóm nó **không** dễ hơn đồ thị trộn (PortScan 0,00% vs 6,32% TPR); Table VI: không áp dụng (PDF §V-A) |
| F4 | Benign train và benign test cùng lấy từ **Friday** (70/30) | **Đã kiểm chứng** | Trung bình: không có dịch chuyển phân phối giữa train và benign test |
| F5 | Detector chạy trên **output của decoder** (bản tái tạo 400 chiều), không phải bottleneck | **Đã kiểm chứng** | Trung bình: detector thực chất chạy trên gần như feature thô |
| F6 | Lớp `GraphAutoencoder` công khai không nối encoder vào decoder và **không chạy được** | **Đã kiểm chứng phần code; chưa chứng minh được mô hình đã chạy** | Không xác định: notebook không phản ánh code đã sinh kết quả |
| F7 | Nhãn gói tin bị trượt hàng (row-shift) trong repo trích xuất | **Đã kiểm chứng và đã định lượng** | Thứ Ba: 13,9% gói sai nhãn, precision nhãn tấn công 11,8%, recall 14,8%, 14,4% flow bị ảnh hưởng (`results/label_shift_f7.csv`) |
| F8 | Detector trong code dùng contamination **0,06/0,09**, không phải 0,01 như Table V | **Đã kiểm chứng** | Trực tiếp: giải thích FPR 9-13% của CSV; không tạo TPR 99% |
| F9 | Hướng gói tin mã hoá nhãn: benign `unknown` -> nửa sau, attack fwd/bwd | **Đã kiểm chứng ở code + tái tạo số** | **Trực tiếp: luật 1 bit TPR 100%/FPR 0%; detector của tác giả 100% TPR @ 17,7% FPR, khớp CSV 13,12%** |
| F10 | Checkpoint công bố không khớp Table III và không tái tạo CSV trên dữ liệu nhóm | **Đã kiểm chứng** | 8 lớp/d_model 400/decoder 400x400 (Table III: 6 lớp, d=64); FPR 19,5%, TPR 2,9-81,8% |

### 5.1 (F1, F2) Luật ensemble và điểm vận hành công bố

**Bài báo viết** (§III-B, tr. 4033): *"we introduce a majority voting ensemble classifier ... The final prediction is determined by selecting the class label that receives the most votes."*

**Code làm** (`GTAE_8pkt.ipynb`, cell 60 và 65):
```python
votes = np.sum([prediction == 1 for prediction in combined_predictions], axis=0)
anomalies_ensemble = (votes >= 1).astype(int)   # OR: chỉ cần 1/4 detector
```

**Bằng chứng F1:** cột *Ensemble* ở Table VII của bài báo trùng khớp từng chữ số với cột `Anomaly Detection Rate (Ensemble)` trong `results/Final_Results_8pkt_Anomaly_Detection_2017.csv` của tác giả. Đối chiếu F9 cho thấy Table VI (99,04/6,56) lại khớp luật **majority** (>=3/4) trên cùng artifact - tức hai bảng dùng hai luật khác nhau, đúng như mâu thuẫn giữa văn bản và code. Ví dụ GoldenEye 99,08; Heartbleed 99,52; Hulk 98,74; PortScan 98,50; DDoS 99,34; FTP 98,85. Tức là Table VII được sinh bởi luật OR, không phải luật đa số như mô tả.

**Bằng chứng F2:** Table VI (tr. 4035), dòng *8 Packets*:

| | OCSVM | IF | HBOS | INNE | Ensemble |
|---|---:|---:|---:|---:|---:|
| TPR | 98,46 | 96,66 | 97,73 | 96,47 | **99,04** |
| FPR | 4,03 | 4,93 | 4,96 | 4,99 | **6,56** |

CSV công khai của tác giả cho dòng Benign: OCSVM 8,06; IF 9,86; HBOS 9,92; INNE 9,98; **Ensemble 13,12**. Cả năm FPR trong bài báo đều thấp hơn số trong CSV, và FPR Ensemble lệch gấp đôi (6,56 so với 13,12). Artefact công khai không cho phép tái tạo điểm vận hành 99,04% / 6,56%.

> **Đính chính so với phiên bản trước** của tài liệu này: trước đây chúng tôi viết rằng bài báo "ghép TPR của Ensemble với FPR của riêng OCSVM (6,56%)". Điều đó **sai**: Table VI ghi rõ OCSVM FPR = 4,03% và 6,56% là FPR của Ensemble. Phát hiện đúng là F1 + F2 ở trên.

### 5.2 (F3) Mỗi lớp tấn công là một đồ thị riêng

Cell 60 lặp qua `df_test_lst = [('Benign', df_test_benign), ('DoS GoldenEye', df_goldeneye), ...]` và gọi `create_graph_from_df(test_df)` **cho từng lớp riêng**. Đồ thị của một lớp DoS gồm hàng nghìn cạnh cùng đổ về một nạn nhân (hub cực lớn). Trong khi đó đồ thị benign có cấu trúc thưa và đa dạng. Với một encoder có attention trên các cạnh kề nhau, **chính topo đồ thị** đã khác biệt, nên mô hình có thể "phát hiện" lớp tấn công mà không cần đặc trưng gói tin. Bài báo (§V-A, tr. 4035) có nói per-class test graph *"containing edges only belonging to a specific attack type"*, nhưng không bàn về hệ quả này.

Protocol `T` và `P_paper` của nhóm trộn benign với attack trong cùng một đồ thị test, đúng như tình huống triển khai. Đây là khác biệt thiết lập của **Table VII** (và của test 2018/ACI vốn chỉ có tấn công). Với Table VI, bài báo ghi rõ test graph gồm benign + mọi lớp, nên F3 **không** giải thích khoảng cách 99,04% — phần đó do F1/F2/F4/F5.

**Đã định lượng** (`scripts/eval_per_class_graphs.py`, `results/per_class_graphs.csv`): dựng lại đúng kiểu paper trên `P_paper` p8 — mỗi lớp một đồ thị chỉ-tấn-công, embed bằng chính encoder đã train, ngưỡng lấy từ calibration benign. TPR trên đồ thị riêng **thấp hơn hoặc bằng** đồ thị trộn ở mọi lớp: PortScan 0,00% vs 6,32%; DoS Hulk 0,07% vs 0,15%; DoS slowloris 0,10% vs 0,67%; Infiltration 0,98% vs 0,00% (trung bình 3 seed). Tức topo chỉ-attack **không** phải lối tắt mà mô hình của nhóm khai thác được, và cũng **không** đưa TPR tới 98–99% của Table VII. Lưu ý: encoder chưa từng thấy đồ thị chỉ-attack khi train (benign-only), nên đây là phép đo "nếu dùng đúng đồ thị của paper thì mô hình hiện tại làm được gì", không phải phép thử công bằng tuyệt đối cho kiến trúc.

### 5.3 (F4) Benign train/test cùng một ngày

**Bài báo viết** (§IV-B, tr. 4034): dữ liệu được coi là *"a snapshot of network traffic at an arbitrary timestamp t"*, và *"we exclusively utilize benign samples from the CIC-IDS2017 data set for training"*. Bài báo **không** nêu ngày nào được dùng để train và không cam kết chia theo thời gian.

**Code làm:** train trên `Friday_benign_train_70%_all_data/friday_benign_8pkt.csv` (cell 9), benign test trên `Friday_benign_test_30%_all_data` (cell 43, 5.000 flow).

**Đánh giá:** đây **không phải mâu thuẫn** giữa bài báo và code. Đây là **điểm yếu phương pháp**: benign test cùng phiên với benign train nên FPR thấp hơn thực tế triển khai. Protocol `T` (train Monday, test Tue–Fri) là **lựa chọn thiết kế của nhóm** để đo trong điều kiện có dịch chuyển phân phối theo thời gian, không phải thiết lập "paper công bố".

> **Đính chính:** phiên bản trước viết "Paper khẳng định dùng phân chia thời gian (train trên Monday benign...)". Điều đó **sai**, bài báo không nhắc tới Monday. Bảng §1 dòng *Graph* (`nhiều ngày coi như một snapshot`) mới là mô tả đúng.

### 5.4 (F5) Detector chạy trên output của decoder

Cell 60: `test_encoded = autoencoder(test_graph, test_graph.edata['features'])`, sau đó `scaler.transform(test_encoded)` rồi đưa vào 4 detector. `autoencoder(...)` trả về `decoded_features` (bản tái tạo cùng chiều với input), **không** phải embedding ở bottleneck như bài báo mô tả (§IV-C: *"the optimized encoder-only models were employed to generate edge embeddings (i.e., bottleneck features)"*). Kết hợp với F6, detector thực chất chạy trên một ánh xạ (gần) tuyến tính của feature thô.

### 5.5 (F6) Lớp `GraphAutoencoder` công khai

`GTAE_8pkt.ipynb`, cell 24:
```python
class GraphAutoencoder(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_layers):
        super().__init__()
        self.transformer_encoder = nn.TransformerEncoder(
            nn.GraphTransformerLayer(d_model=input_dim, nhead=num_heads, ...),
            num_layers=num_layers)
        self.decoder = nn.Linear(input_dim, input_dim)

    def forward(self, g, features):
        edge_features = self.transformer_encoder(features)
        decoded_features = self.decoder(features)   # edge_features không được dùng
        return decoded_features
```
Đã kiểm chứng ba điểm:
1. `edge_features` không được truyền vào decoder; output chỉ phụ thuộc `self.decoder(features)` = `Linear(400, 400)`.
2. `torch.nn` **không có** lớp `GraphTransformerLayer` (lớp cùng tên được định nghĩa ở cell 23 là lớp DGL của người dùng, không thuộc `nn`). Vì vậy cell 24 như đang công bố sẽ báo `AttributeError` khi khởi tạo.
3. `execution_count` không theo thứ tự (cell 24 = 42, cell 35 = 52, cell 41 = 40, cell 60 = 136). Trạng thái kernel lúc sinh kết quả không tương ứng với thứ tự cell.

**Kết luận được phép rút ra:** notebook công khai **không phản ánh được đoạn code thực sự đã sinh ra kết quả**. Chúng tôi **không** khẳng định mô hình đã dùng để sinh Table VI/VII là `Linear(400, 400)`, vì với code công bố, mô hình đó không khởi tạo được.

### 5.6 (F7) Trượt hàng nhãn trong repo trích xuất gói tin

`robust-and-real-time-NIDS/data_extraction/Tuesday_Packet_Level_Data.ipynb`, cell 5: trong cửa sổ thời gian tấn công, chỉ các gói giữa đúng cặp IP attacker/victim được gán vào `dict_d_labels`; gói nền trong cùng cửa sổ **không có nhánh `else`** nên không được gán. Sau đó (cell 22, 37, 39):
```python
d_labels_ = pd.DataFrame(dict_d_labels.values())      # M phần tử, M < N
payload_byte_data['Class Label'] = d_labels_           # căn theo chỉ số 0..M-1
payload_byte_data = payload_byte_data.dropna()          # bỏ N-M hàng cuối
```
Gán theo chỉ số vị trí nên từ gói nền đầu tiên bị bỏ sót trong cửa sổ tấn công trở đi, mọi nhãn bị **dịch lên** một số vị trí bằng số gói đã bỏ sót. Nhãn tấn công vì thế rơi vào các gói đứng trước nó, có thể là lưu lượng nền.

**Đã định lượng** (`scripts/eval_label_shift.py`, `results/label_shift_f7.csv`, Thứ Ba 2017): 851.306 gói, **269.201 gói nền trong cửa sổ bị bỏ qua** (31,6% số gói) ⇒ đúng 269.201 gói cuối bị `dropna()` xoá; sau khi dịch hàng, **80.848 gói (13,9%** số gói còn lại) mang nhãn sai. Precision của nhãn tấn công còn **11,8%**, recall **14,8%** (45.760 nhãn tấn công rơi vào gói benign; 35.088 gói tấn công mất nhãn); **15.893 flow (14,4%)** có ít nhất một gói sai nhãn. Giả định bảo thủ: gói ngoài cửa sổ được gán benign đúng — nếu notebook chỉ đưa gói tấn công vào `dict_d_labels` thì độ lệch còn lớn hơn.

(b) nhãn tấn công rơi vào lưu lượng nền Thứ Ba chỉ làm "tập tấn công" chứa lưu lượng *khác ngày* với benign train Friday, nên không tự giải thích được TPR 99%. F7 vì vậy được xếp là **lỗi phụ về nhãn**, nhưng nay đã có số: nó đủ lớn để làm hỏng bất kỳ so sánh per-class nào dựa trên `.pkl` của tác giả.

---

### 5.7 (F8) Contamination trong code không phải 0,01

Table V của paper ghi contamination = 0,01 cho cả bốn detector. `GTAE_8pkt.ipynb`, cell 55-59:

```python
model_ocsvm  = OCSVM(nu=0.05, contamination=0.06)
model_iforest = IForest(contamination=0.09)
model_inne   = INNE(contamination=0.09)
model_hbos   = HBOS(contamination=0.09)
```

Với contamination 0,09, mỗi detector tự gán ~9-10% benign train là outlier, nên FPR trên
benign test cùng phân phối cũng ~9-10% — đúng cột Benign của CSV (9,86/9,92/9,98; OCSVM
8,06 vì `nu=0,05`). Đây là lời giải thích đầy đủ cho F2 (paper 6,56% so với CSV 13,12%):
con số 6,56% không phải là output của cấu hình trong code.

### 5.8 (F9) Hướng gói tin mã hoá nhãn - nguyên nhân chính của TPR 99%

**Code.** `robust-and-real-time-NIDS/data_extraction/*_Packet_Level_Data.ipynb`, cell 1: chỉ
gói thuộc đúng cặp IP attacker/victim và đúng cửa sổ mới được gán `'fwd'`/`'bwd'`; nhánh cuối
gán `dict_direction[packets] = 'unknown'` cho mọi gói còn lại, tức toàn bộ benign.
`graph-representation-learning-for-NIDS/graph_generation/*_data_preparation_gnn*.ipynb` dựng
`pkt_vals` bằng `if Direction == 'fwd': [header, 25 zeros] else: [25 zeros, header]`. Vì
`'unknown'` rơi vào `else`, mọi gói benign nằm ở **nửa sau** của block 50 chiều, còn gói
attack có thể nằm nửa trước.

**Hệ quả.** 25 chiều đầu của mọi block benign bằng 0. Luật một bit "có byte khác 0 ở nửa
trước" tách benign/attack gần như hoàn hảo; không cần graph, transformer hay học.

**Tái tạo số** (`scripts/eval_direction_leak.py`, `results/direction_leak.csv`): áp đúng cách
mã hoá benign lên graph của nhóm, chạy đúng bốn detector + contamination của code tác giả
(StandardScaler trên benign train). Trên `P_paper`, ngưỡng >=3/4 cho **99,04% @ 5,50% FPR**
(seed 0); trên `T` cho **99,22% @ 6,66% FPR** (seed 0), tái lập Table VI (99,04% @ 6,56%)
trong 0,2/0,1 pp (`results/direction_leak_votes.csv`):

| | Benign (FPR) | DDoS | Hulk | PortScan | Ensemble attack |
|---|---:|---:|---:|---:|---:|
| Nhóm tái tạo (P_paper) | 17,7% (per-detector 6,0-9,8%) | 100% | 100% | 100% | 100% (OCSVM/INNE 100%, IF 96,2-100%) |
| CSV tác giả | 13,12% (8,06-9,98%) | 99,34% | 98,74% | 98,50% | 98,50-99,83% |

Luật 1 bit đạt TPR 100% / FPR 0%. Với cách mã hoá nhất quán của nhóm (hướng = sender gói
đầu, áp cho cả hai lớp), benign cũng có fwd (99,98%) nên luật này vô dụng - và đó là lý do
pipeline sạch không thể đạt 99%.

**Mức kiểm chứng.** Đường code đã kiểm chứng; file `.pkl` gốc không công khai nên không mở
trực tiếp được. Khớp số (FPR từng detector, TPR từng lớp) là bằng chứng bổ sung.

### 5.9 (F10) Checkpoint công bố không khớp Table III và không tái tạo CSV

`best_GTAE_model_8pkt.pth` (sha256 `fe31a4c8...32f1a7d`) chứa 8 lớp
`nn.TransformerEncoderLayer` với `d_model=400`, `nhead=8`, FFN 64, và `decoder` 400x400.
Table III của paper ghi p=8: 6 lớp, 8 head, d=64. Lớp `GraphAutoencoder` công bố không khởi
tạo được (F6), nên checkpoint là manh mối duy nhất về mô hình thật, và nó không khớp paper.

Chạy checkpoint này trên dữ liệu của nhóm (feature 400-d giống hệt về semantics, scaler fit
trên `train1`, bốn detector ở contamination 0,06/0,09): FPR ensemble **19,5%**, TPR theo lớp
**2,9-81,8%** - không tái tạo được CSV 98,5-99,8%. Tức là ngay cả mô hình công khai + cấu
hình công khai + split same-day cũng không sinh ra con số công bố trên dữ liệu công khai.

## 6. Bảng đối chiếu theo lớp (p = 8)

| Lớp tấn công | Paper Table VII | CSV của tác giả | Nhóm, protocol `T` (mean ± std 3 seed, tie) | n (T) | Nhóm, `P_paper` (luật OR) |
|---|---:|---:|---:|---:|---:|
| **Benign (FPR)** | **6,56%** (Table VI) | **13,12%** | **2,79 ± 1,40%** | 5.000 | 6,56% (matched) |
| DoS Hulk | 98,74% | 98,74% | 3,23 ± 4,08% | 5.000 | 0,58% |
| DoS GoldenEye | 99,08% | 99,08% | 3,32 ± 2,86% | 5.000 | 0,75% |
| Heartbleed | 99,52% | 99,52% | 0,00% | 1 | 0,00% (n=11) |
| DoS Slowhttptest | 99,79% | 99,79% | 5,18 ± 4,10% | 1.132 | 0,76% |
| DoS Slowloris | 99,60% | 99,60% | 12,66 ± 12,87% | 2.164 | 2,00% |
| PortScan | 98,50% | 98,50% | 4,74 ± 4,17% | 204 | 25,31% |
| DDoS | 99,34% | 99,34% | 1,07 ± 1,83% | 5.000 | 0,61% |
| Infiltration | 99,83% | 99,83% | 33,33 ± 57,74% | 4 | 0,98% (n=34) |
| FTP-Patator | 98,85% | 98,85% | 8,64 ± 9,34% | 3.972 | 1,72% |
| SSH-Patator | 98,86% | 98,86% | 0,40 ± 0,38% | 2.511 | 0,19% |
| Web Attack – Brute Force | 99,29% | 99,29% | 1,62 ± 1,75% | 144 | 0,48% |

Nguồn: cột 4 tính từ `results/M1_p8_seed{0,1,2}.json` (`ensembles.tie.per_class_tpr`); cột 6 từ `reports/related_work.md` §2.1 / `results/paper_parity/`. Cột "tái hiện theo luật code của tác giả" ở phiên bản trước **đã bị bỏ** vì số đo từ trước lần retrain 2026-11-16 và không có artefact đi kèm. `P_paper` ở cột 6 thay thế nó, và có artefact.

---

## 7. Kết luận của đợt rà soát

1. **Về tính tái lập:** con số 99,04% TPR @ 6,56% FPR **không tái lập được** từ artefact công khai, kể cả khi dựng lại đúng thành phần test (Table II/VII) và đúng luật OR của code (`P_paper`: 3,25% @ 6,56%).
2. **Những gì đã kiểm chứng được về nguồn gốc khoảng cách:**
   - Table VII được sinh bởi luật OR, trái với mô tả *majority voting* (F1).
   - FPR công bố không khớp CSV công khai của chính tác giả (F2).
   - Thiết lập test per-class (F3) và benign cùng ngày (F4) dễ hơn nhiều so với triển khai thực tế.
   - Notebook công khai không phản ánh code đã chạy (F5, F6); contamination thực là 0,06/0,09 (F8);
   - **Hướng gói tin benign bị gán `unknown` và dồn vào nửa sau, trong khi attack giữ fwd/bwd,
     tạo ra một luật 1 bit đạt TPR 100% / FPR 0% (F9)** - đây là nguồn chính của TPR ~99%;
   - checkpoint công bố không khớp Table III và không tái tạo CSV trên dữ liệu nhóm (F10).
3. **Những gì chưa chứng minh được** (không nên trình bày như kết luận):
   - mô hình của tác giả thực chất là `Linear(400, 400)`;
   - lỗi trượt nhãn (F7) gây ra TPR cao;
   - tác giả cố ý chọn số liệu.
   Nhóm chỉ khẳng định các mâu thuẫn **có thể kiểm tra** giữa bài báo, code và CSV.
4. **Đóng góp của đợt rà soát:** cung cấp một danh sách mâu thuẫn có trích dẫn (cell, file, trang) để người đọc tự kiểm tra, kèm protocol `P_paper` cho thấy khoảng cách không đến từ cách dựng tập test của nhóm.
