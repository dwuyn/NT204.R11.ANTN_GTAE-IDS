# Vì sao kết quả tái lập không thể giống paper

**Cập nhật:** 2026-11-29
**Câu hỏi:** paper báo TPR 99,04% @ FPR 6,56% (Table VI), nhóm tái lập được 4-12% TPR ở cùng
vùng FPR. Khoảng cách này đến từ đâu, và có thể "làm cho giống" không?

**Kết luận ngắn:** không thể bằng một cài đặt đúng: (1) con số mục tiêu không nhất quán với
chính artefact công khai của tác giả, và (2) phần lớn khoảng cách được tạo bởi một **artifact
mã hoá hướng gói tin**
trong pipeline trích xuất của tác giả: mọi gói benign bị gán `Direction = 'unknown'` và được
đẩy vào nửa sau của vector 50 chiều, còn gói attack giữ fwd/bwd. Khi tái tạo đúng cách mã hoá
đó trên dữ liệu của nhóm, bốn detector của tác giả đạt **100% TPR** cho mọi lớp tấn công và
FPR 6,0-10,2% mỗi detector (17,7% ensemble) - khớp với CSV công khai của tác giả
(94-99,7% TPR, FPR 8,06-9,98%, ensemble 13,12%). Với bỏ phiếu >=3/4, artifact cho
**99,22% @ 6,66%** trên `T` (seed 0), tái lập Table VI (99,04% @ 6,56%) trong 0,2/0,1 pp.
Khi mã hoá hướng nhất quán cho cả hai lớp (đúng Fig. 3), cùng bộ detector chỉ còn
**3,2-18,8% TPR @ 6,56% FPR**.

---

## 1. "Giống paper" là giống con số nào?

| Nguồn | TPR | FPR | Ghi chú |
|---|---:|---:|---|
| Paper, Table VI (p=8) | 99,04% | 6,56% | Ensemble; OCSVM 98,46/4,03, IF 96,66/4,93, HBOS 97,73/4,96, INNE 96,47/4,99 |
| CSV công khai của tác giả (`Final_Results_8pkt_Anomaly_Detection_2017.csv`) | 98,50-99,83% theo lớp | **13,12%** | Cùng file sinh ra Table VII (F1) |
| Code công bố (`GTAE_8pkt.ipynb`, cell 55-59) | - | 9,86-9,98% mỗi detector | Contamination **0,09** (OCSVM 0,06), không phải 0,01 như Table V |
| Checkpoint công bố (`best_GTAE_model_8pkt.pth`) | - | - | 8 lớp transformer, `d_model=400`, FFN 64, decoder 400×400 (Table III ghi 6 lớp, d=64) |

Ba điểm không khớp đã đủ để nói "không có mục tiêu xác định": paper báo FPR ensemble 6,56%,
artefact của chính tác giả báo 13,12%; paper báo contamination 0,01, code dùng 0,06/0,09;
kiến trúc trong checkpoint không phải kiến trúc trong Table III. Vì vậy mọi phép so sánh
"đúng/sai" với 99,04% đều phải chọn một trong các phiên bản mâu thuẫn đó.

---

## 2. Cơ chế chính: hướng gói tin mã hoá nhãn

### 2.1 Đường đi trong code công bố

1. `jalalgh7/robust-and-real-time-NIDS`, `data_extraction/Friday_Packet_Level_Data.ipynb`,
   cell 1: chỉ các gói thuộc đúng cặp IP attacker/victim và đúng cửa sổ thời gian mới được gán
   `'fwd'`/`'bwd'`. Nhánh cuối:

   ```python
   else:
       dict_direction[packets] = 'unknown'
       dict_d_labels[packets] = 0
       dict_b_labels[packets] = 0
   ```

   Toàn bộ lưu lượng benign (và cả gói không khớp cặp IP trong cửa sổ tấn công) nhận
   `'unknown'`.

2. `jalalgh7/graph-representation-learning-for-NIDS`, `graph_generation/*_data_preparation_gnn*.ipynb`,
   cell dựng `pkt_vals`:

   ```python
   if df_stream['Direction'][k] == 'fwd':
       pkt_val = [*df_stream['pkt_header_values'][k], *pkt_val_pad]
   else:
       pkt_val = [*pkt_val_pad, *df_stream['pkt_header_values'][k]]
   ```

   `'unknown'` rơi vào nhánh `else`, tức 25 byte của gói benign luôn nằm ở **nửa sau** của
   block 50 chiều. Gói attack có thể nằm nửa trước (fwd) hoặc nửa sau (bwd).

### 2.2 Hệ quả

- Vector benign: 25 chiều đầu của **mọi** block bằng 0; 25 chiều sau chứa header.
- Vector attack: các gói client→server nằm ở nửa trước, nên 25 chiều đầu khác 0.
- Một luật một bit "có byte khác 0 ở nửa trước hay không" tách benign/attack gần như hoàn hảo.
  Không cần graph, không cần transformer, không cần học.

Đây là **rò rỉ nhãn qua vị trí**, không phải phát hiện xâm nhập: nhãn `attack` được mã hoá
trong chính cách sắp xếp byte.

### 2.3 Tái tạo trên dữ liệu của nhóm

`scripts/eval_direction_leak.py` áp đúng cách mã hoá benign của tác giả lên graph `P_paper`
(benign dồn về nửa sau, attack giữ nguyên), rồi chạy đúng bốn detector và contamination của
code tác giả (OCSVM 0,06; IForest/HBOS/INNE 0,09; StandardScaler fit trên benign train).

| Lớp | n | Luật 1 bit (fwd ≠ 0) | OCSVM | IForest | INNE | Ensemble |
|---|---:|---:|---:|---:|---:|---:|
| Benign (FPR) | 5.000 | **0,0%** | 6,0% | 9,4% | 9,1% | **17,7%** |
| DDoS | 5.000 | 100% | 100% | 96,2% | 100% | 100% |
| DoS GoldenEye | 6.090 | 100% | 100% | 99,9% | 100% | 100% |
| DoS Hulk | 5.000 | 100% | 100% | 99,2% | 100% | 100% |
| DoS Slowhttptest | 964 | 100% | 100% | 99,8% | 100% | 100% |
| DoS Slowloris | 1.002 | 100% | 100% | 100% | 100% | 100% |
| PortScan | 6.451 | 100% | 100% | 100% | 100% | 100% |
| FTP/SSH-Patator | 174/175 | 100% | 100% | 100% | 100% | 100% |
| Heartbleed/Infiltration | 11/34 | 100% | 100% | 100% | 100% | 100% |
| Web Attack - Brute Force | 140 | 100% | 100% | 100% | 100% | 100% |

HBOS bị loại khỏi bảng vì trong mô phỏng này 200 chiều bị zero hoá hoàn toàn làm histogram
của pyod 3.6.7 suy biến (TPR 0-2,5%), khác với pyod thời điểm bài báo; ensemble OR không phụ
thuộc HBOS vì chỉ cần một detector báo. Trên CSV của tác giả, HBOS đạt 96-99% - nhiều khả
năng pyod cũ xử lý cột hằng khác, hoặc pkl của họ có một ít gói benign mang nhãn fwd.

So với CSV của tác giả: FPR từng detector 8,06 / 9,86 / 9,92 / 9,98% (ensemble 13,12%);
TPR từng lớp 94,25-99,66% (ensemble 98,50-99,83%). Mô phỏng cho cùng bức tranh: FPR 6,0-9,8% (ensemble 17,7%), TPR 96,2-100% ở OCSVM/IF/INNE/ensemble. Chênh lệch còn lại đến từ cách phân luồng pcap
(flow segmentation) và từ các flow attack mà 8 gói đầu toàn là bwd.

Kết quả đầy đủ: `results/direction_leak.csv` (cả `P_paper` và `T`; trên `T` ensemble
TPR 100% / FPR 20,2%).

### 2.4 Đối chứng: mã hoá nhất quán thì artifact biến mất

Với cách mã hoá của nhóm (hướng = sender của gói đầu tiên, áp dụng như nhau cho benign và
attack, đúng Fig. 3):

| Graph | Benign có fwd ≠ 0 | Attack có fwd ≠ 0 | Hệ quả cho luật 1 bit |
|---|---:|---:|---|
| `P_paper` | 99,98% | 100% | không tách được (FPR ≈ TPR) |
| `T` | 100% | 100% | không tách được |

Đó là lý do pipeline của nhóm không thể - và không nên - đạt 99%: nó không chứa tín hiệu
vị trí mà pipeline gốc tình cờ tạo ra.

---

### 2.5 Tái lập đúng Table VI (99,04% @ 6,56%)

Quét ngưỡng bỏ phiếu trên cùng artifact (`results/direction_leak_votes.csv`):

| Protocol | Ngưỡng | FPR (3 seed) | TPR (3 seed) | Seed 0 |
|---|---|---:|---:|---:|
| `P_paper` | >=2/4 | 8,58-8,92% | 100% | 100% @ 8,58% |
| `P_paper` | >=3/4 | 5,44-5,62% | 95,58-99,04% | 99,04% @ 5,50% |
| `T` | >=3/4 | 6,52-6,66% | 99,22-99,99% | **99,22% @ 6,66%** |
| Paper Table VI | majority | 6,56% | 99,04% | - |

Trên `T`, >=3/4 tái lập Table VI gần như chính xác (lệch 0,2 pp TPR, 0,1 pp FPR). Đổi lại,
nó chỉ đạt được khi tái tạo artifact hướng. Đáng chú ý: Table VI khớp **majority** (>=3/4)
đúng như văn bản, còn Table VII khớp **OR** của code (F1): hai bảng của bài báo dùng hai luật
khác nhau, và CSV công khai (13,12%) là kết quả của OR.

## 3. Các mức đo được khi mã hoá nhất quán

Tất cả ở p = 8, protocol ghi rõ, threshold đặt sao cho **FPR trên benign test = 6,56%**
(trừ dòng ghi chú). Nguồn: `results/paper_parity/`, `results/feature_input/`,
`results/supervised_bound.csv`.

| Cấu hình | Split | Đầu vào detector | TPR @ 6,56% | AUROC |
|---|---|---|---:|---:|
| Paper Table VI | same-day (Friday) | decoder output | 99,04% | - |
| CSV tác giả | same-day (Friday) | decoder output | 98,5-99,8% | - |
| Mô phỏng mã hoá benign của tác giả | same-day | raw + vị trí lệch | **100%** @ 17,7% FPR | - |
| Mô phỏng + bỏ phiếu >=3/4 (`T`) | temporal | raw + vị trí lệch | **99,22% @ 6,66%** | - |
| `P_paper` GTAE của nhóm | same-day (Friday 70/30) | bottleneck `z` | 3,25% | 0,478 |
| `P_paper` raw | same-day | 400 byte thô | 3,25% | 0,402 |
| `P_paper` decoder output | same-day | recon 400-d | 4,93% | 0,452 |
| `T` GTAE của nhóm | temporal (Mon→Tue-Fri) | bottleneck `z` | 11,54% | 0,594 |
| `T` raw | temporal | 400 byte thô | 18,78% | 0,698 |
| Supervised RF, same-day | Friday 70/30 | 400 byte thô | **99,9%** | 0,999 |
| Supervised RF, same-day | Friday 70/30 | `z` | 17,8-80,1% | 0,74-0,96 |
| Supervised RF, cross-day | Tue+Wed → Thu+Fri | 400 byte thô | 3,2-3,8% | 0,54 |
| Supervised RF, cross-day | Tue+Wed → Thu+Fri | `z` | 11,0-23,2% | 0,64-0,75 |


Hai quan sát quyết định:

1. **Cùng một split same-day, chỉ supervised RF trên byte thô đạt 99,9%.** Bản thân split
   không tạo ra 99%: GTAE same-day chỉ đạt 3,25% với `z`, 4,93% với decoder output. Con số
   99% cần thêm tín hiệu mà chỉ byte thô (hoặc vị trí fwd/bwd) mang lại.
2. **Mọi cấu hình cross-day dừng ở <= 23,2% TPR @ 6,56%:** raw OD 18,78%, supervised RF
   trên raw 3,2-3,8%, trên `z` 11,0-23,2%. Không cấu hình nào tiến gần 99%, tức giới hạn đến
   từ dữ liệu/feature chứ không từ optimizer.

---

## 4. Từng nghi phạm và mức đóng góp

| # | Nghi phạm | Đo được | Kết luận |
|---|---|---|---|
| F1 | Ensemble là OR chứ không phải majority | Table VII = CSV `votes >= 1` | Giải thích nhãn "Ensemble" và FPR 13,12%; không tạo TPR 99% (tại cùng FPR, strict/tie/or cho cùng TPR) |
| F2 | Điểm vận hành công bố không khớp artifact | Paper 6,56% vs CSV 13,12% | Mục tiêu không xác định |
| F3 | Mỗi lớp một đồ thị attack-only | TPR trên đồ thị riêng <= đồ thị trộn | Không phải lối tắt nhóm khai thác được |
| F4 | Benign train/test cùng Friday | Same-day GTAE vẫn 3,25% | Cần nhưng chưa đủ |
| F5 | Detector trên decoder output | Recon 0,8% với mã hoá nhất quán | Không phải nguyên nhân khi không có artifact hướng |
| F6 | Code không khởi tạo được | `nn.GraphTransformerLayer` không tồn tại | Không xác định được mô hình đã sinh số |
| F7 | Nhãn gói bị trượt hàng | Precision nhãn attack 11,8% (Thứ Ba) | Làm hỏng so sánh per-class, nhưng Engelen L2/L3 cho thấy nhãn của nhóm khớp 99,5-100% |
| F8 | Contamination trong code | 0,06/0,09, không phải 0,01 | Giải thích FPR 9-13%; không tạo TPR 99% |
| F9 | Hướng benign = `unknown` → nửa sau | Luật 1 bit TPR 100%/FPR 0% | **Nguyên nhân chính của TPR 99%** |
| F10 | Checkpoint khác Table III | 8 lớp/d_model 400/decoder 400×400; chạy trên dữ liệu nhóm không tái tạo CSV | Không có mô hình xác định để tái lập |

---

## 5. "Làm cho giống" sẽ phải làm gì?

Để đạt 99% trên đúng dữ liệu này, pipeline phải đồng thời:

1. gán hướng benign khác hướng attack (artifact F9);
2. chia benign train/test cùng ngày (F4);
3. dùng contamination 0,06/0,09 (F8) để FPR rơi vào 9-13%;
4. báo FPR 6,56% (F2) dù artifact cho 13,12%;
5. chạy một lớp mô hình mà repo công bố không khởi tạo được (F6/F10).

Đó là tái lập **lỗi**, không phải tái lập phương pháp. Báo cáo của nhóm vì vậy giữ protocol
`T` sạch, mã hoá hướng nhất quán, và trình bày 99% như một artefact đã truy vết - không phải
một mục tiêu cần "khớp bằng mọi giá".

---

## 6. Ghi chú tái lập

```bash
# 1) Mô phỏng mã hoá hướng của tác giả (không cần dữ liệu ngoài)
python scripts/eval_direction_leak.py --graphs data/graphs/P_paper data/graphs/T \
  --out results/direction_leak.csv

# 2) Trần supervised: same-day vs cross-day, raw vs z
python scripts/eval_supervised_bound.py --graphs data/graphs/T --p 8 --seeds 0 1 2 \
  --embedding-template 'experiments/paper_parity_cache/T_p8_seed{seed}/test.npz' \
  --out results/supervised_bound.csv

# 3) Detector trên raw / decoder output, cùng threshold-matched FPR
python scripts/eval_paper_parity.py --protocols P_paper --ps 8 --seeds 0 1 2 \
  --feature-input raw --out results/feature_input/P_paper_raw --device cpu
python scripts/eval_paper_parity.py --protocols P_paper --ps 8 --seeds 0 1 2 \
  --feature-input recon --out results/feature_input/P_paper_recon --device cpu
python scripts/eval_paper_parity.py --protocols T --ps 8 --seeds 0 1 2 \
  --feature-input raw --out results/feature_input/T_raw --device cpu
```

Kiểm chứng thủ công với checkpoint của tác giả (không redistribute):
`best_GTAE_model_8pkt.pth`, sha256
`fe31a4c84241d3bbe119fce1ea67f49e966e0226158f85ad8b6fe0dc232f1a7d`. Áp decoder 400×400
lên feature `P_paper` (400-d), scaler fit trên `train1`, bốn detector ở contamination
0,06/0,09: FPR ensemble 19,5%; TPR theo lớp 2,9-81,8% - không tái tạo được CSV 98,5-99,8%.
Điều này xác nhận checkpoint công khai không phải mô hình đã sinh ra kết quả.

---

## 7. Hạn chế của kết luận

- File `.pkl` gốc của tác giả không công khai, nên F9 được chứng minh bằng **đường code**
  (extractor + prep) và bằng **khớp số** (FPR và TPR theo lớp trùng CSV), không bằng cách
  đọc trực tiếp pkl. Đây là mức "đã kiểm chứng ở code + tái tạo số", không phải "đã mở pkl".
- F10 dựa trên checkpoint công khai; nếu nhóm tác giả dùng checkpoint khác, mô hình thật
  vẫn không xác định.
- Các số same-day supervised dùng nhãn của ngày test để huấn luyện; chúng là **trần**, không
  phải một phương pháp hợp lệ để báo cáo.
