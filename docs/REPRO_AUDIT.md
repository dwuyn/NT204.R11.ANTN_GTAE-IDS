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

## 5. Các khả năng giải thích khoảng cách

1. **Siêu tham số không công bố** (hidden d, LapPE k, edge PE, K_max, sampler, định nghĩa epoch) — có thể làm embedding khác đáng kể.
2. **Flow segmentation:** paper không mô tả flow tracker; nếu dùng CICFlowMeter/CIC CSV flows thay vì 5-tuple + SYN, “p gói đầu” khác.
3. **Test composition:** Table VI có thể chỉ gồm DDoS/DoS Hulk, trong khi bảng của nhóm gồm 14 lớp; tuy nhiên per-class DDoS/Hulk vẫn thấp.
4. **Random split/leakage** ở paper: TPR 99% khó đạt với protocol flow-level sạch.
5. **Paper overclaim** hoặc dùng supervised information trong detector (không mô tả).

Chưa đủ bằng chứng để khẳng định paper sai; chỉ khẳng định **không tái lập được dưới protocol và giả định đã ghi**.

---

## 6. Hướng kiểm tra tiếp (chưa làm)

- [ ] Subgraph lớn hơn (1.000 cạnh) + K_max=64/128 — đang chạy.
- [ ] Feature standardization + loss weighting vị trí khác 0.
- [ ] Bottleneck nhỏ hơn (d=16/32); detector trên reconstruction error (A3).
- [ ] Đúng test composition DDoS/Hulk; đúng Table II graph sizes.
- [ ] So sánh với nhãn corrected Engelen (A3 trong work plan).
- [ ] Thử flow segmentation kiểu CICFlowMeter (nếu có thể tái tạo).

---

## 7. Lệnh tái chạy

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/audit_artifacts.py
.venv/bin/python -m src.eval --ps 2 3 4 5 6 7 8 --seeds 0 1 2 --out results --device cpu
```

Kết quả checkpoint: `artifacts/checkpoint_2026-10-24.tar.gz`, git tag `checkpoint-2026-10-24`.

---

## 8. Kết luận

- **Đúng paper về mô tả kỹ thuật** trong phạm vi paper công bố, với các giả định đã ghi.
- **Không tái hiện được số TPR 99%**; kết quả hiện tại thấp hơn một bậc, kể cả khi bỏ sampler/giới hạn K_max/PE.
- Nguyên nhân nằm ở **khả năng biểu diễn của one-class AE + detector** và **độ tách của features với lớp tấn công chưa thấy**, không phải GPU, không phải lỗi feature/label thô.
- Với dữ liệu hiện có, **không có bằng chứng pipeline sai**; có bằng chứng paper dùng protocol/leakage khác hoặc kết quả không tái lập được.
- Đề xuất: chốt báo cáo **partial/negative reproduction**, kèm upper bound supervised cross-day (18,1% @ FPR 6,7%) và same-session (99,4% @ FPR 6,1%) để giải thích khoảng cách.
