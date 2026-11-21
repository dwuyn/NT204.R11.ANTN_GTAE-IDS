# Paper-parity: P_paper và T ở đúng điểm vận hành của paper

**Trạng thái:** sinh tự động bởi `scripts/eval_paper_parity.py`; không sửa tay.

**Nguồn số liệu:** `results/paper_parity/*.csv`, `results/P_paper_counts.csv`, `data/graphs/P_paper/summary.json`.

**Thiết lập:** p = 8, 3 seed, contamination grid [0.001, 0.01, 0.04, 0.05, 0.1], điểm vận hành mục tiêu FPR = 6,56% (paper Table VI).

## 1. Thành phần tập test (paper Table II/VII, p = 8)

| tập test | edge | node | benign | PortScan | Heartbleed | Infiltration | DoS Hulk |
|---|---:|---:|---:|---:|---:|---:|---:|
| paper | 33228 | 40744 | 5000 | 6451 | 1468 | 1764 | 5000 |
| P_paper | 30041 | 22328 | 5000 | 6451 | 11 | 34 | 5000 |
| T | 30907 | 24030 | 5000 | 204 | 1 | 4 | 5000 |
| T_fixed | 30907 | 24030 | 5000 | 204 | 1 | 4 | 5000 |
| ACI | 20000 | 18980 | 5000 | 5000 | 0 | 0 | 0 |

Paper Table VII cần 1.468 edge Heartbleed và 1.764 edge Infiltration. CSV CICFlowMeter chỉ có 11 và 36 dòng flow TCP cho hai nhãn này, nên không cách dựng nào từ CSV đạt được các con số đó (protocol `T` dựng từ pcap được 1 và 4). Đây là phát hiện về cách dựng dữ liệu của paper, không phải lỗi build: `scripts/check_paper_counts.py` ghi nhận là `csv_pool_exhausted`.

### 1b. Đối chiếu Table II (nút, cạnh) — built vs paper

Sinh bởi `scripts/check_paper_counts.py --all-p`; node chỉ để tham chiếu.

| p | split | node built | node paper | cạnh built | cạnh paper |
|---:|---|---:|---:|---:|---:|
| 2 | train1 | 7178 | 7160 | 5000 | 5000 |
| 2 | train2 | 3105 | 3736 | 2000 | 2000 |
| 2 | test | 22328 | 44767 | 30041 | 38984 |
| 3 | train1 | 7178 | 7144 | 5000 | 5000 |
| 3 | train2 | 3105 | 3351 | 2000 | 2000 |
| 3 | test | 22328 | 46285 | 30041 | 37971 |
| 4 | train1 | 7178 | 7135 | 5000 | 5000 |
| 4 | train2 | 3105 | 3145 | 2000 | 2000 |
| 4 | test | 22328 | 45008 | 30041 | 36964 |
| 5 | train1 | 7178 | 7135 | 5000 | 5000 |
| 5 | train2 | 3105 | 3143 | 2000 | 2000 |
| 5 | test | 22328 | 44118 | 30041 | 36093 |
| 6 | train1 | 7178 | 7129 | 5000 | 5000 |
| 6 | train2 | 3105 | 3136 | 2000 | 2000 |
| 6 | test | 22328 | 43417 | 30041 | 35482 |
| 7 | train1 | 7178 | 7112 | 5000 | 5000 |
| 7 | train2 | 3105 | 3126 | 2000 | 2000 |
| 7 | test | 22328 | 41643 | 30041 | 33974 |
| 8 | train1 | 7178 | 7023 | 5000 | 5000 |
| 8 | train2 | 3105 | 3106 | 2000 | 2000 |
| 8 | test | 22328 | 40744 | 30041 | 33228 |

Hai khác biệt đã biết, không phải lỗi build: (i) `P_paper` **zero-pad** flow ngắn nên số cạnh test không đổi theo p (30.041), trong khi cạnh test của paper giảm 38.984 → 33.228, tức paper dựng lại tập test theo từng p với điều kiện `n_pkts >= p`; (ii) node test của nhóm ít hơn (22.328 vs 40.744) vì cùng một endpoint dịch vụ lặp lại trên nhiều flow, trong khi paper đếm nhiều endpoint nguồn tạm thời hơn trên cùng số cạnh.

### 1c. Per-class p = 8: P_paper so với paper Table VII

Cùng cấu hình đã chọn (contamination theo calibration benign) và cùng luật vote; cột `paper` là Table VII của bài báo.

| lớp | paper TPR | P_paper (luật or) | P_paper (luật tie) |
|---|---:|---:|---:|
| DDoS | 99.34% | 9,23 | 0,61 |
| DoS GoldenEye | 99.08% | 7,65 | 0,75 |
| DoS Hulk | 98.74% | 7,57 | 0,58 |
| DoS Slowhttptest | 99.79% | 6,43 | 0,76 |
| DoS Slowloris | 99.60% | 8,55 | 2,00 |
| FTP-Patator | 98.85% | 6,32 | 1,72 |
| Heartbleed | 99.52% | 33,33 | 0,00 |
| Infiltration | 99.83% | 0,98 | 0,98 |
| PortScan | 98.50% | 28,56 | 25,31 |
| SSH-Patator | 98.86% | 5,52 | 0,19 |
| Web Attack - Brute Force | 99.29% | 5,71 | 0,48 |
## 2. Điểm vận hành (FPR mục tiêu 6,56%)

Ba cách đặt ngưỡng, cùng một embedding:

1. **ngưỡng riêng của detector**: `contamination` quyết định ngưỡng nội bộ; `FPR@ngưỡng riêng` là FPR thực trên test.
2. **quantile calibration**: ngưỡng = phân vị `1 - FPR` của điểm benign trên split calibration (400 flow `train2`); cho thấy ảnh hưởng lệch phân phối.
3. **matched test FPR**: ngưỡng = phân vị sao cho FPR thực trên benign test đúng bằng 6,56%; đây là cột so sánh trực tiếp với paper.

| thiết lập | luật | contamination | FPR@ngưỡng riêng | TPR@FPR 6,56% (quantile calibration) | TPR@FPR 6,56% (matched test FPR) | TPR@FPR 1% (matched test FPR) | AUROC |
|---|---|---:|---:|---:|---:|---:|---:|
| paper Table VI (p=8, FPR 6,56%) | n/a | n/a | 6,56 | n/a | 99,04 | n/a | n/a |
| P_paper (mean 3 seed) | strict | 0,080 | 6,41 | 3,21 | 3,25 | 1,39 | 0,4785 |
| P_paper (mean 3 seed) | tie | 0,050 | 6,00 | 3,21 | 3,25 | 1,39 | 0,4785 |
| P_paper (mean 3 seed) | or | 0,040 | 8,41 | 3,21 | 3,25 | 1,39 | 0,4785 |
| P_paper (mean 3 seed) | IForest | 0,050 | 5,19 | 8,54 | 8,90 | 0,96 | 0,5185 |
| P_paper (mean 3 seed) | OCSVM | 0,047 | 4,53 | 3,10 | 2,95 | 1,50 | 0,3880 |
| P_paper (mean 3 seed) | HBOS | 0,047 | 4,27 | 5,97 | 5,99 | 5,05 | 0,4183 |
| P_paper (mean 3 seed) | INNE | 0,050 | 6,44 | 11,94 | 8,31 | 4,12 | 0,5897 |
| T (mean 3 seed) | strict | 0,067 | 9,59 | 24,02 | 11,54 | 2,79 | 0,5937 |
| T (mean 3 seed) | tie | 0,047 | 9,31 | 24,02 | 11,54 | 2,79 | 0,5937 |
| T (mean 3 seed) | or | 0,040 | 9,70 | 24,02 | 11,54 | 2,79 | 0,5937 |
| T (mean 3 seed) | IForest | 0,047 | 9,18 | 24,33 | 15,75 | 2,11 | 0,6010 |
| T (mean 3 seed) | OCSVM | 0,047 | 8,68 | 22,45 | 8,80 | 0,04 | 0,5951 |
| T (mean 3 seed) | HBOS | 0,043 | 7,77 | 42,35 | 12,27 | 6,53 | 0,5427 |
| T (mean 3 seed) | INNE | 0,040 | 7,97 | 23,37 | 21,21 | 4,80 | 0,5778 |
| ACI (mean 3 seed) | strict | 0,083 | 4,67 | 5,20 | 8,03 | 1,85 | 0,5355 |
| ACI (mean 3 seed) | tie | 0,047 | 3,78 | 5,20 | 8,03 | 1,85 | 0,5355 |
| ACI (mean 3 seed) | or | 0,030 | 4,40 | 5,20 | 8,03 | 1,85 | 0,5355 |
| ACI (mean 3 seed) | IForest | 0,063 | 4,50 | 4,90 | 7,40 | 1,56 | 0,5368 |
| ACI (mean 3 seed) | OCSVM | 0,067 | 4,34 | 4,25 | 6,61 | 1,31 | 0,5304 |
| ACI (mean 3 seed) | HBOS | 0,047 | 4,19 | 5,61 | 7,50 | 1,69 | 0,5286 |
| ACI (mean 3 seed) | INNE | 0,050 | 2,64 | 5,22 | 9,00 | 1,69 | 0,5401 |

## 3. Chi tiết theo seed (contamination đã chọn)

### P_paper

| seed | luật | contamination | TPR@6,56% (calib.) | FPR@6,56% (calib.) | TPR@6,56% (matched) | TPR@1% (matched) |
|---:|---|---:|---:|---:|---:|---:|
| 0 | IForest | 0,050 | 1,41 | 10,62 | 0,78 | 0,10 |
| 0 | OCSVM | 0,050 | 1,31 | 9,96 | 0,85 | 0,08 |
| 0 | HBOS | 0,050 | 0,97 | 15,74 | 0,97 | 0,06 |
| 0 | INNE | 0,050 | 11,53 | 9,62 | 1,19 | 0,14 |
| 0 | strict | 0,100 | 1,43 | 9,70 | 0,83 | 0,06 |
| 0 | tie | 0,050 | 1,43 | 9,70 | 0,83 | 0,06 |
| 0 | or | 0,040 | 1,43 | 9,70 | 0,83 | 0,06 |
| 1 | IForest | 0,050 | 24,03 | 6,14 | 25,68 | 2,77 |
| 1 | OCSVM | 0,040 | 7,99 | 6,48 | 7,99 | 4,44 |
| 1 | HBOS | 0,040 | 16,84 | 24,60 | 16,84 | 15,07 |
| 1 | INNE | 0,050 | 17,66 | 11,42 | 16,85 | 8,82 |
| 1 | strict | 0,040 | 8,00 | 6,58 | 8,00 | 4,09 |
| 1 | tie | 0,050 | 8,00 | 6,58 | 8,00 | 4,09 |
| 1 | or | 0,040 | 8,00 | 6,58 | 8,00 | 4,09 |
| 2 | IForest | 0,050 | 0,18 | 4,88 | 0,25 | 0,00 |
| 2 | OCSVM | 0,050 | 0,00 | 4,96 | 0,00 | 0,00 |
| 2 | HBOS | 0,050 | 0,09 | 4,36 | 0,16 | 0,02 |
| 2 | INNE | 0,050 | 6,63 | 5,84 | 6,91 | 3,40 |
| 2 | strict | 0,100 | 0,20 | 4,72 | 0,91 | 0,01 |
| 2 | tie | 0,050 | 0,20 | 4,72 | 0,91 | 0,01 |
| 2 | or | 0,040 | 0,20 | 4,72 | 0,91 | 0,01 |

### T

| seed | luật | contamination | TPR@6,56% (calib.) | FPR@6,56% (calib.) | TPR@6,56% (matched) | TPR@1% (matched) |
|---:|---|---:|---:|---:|---:|---:|
| 0 | IForest | 0,050 | 48,20 | 14,10 | 32,89 | 6,32 |
| 0 | OCSVM | 0,050 | 45,23 | 12,62 | 12,38 | 0,11 |
| 0 | HBOS | 0,040 | 100,00 | 100,00 | 16,76 | 16,76 |
| 0 | INNE | 0,040 | 43,88 | 8,80 | 43,33 | 10,66 |
| 0 | strict | 0,100 | 47,69 | 13,60 | 20,41 | 7,48 |
| 0 | tie | 0,050 | 47,69 | 13,60 | 20,41 | 7,48 |
| 0 | or | 0,040 | 47,69 | 13,60 | 20,41 | 7,48 |
| 1 | IForest | 0,040 | 21,88 | 8,82 | 11,73 | 0,00 |
| 1 | OCSVM | 0,040 | 19,34 | 9,18 | 11,41 | 0,00 |
| 1 | HBOS | 0,040 | 24,02 | 11,66 | 17,26 | 2,82 |
| 1 | INNE | 0,040 | 22,95 | 9,12 | 17,62 | 3,72 |
| 1 | strict | 0,050 | 21,32 | 8,94 | 11,63 | 0,86 |
| 1 | tie | 0,040 | 21,32 | 8,94 | 11,63 | 0,86 |
| 1 | or | 0,040 | 21,32 | 8,94 | 11,63 | 0,86 |
| 2 | IForest | 0,050 | 2,91 | 6,78 | 2,61 | 0,00 |
| 2 | OCSVM | 0,050 | 2,77 | 6,78 | 2,62 | 0,00 |
| 2 | HBOS | 0,050 | 3,03 | 6,86 | 2,79 | 0,02 |
| 2 | INNE | 0,040 | 3,27 | 7,14 | 2,68 | 0,00 |
| 2 | strict | 0,050 | 3,04 | 6,96 | 2,59 | 0,02 |
| 2 | tie | 0,050 | 3,04 | 6,96 | 2,59 | 0,02 |
| 2 | or | 0,040 | 3,04 | 6,96 | 2,59 | 0,02 |

### ACI

| seed | luật | contamination | TPR@6,56% (calib.) | FPR@6,56% (calib.) | TPR@6,56% (matched) | TPR@1% (matched) |
|---:|---|---:|---:|---:|---:|---:|
| 0 | IForest | 0,040 | 3,51 | 2,76 | 7,20 | 1,55 |
| 0 | OCSVM | 0,050 | 3,05 | 3,20 | 7,42 | 1,19 |
| 0 | HBOS | 0,040 | 4,23 | 3,28 | 7,42 | 1,80 |
| 0 | INNE | 0,050 | 8,23 | 6,06 | 9,06 | 1,43 |
| 0 | strict | 0,050 | 3,81 | 2,48 | 7,75 | 2,33 |
| 0 | tie | 0,040 | 3,81 | 2,48 | 7,75 | 2,33 |
| 0 | or | 0,010 | 3,81 | 2,48 | 7,75 | 2,33 |
| 1 | IForest | 0,100 | 7,16 | 6,20 | 7,63 | 1,25 |
| 1 | OCSVM | 0,100 | 5,01 | 5,88 | 5,61 | 1,00 |
| 1 | HBOS | 0,050 | 8,15 | 7,06 | 7,77 | 1,28 |
| 1 | INNE | 0,050 | 3,96 | 1,86 | 10,10 | 2,17 |
| 1 | strict | 0,100 | 7,44 | 6,00 | 8,18 | 1,30 |
| 1 | tie | 0,050 | 7,44 | 6,00 | 8,18 | 1,30 |
| 1 | or | 0,040 | 7,44 | 6,00 | 8,18 | 1,30 |
| 2 | IForest | 0,050 | 4,04 | 3,32 | 7,36 | 1,87 |
| 2 | OCSVM | 0,050 | 4,68 | 4,30 | 6,81 | 1,73 |
| 2 | HBOS | 0,050 | 4,46 | 3,86 | 7,33 | 1,99 |
| 2 | INNE | 0,050 | 3,46 | 2,70 | 7,85 | 1,47 |
| 2 | strict | 0,100 | 4,34 | 3,24 | 8,17 | 1,92 |
| 2 | tie | 0,050 | 4,34 | 3,24 | 8,17 | 1,92 |
| 2 | or | 0,040 | 4,34 | 3,24 | 8,17 | 1,92 |


## 3b. Đường cong p (paper Table VI)

Cùng cách chọn contamination theo calibration benign, lặp cho từng p. Cột `matched` đặt ngưỡng sao cho FPR thực trên benign test đúng 6,56%, nên so được với Table VI; `paper` là số của paper.

| p | paper TPR@FPR 6,56% | P_paper OR TPR@6,56% | P_paper tie TPR@6,56% | P_paper AUROC | T OR TPR@6,56% | T AUROC |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 84.47 / 8.94 % | 3,79 | 3,79 | 0,4332 | 10,22 | 0,5052 |
| 3 | 91.02 / 7.61 % | 12,47 | 12,47 | 0,5661 | 8,37 | 0,5054 |
| 4 | 94.72 / 6.60 % | 5,36 | 5,36 | 0,4728 | 19,67 | 0,5773 |
| 5 | 97.16 / 6.84 % | 1,10 | 1,10 | 0,4243 | 11,48 | 0,6327 |
| 6 | 98.44 / 6.73 % | 5,40 | 5,40 | 0,4114 | 33,77 | 0,8011 |
| 7 | 98.72 / 5.91 % | 26,77 | 26,77 | 0,5346 | 19,99 | 0,6904 |
| 8 | 99.04 / 6.56 % | 3,25 | 3,25 | 0,4785 | 11,54 | 0,5854 |


## 4. Chẩn đoán zero-pad (AUROC, IForest contamination 0,05)

Chẩn đoán, không phải điểm vận hành: tách AUROC theo số gói tin thực của edge test để kiểm tra liệu edge zero-pad có tạo ra khả năng phân biệt giả.

| protocol | seed | tập con | edge tấn công | edge benign | AUROC |
|---|---:|---|---:|---:|---:|
| P_paper | 0 | all_edges | 25041 | 5000 | 0,5091 |
| P_paper | 0 | full_2_packets | 25038 | 5000 | 0,5090 |
| P_paper | 0 | padded_attacks | 3 | 5000 | 0,7945 |
| P_paper | 1 | all_edges | 25041 | 5000 | 0,3859 |
| P_paper | 1 | full_2_packets | 25038 | 5000 | 0,3859 |
| P_paper | 1 | padded_attacks | 3 | 5000 | 0,8801 |
| P_paper | 2 | all_edges | 25041 | 5000 | 0,3829 |
| P_paper | 2 | full_2_packets | 25038 | 5000 | 0,3828 |
| P_paper | 2 | padded_attacks | 3 | 5000 | 0,9754 |
| T | 0 | all_edges | 37362 | 5000 | 0,5182 |
| T | 0 | full_2_packets | 37362 | 5000 | 0,5182 |
| T | 0 | padded_attacks | 0 | 5000 | n/a |
| T | 1 | all_edges | 37362 | 5000 | 0,4949 |
| T | 1 | full_2_packets | 37362 | 5000 | 0,4949 |
| T | 1 | padded_attacks | 0 | 5000 | n/a |
| T | 2 | all_edges | 37362 | 5000 | 0,4877 |
| T | 2 | full_2_packets | 37362 | 5000 | 0,4877 |
| T | 2 | padded_attacks | 0 | 5000 | n/a |
| ACI | 0 | all_edges | 15000 | 5000 | 0,5260 |
| ACI | 0 | full_2_packets | 15000 | 5000 | 0,5260 |
| ACI | 0 | padded_attacks | 0 | 5000 | n/a |
| ACI | 1 | all_edges | 15000 | 5000 | 0,5115 |
| ACI | 1 | full_2_packets | 15000 | 5000 | 0,5115 |
| ACI | 1 | padded_attacks | 0 | 5000 | n/a |
| ACI | 2 | all_edges | 15000 | 5000 | 0,6602 |
| ACI | 2 | full_2_packets | 15000 | 5000 | 0,6602 |
| ACI | 2 | padded_attacks | 0 | 5000 | n/a |

## 5. Kết luận

`P_paper` đạt 3,25% TPR ở FPR matched 6,56% với luật OR của code tác giả (luật tie: 3,25%; cả ba luật vote cho cùng TPR vì dùng chung score fusion). Detector tốt nhất (IForest) đạt 8,90%. Trên cùng pipeline, protocol `T` sạch (luật tie) đạt 11,54%. So với 99,04% của paper, khoảng cách vẫn hơn 60 điểm phần trăm. Khớp thành phần tập test (Table VII), grid contamination (Table V) và luật OR của code tác giả **không** thu hẹp khoảng cách, nên kết quả âm của bản tái hiện là bền vững theo cách dựng dữ liệu: con số ~99% không tái lập được từ artefact công khai dưới cả hai định nghĩa flow.
