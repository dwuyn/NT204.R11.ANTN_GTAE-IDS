# QA labeling — CIC-IDS2017

Sinh tự động bởi `scripts/make_qa_report.py`. Nguồn: `reports/qa_labeling_{day}.json`, `reports/crosscheck_{day}.json`, `data/processed/parse_summary_{day}.json`.

## 1. Parse

| Ngày | Gói đọc | Flow | Packet rows | RST flows | Idle split | Reopened |
|---|---:|---:|---:|---:|---:|---:|
| monday | 11,709,971 | 133,793 | 1,046,065 | 38,389 | 1,608 | 508 |
| tuesday | 11,551,954 | 110,550 | 851,306 | 31,981 | 1,389 | 971 |
| wednesday | 13,788,878 | 280,306 | 2,200,112 | 196,374 | 17,537 | 145,103 |
| thursday | 9,322,025 | 170,872 | 937,490 | 65,311 | 588 | 10,667 |
| friday | 9,997,874 | 349,256 | 1,785,920 | 282,326 | 18,975 | 36,150 |

## 2. Nhãn

| Ngày | Flows | Benign | Attack | UNCERTAIN | UNCERTAIN % | Khớp CSV | Đồng thuận |
|---|---:|---:|---:|---:|---:|---:|---:|
| monday | 133,793 | 132,254 | 0 | 1,539 | 1.15% | 99.99% | 100.00% |
| tuesday | 110,550 | 102,655 | 6,483 | 1,412 | 1.28% | 99.97% | 99.52% |
| wednesday | 280,306 | 103,929 | 174,426 | 1,951 | 0.70% | 99.98% | 99.18% |
| thursday | 170,872 | 166,316 | 2,057 | 2,499 | 1.46% | 99.95% | 99.86% |
| friday | 349,256 | 87,400 | 255,745 | 6,111 | 1.75% | 99.94% | 96.82% |

Ngưỡng QA của design doc: `UNCERTAIN ≤ 2%`; bất đồng lịch-vs-CSV > 5% phải giải thích.

### Confusion với CSV

| Ngày | TN | FP | FN | TP |
|---|---:|---:|---:|---:|
| monday | 132,244 | 0 | 0 | 0 |
| tuesday | 102,159 | 56 | 466 | 6,427 |
| wednesday | 103,906 | 2,279 | 4 | 172,120 |
| thursday | 166,218 | 227 | 6 | 1,830 |
| friday | 87,390 | 10,909 | 7 | 244,630 |

### Attack types

| Ngày | Loại tấn công | Số flow |
|---|---|---:|
| tuesday | FTP-Patator | 3,972 |
| tuesday | SSH-Patator | 2,511 |
| wednesday | DoS GoldenEye | 7,545 |
| wednesday | DoS Hulk | 158,770 |
| wednesday | DoS Slowhttptest | 4,216 |
| wednesday | DoS slowloris | 3,894 |
| wednesday | Heartbleed | 1 |
| thursday | Infiltration | 8 |
| thursday | Web Attack - Brute Force | 1,358 |
| thursday | Web Attack - Sql Injection | 12 |
| thursday | Web Attack - XSS | 679 |
| friday | Bot | 736 |
| friday | DDoS | 94,911 |
| friday | PortScan | 160,098 |

## 3. Ghi chú kỹ thuật

- **Múi giờ:** hiệu chuẩn từ 510 flow smoke khớp CSV → `utc_offset_minutes = -180` (UTC−3).
- **CSV CIC bị lỗi AM/PM:** cross-check thử `t`, `t+12h`, `t−12h`; tolerance 120 s vì CSV chỉ có phút.
- **Infiltration lateral (192.168.10.8 → LAN)** đã loại khỏi nhãn chính: CSV label BENIGN, paper Table VII chỉ có 1.764 cạnh; giữ lại sẽ tạo ~71k FP.
- **PortScan** dùng cửa sổ gộp 13:55–14:35 và 14:51–15:29; từng burst cho đồng thuận thấp hơn.
- **Pad 60 s**; pad nhỏ (0/5/15 s) làm FN tăng mạnh.
- **Heartbleed chỉ 1 flow** (một phiên dài 20 phút); per-class TPR của Heartbleed không có ý nghĩa thống kê.
- **PortScan p=8 chỉ 204 flow** vì scan toàn flow 1–2 gói; TPR(p=8) của PortScan có mẫu nhỏ.
