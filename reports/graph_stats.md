# Graph statistics

Sinh tự động bởi `scripts/make_graph_stats.py` từ `data/graphs/{T,R}/summary.json`.

## Protocol T (temporal)

| p | train1 | train2 | test | benign | attack | nodes |
|---|---:|---:|---:|---:|---:|---:|
| 2 | 5,000 | 2,000 | 42,362 | 5,000 | 37,362 | 25,663 |
| 3 | 5,000 | 2,000 | 38,521 | 5,000 | 33,521 | 24,758 |
| 4 | 5,000 | 2,000 | 36,397 | 5,000 | 31,397 | 24,660 |
| 5 | 5,000 | 2,000 | 35,923 | 5,000 | 30,923 | 24,680 |
| 6 | 5,000 | 2,000 | 35,912 | 5,000 | 30,912 | 24,684 |
| 7 | 5,000 | 2,000 | 34,089 | 5,000 | 29,089 | 24,561 |
| 8 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |

### Attack types trong test

**p=2**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| PortScan | 5,000 |
| DoS Slowhttptest | 4,216 |
| FTP-Patator | 3,972 |
| DoS slowloris | 3,869 |
| SSH-Patator | 2,511 |
| Web Attack - Brute Force | 1,358 |
| Bot | 736 |
| Web Attack - XSS | 679 |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 8 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=3**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| DoS Slowhttptest | 4,212 |
| FTP-Patator | 3,972 |
| DoS slowloris | 3,865 |
| SSH-Patator | 2,511 |
| Web Attack - Brute Force | 1,358 |
| PortScan | 1,171 |
| Bot | 736 |
| Web Attack - XSS | 679 |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=4**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| DoS Slowhttptest | 4,199 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,239 |
| Web Attack - Brute Force | 1,358 |
| Bot | 736 |
| PortScan | 686 |
| Web Attack - XSS | 679 |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=5**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| DoS Slowhttptest | 4,199 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,239 |
| Web Attack - Brute Force | 1,358 |
| Bot | 736 |
| Web Attack - XSS | 679 |
| PortScan | 212 |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=6**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| DoS Slowhttptest | 4,199 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,228 |
| Web Attack - Brute Force | 1,358 |
| Bot | 736 |
| Web Attack - XSS | 679 |
| PortScan | 212 |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=7**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| DoS Slowhttptest | 4,198 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,227 |
| Bot | 736 |
| PortScan | 207 |
| Web Attack - Brute Force | 178 |
| Web Attack - XSS | 43 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=8**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

⚠️ = dưới 50 mẫu; không nên báo per-class TPR cho lớp này.

## Protocol R (random)

| p | train1 | train2 | test | benign | attack | nodes |
|---|---:|---:|---:|---:|---:|---:|
| 2 | 5,000 | 2,000 | 42,362 | 5,000 | 37,362 | 25,780 |
| 4 | 5,000 | 2,000 | 36,397 | 5,000 | 31,397 | 24,798 |
| 8 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,106 |

### Attack types trong test

**p=2**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| PortScan | 5,000 |
| DoS Slowhttptest | 4,216 |
| FTP-Patator | 3,972 |
| DoS slowloris | 3,869 |
| SSH-Patator | 2,511 |
| Web Attack - Brute Force | 1,358 |
| Bot | 736 |
| Web Attack - XSS | 679 |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 8 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=4**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| DoS Slowhttptest | 4,199 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,239 |
| Web Attack - Brute Force | 1,358 |
| Bot | 736 |
| PortScan | 686 |
| Web Attack - XSS | 679 |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=8**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

⚠️ = dưới 50 mẫu; không nên báo per-class TPR cho lớp này.

## Fixed population (flow ≥ 8 packets)

| p | train1 | train2 | test | benign | attack | nodes |
|---|---:|---:|---:|---:|---:|---:|
| 2 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |
| 3 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |
| 4 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |
| 5 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |
| 6 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |
| 7 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |
| 8 | 5,000 | 2,000 | 30,907 | 5,000 | 25,907 | 24,030 |

### Attack types trong test

**p=2**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=3**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=4**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=5**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=6**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=7**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

**p=8**

| Attack type | Edges |
|---|---:|
| DDoS | 5,000 |
| DoS GoldenEye | 5,000 |
| DoS Hulk | 5,000 |
| FTP-Patator | 3,972 |
| SSH-Patator | 2,511 |
| DoS slowloris | 2,164 |
| DoS Slowhttptest | 1,132 |
| Bot | 736 |
| PortScan | 204 |
| Web Attack - Brute Force | 144 |
| Web Attack - XSS | 27 ⚠️ |
| Web Attack - Sql Injection | 12 ⚠️ |
| Infiltration | 4 ⚠️ |
| Heartbleed | 1 ⚠️ |

⚠️ = dưới 50 mẫu; không nên báo per-class TPR cho lớp này.
