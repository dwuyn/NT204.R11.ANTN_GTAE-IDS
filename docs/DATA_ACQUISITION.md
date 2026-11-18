# Data acquisition for the MAY cross-dataset experiments

**Status:** downloaded and verified readable; **no experiment has been run on either dataset yet.**
**Date:** 2026-11-19. **Scope decisions:** `docs/DECISIONS.md` §1 (2018 = one day, ACI = TCP subset).
**Disk:** 102 GB free before the downloads, 68 GB after (2017 data 51 GB + these 34 GB).

Two MAY items needed raw pcaps that were not on this machine:

| dataset | item | what the paper uses it for |
|---|---|---|
| CIC-IDS2018 | one day, benign + attacks, so FPR is measurable | Table VIII cross-dataset TPR (malicious only) |
| ACI-IoT-2023 | TCP-only subset | Table IX cross-dataset TPR (malicious only) |

## Why the archives are fetched partially

| archive | whole size | what is needed |
|---|---:|---|
| CIC-IDS2018 `Friday-16-02-2018/pcap.zip` | 35.9 GiB compressed (50.23 GiB of pcaps, 445 per-host captures) | the victim-side capture + a few client captures |
| ACI-IoT-2023 (Kaggle mirror `emilynack/...`) | 82.70 GiB compressed (3,068 files) | 2,352 files of benign/PortScan/Slowloris/Dictionary-BruteForce |

Both are plain zip archives, so `scripts/fetch_dataset.py` reads the central directory over
HTTP and pulls only the selected members with Range requests (12 threads, size-verified,
atomic rename). Measured throughput ≈ 34 MB/s; a full archive would not fit on the disk anyway.

## CIC-IDS2018 — Friday 2018-02-16

Day chosen because it is the only day whose attacks are **TCP DoS** (SlowHTTPTest, Hulk) against
the web server, i.e. the family the GTAE pipeline models, with benign background traffic.

Selection: the 6 largest captures of the day. The victim's own capture (`UCAP172.31.69.25-part1`,
4.31 GB) contains benign traffic and both attack windows; the other five are client-side captures.

```bash
python scripts/fetch_dataset.py list  cicids2018 --day Friday-16-02-2018 --captures 6
python scripts/fetch_dataset.py fetch cicids2018 --day Friday-16-02-2018 --captures 6 \
  --out data/raw/cicids2018
```

Result: 6 captures + the day's per-flow CSV, 6.13 GiB of pcapng + 0.32 GiB CSV:

```
data/raw/cicids2018/Friday-16-02-2018/pcap/UCAP172.31.69.25-part1.pcap   4.31 GB   victim
data/raw/cicids2018/Friday-16-02-2018/pcap/capPC1-172.31.64.31           0.62 GB
data/raw/cicids2018/Friday-16-02-2018/pcap/capPC1-172.31.67.124          0.43 GB
data/raw/cicids2018/Friday-16-02-2018/pcap/capPC1-172.31.67.59           0.42 GB
data/raw/cicids2018/Friday-16-02-2018/pcap/capPC1-172.31.64.48           0.40 GB
data/raw/cicids2018/Friday-16-02-2018/pcap/capPC1-172.31.65.80           0.39 GB
data/raw/cicids2018/Friday-16-02-2018_TrafficForML_CICFlowMeter.csv      319 MB
```

**Label source is the schedule, not the CSV.** The shipped CSV has 80 columns and **no Src/Dst IP**,
and its clock is degenerate: 446,390 of 446,757 benign rows fall in one 10-minute bucket (01:40),
while the documented attack windows are 10:12–11:08 and 13:45–14:19. A CSV row therefore cannot be
tied to a pcap flow. Windows, attacker IPs and the victim (`172.31.69.25`) come from the UNB
schedule table, recorded in `configs/cicids2018_schedule.yaml`; the CSV is kept only to cross-check
order of magnitude (139,890 SlowHTTPTest rows, 461,912 Hulk rows).

**Clock measured, not assumed.** The parsed victim capture contains two flow bursts and nothing
else above background (~3 flows/min): 14:10–15:08 and 17:40–17:58 (the capture's epoch end). The
scheduled windows are 10:12–11:08 and 13:45–14:19, so the capture clock runs ~3h58m ahead of the
schedule: `utc_offset_minutes: -240` in the config, with all four boundaries matching within 2 min
(10:12+4h = 14:12, 11:08+4h = 15:08, 13:45+4h = 17:45). Consequence to state in any report: the
capture ends at 17:58, so it covers the first **13 of the 34 Hulk minutes**; SlowHTTPTest is
covered in full (56/56 min).

**Parse result** (`data/processed/2018/parse_summary_f20180216.json`): 18,890,171 packets read,
14,638,618 stored (first 8 per flow), **1,909,802 flows**, 1,789,454 of them "reopened" (a new SYN
after FIN/RST on the same 5-tuple — expected under an HTTP flood). Runtime ≈ 20 min on one core.

## ACI-IoT-2023 — TCP subset

Chosen as the primary cross-dataset source: it ships **two full benign days** plus dated attack
windows in the README, with no label defect, so FPR is measurable on unseen benign traffic.

Selection (2,352 of 3,068 members, 26.97 GiB raw / 25.25 GiB fetched):

| class | day | window (README) | files | on disk |
|---|---|---|---|---|
| Benign 1 | 2023-10-31 | 09:00–16:05 | all | 852 |
| Benign 2 | 2023-11-03 | 09:00–16:05 | all | 705 |
| PortScan (`Recon Pcaps`) | 2023-10-30 | 12:20–15:56 | hours 12–15 | 469 (of 823) |
| Slowloris (`DoS_Pcaps`) | 2023-11-01 | 09:58–10:26 | minutes 09:58–10:26 | 58 |
| Dictionary Brute Force | 2023-11-02 | 09:30–11:44 | all | 268 |

```bash
python scripts/fetch_dataset.py list  aci-iot2023
python scripts/fetch_dataset.py fetch aci-iot2023 --out data/raw/aci
```

The Kaggle URL is resolved from `~/.kaggle/access_token` and is signed for three days; rerun the
command to refresh it.

Slowloris captures are tiny (39 MB for the whole window, 58 files) — slow-rate traffic, unlike the
1.2 GiB/minute ICMP/UDP/DNS flood captures that were excluded.

**Clock measured, not assumed:** file `2023-10-31-09_02_06_wireless.pcap` starts at epoch
1698757326 = 2023-10-31 09:02:06 UTC, so the filename clock, the capture clock and the README
windows share one clock → `utc_offset_minutes: 0` in `configs/aci_iot2023_schedule.yaml`.

**Deliberately not fetched** (see the config's `excluded` block): ICMP Flood, UDP Flood, DNS Flood
(UDP/ICMP, out of the paper's TCP scope); SYN Flood (single-packet flows, below `p ≥ 2`);
ARP Spoofing (not IP/TCP).

**Caveat for any experiment on this subset:** every minute is captured by a wired **and** a wireless
sniffer, so the same flow normally appears in two files. Flow counts over the whole selection
double-count; use one capture type per class or deduplicate by 5-tuple + timestamp.

**Open item:** the README gives windows but **no attacker IPs**, so `src/label.py` cannot mark
attacks by initiator. Labeling needs a window-membership variant (all flows whose start falls in
the window and whose 5-tuple is not a known background pair), which also means the label quality
depends on the README window being exact — state that in the eventual report.

## Verification performed

```bash
python scripts/fetch_dataset.py list aci-iot2023            # 2352 members, 26.97 GiB raw, 25.25 GiB to fetch
python scripts/fetch_dataset.py list cicids2018 --day Friday-16-02-2018 --captures 6
                                                           # 6 members, 6.13 GiB raw, 2.50 GiB to fetch
```

- **Extractor correctness:** three members extracted both ways (range extractor vs `remotezip`)
  are byte-identical (SHA-256 match), including one 470 MB flood capture.
- **Whole-selection integrity:** all 2,352 ACI files match the zip's central-directory CRC-32;
  0 bad, 0 missing (verification run 37 s on cached data).
- **Readability:** every sampled capture opens with the repo reader (`src.parse_pcap._open_reader`);
  CIC-IDS2018 files are pcapng, ACI files are classic pcap.
- **Checksums:** the six 2018 pcaps + the CSV are appended to `data/raw/SHA256SUMS` (that file lives
  in the git-ignored `data/` tree, like the 2017 entries).
- **Parse smoke test:** `python -m src.parse_pcap --pcap .../UCAP172.31.69.25-part1.pcap
  --out data/processed/2018 --day f20180216` completed on the full 4.31 GB capture: 18,890,171
  packets read, 14,638,618 stored, **1,909,802 flows** (see `data/processed/2018/parse_summary_f20180216.json`).

## What this does **not** do

- No labels applied, no graphs built, no model trained on either dataset.
- CIC-IDS2018: the other 439 captures of the day and the other days are not downloaded; one capture
  per host is enough to see both directions of that host's flows, not the whole network.
- ACI: the excluded classes are not downloaded and will not be reported.
