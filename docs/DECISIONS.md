# Locked decisions

Decisions taken for the retrain-from-scratch + online-latency + Engelen-label run.
Every number below is a measurement from this repository (`results/*.csv`), not a
paper claim. Each entry records what was decided, the evidence that forced it, and
the consequence for how results are reported.

---

## 1. Scope

**Decision.** MUST + SHOULD + MAY on CIC-IDS2017. CSE-CIC-IDS2018 is covered by
**one day only**. ACI-IoT-2023 is covered by its **TCP-representable subset only**.

**Evidence.**
- CIC-IDS2017 is fully local: 51 GB of pcap in `data/raw/` plus the
  `GeneratedLabelledFlows` CSVs; every graph in `data/graphs/T` derives from it.
- The full CSE-CIC-IDS2018 pcap is 444.5 GiB compressed; this workstation has
  122 GB free. A 2018 subset that fits is not the same dataset as the published one,
  so only one day is defensible as a second-dataset probe.
- ACI-IoT-2023 (Kaggle mirror `emilynack/aci-iot-network-traffic-dataset-2023`,
  CC BY 4.0, 3,068 files / 82.70 GiB) is not TCP-only. Only Port Scan (436,502
  flows), Slowloris (18,643) and Dictionary Attack (6,343) are TCP-representable;
  ICMP Flood (225,234) and ARP Spoofing (5) are not.

**Consequence.** The pipeline contract (TCP-over-IPv4, 25-byte header encoding,
`(IP, port)` nodes) is preserved. ACI's ICMP Flood and ARP Spoofing classes are
excluded by construction, and the ACI full download is not attempted; CIC-IDS2017
remains the only dataset on which the headline numbers are computed.

---

## 2. Headline protocol

**Decision.** `T` (temporal: train Monday benign, test Tuesday–Friday) is the
headline protocol. `P_paper` is a **mandatory companion column** at the paper's
matched operating point FPR = 6.56%. `R` (random) and `T_fixed`
(fixed-population) are auxiliary.

**Evidence.** At matched benign-test FPR 6.56% (3 seeds, mean): paper 99.04%,
`T` 11.54%, `P_paper` 3.25%. `P_paper` reproduces the paper's counts and operating
point, but its benign splits are all drawn from Friday, so benign training and
test edges share the day — it is not leak-free, and it does not even outperform
the leak-free `T` protocol. Measured from `results/paper_parity/p8_selected.csv`
and `T_p8_selected.csv` (recipes: 100 epochs, no early stopping).

**Consequence.** Every headline table lists `T` first and `P_paper` next to it at
the same FPR. `P_paper` is labelled "parity reconstruction, same-day benign split"
wherever it appears. The leak-free claim is attached to `T` alone.

---

## 3. p-curve criterion

**Decision.** Publish the **AUROC trend** across packet budget `p`, not monotone
TPR.

**Evidence.** AUROC (ensemble tie, 3-seed mean) rises 0.505 → 0.835 for p = 2 → 6,
then falls to 0.711 (p = 7) and 0.594 (p = 8). TPR at the same operating point is
non-monotone: 3.30 / 4.18 / 8.56 / 6.31 / 14.93 / 6.90 / 4.18 % for p = 2..8, and
per-seed AUROC at p = 8 spans 0.70 / 0.59 / 0.51 — the budget interacts with the
seed, not just with p. A monotonicity claim would be false.

Recipe for every number in this run: 100 epochs, `--patience 100` (no early
stopping), `--device cpu`, seeds 0/1/2. The archived pre-retrain numbers came from
early-stopped checkpoints and are not comparable.

**Consequence.** The p-curve figure and table report AUROC (and TPR@FPR=1%) with
per-seed spread, and state that the ranking signal peaks at p = 6 while the
thresholded TPR does not increase monotonically.

---

## 4. Online definition and measurement population

**Decision.** "Real-time" means **per-flow wall clock from flow close to alert**
during a pcap replay, reported **per stage** (graph update, line graph, PE,
encoder forward, detectors) plus µs/packet, so the paper's 1.28 µs/packet
(model-only) is directly comparable. Locked choices:

* headline = **no-PE** model (`experiments/T_noPE`); `window_pe`
  (`experiments/T`) is the secondary column that shows what positional encoding
  costs;
* population = the **full Friday replay** (349,256 flows) for the headline;
  every flow is parsed and kept in the window graph, but the end-to-end cost is
  timed on every *K*-th flow, because recomputing the window transformer per
  flow is hours of CPU (measured: 122 ms/flow × 349k = 11.8 h single-stream);
* window semantics = a monotone watermark (`max t_last` seen) defines "now"; a
  flow is scored against its own window even when its last packet already fell
  behind the watermark (counted and reported as *stale*).

**Evidence** (`results/latency_summary.json`, `reports/latency.md`; p = 8,
seed 0, window 120 s):

| mode | flows replayed | timed (K) | mean | p50 | p95 | µs/packet | capacity |
|---|---|---|---|---|---|---|---|
| no_pe | 349,256 | 3,492 (100) | 122.2 ms | 48.0 ms | 488.0 ms | 15,272 | 8.2 flows/s |
| window_pe | 80,000 | 80 (1,000) | 259.7 ms | 201.0 ms | 594.7 ms | 32,468 | 3.8 flows/s |

* Stage split (no_pe, mean): detector 36.3 ms, line graph 72.4 ms (p50 6.3 ms —
  heavy tail from hub cliques), forward 13.3 ms, graph update 0.1 ms.
* Friday's own arrival rate is 12.1 flows/s (349,256 flows / 8 h), so the
  full-window recompute path runs *below* replay speed: it is not real-time at
  this window size on one CPU core-equivalent.
* The paper's 1.28 µs/packet is model-only; our model-only forward is
  1,663 µs/packet (13.3 ms/flow) and the end-to-end path is 15,272 µs/packet.
* 3,116 of the 3,492 timed flows (89%) are *stale*: their own last packet sits
  outside the window when the decision is taken. That is structural, not a bug —
  with `W = idle_timeout`, an idle-timeout closure is by definition at the window
  edge, and 294k of Friday's flows are closed only by the capture boundary. The
  report gives the fresh/stale split separately; a deployed system would decide
  at `t_last` (no idle wait) or use `W > idle_timeout`.

**Consequence.** The latency claim is a *measured negative* at this scale: the
detector layer (4 PyOD models at batch-1) and the Python line-graph build, not
the encoder, dominate; and full-window recompute cannot keep up with 12 flows/s.
Streaming AUROC (0.717 no-PE) is reported next to the offline `T` number (0.594)
with the population, graph and threshold-transfer caveats spelled out, because
they are not the same measurement.

---

## 5. Engelen labels

**Decision.** Use the Engelen et al. (WTMC 2021) labels at four levels:
L1 composition corroboration, L2 label confusion + match rate, L3 re-scoring under
their labels, L4 retrain with their labels applied to our graphs. `X - Attempted`
counts as **attack**. L3/L4 are skipped if the per-day match rate falls below 85%.

**Evidence.**

*L1 — composition* (`results/engelen_composition.csv`). The Engelen labelling
covers the same capture: 1,657,693 benign rows plus per-class attack counts. The
two classes the paper cannot be checked against are exactly where the counts
collapse — Heartbleed **11** (paper 1,468; our `P_paper` build 11) and
Infiltration **32** (paper 1,764; our build 34). Engelen also flags `- Attempted`
sessions the paper never mentions: DoS Slowhttptest 3,369, DoS slowloris 1,731,
Bot 1,470, Web Attack Brute Force 1,214, XSS 652, DoS Hulk 593.

*L2 — matching* (`results/engelen_confusion.csv`, `data/processed/engelen_label_map.parquet`).
5-tuple + timestamp matching with a data-driven clock offset (+7,200 s for every
day) matches **99.7–100%** of our flows on Monday/Tuesday/Wednesday/Friday and
**98.2%** on Thursday. Agreement on the matched subset is 99.5–100%. The
asymmetry is the interesting part: we call almost nothing an attack that they call
benign (0 / 0 / 1 / 5 / 39 per day), while they call 481 (Tue), 1,283 (Wed), 26
(Thu) and 1,698 (Fri) flows attacks that we label benign — overwhelmingly
`- Attempted` sessions and Bot/DDoS flows our schedule-based labeler misses.

*L3 — re-scoring* (`results/engelen_relabel_metrics.csv`). On the p8 `T` test
graph, all 30,907 edges map to an Engelen label, but only **6** change class
(1 attack → benign, 5 benign → attack). Ensemble-tie AUROC stays 0.705 / 0.581 /
0.495 per seed versus 0.704 / 0.587 / 0.511 with our labels: the two labellings are
the same measurement on this population.

*L4 — retrain* (`data/graphs/T_engelen`, `results/engelen_retrain/M1_summary.csv`).
Benign-only training edges drop **0** (Monday is all-BENIGN in both labellings), so
the retrain isolates the test-label change: ensemble-tie AUROC 0.705 / 0.676 /
0.540 versus M1's 0.704 / 0.587 / 0.511. The spread is training nondeterminism
(CPU training is not bit-reproducible: identical seeds/graphs give near-identical
loss curves but a different `best_state` epoch, hence different weights), not a
label effect.

**Consequence.** The label audit *corroborates* our labelling where it matters for
the headline (test-set classes) and documents where it diverges (attempted
sessions we do not model). It does not change the negative result: no labelling of
this capture brings `T` anywhere near the paper's 99%. The disagreements are
recorded per flow so a future labeler can act on them instead of re-deriving them.

---

## 6. P1 (conformal + sequential early exit)

**Decision.** P1 is presented as a **decision-layer** improvement only — no
architecture change. Claim set: TPR 14.11% @ FPR 5.78% (α = 0.10, Bonferroni) vs
M1 p8 4.18% @ 2.79%; APD 8.00 → 7.61 packets; 13.22% of attacks decided before
packet 8. α = 0.01 is structurally unreachable.

**Evidence.** Bonferroni at α = 0.01 with 7 steps needs `n_calib ≥ 2799`
(`4/(n+1) ≤ 0.01/7`), and `train2` provides 2,000 edges. P1 reuses the same
embeddings and detectors as M1, so any gain is attributable to the sequential rule,
not to representation learning.

**Consequence.** The P1 report carries the structural-floor explanation next to
the `Aborted` α = 0.01 rows, and no method change (no Holm, no max-p combination)
is introduced to work around it.
