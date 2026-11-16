# P_paper training kernel

Trains p=8 M1 (GTAE edge autoencoder) on the paper-parity split for seeds 0/1/2,
then bundles each `model.pt` into `/kaggle/working/P_paper_models.zip`.

## Dataset

`tdwuyn/gtae-ids-paper-parity` is staged locally from the repo and must contain:

```
src/                      # package source
scripts/train_all.py      # resumable runner
configs/
pytest.ini
data/graphs/P_paper/p8/{train1,train2,test}.npz
```

Build the graphs first (`scripts/build_paper_graphs.py --ps 8`), then stage and
upload:

```bash
python scripts/stage_kaggle_paper_dataset.py          # writes artifacts/kaggle_paper_parity/
kaggle datasets create -p artifacts/kaggle_paper_parity   # or: kaggle datasets version -p ...
```

## Run

```bash
kaggle kernels push -p kaggle/paper_parity
kaggle kernels status tdwuyn/gtae-ids-paper-parity-train
kaggle kernels output tdwuyn/gtae-ids-paper-parity-train -p experiments/P_paper_models
unzip -o experiments/P_paper_models/P_paper_models.zip -d experiments/P_paper
```

The kernel uses `--resume`, so pushing it again after a session limit continues
where it stopped instead of retraining finished seeds.

## Why a separate split

`data/graphs/P_paper` re-uses the CICFlowMeter CSV rows as flow definitions and
the paper's Table VII per-class test counts, so the trained checkpoints are only
comparable within `P_paper`; never mix them with `experiments/T`.

## Training record

The reported checkpoints (`experiments/P_paper/p8/seed{0,1,2}`) were trained
locally on CPU — 2 minutes per seed, same code path, seeds and hyperparameters,
so the numbers are bit-identical in intent to a T4 run. The GPU queue never left
`QUEUED` for this kernel; it stays here as the GPU reproduction path:

```bash
.venv/bin/python scripts/train_all.py --graphs data/graphs/P_paper \
  --out experiments/P_paper --ps 8 --seeds 0 1 2 --epochs 100 --patience 100 \
  --device cpu --resume
```
