"""Kaggle GPU runner for the A2 no-LapPE ablation.

Reuses tdwuyn/gtae-ids-ablation (code + T graphs) and trains p=8 x 3 seeds
with --no-pe. The checkpoints are downloaded for local detector evaluation.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

INPUT = Path("/kaggle/input")
WORK = Path("/kaggle/working")
ROOT = WORK / "gtae"
ROOT.mkdir(parents=True, exist_ok=True)

archives = list(INPUT.glob("**/ablation_artifacts.tar.gz"))
if archives:
    with tarfile.open(archives[0], "r:*") as handle:
        handle.extractall(ROOT)
else:
    code_root = None
    for base, _dirs, files in os.walk(INPUT):
        base_path = Path(base)
        if base_path.name == "scripts" and "train_all.py" in files:
            code_root = base_path.parent
            break
    if code_root is None:
        raise FileNotFoundError(f"no training files under {INPUT}")
    for name in ("src", "scripts", "configs", "pytest.ini", "requirements.txt", "data"):
        source = code_root / name
        target = ROOT / name
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        elif source.exists():
            shutil.copy2(source, target)

import torch  # noqa: E402

print("=== environment", flush=True)
print("torch", torch.__version__, "cuda", torch.cuda.is_available(), flush=True)
if torch.cuda.is_available():
    print("gpu", torch.cuda.get_device_name(0), flush=True)

cmd = [
    sys.executable,
    "scripts/train_all.py",
    "--graphs", "data/graphs/T",
    "--out", "experiments/T_noPE",
    "--ps", "8",
    "--seeds", "0", "1", "2",
    "--epochs", "100",
    "--patience", "10",
    "--no-pe",
    "--device", "auto",
    "--resume",
]
print("=== train:", " ".join(cmd), flush=True)
subprocess.run(cmd, cwd=ROOT, check=True)

out = WORK / "experiments" / "T_noPE"
shutil.copytree(ROOT / "experiments" / "T_noPE", out, dirs_exist_ok=True)
print("=== outputs", flush=True)
for path in sorted(out.rglob("*")):
    if path.is_file():
        print(path.relative_to(WORK), path.stat().st_size, flush=True)
