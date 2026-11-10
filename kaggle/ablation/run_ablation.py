"""Kaggle GPU runner for the A3 reconstruction-error ablation."""

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
        if base_path.name == "scripts" and "eval_recon_ablation.py" in files:
            code_root = base_path.parent
            break
    if code_root is None:
        raise FileNotFoundError(f"no ablation files under {INPUT}")
    for name in ("src", "scripts", "configs", "pytest.ini", "requirements.txt", "data", "experiments", "results"):
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
    "scripts/eval_recon_ablation.py",
    "--graphs", "data/graphs/T",
    "--models", "experiments/T",
    "--ps", "2", "4", "8",
    "--seeds", "0", "1", "2",
    "--out", "results",
    "--device", "auto",
]
print("=== recon:", " ".join(cmd), flush=True)
subprocess.run(cmd, cwd=ROOT, check=True)

print("=== ablation report", flush=True)
subprocess.run(
    [sys.executable, "scripts/make_ablation_report.py"],
    cwd=ROOT,
    check=True,
)

shutil.copytree(ROOT / "results", WORK / "results", dirs_exist_ok=True)
shutil.copy2(ROOT / "reports" / "ablation.md", WORK / "ablation.md")
print("=== outputs", flush=True)
for path in sorted((WORK / "results").glob("*")):
    print(path.name, path.stat().st_size, flush=True)
print("ablation.md", (WORK / "ablation.md").stat().st_size, flush=True)
