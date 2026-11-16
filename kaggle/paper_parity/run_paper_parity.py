"""Kaggle GPU runner: train p=8 M1 on the paper-parity split ``P_paper``.

The attached dataset carries ``src/``, ``scripts/`` and
``data/graphs/P_paper/p8``; the kernel copies them into a writable workspace and
runs ``scripts/train_all.py`` for seeds 0/1/2 with ``--resume`` so a session
restart continues instead of retraining.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

INPUT = Path("/kaggle/input")
WORK = Path("/kaggle/working")
ROOT = WORK / "gtae"

ROOT.mkdir(parents=True, exist_ok=True)
archives = list(INPUT.glob("**/paper_parity_artifacts.tar.gz"))
if archives:
    with tarfile.open(archives[0], "r:*") as handle:
        handle.extractall(ROOT)
    print(f"extracted {archives[0]}", flush=True)
else:
    code_mount = None
    graph_roots: list[Path] = []
    for base, _dirs, files in os.walk(INPUT):
        base_path = Path(base)
        if code_mount is None and "train_gtae.py" in files and base_path.name == "src":
            code_mount = base_path.parent
        if base_path.name == "P_paper" and base_path.parent.name == "graphs":
            graph_roots.append(base_path)
    if code_mount is None:
        raise FileNotFoundError(f"no code mount under {INPUT}")
    if not graph_roots:
        raise FileNotFoundError(f"no data/graphs/P_paper mount under {INPUT}")
    for name in ("src", "configs", "scripts", "pytest.ini", "requirements.txt"):
        source = code_mount / name
        target = ROOT / name
        if source.is_dir():
            shutil.copytree(source, target, dirs_exist_ok=True)
        elif source.exists():
            shutil.copy2(source, target)
    graph_root = ROOT / "data" / "graphs" / "P_paper"
    for source in graph_roots:
        shutil.copytree(source, graph_root, dirs_exist_ok=True)

graph_root = ROOT / "data" / "graphs" / "P_paper"
for part in sorted(graph_root.glob("p*")):
    test = part / "test.npz"
    print(
        f"{part.name}: train1={part.joinpath('train1.npz').exists()} "
        f"train2={part.joinpath('train2.npz').exists()} test={test.exists()} "
        f"test_bytes={test.stat().st_size if test.exists() else 0}",
        flush=True,
    )

import torch  # noqa: E402

print("=== environment", flush=True)
print("torch", torch.__version__, "cuda", torch.cuda.is_available(), flush=True)
if torch.cuda.is_available():
    print("gpu", torch.cuda.get_device_name(0), flush=True)

cmd = [
    sys.executable,
    str(ROOT / "scripts" / "train_all.py"),
    "--graphs",
    str(graph_root),
    "--out",
    str(WORK / "experiments" / "P_paper"),
    "--ps",
    "8",
    "--seeds",
    "0",
    "1",
    "2",
    "--epochs",
    "100",
    "--batch-subgraphs",
    "50",
    "--max-edges",
    "200",
    "--patience",
    "100",
    "--device",
    "auto",
    "--resume",
]
print("=== CMD:", " ".join(cmd), flush=True)
subprocess.run(cmd, check=True, cwd=str(ROOT))

run_log = WORK / "experiments" / "P_paper" / "runs.jsonl"
if run_log.exists():
    print(run_log.read_text(), flush=True)

models = sorted((WORK / "experiments" / "P_paper").glob("p8/seed*/model.pt"))
print("=== models", [str(p) for p in models], flush=True)
if not models:
    raise FileNotFoundError("no model.pt produced")

archive = WORK / "P_paper_models.zip"
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
    for model in models:
        bundle.write(model, str(model.relative_to(WORK / "experiments" / "P_paper")))
print(f"=== wrote {archive} ({archive.stat().st_size} bytes)", flush=True)
