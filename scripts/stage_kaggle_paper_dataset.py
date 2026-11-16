#!/usr/bin/env python3
"""Stage the Kaggle dataset for the ``P_paper`` p=8 training kernel.

    python scripts/stage_kaggle_paper_dataset.py
    kaggle datasets create -p artifacts/kaggle_paper_parity
    kaggle kernels push -p kaggle/paper_parity

Writes ``artifacts/kaggle_paper_parity/paper_parity_artifacts.tar.gz`` (code +
``data/graphs/P_paper``) and its ``dataset-metadata.json``. ``artifacts/`` is
git-ignored, so nothing here is committed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CODE_PATHS = ("src", "scripts", "configs", "pytest.ini", "requirements.txt")
DATASET_ID = "tdwuyn/gtae-ids-paper-parity"
DATASET_TITLE = "GTAE-IDS paper parity graphs"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graphs", default="data/graphs/P_paper")
    parser.add_argument("--out", default="artifacts/kaggle_paper_parity")
    parser.add_argument("--dataset-id", default=DATASET_ID)
    args = parser.parse_args(argv)

    graph_root = (REPO_ROOT / args.graphs).resolve()
    if not (graph_root / "p8" / "test.npz").exists():
        raise FileNotFoundError(
            f"{graph_root}/p8/test.npz missing; run scripts/build_paper_graphs.py --ps 8 first"
        )
    out = (REPO_ROOT / args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    members = [p for p in CODE_PATHS if (REPO_ROOT / p).exists()]
    relative_graphs = graph_root.relative_to(REPO_ROOT)
    archive = out / "paper_parity_artifacts.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name in members:
            bundle.add(REPO_ROOT / name, arcname=name)
        bundle.add(graph_root, arcname=str(relative_graphs))
    print(f"wrote {archive} ({archive.stat().st_size / 1e6:.1f} MB)", flush=True)
    print("members:", ", ".join(members + [str(relative_graphs)]), flush=True)

    metadata = out / "dataset-metadata.json"
    metadata.write_text(
        json.dumps(
            {
                "title": DATASET_TITLE,
                "id": args.dataset_id,
                "licenses": [{"name": "CC0-1.0"}],
            }
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {metadata}", flush=True)
    if subprocess.run(["which", "kaggle"], capture_output=True).returncode != 0:
        print("kaggle CLI not on PATH; upload manually", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
