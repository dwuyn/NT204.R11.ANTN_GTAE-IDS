"""Concatenate classic pcap files into ONE valid pcap stream.

Plain ``cat a.pcap b.pcap`` is **not** valid: every file starts with a 24-byte global
header, and a reader interprets that header as a packet record (ts_sec = 0xa1b2c3d4,
a huge incl_len), so parsing stops shortly after the first file. This script validates
that all global headers are byte-identical, keeps the first one and appends only the
record areas (fast stream copy). It aborts on the first mismatch instead of silently
producing garbage.

Usage::

    python scripts/merge_pcaps.py --out data/raw/aci/merged/benign1.pcap \\
        --include "Benign Pcaps" --glob "2023-10-31-*"

``--include`` is a subdirectory of ``--root``; ``--glob`` filters file names.
"""

from __future__ import annotations

import argparse
import pathlib
import shutil

HEADER = 24
CHUNK = 8 << 20
MAGICS = {b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"}  # little-endian, us and ns


def merge(paths: list[pathlib.Path], out: pathlib.Path) -> tuple[int, int]:
    """Write one pcap; return (files merged, bytes written)."""
    if not paths:
        raise SystemExit("no input files")
    with paths[0].open("rb") as fh:
        header = fh.read(HEADER)
    if len(header) < HEADER:
        raise SystemExit(f"{paths[0]} is shorter than a pcap global header")
    if header[:4] not in MAGICS:
        raise SystemExit(
            f"{paths[0]}: unsupported pcap magic {header[:4].hex()} "
            "(pcapng or big-endian is not mergeable this way)"
        )

    out.parent.mkdir(parents=True, exist_ok=True)
    written = HEADER
    with out.open("wb") as dst:
        dst.write(header)
        for path in paths:
            with path.open("rb") as src:
                if src.read(HEADER) != header:
                    size = path.stat().st_size
                    raise SystemExit(
                        f"{path} ({size} B): global header differs from {paths[0]}; "
                        "refusing to build an invalid stream"
                    )
                shutil.copyfileobj(src, dst, CHUNK)
            written += path.stat().st_size - HEADER
    return len(paths), written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default="data/raw/aci/pcap_combined/Combined_Pcaps")
    parser.add_argument("--include", required=True)
    parser.add_argument("--glob", default="*.pcap")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)

    folder = pathlib.Path(args.root) / args.include
    paths = sorted(folder.glob(args.glob))
    files, size = merge(paths, pathlib.Path(args.out))
    print(f"{args.out}: {files} files, {size / 2**30:.2f} GiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
