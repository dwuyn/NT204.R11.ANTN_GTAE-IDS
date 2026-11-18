"""Fetch the MAY cross-dataset pcaps without downloading whole archives.

Neither source fits on this workstation as a whole:
  * CIC-IDS2018 one day  = 35.9-55.0 GiB compressed (per-host captures; 50.2 GiB raw for the
    day used here), while only the victim-side capture is needed;
  * ACI-IoT-2023         = 82.70 GiB compressed, while only 26.97 GiB of it is TCP-relevant.

Both are plain zip archives served over HTTP(S), so `remotezip` reads the central directory
and the extractor below fetches only selected members with Range requests (12 threads,
size-verified, atomic rename). The Kaggle URL is resolved through the API token in
``~/.kaggle/access_token``; the resulting GCS URL is signed for three days.

Usage::

    python scripts/fetch_dataset.py list  aci-iot2023
    python scripts/fetch_dataset.py list  cicids2018 --day Friday-16-02-2018 --captures 6
    python scripts/fetch_dataset.py fetch aci-iot2023      --out data/raw/aci
    python scripts/fetch_dataset.py fetch cicids2018 --day Friday-16-02-2018 --captures 6 \
        --out data/raw/cicids2018

Selection rules are the ones documented in ``docs/DATA_ACQUISITION.md`` and
``configs/{cicids2018,aci_iot2023}_schedule.yaml``; keep the three in sync.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import pathlib
import re
import sys
import threading
import time
import zlib
from typing import Iterable

import requests

S3_ROOT = "https://cse-cic-ids2018.s3.amazonaws.com/Original+Network+Traffic+and+Log+data"
KAGGLE_ACI = "emilynack/aci-iot-network-traffic-dataset-2023"
KAGGLE_TOKEN = pathlib.Path("~/.kaggle/access_token").expanduser()

_thread = threading.local()


def session() -> requests.Session:
    sess = getattr(_thread, "session", None)
    if sess is None:
        sess = requests.Session()
        _thread.session = sess
    return sess


def kaggle_signed_url(slug: str) -> str:
    """Resolve the time-limited GCS URL behind a Kaggle dataset download."""
    token_file = KAGGLE_TOKEN
    if not token_file.exists():
        raise FileNotFoundError(f"{token_file} missing; run `kaggle datasets list` once to authenticate")
    token = token_file.read_text().strip()
    resp = requests.get(
        f"https://www.kaggle.com/api/v1/datasets/download/{slug}",
        headers={"Authorization": f"Bearer {token}", "User-Agent": "kaggle-api"},
        allow_redirects=False,
        timeout=120,
    )
    if resp.status_code not in (301, 302, 303, 307, 308):
        raise RuntimeError(f"Kaggle did not redirect ({resp.status_code}); check the token")
    return resp.headers["location"]


def select_aci(name: str) -> bool:
    """TCP-relevant members: 2 benign days, PortScan, Dictionary Brute Force, Slowloris."""
    parts = name.split("/")
    if len(parts) < 4:
        return False
    folder, fn = parts[2], parts[-1]
    if folder == "Benign Pcaps":
        return fn.startswith(("2023-10-31", "2023-11-03"))
    if folder == "Brute Force Pcaps":
        return fn.startswith("2023-11-02")
    if folder == "Recon Pcaps":
        return fn.startswith(("2023-10-30-12", "2023-10-30-13", "2023-10-30-14", "2023-10-30-15"))
    if folder == "DoS_Pcaps":
        m = re.match(r"2023-11-01-(\d{2})_(\d{2})", fn)
        if not m:
            return False
        hh, mm = int(m.group(1)), int(m.group(2))
        return (hh == 9 and mm >= 58) or (hh == 10 and mm <= 26)
    return False


def select_cicids2018(name: str, largest: int) -> bool:
    """The `largest` biggest captures of the day (victim-side capture dominates)."""
    del name
    return largest > 0


def fetch_range(url: str, start: int, end: int) -> bytes:
    last: Exception | None = None
    for attempt in range(4):
        try:
            resp = session().get(url, headers={"Range": f"bytes={start}-{end}"}, timeout=300)
            if resp.status_code == 206:
                return resp.content
            last = RuntimeError(f"HTTP {resp.status_code}")
        except Exception as exc:  # noqa: BLE001 - retried below
            last = exc
        time.sleep(1.5 * (attempt + 1))
    raise last  # type: ignore[misc]


CHUNK = 32 << 20  # stream in 32 MiB ranges: a 1.2 GiB flood capture must not be buffered


def extract_member(url: str, info, dest: pathlib.Path) -> int:
    """Write one member from the remote zip; returns compressed bytes fetched (0 if skipped).

    Members are streamed to a ``.part`` file in 32 MiB ranges and decompressed incrementally,
    so memory stays ~CHUNK per worker instead of the whole member (the ACI flood captures are
    1.2 GiB compressed; buffering 12 of them exhausted this machine's 14 GiB of RAM).
    """
    if dest.exists() and dest.stat().st_size == info.file_size:
        return 0
    head = fetch_range(url, info.header_offset, info.header_offset + min(4095, info.compress_size - 1))
    if len(head) < 30 or head[:4] != b"PK\x03\x04":
        raise RuntimeError(f"bad local header for {info.filename}")
    name_len = int.from_bytes(head[26:28], "little")
    extra_len = int.from_bytes(head[28:30], "little")
    data_abs = info.header_offset + 30 + name_len + extra_len
    if info.compress_type not in (0, 8):
        raise RuntimeError(f"unsupported compression {info.compress_type}: {info.filename}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    decoder = zlib.decompressobj(-15) if info.compress_type == 8 else None
    written = 0
    with tmp.open("wb") as fh:
        pos = 0
        while pos < info.compress_size:
            stop = min(pos + CHUNK, info.compress_size)
            chunk = fetch_range(url, data_abs + pos, data_abs + stop - 1)
            if len(chunk) != stop - pos:
                raise RuntimeError(f"short read for {info.filename} at {pos}: {len(chunk)}")
            fh.write(decoder.decompress(chunk) if decoder else chunk)
            pos = stop
        if decoder:
            fh.write(decoder.flush())
    written = tmp.stat().st_size
    if written != info.file_size:
        tmp.unlink()
        raise RuntimeError(f"size mismatch for {info.filename}: {written} != {info.file_size}")
    tmp.replace(dest)
    return info.compress_size


def plan(name: str, args: argparse.Namespace) -> tuple[str, Iterable]:
    from remotezip import RemoteZip

    if name == "aci-iot2023":
        url = args.url or kaggle_signed_url(KAGGLE_ACI)
        with RemoteZip(url) as archive:
            selected = [i for i in archive.infolist() if select_aci(i.filename)]
        return url, selected
    if name == "cicids2018":
        if not args.day:
            raise SystemExit("--day is required for cicids2018")
        url = args.url or f"{S3_ROOT}/{args.day}/pcap.zip"
        with RemoteZip(url) as archive:
            members = sorted(archive.infolist(), key=lambda i: -i.file_size)
            if args.captures <= 0:
                raise SystemExit("--captures must be positive for cicids2018")
            selected = members[: args.captures]
        return url, selected
    raise SystemExit(f"unknown dataset: {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("list", "fetch"):
        p = sub.add_parser(command)
        p.add_argument("dataset", choices=["aci-iot2023", "cicids2018"])
        p.add_argument("--day", help="CIC-IDS2018 day folder, e.g. Friday-16-02-2018")
        p.add_argument("--captures", type=int, default=6, help="CIC-IDS2018: take the N largest captures")
        p.add_argument("--url", help="override the resolved archive URL")
        if command == "fetch":
            p.add_argument("--out", required=True, help="destination root for extracted files")
            p.add_argument("--workers", type=int, default=12)
    args = parser.parse_args(argv)

    url, selected = plan(args.dataset, args)
    raw = sum(i.file_size for i in selected)
    comp = sum(i.compress_size for i in selected)
    print(f"{args.dataset}: {len(selected)} members, {raw / 2**30:.2f} GiB raw, "
          f"{comp / 2**30:.2f} GiB to fetch", flush=True)
    for info in sorted(selected, key=lambda i: -i.file_size)[:5]:
        print(f"  {info.file_size / 2**20:8.1f} MiB  {info.filename}", flush=True)
    if args.command == "list":
        return 0

    out = pathlib.Path(args.out)
    t0 = time.time()
    done = 0
    fetched = 0
    with cf.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(extract_member, url, i, out / i.filename): i for i in selected}
        for fut in cf.as_completed(futures):
            fetched += fut.result()
            done += 1
            if done % 50 == 0 or done == len(selected):
                print(f"[{done}/{len(selected)}] {fetched / 2**30:6.2f} GiB "
                      f"in {(time.time() - t0) / 60:5.1f} min", flush=True)
    print(f"done: {done} members under {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
