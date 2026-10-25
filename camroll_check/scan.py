"""camroll-check: find screenshots and photos with secrets in a folder.

Usage:
    python -m camroll_check.scan ~/Pictures/iphone-export
    python -m camroll_check.scan ./photos --since 2024-01-01 --out ./report

Everything runs locally. Only masked values are printed or saved.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import html
import io
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path

from PIL import ImageFilter

from . import ocr
from .detectors import HIGH, LOW, MEDIUM, scan_text

EXTS = {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tif", ".tiff"}
if ocr.HEIC:
    EXTS |= {".heic", ".heif"}

SEV_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


def iter_images(root: Path, since: dt.date | None):
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            p = Path(dirpath) / name
            if p.suffix.lower() not in EXTS:
                continue
            if since and dt.date.fromtimestamp(p.stat().st_mtime) < since:
                continue
            yield p


def scan_one(path: str):
    try:
        text = ocr.read_text(path)
    except Exception as e:  # unreadable file, keep going
        return path, None, str(e)
    return path, [asdict(f) for f in scan_text(text)], None


def blurred_thumb(path: str, width: int = 220) -> str:
    img = ocr.open_image(path)
    k = width / img.width
    img = img.resize((width, max(1, int(img.height * k))))
    img = img.filter(ImageFilter.GaussianBlur(radius=9))
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=70)
    return base64.b64encode(buf.getvalue()).decode()


def write_report(results, out: Path, scanned: int):
    out.mkdir(parents=True, exist_ok=True)
    (out / "findings.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    cards = []
    for r in results:
        thumb = blurred_thumb(r["path"])
        rows = "".join(
            f'<li class="{html.escape(f["severity"])}"><b>{html.escape(f["kind"])}</b> '
            f'{html.escape(f["masked"])} <span>{html.escape(f["note"])}</span></li>'
            for f in r["findings"])
        cards.append(
            f'<div class="card"><img src="data:image/jpeg;base64,{thumb}">'
            f'<div class="meta"><code>{html.escape(r["path"])}</code><ul>{rows}</ul></div></div>')
    counts = {s: sum(1 for r in results for f in r["findings"] if f["severity"] == s)
              for s in (HIGH, MEDIUM, LOW)}
    page = f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>camroll-check report</title><style>
body{{background:#0a0c12;color:#d6dae0;font:14px ui-monospace,Menlo,monospace;margin:0;padding:16px}}
h1{{color:#f06464;font-size:20px}} .sum span{{margin-right:18px}}
.card{{display:flex;gap:14px;border:1px solid #f0646455;border-radius:8px;padding:10px;margin:10px 0}}
.card img{{width:110px;border-radius:4px;border:2px solid #f06464}}
code{{color:#7c8590;font-size:12px;word-break:break-all}} ul{{padding-left:18px;margin:6px 0}}
li.high b{{color:#f06464}} li.medium b{{color:#f0c85a}} li.low b{{color:#78d2e6}} li span{{color:#7c8590}}
</style></head><body>
<h1>{len(results)} of {scanned} images contain sensitive text</h1>
<p class="sum"><span style="color:#f06464">high: {counts[HIGH]}</span>
<span style="color:#f0c85a">medium: {counts[MEDIUM]}</span>
<span style="color:#78d2e6">low: {counts[LOW]}</span></p>
<p>thumbnails are blurred and values are masked. open the original file to check it, then delete it
and empty Recently Deleted.</p>
{''.join(cards)}</body></html>"""
    (out / "report.html").write_text(page)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", type=Path)
    ap.add_argument("--out", type=Path, default=Path("camroll-report"))
    ap.add_argument("--since", type=dt.date.fromisoformat, help="only files modified on/after YYYY-MM-DD")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    ap.add_argument("--limit", type=int, default=0, help="stop after N images (0 = all)")
    a = ap.parse_args(argv)

    if not a.folder.is_dir():
        sys.exit(f"not a folder: {a.folder}")
    paths = [str(p) for p in iter_images(a.folder, a.since)]
    if a.limit:
        paths = paths[: a.limit]
    print(f"[camroll-check] ocr: {ocr.BACKEND}, heic: {ocr.HEIC}, images: {len(paths)}")

    results, errors, done = [], 0, 0
    with ProcessPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(scan_one, p) for p in paths]
        for fut in as_completed(futs):
            path, findings, err = fut.result()
            done += 1
            if err:
                errors += 1
            elif findings:
                findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
                results.append({"path": path, "findings": findings})
                top = findings[0]
                print(f"  found: {top['kind']:<15} {top['severity']:<6} {Path(path).name}")
            if done % 200 == 0:
                print(f"  ... {done}/{len(paths)}")

    results.sort(key=lambda r: (SEV_ORDER[r["findings"][0]["severity"]], r["path"]))
    write_report(results, a.out, len(paths))
    by_kind: dict[str, int] = {}
    for r in results:
        for f in r["findings"]:
            by_kind[f["kind"]] = by_kind.get(f["kind"], 0) + 1
    print(f"\n[camroll-check] scanned {len(paths)}, flagged {len(results)}, unreadable {errors}")
    for k, n in sorted(by_kind.items(), key=lambda x: -x[1]):
        print(f"  {k:<18} {n}")
    print(f"report: {a.out / 'report.html'}")


if __name__ == "__main__":
    main()
