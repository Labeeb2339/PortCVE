#!/usr/bin/env python3
"""Render the README terminal screenshot from a real `portcve list` run.

Requires a published Windows x64 build first:

    dotnet publish src\\PortCVE\\PortCVE.csproj -c Release -r win-x64 --self-contained true -o artifacts\\win-x64

Then:

    python tools/render_list_svg.py
    python tools/render_list_svg.py --check
"""

from __future__ import annotations

import argparse
import html
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "assets" / "portcve-list.svg"

FONT_SIZE = 13
CHAR_W = 7.8
LINE_H = 20
PAD = 22
TITLE_H = 38


def render(exe: Path, rows: int = 12) -> str:
    out = subprocess.run(
        [str(exe), "list"], capture_output=True, text=True,
        encoding="utf-8", errors="replace",
    ).stdout
    lines = out.splitlines()[:rows]

    maxlen = max(len(line) for line in lines)
    width = PAD * 2 + maxlen * CHAR_W
    height = TITLE_H + PAD + len(lines) * LINE_H + PAD

    texts = []
    y = TITLE_H + PAD + FONT_SIZE
    for i, line in enumerate(lines):
        color = "#58a6ff" if i == 0 else ("#484f58" if i == 1 else "#e6edf3")
        texts.append(f'<text x="{PAD}" y="{y:.0f}" fill="{color}">{html.escape(line)}</text>')
        y += LINE_H

    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" viewBox="0 0 {width:.0f} {height:.0f}" role="img" aria-labelledby="title desc">
  <title id="title">PortCVE list command output</title>
  <desc id="desc">Real terminal output of `portcve list` showing local listening ports mapped to owner process, scope, and PID.</desc>
  <style>
    text {{ font: {FONT_SIZE}px ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
    .title {{ font: 13px system-ui, sans-serif; fill: #8b949e; }}
  </style>
  <rect width="{width:.0f}" height="{height:.0f}" rx="12" fill="#0d1117"/>
  <rect width="{width:.0f}" height="{TITLE_H}" rx="12" fill="#161b22"/>
  <rect y="{TITLE_H - 6}" width="{width:.0f}" height="6" fill="#161b22"/>
  <circle cx="28" cy="{TITLE_H / 2:.0f}" r="6" fill="#f85149"/>
  <circle cx="48" cy="{TITLE_H / 2:.0f}" r="6" fill="#d29922"/>
  <circle cx="68" cy="{TITLE_H / 2:.0f}" r="6" fill="#3fb950"/>
  <text x="{width / 2:.0f}" y="{TITLE_H / 2 + 5:.0f}" text-anchor="middle" class="title">portcve list</text>
  {''.join(texts)}
</svg>
'''


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", default=str(ROOT / "artifacts" / "win-x64" / "portcve.exe"),
                        help="path to a published portcve.exe")
    parser.add_argument("--check", action="store_true", help="fail when the committed SVG is stale")
    args = parser.parse_args()

    exe = Path(args.exe)
    if not exe.exists():
        raise SystemExit(f"portcve.exe not found at {exe} — run dotnet publish first (see docstring)")

    expected = render(exe)

    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != expected:
            raise SystemExit(f"stale generated asset: {OUTPUT.relative_to(ROOT)}")
        print(f"up to date: {OUTPUT.relative_to(ROOT)}")
        return

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"wrote {OUTPUT.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
