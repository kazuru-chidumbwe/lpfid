#!/usr/bin/env python3
"""S43 draw: per architecture, ten packages from each of the 6.1, 6.12 and 6.18 series (all of a series if it has
fewer than ten unopened), seed 43 (random.Random("43:<arch>:<series>")), over the series-sorted list of frame
packages not in opened.txt. usage: s43_draw.py > draw.json"""
import json, random, re
from datetime import date
opened = set(open("opened.txt").read().split())
SER = re.compile(r"^kernel-livepatch-(6\.(?:1|12|18))\.\d+-")
out = {"seed": 43, "date": str(date.today()), "opened": len(opened), "draw": {}, "frame": {}, "unopened": {}}
for arch in ("x86_64", "aarch64"):
    frame = sorted(n for n in open(f"frame-{arch}.txt").read().split() if SER.match(n))
    out["frame"][arch] = len(frame)
    out["draw"][arch], out["unopened"][arch] = {}, {}
    for ser in ("6.1", "6.12", "6.18"):
        pool = sorted(n for n in frame if SER.match(n).group(1) == ser and n not in opened)
        out["unopened"][arch][ser] = len(pool)
        out["draw"][arch][ser] = sorted(random.Random(f"43:{arch}:{ser}").sample(pool, min(10, len(pool))))
print(json.dumps(out, indent=1))
