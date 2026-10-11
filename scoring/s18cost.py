#!/usr/bin/env python3
"""S18: cost and determinism of the static checks (manuscript 6.6), on the build host while nothing else runs.

For each of the 123 unmodified S12 modules (reference R-kp): the oracle (v1.2 if its validation passed, else v1.1)
is run 30 times, one run at a time, with the pin vmlinux (so the sympos check is included). Recorded: wall-clock
seconds per run; median and interquartile range per module and overall; whether the 30 reports are identical
(SHA-256 of the JSON report). Usage: python3 s18cost.py   (writes /opt/atlas/s18/cost.json)
"""
import hashlib
import json
import statistics
import subprocess
import time
from pathlib import Path

A = Path("/opt/atlas")
C = A / "livepatch-corpus"
PY = A / "venvs/lpfid-oracle-v11/bin/python"
TREES = {"6.1": C / "linux-second-pin", "6.6": C / "pilot-work/linux", "6.12": C / "linux-6.12.51"}
OUT = A / "s18/cost.json"
REPEATS = 30


def quart(xs):
    q = statistics.quantiles(xs, n=4)
    return [round(q[0], 3), round(q[2], 3)]


def main() -> int:
    v12 = json.loads((A / "lpfid/oracle-v12-validation.json").read_text())["summary"].get("pass") is True
    oracle = A / ("lpfid/blind-reloc-oracle-v1.2.py" if v12 else "lpfid/blind-reloc-oracle-v1.1.py")
    rows = []
    for r in json.loads((A / "s12/oracle/rkp.json").read_text())["rows"]:
        tree = TREES[r["branch"]]
        cmd = [str(PY), str(oracle), r["module"], *r["refs"], "--vmlinux", str(tree / "vmlinux"), "--modules-dir", str(tree)]
        secs, digests = [], set()
        for _ in range(REPEATS):
            t0 = time.perf_counter()
            p = subprocess.run(cmd, capture_output=True, text=True)
            secs.append(time.perf_counter() - t0)
            digests.add(hashlib.sha256(p.stdout.encode()).hexdigest())
        rows.append({"module": f"{r['branch']}/{r['cve']}", "median_s": round(statistics.median(secs), 3),
                     "iqr_s": quart(secs), "identical_reports": len(digests) == 1})
        print(rows[-1], flush=True)
    meds = [x["median_s"] for x in rows]
    summary = {"oracle": oracle.name, "oracle_sha256": hashlib.sha256(oracle.read_bytes()).hexdigest(), "modules": len(rows),
               "repeats": REPEATS, "median_of_medians_s": round(statistics.median(meds), 3), "iqr_of_medians_s": quart(meds),
               "max_median_s": max(meds), "deterministic_modules": sum(x["identical_reports"] for x in rows)}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({"summary": summary, "rows": rows}, indent=1))
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
