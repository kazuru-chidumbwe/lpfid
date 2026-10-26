"""Distinct fixes per stratum pooled over both architectures (a fix alarms if any module on either arch alarms)."""
import json, re, math, sys
CVE = re.compile(r"CVE-\d{4}-\d+")
seen = set(json.load(open("seen-fixes-2026-10-24.json"))["fixes"])
def key(name):
    m = CVE.search(name)
    if m: return m.group(0)
    k = re.sub(r"\.ko$", "", re.sub(r"^livepatch-", "", name.lower())).replace(".", "-").replace("&", "-")
    return re.sub(r"-6-(1|12|18)$", "", k)
def wilson(k, n, z=1.959964):
    p=k/n; d=1+z*z/n; c=p+z*z/(2*n); h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n)); return [round(max(0,(c-h)/d),4), round(min(1,(c+h)/d),4)]
fx = {}
mods = {}
for f in ("from-tb/results-x86_64.jsonl", "from-graviton/s44/results-aarch64.jsonl"):
    for l in open(f):
        r = json.loads(l)
        for m in r.get("modules", []):
            name = m.get("patch") or m["ko"]
            st = "D" if ("CVE-2026-31431" in name or "CVE-2026-31431" in m["ko"] or "memcpy_sglist" in (m["v21"].get("compared") or [])) else ("H-seen" if key(name) in seen else "H-new")
            k = key(name); a = m["v21"]["overall"] != "CONSISTENT"
            fx.setdefault(st, {}); fx[st][k] = fx[st].get(k, False) or a
            mods[st] = mods.get(st, 0) + 1
tot = {}
for st, d in sorted(fx.items()):
    k = sum(d.values()); n = len(d); print(st, "fixes", k, "/", n, wilson(k, n), "modules", mods[st])
allf = {}
for d in fx.values():
    for k, v in d.items(): allf[k] = allf.get(k, False) or v
H = {}
for st in ("H-new", "H-seen"):
    for k, v in fx[st].items(): H[k] = H.get(k, False) or v
print("H", sum(H.values()), "/", len(H), wilson(sum(H.values()), len(H)))
print("all", sum(allf.values()), "/", len(allf), wilson(sum(allf.values()), len(allf)))
