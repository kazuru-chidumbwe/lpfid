#!/usr/bin/env python3
# S26 divergence classifier. Reads every results/<pkg>/keep/<patch>/v14.json and buckets each
# DIVERGENT module by whether its divergent functions are ONLY kpatch loader scaffolding
# (init_module / cleanup_module, with __pfx_ variants) or include a real patched function.
# Scaffolding-only -> non-fault (Deviation-4 class). Anything else -> FLAG for manual review
# (candidate genuine fault, may trip the Amazon-disclosure pre-registration gate).
import json, glob, os
from collections import defaultdict

SCAFFOLD = {"init_module", "cleanup_module",
            "__pfx_init_module", "__pfx_cleanup_module"}

scaffold_only = []
flagged = []
by_patch = defaultdict(list)

for f in sorted(glob.glob(os.path.expanduser("~/s26/results/*/keep/*/v14.json"))):
    pkg = f.split("/results/")[1].split("/keep/")[0]
    patch = os.path.basename(os.path.dirname(f))
    try:
        d = json.load(open(f))
    except Exception as e:
        flagged.append((pkg, patch, f"READ_ERROR:{e}"))
        continue
    dfns = [x.get("function") for x in d.get("divergent_functions", [])]
    mc = d.get("module_compilers"); rc = d.get("reference_compilers")
    comp_match = (mc == rc)
    nonscaffold = [fn for fn in dfns if fn not in SCAFFOLD]
    rec = (pkg, patch, dfns, comp_match)
    by_patch[patch].append((pkg, tuple(sorted(dfns)), comp_match))
    if nonscaffold:
        flagged.append((pkg, patch, nonscaffold, comp_match))
    else:
        scaffold_only.append(rec)

print(f"TOTAL divergent modules: {len(scaffold_only) + len(flagged)}")
print(f"SCAFFOLD-ONLY (non-fault, init/cleanup_module): {len(scaffold_only)}")
print(f"FLAGGED (non-scaffolding divergent fn): {len(flagged)}")
print()
print("=== distinct patch names and their divergent-function signatures ===")
for patch in sorted(by_patch):
    sigs = set(s for _, s, _ in by_patch[patch])
    cm = all(c for _, _, c in by_patch[patch])
    n = len(by_patch[patch])
    print(f"  {patch}  (x{n}, compilers_match={cm})")
    for sig in sorted(sigs):
        print(f"      divergent_functions={list(sig)}")
print()
print("=== FLAGGED detail (need manual root-cause) ===")
if not flagged:
    print("  none - every divergence is init_module/cleanup_module scaffolding")
for rec in flagged:
    print(" ", rec)
