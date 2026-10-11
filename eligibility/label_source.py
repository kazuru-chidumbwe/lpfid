#!/usr/bin/env python3
"""S6b: mechanical source labels for the revert-eligibility check, by the rules of the S6 labelling protocol
(pilot/results/LP-PRE-REAL/LABEL-PROTOCOL.md, written 14 Sep 2026). Labels come from source only; no binary is read.

  in-tree C source (local #include "*.c" resolved; target modules without klp_enable_patch and without
  MODULE_INFO(livepatch, ...) are excluded):
    SHADOW     a call to klp_shadow_{alloc,get,get_or_alloc,free,free_all}
    CALLBACKS  an assignment to pre_patch, post_patch, pre_unpatch or post_unpatch (designated initialiser or
               runtime assignment)
    REPLACE    an assignment to .replace / ->replace whose value is not false or 0 (a module parameter counts,
               recorded as conditional)
    STATES     an assignment of a non-NULL .states, or a call to klp_get_state / klp_get_prev_state
  patch (kpatch integration patch or CVE fix), added lines only:
    SHADOW     klp_shadow_* or kpatch_shadow_*
    CALLBACKS  KPATCH_ or KLP_ {PRE,POST}_{PATCH,UNPATCH}_CALLBACK
    STATES     klp_get_state / klp_get_prev_state
    REPLACE    fixed by the recorded build flag (kpatch-build -R, klp-build --no-replace: 0)
Class: OUT_OF_SCOPE if any label is 1, else PASSES_PRE.
Usage: label_source.py c FILE.c [--replace-flag 0|1] | label_source.py patch FILE.patch --replace-flag 0|1
Prints one JSON object.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SHADOW_C = re.compile(r"\bklp_shadow_(alloc|get|get_or_alloc|free|free_all)\s*\(")
CB_C = re.compile(r"(\.|->)\s*(pre|post)_(un)?patch\s*=(?!=)")
REPL_C = re.compile(r"(\.|->)\s*replace\s*=(?!=)\s*([^,;}\n]+)")
STATES_C = re.compile(r"(\.|->)\s*states\s*=(?!=)\s*([^,;}\n]+)")
STATEFN = re.compile(r"\bklp_get_(prev_)?state\s*\(")
SHADOW_P = re.compile(r"\b(klp|kpatch)_shadow_\w+\s*\(")
CB_P = re.compile(r"\b(KPATCH|KLP)_(PRE|POST)_(UN)?PATCH_CALLBACK\b")
PARAM = re.compile(r"module_param\(\s*(\w+)\s*,[^)]*\)")


def strip_comments(s: str) -> str:
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    return re.sub(r"//[^\n]*", " ", s)


def resolve(path: Path, seen: set | None = None) -> str:
    seen = seen or set()
    text = path.read_text(errors="replace")
    out = []
    for line in text.splitlines():
        m = re.match(r'\s*#\s*include\s+"([^"]+\.c)"', line)
        if m and (path.parent / m.group(1)).exists() and m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(resolve(path.parent / m.group(1), seen))
        else:
            out.append(line)
    return "\n".join(out)


def label_c(path: Path) -> dict:
    s = strip_comments(resolve(path))
    if "klp_enable_patch" not in s and not re.search(r'MODULE_INFO\(\s*livepatch', s):
        return {"excluded": "target module (no klp_enable_patch, no MODULE_INFO(livepatch))"}
    params = set(PARAM.findall(s))
    repl, cond = 0, ""
    for _, v in REPL_C.findall(s):
        v = v.strip()
        if v in ("false", "0"):
            continue
        repl = 1
        if v in params:
            cond = f"param:{v}"
    states = int(bool(STATEFN.search(s)) or any(v.strip() not in ("NULL", "0") for _, v in STATES_C.findall(s)))
    lab = {"SHADOW": int(bool(SHADOW_C.search(s))), "CALLBACKS": int(bool(CB_C.search(s))), "REPLACE": repl,
           "STATES": states, "conditional": cond}
    lab["class"] = "OUT_OF_SCOPE" if any(lab[k] for k in ("SHADOW", "CALLBACKS", "REPLACE", "STATES")) else "PASSES_PRE"
    return lab


def label_patch(path: Path, replace_flag: int) -> dict:
    added = "\n".join(l[1:] for l in path.read_text(errors="replace").splitlines()
                      if l.startswith("+") and not l.startswith("+++"))
    added = strip_comments(added)
    lab = {"SHADOW": int(bool(SHADOW_P.search(added))), "CALLBACKS": int(bool(CB_P.search(added))),
           "REPLACE": replace_flag, "STATES": int(bool(STATEFN.search(added))), "conditional": ""}
    lab["class"] = "OUT_OF_SCOPE" if any(lab[k] for k in ("SHADOW", "CALLBACKS", "REPLACE", "STATES")) else "PASSES_PRE"
    return lab


def main() -> int:
    kind, f = sys.argv[1], Path(sys.argv[2])
    flag = int(sys.argv[sys.argv.index("--replace-flag") + 1]) if "--replace-flag" in sys.argv else 0
    print(json.dumps(label_c(f) if kind == "c" else label_patch(f, flag)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
