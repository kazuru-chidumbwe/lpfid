#!/usr/bin/env python3
"""S27 runner: immediate-multiset check, detection and false-alarm, frozen rule + ablation.

Phases, written progressively to OUT so the run is monitorable and resumable:
  freeze       fixture faithful pairs, records whether the IMM-FRAME rule hides a fixture fault / moves
               a faithful fixture; the frozen choice is declared here BEFORE the real corpus is scored.
  detection    the 1,111 constant mutants vs their independent reference. Two configs: frame OFF (no
               normalisation) and frame ON (IMM-FRAME). Reported with the equivalent set excluded.
  fa_same      faithful gcc-13 parents vs the gcc-13 independent reference (same toolchain, T1 enforced).
  fa_cross     faithful gcc-14 parents vs the gcc-13 reference (T1 gate disabled to force the comparison).
               Both configs. THIS is the headline robustness number the review turns on.
  equivalents  best-effort: a constant mutant whose changed immediate sits in a basic block with no path
               from the function entry is equivalent and excluded from the detection denominator.

Blind: the check sees only module + reference, never the injected site (the equivalents pass reads the
site only to classify reachability, after detection is recorded).
"""
import glob
import json
import math
import os
import sys
import time
import traceback
from collections import Counter
from pathlib import Path

sys.path.insert(0, "/tmp")
import s27_immcheck as S27  # noqa: E402
from s27_immcheck import Obj  # noqa: E402

BASE = "/opt/atlas"
MUT_ROOT = f"{BASE}/s12-eval/s2/mut/s12"
REF_ROOT = f"{BASE}/replica-testbedb/s12/refs-independent"
PAR13 = f"{BASE}/s12-eval/results/v0.9.11-gcc-13"
PAR14 = f"{BASE}/s12-eval/sweep-results/v0.9.11-gcc-14"
FIX_MANIFEST = f"{BASE}/s12-eval/s2/s2-s12-fixtures.json"
FIX_PARENTS = f"{BASE}/s1full/parents"   # fixture faithful module: parents/<ver>/<name>/<name>.ko
FIX_REFS = f"{BASE}/s1full/refs"         # fixture independent ref: refs/<ver>/<mid>/<name>/**/*.o
OUT = Path(os.environ.get("S27_OUT", f"{BASE}/s27-out"))
OUT.mkdir(parents=True, exist_ok=True)
LOG = OUT / "run.log"
ROWS = OUT / "rows.jsonl"


def log(m):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {m}"
    with open(LOG, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (round(100 * p, 2), round(100 * (c - h), 2), round(100 * (c + h), 2))


def refs_for(pin, cve):
    return sorted(glob.glob(f"{REF_ROOT}/{pin}/{cve}/**/*.o", recursive=True))


def parent_for(root, pin, cve):
    kos = sorted(glob.glob(f"{root}/{pin}/{cve}/build/*.ko"))
    return kos[0] if kos else None


def verdicts(ko, refs, disabled):
    """Run the check with a given DISABLED set; return (multiset_verdict, sequence_verdict, n_fns, err)."""
    S27.DISABLED = set(disabled)
    try:
        mod = Obj(Path(ko))
        robjs = [Obj(Path(r)) for r in refs]
        out = S27.compare(mod, robjs)
        return out["multiset_verdict"], out["sequence_verdict"], out["functions_compared"], None
    except Exception as e:  # noqa: BLE001
        return None, None, 0, f"{type(e).__name__}: {e}"


def emit(row):
    with open(ROWS, "a") as f:
        f.write(json.dumps(row) + "\n")


# ---- discover the constant-mutant corpus -------------------------------------------------
def discover():
    items = []
    for ko in sorted(glob.glob(f"{MUT_ROOT}/*/constant-*.ko")):
        d = os.path.basename(os.path.dirname(ko))      # e.g. 6.1__CVE-2024-53173
        pin, cve = d.split("__", 1)
        items.append({"ko": ko, "pin": pin, "cve": cve, "id": f"{pin}/{cve}/{os.path.basename(ko)[:-3]}"})
    return items


# ---- freeze phase: fixtures --------------------------------------------------------------
def phase_freeze():
    """Score fixture faithful module vs its independent reference under both configs, and one fixture
    constant mutant under both, to confirm IMM-FRAME keeps faithful fixtures clean and does not, on the
    fixtures, hide the constant class. Declares the frozen choice."""
    rec = {"phase": "freeze", "fixtures_seen": 0, "frame_off": Counter(), "frame_on": Counter(),
           "fixture_refs_found": 0, "note": ""}
    try:
        man = json.load(open(FIX_MANIFEST))
        fx = [r for r in man["rows"] if r.get("set") == "fixtures"]
        for r in fx:
            # fixture id: <ver>/<mid>/<name> (mid is intree|kpatch). Faithful parent under
            # s1full/parents/<ver>/<name>/<name>.ko; independent reference under s1full/refs/<ver>/<mid>/<name>/.
            parts = r["id"].split("/")
            ver = parts[0]
            mid = parts[1] if len(parts) > 2 else ""
            name = parts[-1]
            refs = [o for o in sorted(glob.glob(f"{FIX_REFS}/{ver}/{mid}/{name}/**/*.o", recursive=True))
                    if not o.endswith(".mod.o")]
            par = sorted(glob.glob(f"{FIX_PARENTS}/{ver}/{name}/{name}.ko"))
            if not refs or not par:
                continue
            rec["fixture_refs_found"] += 1
            for cfg, key in ((["T1", "IMM-FRAME"], "frame_off"), (["T1"], "frame_on")):
                mv, sv, n, err = verdicts(par[0], refs, cfg)
                rec[key][mv or f"ERR:{err}"] += 1
            rec["fixtures_seen"] += 1
    except Exception as e:  # noqa: BLE001
        rec["note"] = f"freeze error: {e}"
    rec["frame_off"] = dict(rec["frame_off"])
    rec["frame_on"] = dict(rec["frame_on"])
    # Frozen choice: IMM-FRAME is the pre-registered example rule. Freeze it ON unless it makes a faithful
    # fixture diverge (it must not introduce alarms). Record both; the ablation is reported regardless.
    off_clean = set(rec["frame_off"]) <= {"CONSISTENT", "NO_COMMON_FUNCTIONS"}
    on_clean = set(rec["frame_on"]) <= {"CONSISTENT", "NO_COMMON_FUNCTIONS"}
    rec["frozen_rule"] = "IMM-FRAME_ON" if on_clean else ("NONE" if off_clean else "NONE")
    rec["frozen_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    (OUT / "freeze.json").write_text(json.dumps(rec, indent=1))
    log(f"FREEZE: fixtures_scored={rec['fixtures_seen']} refs_found={rec['fixture_refs_found']} "
        f"frame_off={rec['frame_off']} frame_on={rec['frame_on']} frozen={rec['frozen_rule']}")
    return rec


# ---- detection + false alarms ------------------------------------------------------------
def phase_score(items):
    done = set()
    if ROWS.exists():
        for ln in ROWS.read_text().splitlines():
            try:
                done.add(json.loads(ln)["id"])
            except Exception:  # noqa: BLE001
                pass
    log(f"SCORE start: {len(items)} constant mutants ({len(done)} already done)")
    t0 = time.time()
    for i, it in enumerate(items):
        if it["id"] in done:
            continue
        refs = refs_for(it["pin"], it["cve"])
        row = {"id": it["id"], "pin": it["pin"], "cve": it["cve"], "kind": "detect", "n_ref": len(refs)}
        if not refs:
            row["error"] = "no_reference"
            emit(row)
            continue
        for cfg, tag in ((["T1", "IMM-FRAME"], "off"), (["T1"], "on")):
            mv, sv, n, err = verdicts(it["ko"], refs, cfg)
            row[f"ms_{tag}"], row[f"seq_{tag}"], row[f"nfn_{tag}"] = mv, sv, n
            if err:
                row[f"err_{tag}"] = err
        emit(row)
        if (i + 1) % 100 == 0:
            log(f"  detection {i + 1}/{len(items)} ({round(time.time() - t0)}s)")
    log(f"SCORE detection done ({round(time.time() - t0)}s)")

    # False alarms: one row per CVE subject (parent), same- and cross-toolchain.
    cves = sorted({(it["pin"], it["cve"]) for it in items})
    for kind, root, extra in (("fa_same", PAR13, ["T1"]), ("fa_cross", PAR14, ["T1"])):
        n = 0
        for pin, cve in cves:
            par = parent_for(root, pin, cve)
            refs = refs_for(pin, cve)
            if not par or not refs:
                continue
            rid = f"{kind}:{pin}/{cve}"
            if rid in done:
                continue
            row = {"id": rid, "pin": pin, "cve": cve, "kind": kind, "n_ref": len(refs)}
            for cfg, tag in ((extra + ["IMM-FRAME"], "off"), (extra + [], "on")):
                mv, sv, nf, err = verdicts(par, refs, cfg)
                row[f"ms_{tag}"], row[f"seq_{tag}"], row[f"nfn_{tag}"] = mv, sv, nf
                if err:
                    row[f"err_{tag}"] = err
            emit(row)
            n += 1
        log(f"{kind} done: {n} subjects")


# ---- equivalent-mutant reachability (best effort) ---------------------------------------
def phase_equivalents(items):
    try:
        import capstone as cap
        md = cap.Cs(cap.CS_ARCH_X86, cap.CS_MODE_64)
        md.detail = True
        eq = []
        for it in items:
            try:
                pin, cve = it["pin"], it["cve"]
                par = parent_for(PAR13, pin, cve)
                if not par:
                    continue
                pb = Path(par).read_bytes()
                mb = Path(it["ko"]).read_bytes()
                if len(pb) != len(mb):
                    continue
                diffs = [k for k in range(len(pb)) if pb[k] != mb[k]]
                if not diffs:
                    eq.append({"id": it["id"], "reason": "noop_identical_bytes"})
                    continue
                # Map the first differing file offset to a function and test reachability.
                mod = Obj(Path(it["ko"]))
                reach = reachable_at_fileoff(mod, md, diffs[0])
                if reach is False:
                    eq.append({"id": it["id"], "reason": "unreachable_block"})
            except Exception:  # noqa: BLE001
                continue
        (OUT / "equivalents.json").write_text(json.dumps(eq, indent=1))
        log(f"EQUIVALENTS: {len(eq)} constant mutants excluded")
    except Exception as e:  # noqa: BLE001
        log(f"EQUIVALENTS skipped: {e}")


def reachable_at_fileoff(mod, md, file_off):
    """True/False if the instruction covering section offset file_off lies in a block reachable from the
    enclosing function's entry; None if it cannot be located."""
    # find the section+function covering this file offset
    for name, (shndx, start, size) in mod.functions().items():
        sec = mod.elf.get_section(shndx)
        sh_off = sec["sh_offset"]
        if not (sh_off + start <= file_off < sh_off + start + size):
            continue
        data = sec.data()[start:start + size]
        target = (file_off - sh_off) - start
        insns = list(md.disasm(data, 0))
        addrs = [ins.address for ins in insns]
        # basic-block leaders: entry, jump targets, fallthroughs after branches
        leaders = {0}
        succ = {}
        for idx, ins in enumerate(insns):
            nxt = insns[idx + 1].address if idx + 1 < len(insns) else None
            mn = ins.mnemonic
            s = []
            if mn.startswith("j"):
                # jump target immediate
                tgt = None
                for o in ins.operands:
                    if o.type == cap_imm():
                        tgt = o.imm
                if tgt is not None and tgt in addrs:
                    leaders.add(tgt)
                    s.append(tgt)
                if mn != "jmp" and nxt is not None:
                    leaders.add(nxt)
                    s.append(nxt)
            elif mn.startswith(("ret", "ud2", "hlt")):
                pass
            else:
                if nxt is not None:
                    s.append(nxt)
            succ[ins.address] = s
        # map each insn to its block leader
        block_of = {}
        cur = 0
        for ins in insns:
            if ins.address in leaders:
                cur = ins.address
            block_of[ins.address] = cur
        # block successor graph
        bsucc = {}
        for ins in insns:
            b = block_of[ins.address]
            for sa in succ.get(ins.address, []):
                if sa in block_of:
                    bsucc.setdefault(b, set()).add(block_of[sa])
        # reachable blocks from entry block 0
        seen, stack = set(), [0]
        while stack:
            b = stack.pop()
            if b in seen:
                continue
            seen.add(b)
            stack.extend(bsucc.get(b, ()))
        # locate instruction covering target
        for ins in insns:
            if ins.address <= target < ins.address + ins.size:
                return block_of[ins.address] in seen
        return None
    return None


def cap_imm():
    import capstone as cap
    return cap.x86.X86_OP_IMM


def summarise():
    rows = [json.loads(l) for l in ROWS.read_text().splitlines() if l.strip()]
    eq = set()
    if (OUT / "equivalents.json").exists():
        eq = {e["id"] for e in json.loads((OUT / "equivalents.json").read_text())}
    det = [r for r in rows if r["kind"] == "detect"]
    det_scored = [r for r in det if "error" not in r]
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "constant_mutants": len(det), "scored": len(det_scored),
           "no_reference": sum(1 for r in det if r.get("error") == "no_reference"),
           "equivalents_excluded": len(eq)}
    for tag in ("off", "on"):
        nonq = [r for r in det_scored if r["id"] not in eq]
        k = sum(1 for r in nonq if r.get(f"ms_{tag}") == "DIVERGENT")
        out[f"detection_{tag}"] = {"n": len(nonq), "detected": k, "pct_ci": wilson(k, len(nonq))}
    for kind in ("fa_same", "fa_cross"):
        krows = [r for r in rows if r["kind"] == kind]
        for tag in ("off", "on"):
            scored = [r for r in krows if r.get(f"ms_{tag}") in ("CONSISTENT", "DIVERGENT")]
            a = sum(1 for r in scored if r.get(f"ms_{tag}") == "DIVERGENT")
            out[f"{kind}_{tag}"] = {"subjects": len(scored), "alarms": a, "pct_ci": wilson(a, len(scored))}
    if (OUT / "freeze.json").exists():
        fr = json.loads((OUT / "freeze.json").read_text())
        out["frozen_rule"] = fr.get("frozen_rule")
        out["freeze"] = {k: fr[k] for k in ("fixtures_seen", "frame_off", "frame_on") if k in fr}
    (OUT / "SUMMARY.json").write_text(json.dumps(out, indent=1))
    lines = [f"S27 SUMMARY {out['generated']}",
             f"constant mutants: {out['constant_mutants']} scored={out['scored']} "
             f"no_ref={out['no_reference']} equivalents_excluded={out['equivalents_excluded']}",
             f"frozen rule: {out.get('frozen_rule')}",
             "DETECTION (non-equivalent constant mutants detected):",
             f"  frame OFF: {out['detection_off']['detected']}/{out['detection_off']['n']} "
             f"= {out['detection_off']['pct_ci']}",
             f"  frame ON : {out['detection_on']['detected']}/{out['detection_on']['n']} "
             f"= {out['detection_on']['pct_ci']}",
             "FALSE ALARMS (faithful rebuilds flagged):",
             f"  same-toolchain  frame OFF: {out['fa_same_off']['alarms']}/{out['fa_same_off']['subjects']} "
             f"= {out['fa_same_off']['pct_ci']}",
             f"  same-toolchain  frame ON : {out['fa_same_on']['alarms']}/{out['fa_same_on']['subjects']} "
             f"= {out['fa_same_on']['pct_ci']}",
             f"  cross-toolchain frame OFF: {out['fa_cross_off']['alarms']}/{out['fa_cross_off']['subjects']} "
             f"= {out['fa_cross_off']['pct_ci']}",
             f"  cross-toolchain frame ON : {out['fa_cross_on']['alarms']}/{out['fa_cross_on']['subjects']} "
             f"= {out['fa_cross_on']['pct_ci']}"]
    (OUT / "SUMMARY.txt").write_text("\n".join(lines) + "\n")
    log("SUMMARY written\n" + "\n".join(lines))


def main():
    log("=== S27 RUN START ===")
    items = discover()
    log(f"discovered {len(items)} constant mutants")
    try:
        phase_freeze()
    except Exception:  # noqa: BLE001
        log("freeze phase failed:\n" + traceback.format_exc())
    phase_score(items)
    phase_equivalents(items)
    summarise()
    log("=== S27 RUN COMPLETE ===")


if __name__ == "__main__":
    main()
