#!/usr/bin/env python3
"""PRE(A) static revert-soundness scan for Linux livepatch .ko artifacts."""
from __future__ import annotations
import json, re, subprocess, sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable
SHADOW_SYMBOLS = ("klp_shadow_alloc","klp_shadow_get_or_alloc","klp_shadow_free","klp_shadow_free_all")
STATE_SYMBOLS = ("klp_states","klp_get_state")
CALLBACK_RE = re.compile(r"__klp_.*_callback_", re.I)
@dataclass(frozen=True)
class PreResult:
    pre_class: str
    uses_shadow: bool
    has_state_callbacks: bool
    is_replace: bool
    uses_klp_states: bool
    trigger_symbols: tuple[str, ...]
    module: str
    @property
    def runtime_p3_eligible(self) -> bool:
        return self.pre_class == "SOUND"
def _run(cmd): return subprocess.check_output(cmd, text=True, errors="replace")
def undefined_symbols(ko: Path):
    try: out = _run(["nm","-u",str(ko)])
    except (FileNotFoundError, subprocess.CalledProcessError): out = _run(["readelf","-sW",str(ko)])
    syms=set()
    for line in out.splitlines():
        parts=line.split()
        if parts:
            sym=parts[-1]
            if sym and not sym.startswith("."): syms.add(sym)
    return syms
def defined_symbols(ko: Path):
    out=_run(["readelf","-sW",str(ko)]); syms=set()
    for line in out.splitlines():
        if " FUNC " not in line and " OBJECT " not in line: continue
        parts=line.split()
        if len(parts)>=8: syms.add(parts[-1])
    return syms
def all_symbol_names(ko: Path): return undefined_symbols(ko)|defined_symbols(ko)
def strings_blob(ko: Path):
    """Strings from a debug-stripped copy so DWARF field names are not PRE triggers."""
    import os, tempfile
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".ko")
        os.close(fd)
        subprocess.check_call(["objcopy", "--strip-debug", str(ko), tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return _run(["strings", tmp])
    except (FileNotFoundError, subprocess.CalledProcessError):
        try:
            return _run(["strings", str(ko)])
        except (FileNotFoundError, subprocess.CalledProcessError):
            return ""
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
def detect_replace(ko, syms, blob):
    if re.search(r"\breplace\b", blob) and (".replace" in blob or "klp_patch" in blob): return True
    return any("replace" in s.lower() and "klp" in s.lower() for s in syms)
def scan_ko(ko: Path) -> PreResult:
    syms=all_symbol_names(ko); blob=strings_blob(ko); triggers=[]
    uses_shadow=any(s in syms for s in SHADOW_SYMBOLS)
    if uses_shadow: triggers.extend(s for s in SHADOW_SYMBOLS if s in syms)
    has_callbacks=any(CALLBACK_RE.search(s) for s in syms)
    if has_callbacks: triggers.extend(sorted(s for s in syms if CALLBACK_RE.search(s)))
    uses_states=any(s in syms for s in STATE_SYMBOLS)
    if uses_states: triggers.extend(s for s in STATE_SYMBOLS if s in syms)
    is_replace=detect_replace(ko, syms, blob)
    if is_replace: triggers.append("klp_patch.replace")
    pre_class="OUT_OF_SCOPE" if (uses_shadow or has_callbacks or is_replace or uses_states) else "SOUND"
    return PreResult(pre_class, uses_shadow, has_callbacks, is_replace, uses_states, tuple(dict.fromkeys(triggers)), str(ko))
def emit_human(r):
    print(f"PRE_CLASS={r.pre_class}")
    print(f"PRE_USES_SHADOW={int(r.uses_shadow)}")
    print(f"PRE_HAS_STATE_CALLBACKS={int(r.has_state_callbacks)}")
    print(f"PRE_IS_REPLACE={int(r.is_replace)}")
    print(f"PRE_USES_KLP_STATES={int(r.uses_klp_states)}")
    print(f"PRE_RUNTIME_P3_ELIGIBLE={int(r.runtime_p3_eligible)}")
    if r.trigger_symbols: print(f"PRE_TRIGGER_SYMBOLS={','.join(r.trigger_symbols)}")
def main():
    args=sys.argv[1:]
    as_json=args[0]=="--json" if args else False
    if as_json: args=args[1:]
    if len(args)!=1:
        print("usage: pre-revert-scan.py [--json] MODULE.ko", file=sys.stderr); return 2
    ko=Path(args[0])
    if not ko.is_file(): print(f"error: not found: {ko}", file=sys.stderr); return 1
    r = scan_ko(ko)
    if as_json:
        print(json.dumps(asdict(r), indent=2))
    else:
        emit_human(r)
    return 0
if __name__=="__main__": raise SystemExit(main())

