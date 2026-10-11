#!/usr/bin/env python3
"""S11-PREREG Deviation 2: score the klp-build modules on the 6.19 pin against R-ind with oracle v1, v1.1,
v1.2 and v1.3, each with the wrong-reference and no-op controls. Runs s21oracle.py unchanged, with v1.3 added
to its oracle table under the frozen hash (S16 Deviation 3); s21oracle checks every hash before any call.
Usage (build host): nice -n 19 python3 s11_rind_allver.py [WORKERS]
Writes s21oracle's output for the set klp-gcc-13-6.19-rind in /opt/atlas/s12/oracle/.
"""
import importlib.util
import sys
from pathlib import Path

A = Path("/opt/atlas")
spec = importlib.util.spec_from_file_location("s21oracle", A / "s12/s21oracle.py")
S = importlib.util.module_from_spec(spec)
spec.loader.exec_module(S)

_gate = S.gate_v12


def gate_with_v13() -> str:
    note = _gate()
    S.ORACLES["v1.3"] = ([str(A / "venvs/lpfid-oracle-v11/bin/python")], A / "lpfid/blind-reloc-oracle-v1.3.py",
                         "c6add9ab14d994cf6d7920ff6d6820840c9fa554001727865990957b9e200133")
    return note + "; v1.3 added (S11-PREREG Deviation 2)"


S.gate_v12 = gate_with_v13
workers = sys.argv[1] if len(sys.argv) > 1 else "4"
sys.argv = ["s21oracle.py", "klp", "gcc-13", "--workers", workers, "--branches", "6.19", "--reference", "ind"]
sys.exit(S.main())
