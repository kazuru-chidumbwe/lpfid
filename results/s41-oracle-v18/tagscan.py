#!/usr/bin/env python3
"""S41: module-side N1C reach. For each module, count the relocations in its functions (scaffolding excluded)
whose v1.8 label carries a content tag. A module with none cannot change verdict under N1C: every base name it
references is untagged on the module side, so N1C either drops that base's tags on both sides (v1.7 behaviour)
or the base was already a v1.7 difference. usage: tagscan.py <oracle-v1.8.py> <ko> [<ko> ...]"""
import importlib.util, json, sys
from pathlib import Path

spec = importlib.util.spec_from_file_location("orc18", sys.argv[1])
orc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(orc)
SCAFFOLD = {"init_module", "cleanup_module", "__pfx_init_module", "__pfx_cleanup_module"}
for ko in sys.argv[2:]:
    try:
        m = orc.Obj(Path(ko))
        tagged = []
        for name, loc in m.functions().items():
            if name in SCAFFOLD:
                continue
            for _, t, x in m.relocs_in(*loc):
                if "#" in str(x):
                    tagged.append((name, str(x)))
        print(json.dumps({"ko": ko, "tagged": len(tagged), "examples": tagged[:4]}))
    except Exception as e:  # noqa: BLE001
        print(json.dumps({"ko": ko, "error": str(e)[:200]}))
