"""Build oracle v2.1 from frozen v2.0 (lab/s42/blind-reloc-oracle-v2.0.py, sha256 7686843c93f5cb58...) by exact
string edits. Each edit must match once. Rule MDUP, pre-registered in internal/S44-PREREG-2026-10-24.md.
usage: make_v21.py <v2.0 source> <v2.1 output>"""
import sys

src, dst = sys.argv[1:3]
s = open(src, encoding="utf-8").read()


def sub(old, new):
    global s
    assert s.count(old) == 1, old[:80]
    s = s.replace(old, new)


sub('''"""Blind reference-differential relocation oracle for livepatch modules, v2.0.
''', '''"""Blind reference-differential relocation oracle for livepatch modules, v2.1.

v2.1 = v2.0 (sha256 7686843c93f5cb58...) plus one rule, pre-registered in internal/S44-PREREG-2026-10-24.md after the
S43 classification (lab/s43/S43-MISS-CLASSIFY-2026-10-24.md):
  MDUP when the module defines a function name more than once (a livepatch for two target objects that each have a
       static function of that name), every definition is compared, not only the first. Each definition is keyed
       name@file by the STT_FILE that precedes it, and is paired with the reference definitions of that name whose
       own file (P1F rule) is the same; when none is, with all of them, as before. Among those candidates the DUP
       rule (closest relocation multiset) chooses. A klp relocation inside a definition is checked by sympos against
       that definition's pairing. A name defined once is compared exactly as in v2.0.
Disable with LPFID_DISABLE=MDUP, which gives v2.0.

v2.0 header follows.

Blind reference-differential relocation oracle for livepatch modules, v2.0.
''')

# function definitions, all copies, with their file
sub('''    def _func_index(self) -> dict:
        """Performance (S16 Deviation 7''', '''    def function_defs(self) -> dict[str, list[tuple[tuple[int, int, int], str | None]]]:
        """MDUP: name -> [((section index, start, size), file)] for every defined FUNC symbol with size, in
        symbol-table order. file is the basename of the STT_FILE that precedes the symbol (None for a global)."""
        if "_fdefs" in self.__dict__:
            return self._fdefs
        out, cur = {}, None
        for s in self.syms:
            typ = s["st_info"]["type"]
            if typ == "STT_FILE":
                cur = os.path.basename(s.name) if s.name else None
                continue
            if typ != "STT_FUNC" or s["st_size"] == 0 or not isinstance(s["st_shndx"], int):
                continue
            local = s["st_info"]["bind"] == "STB_LOCAL"
            out.setdefault(s.name, []).append(((s["st_shndx"], s["st_value"], s["st_size"]), cur if local else None))
        self._fdefs = out
        return out

    def function_keys(self) -> dict[str, tuple[tuple[int, int, int], str | None, str]]:
        """MDUP: comparison key -> (location, file, name). A name defined once keeps its name as key. When a name is
        defined more than once, the first definition keeps the name and each later one is keyed name@file (name@#i
        when the file is unknown or repeats)."""
        if "_fkeys" in self.__dict__:
            return self._fkeys
        out = {}
        for name, defs in self.function_defs().items():
            if len(defs) == 1 or "MDUP" in DISABLED:
                out[name] = (defs[0][0], defs[0][1], name)
                continue
            seen = set()
            for i, (loc, f) in enumerate(defs):
                if i == 0:
                    key = name
                else:
                    key = f"{name}@{f}" if f and f not in seen else f"{name}@#{i}"
                seen.add(f)
                out[key] = (loc, f, name)
        self._fkeys = out
        return out

    def function_key_at(self, shndx: int, off: int) -> str | None:
        """MDUP: the comparison key of the function definition that covers byte off of section shndx."""
        for key, (loc, _, _) in self.function_keys().items():
            if loc[0] == shndx and loc[1] <= off < loc[1] + loc[2]:
                return key
        return None

    def _func_index(self) -> dict:
        """Performance (S16 Deviation 7''')

# klp relocations carry the key of the definition they sit in
sub('''                yield (self.function_at(tgt_idx, r["r_offset"]) if tgt_idx is not None else None,
                       self.syms[r["r_info_sym"]].name)''', '''                at = self.function_key_at if "MDUP" not in DISABLED else self.function_at
                yield (at(tgt_idx, r["r_offset"]) if tgt_idx is not None else None,
                       self.syms[r["r_info_sym"]].name)''')

# compare(): iterate keys, pair by file for repeated names
sub('''    mfuncs = mod.functions()
    rfuncs: dict''', '''    mkeys = mod.function_keys()
    mfuncs = {k: loc for k, (loc, _, _) in mkeys.items()}
    base = lambda k: mkeys[k][2] if k in mkeys else k
    mdup = sorted(k for k in mkeys if "MDUP" not in DISABLED and len(mod.function_defs()[mkeys[k][2]]) > 1)
    rfuncs: dict''')
sub('''    rname = lambda n: clone_map.get(n, n)
    common = sorted(n for n in mfuncs if rname(n) in rfuncs and (only is None or n in only))''',
    '''    rname = lambda n: clone_map.get(base(n), base(n))
    common = sorted(n for n in mfuncs if rname(n) in rfuncs and (only is None or base(n) in only))
    mdup_pairings = []''')
sub('''        cands = rall[rname(name)] if "DUP" not in DISABLED else rall[rname(name)][:1]
        best = None''', '''        cands = rall[rname(name)] if "DUP" not in DISABLED else rall[rname(name)][:1]
        if name in mdup:
            same = [c for c in cands if c[0].file_of(rname(name)) == mkeys[name][1]]
            mdup_pairings.append({"function": name, "file": mkeys[name][1],
                                  "candidates_in_file": [str(c[0].path) for c in same]})
            cands = same or cands
        best = None''')
sub('''            if res["function"] in SCAFFOLD:''', '''            if base(res["function"]) in SCAFFOLD:''')
sub('''        rfiles = {name: r_obj.file_of(name) for name, (r_obj, _) in rfuncs.items()}''',
    '''        rfiles = {name: r_obj.file_of(base(name)) for name, (r_obj, _) in rfuncs.items()}''')
sub('''        "compared_functions": sorted({r["function"] for r in results}),
        "oracle_version": "2.0",''', '''        "compared_functions": sorted({base(r["function"]) for r in results}),
        "compared_keys": sorted({r["function"] for r in results}),
        "oracle_version": "2.1",
        "mdup_pairings": mdup_pairings,''')
sub('''        "functions_in_module_not_in_reference": sorted(set(mfuncs) - set(rfuncs)),''',
    '''        "functions_in_module_not_in_reference": sorted({base(k) for k in set(mfuncs) - set(rfuncs)}),''')
open(dst, "w", encoding="utf-8", newline="\n").write(s)
print("wrote", dst)
