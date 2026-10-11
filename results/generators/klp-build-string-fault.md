# S11: klp-build modules rejected at load (10 Oct 2026)

Load check of the 34 klp-build modules on the 6.19 pin (runtime host; 16 in `loader-sweep`, 18 in `loader-klp`): 32 LOADED_ENABLED, 2 LOAD_FAIL.

| Fix | Function | Kernel message | Cause |
| --- | --- | --- | --- |
| CVE-2026-43210 | `rb_read_data_buffer.isra.0` | `livepatch: failed to find location for function 'rb_read_data_buffer.isra.0'` | no ftrace call site |
| CVE-2026-31554 | `__do_sys_futex_requeue` | `livepatch: failed to find location for function '__do_sys_futex_requeue'` | no ftrace call site |

`kernel/livepatch/patch.c:177` (klp_patch_func): the message is printed when `ftrace_location()` finds no ftrace site for the old function. In the 6.19 pin `vmlinux` neither function starts with a `call __fentry__` (objdump at the System.map address, first 24 bytes), while a traced control function (`vfs_read`) does. Both symbols exist once in System.map, so the lookup itself succeeds; the functions cannot be patched through ftrace.

Reading: klp-build built modules for functions the kernel cannot live-patch, and the kernel refused them at load (loud, safe). kpatch-build refuses such functions at build time (its check for a missing fentry call), so the same fix fails there earlier in the pipeline. For RQ4 this is a difference in where the eligibility check sits, not a fidelity fault.

## Cost and a first look at the verdicts (10 Oct 2026)

- Cost: against the independent reference (the changed objects only), v1.3 takes about 9 s per klp-build module (3 sampled: 8.9, 8.9, 8.8 s), the same as for kpatch modules. Against klp-build's own reference, which is the whole patched `vmlinux.o`, each call takes 10 to 15 minutes, because the oracle indexes every function of every reference object.
- The three sampled modules are DIVERGENT against R-ind. In CVE-2025-71295 the only difference is two extra relocations of type 0 (`R_X86_64_NONE`) to `drop_buffers.constprop` in `try_to_free_buffers` (module 27 rows, reference 25; every other row matches). `R_X86_64_NONE` has no effect when applied. To check on all 34 modules before any oracle change: if every R-ind divergence is of this kind, it is a systematic false alarm on klp-build output, and the fix is a rule that drops relocations without effect (a new oracle version with its own deviation and validation).

## All 34 against R-ind, v1.3 (10 Oct 2026, afternoon)

Scripts: `klp_rind_v13.py` (oracle v1.3, R-ind only, relocation detail), `klp_rind_equiv.py` (drops type-0 rows, pairs the rest in offset order, compares the bytes each pair points at), `klp_rind_rodata_offsets.py` (distance between a module's target and the nearest exact copy of the reference string). Outputs on the build host: `/opt/atlas/s12/oracle/s11-klp-rind-v13-detail.json`, `-equiv.json`, `-rodata-offsets.json`. No oracle change.

- v1.3 verdicts: 3 CONSISTENT, 31 DIVERGENT.
- 10 divergent modules differ only by `R_X86_64_NONE` rows (no effect when applied).
- 13 more are fully explained by representation: type-0 rows, plus klp-build's linked `.ko` keeping one merged `.rodata` (no `SHF_STRINGS`, no object symbols), so the oracle prints `sec:.rodata+X` where the reference has `str:"..."` or `__func__.N`; the bytes at X equal the reference bytes in every pair. `__bug_table` rows differ only in naming (`__bug_table_N` symbol vs section+offset).
- CVE-2026-31555 (`futex_lock_pi`): the module carries its own copy of the const `futex_q_init` (136 bytes at `.rodata+0x40`, bitset `0xffffffff` at +0x74, `futex_wake_mark` pointer filled by a `.klp.rela.vmlinux..rodata` entry at load); the kernel's object is identical (vmlinux bytes compared). Same content, different address: benign.
- **7 modules point into the wrong place in their own `.rodata`**: CVE-2026-23467, 31447, 31449, 31521, 31571, 43152, 43163; 62 relocations (31521: 47; 23467, 31447: 4; 31571: 3; 31449: 2; 43152, 43163: 1). The addend misses the start of the intended string by 1 to 224 bytes (one pointer in 31521 sits 71 bytes before the nearest copy), growing along the section (31449: `.rodata+0x120` while "path[%d].p_idx %p > EXT_LAST_INDEX %p" starts at 0x11f; 31521 `load_module`: 47 of 107 string pointers off, up to 224 bytes). The addends sit on 8-byte steps (0x68, 0x98, 0xc0, 0x100), the strings in the `.ko` are packed: the relocations appear to follow a padded `.rodata.str1.8` layout that was later packed. If confirmed, the patched functions print from the middle of the wrong strings: a silent fidelity fault in klp-build output, found by the oracle against R-ind.
- To confirm before any manuscript text: rebuild CVE-2026-31449 with klp-tmp kept (`s11_repro_klp.py`, running) and follow the layout through objtool's diff object, the kmod object and the final `.ko`; then show it at run time (a patched `load_module` message on the VM, CVE-2026-31521).

## Cause of the 7 (11 Oct 2026)

- Diagnostic rebuild of CVE-2026-31449 with klp-tmp kept (`s11_repro_klp.py`; same relocations as the campaign module). `klp_stage_trace.py` on each stage: the wrong addends are already in objtool's klp-diff output (`klp-tmp/diff/vmlinux.o`: `.rodata.ext4_ext_correct_indexes.str1.8+0x20` and `+0x48`, strings at 0x1f and 0x45); `kmod/*.o`, `*.ko.orig`, the final `.ko` carry them unchanged.
- Code (6.19 `tools/objtool/elf.c`): `elf_add_string()` returns `ALIGN(sh_size, sh_addralign)` as the string's offset and `elf_add_data()` advances `sh_size` the same way, but each new data block gets `d_align = 1`, so libelf writes the strings packed. In a string section with alignment above 1 (`.str1.8`), every string after one whose length is not a multiple of the alignment is referenced past its start, and the gap accumulates.
- Upstream: fixed by Josh Poimboeuf, "objtool: Fix data alignment in elf_add_data()" (mainline 356e4b2f5b80, 4 Mar 2026; `Fixes: dd590d4d57eb`, the commit introducing klp diff; message: "Otherwise you may get some funky strings"), backported as fa31c5b01 in v6.19.9. The S11 pin is the 6.19 base release (Deviation 1), so these modules are what klp-build produced for users of 6.19 to 6.19.8.
- Reading: a real, upstream-confirmed, silent klp-build fidelity fault (modules load and enable; patched code reads the wrong bytes), detected by the oracle against R-ind in 7 of 34 modules.

## Control: rebuild the 7 with only the upstream fix in objtool (registered before the run)

Same recipe as s11klp.py (worker tree restore, gcc 13, klp-build -T --no-replace); after the restore, apply fa31c5b01's diff to `tools/objtool/elf.c` and nothing else. Expected: every one of the 62 relocations points at the start of an exact copy of its reference string (delta 0), and the residual R-ind difference of the 7 is representation only (type-0 rows, merged `.rodata`, `__bug_table` naming), as for the other 23. Any other outcome is reported as found. Script `s11_fixobjtool.py`; output `/opt/atlas/s12/s11-fixobjtool/`.

## Control result (11 Oct 2026)

`s11_fixobjtool.py`: 7 of 7 rebuilt with fa31c5b01 in objtool (2,289 to 2,731 s each). `klp_fix_score.py` (`/opt/atlas/s12/oracle/s11-fixobjtool-rind-v13.json`): v1.3 still DIVERGENT on all 7 (representation), but every paired row is SAME (777), RODATA_EQ (183) or BUG_TABLE (2); RODATA_NE 0, OTHER 0. CVE-2026-31449: `.rodata+0x120` and `+0x148` now start "path[%d].p_idx ..." (previous byte NUL). As registered: the upstream objtool fix alone removes all 62 wrong pointers, so the fault is caused by the objtool bug.

## All oracle versions against R-ind with controls (S11-PREREG Deviation 2, 11 Oct 2026)

`s11_rind_allver.py` (s21oracle.py unchanged, v1.3 added under its frozen hash): `/opt/atlas/s12/oracle/s21-klp-gcc-13-6.19-rind.json`. v1, v1.1, v1.2 and v1.3 give the same verdicts on all 34: 31 DIVERGENT, 3 CONSISTENT; sympos 28 CONSISTENT, 6 not applicable. Both controls pass on every module for every version (wrong reference never CONSISTENT; no-op copy byte-identical and same verdict). 

Reading for the detection claim: the frozen oracle flags all 7 faulty modules (7 of 7) but also 24 of the 27 modules without a generator fault (3 cleared), so its verdict alone does not separate them on klp-build output. The 7 were separated by the registered alarm triage (Outcome: every alarm root-caused), using the byte-level diagnostics above, and confirmed by the upstream fix and the control rebuild.

## Severity of the 62 wrong pointers (11 Oct 2026)

`klp_string_severity.py` (`/opt/atlas/s12/oracle/s11-klp-string-severity.json`): intended string, the bytes actually pointed at (to the next NUL), and the printf conversions of both.

- 29 change text only (12 keep the same conversions, 17 have none); 33 change the conversions the kernel reads, 32 of them in the patched `load_module` (CVE-2026-31521) and one in `intel_plane_atomic_check` (CVE-2026-31571).
- Normal paths are affected, not only error paths: with lp2026_31521 applied, loading any livepatch module prints "TCH" instead of "<mod>: tainting kernel with TAINT_LIVEPATCH"; a module with an unknown symbol prints "taints kernel." instead of "<mod>: Unknown symbol <sym> (err <n>)"; a non-GPL module's licence warning becomes "lid ELF sh_link!=SHN_UNDEF(%d) or ..." with three `%d` and one argument.
- Argument hazards: two `%s` read an argument the caller never passed (0x1cdd "module has no symbols (stripped?)" with one argument now formats "version magic '%s' should be '%s'"; 0x1f1e "symbol string table isn't NUL terminated", no arguments, now formats "init of module %s."). Two `%s` receive a small integer (0x19b2 ELF `e_machine`; 31571 plane id), which vsnprintf's pointer check prints as "(efault)". 0x1db1 is the fallback module-name string, not a format, so its new text is harmless.
- Next: show it at run time on the runtime host with lp2026_31521 applied (livepatch load message; unknown-symbol message; stripped module for the missing-argument `%s`), and the same with the fa31c5b01-objtool module.

## Run-time demonstration, CVE-2026-31521 (11 Oct 2026)

`demo31521/demo.sh` on the runtime host (6.19 pin, KVM, busybox initramfs; serial logs and input hashes in `demo31521/logs/`). Three boots that differ only in the livepatch applied first: none, the campaign's lp2026_31521.ko (stock objtool), or the same fix rebuilt with fa31c5b01 in objtool. All three modules load, enable and complete the transition; no boot crashed. Then the same four insmods:

| Step | Baseline and fixed-objtool module | Campaign module (stock 6.19 klp-build) |
| --- | --- | --- |
| second livepatch module | `lp2025_71295: tainting kernel with TAINT_LIVEPATCH` | `TCH` |
| module with an unknown symbol | `unknownsym: Unknown symbol lpfid_no_such_symbol (err -2)` | `taints kernel.` |
| non-GPL module | `nongpl: module license 'Proprietary' taints kernel.` | `3Invalid ELF section name index: -1071574952 \|\| e_shstrndx (7804432) >= e_shnum (-2127844627)` and a second line of the same kind |
| module without a symbol table | `tiny: module has no symbols (stripped?)` | `version magic 'tiny' should be ''` |

Return codes are the same in all three boots (the fault does not change what load_module decides). The fixed-objtool module prints exactly the baseline messages. With the campaign module the kernel log loses the module name, the symbol name and the error code, prints a log-level byte as text ("3Invalid"), reports an ELF error that did not happen, and prints register contents as integers for arguments the caller never passed. The missing-argument `%s` printed an empty string in this run, not a crash; what it reads depends on register contents.
