# S40 divergence root causes

## 4.19.90 20.03-SP4 ACC-1-7 x86_64, `pinctrl_enable`

Oracle v1.7: 9 of 10 patched functions consistent; `pinctrl_enable` differs in one PC32 relocation,
module `sec:.text+0x9c`, reference `sec:.text+0x18` (raw: `.text..refcount+0x98` vs `+0x14`, site 0x3a).

- Call site is byte-identical in module and reference: `lock incl 0x40(%rax); js <stub>` (refcount_inc).
- Both targets are the same stub, `lea 0x40(%rax),%rcx; ud2`, the x86 refcount-overflow handler.
- kpatch concatenates the `.text..refcount` stubs of every patched object into one section (module section
  0xa2 bytes, reference 0x1e), so the same stub sits at a different offset.
- Classification: representation difference, not a binding/position/addend/call/value fault. Under the frozen
  rules it is a false alarm and is reported as one, as CVE-2023-5090 is on Amazon. No rule added.
- Scope: x86 arch refcount stubs (`.text..refcount`) exist only before Linux 5.5, so this cause is specific to the
  x86-64 4.19 unit. The aarch64 4.19 unit also flags `pinctrl_enable`, for a different reason (next section);
  an earlier note in this file that the function would diverge only on x86 was wrong and is withdrawn.

## 5.10.0 22.03-SP1 ACC-1-17 x86_64 (reference with -fno-reorder-blocks-and-partition)

- Without the flag, `hugetlbfs_parse_param` and `ima_collect_measurement` differed: the reference split their
  cold paths into `.cold` functions, the shipped module has no `.cold` symbol. With the flag both match. This is
  a reference-build mismatch, fixed by pre-reg A2, not a finding.
- Residual: `ip6_finish_output2`, one R_X86_64_32S self-reference, module +0x4cb, reference +0x4d3. It is
  `_THIS_IP_` passed to `__local_bh_enable_ip(_THIS_IP_, 0x200)`; both point at the same instruction
  (`mov $0x200,%esi`). Earlier in the function the module recomputes `lea 0xe8(%r12),%rsi` where the reference
  spills and reloads it, and one branch is inverted, so the body is 8 bytes shorter before that point (1794 vs
  1804 bytes). All external bindings equal. Classification: code-generation difference between gcc 10.3.1
  rebuilds (the 22.03 `.comment` records no rebuild id); false alarm under the frozen rules.

## 4.19.90 20.03-SP4 ACC-1-6 aarch64, `pinctrl_enable` (counted run, 20 Oct)

Oracle v1.7: multiset EQUAL (51 relocations each side), sequence DIVERGENT; sympos CONSISTENT.
- Every CALL26 target appears in the same order on both sides; no call target is exchanged (not the `swap` class).
- The order differs only at the three `__dynamic_dev_dbg` sites (0x254, 0x374, 0x394). The module names the
  dynamic-debug descriptor directly (`descriptor.30281`, `.30290`, `.30286`) with an ADRP/ADD pair; the reference
  reaches it as `__verbose` + 0 plus a separate unrelocated `add x0, x0, #off` (0xe0, 0x150, 0x118), so the module
  is one instruction shorter per site and its two address loads interleave differently.
- Argument registers match at every site: x0 = descriptor, x1 = device (`ldr [x19,#56]`), x2 = format string.
- The reference's descriptors sit at exactly those offsets: `descriptor.30281` @0xe0, `.30286` @0x118,
  `.30290` @0x150 in `__verbose`, i.e. the same descriptor per site as the module names.
- Classification: representation difference (named symbol vs section base plus offset) plus instruction
  scheduling; same bindings and same argument registers. False alarm under the frozen rules; no rule added.
