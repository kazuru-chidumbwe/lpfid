# S5: behavioural check on three fixes, result (11 Oct 2026)

Pre-registration `internal/S5-PREREG-2026-10-11.md`; runner `s5run.sh` on the runtime host; score `s5_score.py` -> `s5-score.json`; runner output `rows-mut.tsv`; contract validation `validation/orig-rows.tsv`.

- Contracts: valid on all three unmodified modules (phase 1 vulnerable, phase 2 fixed, phase 3 vulnerable, 3/3 each). CVE-2024-50195 needed a second probe revision (glibc rejected the invalid timespec before the system call).
- Mutants: 122 (6.1 CVE-2024-57903: 45; 6.6 CVE-2024-50195: 37; 6.19 CVE-2026-31774, klp-build: 40). LOUD 28 (failed to load, enable or complete, or crashed), contract failures 0, judged 94, flaky 0.
- Behavioural check detected 4 of 94 judged mutants (4.3%, Wilson 1.7 to 10.4%): binding (redirect and swap) 3 of 38 (7.9%, 2.7 to 20.8), scope (dropcall) 1 of 28 (3.6%, 0.6 to 17.7), addend 0 of 14 (0 to 21.5), body (constant) 0 of 14 (0 to 21.5).
- All 4 are genuine wrong results on the probed path (phase 2 printed errno 14, a negative garbage result, or the vulnerable result) and all 4 sit in the fixed function. The binding oracle also detected all 4; the behavioural check detected nothing the oracle missed. The oracle detected 78 of the 94 judged mutants (v1.3 vs R-ind for the kpatch fixes, v1.4 vs R-ind for the klp-build fix) and 0 of the 14 constant mutants.
- Inside the fixed functions (kpatch fixes, S2 hunk field): 4 detected of 52 judged. sk_setsockopt is a large switch and pc_clock_settime has several branches; one probe exercises one path, and most mutation sites lie off it.
- Reading: a one-probe contract detects a fault only on the path it exercises. On these three fixes it added no detection to the binding oracle and did not reach the constant mutants, the class the oracle cannot see. The contracts cost 15, 17 and 60 probe lines (one revision for CVE-2024-50195). As registered, this says nothing about the share of fixes that admit a contract (3 of 14 diffs read).
