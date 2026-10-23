# Same-toolchain baseline, 23 Oct 2026

Relocation-masked bytes of each common function, plus the plain relocation multiset. No normalisation rule. Same toolchain. Read-only. Developer Node.

Instrument: `lab/s42/naive_baseline.py`. A function is common when both sides have an `STT_FUNC` of that name. Bytes covered by a relocation are zeroed before the byte compare. The multiset is `(relocation type, symbol name, addend)` over relocations whose offset falls inside the function. Symbol names are kept as recorded, including a `.klp.sym` prefix. The two references are kpatch-build's patched objects and the independent compile. They give the same verdict on every module and every mutant below.

Rows: `lab/s42/naive-faithful.jsonl` (123 modules) and `lab/s42/naive-mutants.jsonl`. The mutant file has 5,389 built modules. The study's scored set drops five swap modules (four byte-identical to the parent, and two duplicates counted once), which leaves 5,384. Those five sit on modules whose unmodified multiset already differs, so the rates below are the 5,384. The filter is `lab/s42/_naive_filter.py`.

## Unmodified modules

Masked bytes agree on 123 of 123, against both references. The multiset agrees on 20 and differs on 103. Every one of the 103 differs in the multiset only.

## Mutants, on the 20 modules whose multiset agrees

| Operator | Detected |
| --- | --- |
| addend | 25 of 25 |
| constant | 175 of 175 |
| dropped call | 164 of 164 |
| redirect | 91 of 193 |
| swap | 0 of 156 |

The 102 redirect mutants that stay consistent edit a function the module and the reference do not share. A swap exchanges two targets, so the multiset is unchanged and the masked bytes still agree.

## Mutants, on the 103 modules whose multiset already differs

All 4,671 keep the unmodified verdict: addend 746, constant 936, dropped call 971, redirect 1,024, swap 962, position 32.
