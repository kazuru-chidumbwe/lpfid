# S26 pre-registration: shipped vendor livepatches (Amazon Linux 2023) (11 Oct 2026)

Written before any shipped module is downloaded for evaluation. Source: the Amazon Linux 2023 `kernel-livepatch` repository (scouting: `lab/vendor/SCOUTING-2026-10-11.md`), 818 shipped modules with their source packages.

## Sample

From the repository's primary metadata at the time of download (date and repomd checksum recorded), group the binary packages by kernel series (6.1, 6.12, 6.18) and draw 10 per series with `random.Random(20261012)` over the package names sorted, so 30 modules. A package whose source package or kernel debug information cannot be obtained is replaced by the next draw, and the replacement is reported.

## Per module

- Module: the `.ko` files in the binary package (a package can carry several; each is a subject).
- Reference: the patch files of its source package applied to the kernel source of its source package, built in an `amazonlinux:2023` container with the compiler that built the kernel (read from the module's `.comment` section), with the kernel's own config, compiling only the objects the patches change, as in S22.
- vmlinux: from the matching `kernel-debuginfo` package, for the sympos check.
- Checks: binding oracle versions 1.3 and 1.4, the eligibility check (second version), the instruction-level check (S25, once frozen), and the loader check (the module alone in Amazon's own kernel under KVM on the runtime host).
- Every alarm is root-caused to one of: a fault in the shipped module, a difference between our reference build and Amazon's, or an oracle rule. A shipped-module fault is reported to Amazon before publication.

## Rules

No rule above changes after the first module is downloaded for evaluation. Every module is reported, including those that cannot be judged and why.
