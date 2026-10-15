# S34 pre-registration: shipped OpenAnolis livepatches (15 Oct 2026)

Written before any sample package is downloaded for evaluation. The frame is the directory listing of `https://mirrors.openanolis.cn/anolis/7.7/Plus/x86_64/os/Packages/` fetched on 15 Oct 2026: 40 `kernel-hotfix-*.an7.x86_64.rpm` files. Each matching kernel source package `kernel-<version>.an7.src.rpm` in `.../7.7/Plus/source/Packages/` returned HTTP 200 on that same day (17 versions, about 104–109 MB each).

## Already scored, excluded from this census

`kernel-hotfix-CVE-2023-0461-4.19.91-25.6-1.0-20230327164636.an7.x86_64.rpm` was fetched and judged earlier on 15 Oct as a feasibility probe (reference object built, binding oracle v1.3, `LPFID_T1=version`, one function, CONSISTENT). It is not a member of the census and is not counted in its denominator.

## Census

Every other package in that listing, 39 packages. No draw. A package whose patch does not apply, or whose reference objects do not compile, stays in the denominator as a build failure.

## Per package

- Module: every `.ko` in the binary RPM. The RPM also carries a `patch` file and a `changeinfo` file.
- Reference: that patch applied to the kernel tree from the matching source RPM, configured with that source RPM's x86-64 config, compiled with the Anolis 7.7 gcc (4.8.5-39.0.1) inside an Anolis 7.7 rootfs. The objects built are the `.c` files the patch modifies. `KCFLAGS` includes `-ffunction-sections -fdata-sections`, as in the feasibility build.
- Toolchain rule, fixed before the census: the feasibility module's `.comment` is gcc 4.8.5-44.0.1 and the 7.7 repository's gcc is 4.8.5-39.0.1. The registered verdict uses `LPFID_T1=version` (version-only match). A strict match is not the verdict.
- Checks: binding oracle v1.3 and v1.4 (`/opt/atlas/lpfid/blind-reloc-oracle-v1.3.py` and `blind-reloc-oracle-v1.4.py`), then the instruction-level check `body_check.py` on the same reference objects.
- Every DIVERGENT verdict is root-caused to one of: a fault in the shipped module, a difference between this reference build and Anolis's, or an oracle rule. A shipped-module fault is reported to the vendor before publication.

## Rules

No rule above changes after the first census package is downloaded. Every package is reported, including those that cannot be judged and why.
