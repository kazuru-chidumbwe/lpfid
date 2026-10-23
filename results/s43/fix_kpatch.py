#!/usr/bin/env python3
"""Patch the in-container kpatch-build (0.9.10) so it finds the kernel spec under Amazon's
kernel<basever> package naming. kpatch-build sets SPECNAME="kernel$ALT.spec" and only sets ALT
for el7a kernels, so for Amazon 6.12/6.18 it looks for 'kernel.spec' while the srpm installs
'kernel6.12.spec' / 'kernel6.18.spec'. Insert a fallback, right before rpmbuild -bp runs, to the
actual kernel*.spec present in RPMTOPDIR/SPECS. No effect on 6.1 (kernel.spec exists). This fixes
only where kpatch-build locates the spec; the compiled reference objects are unchanged."""
import sys

PATH = "/usr/bin/kpatch-build"
ANCHOR = 'rpmbuild -D "_topdir $RPMTOPDIR" -bp'
MARKER = 'SPECS/kernel*.spec 2>/dev/null'
FALLBACK = ('[ -f "$RPMTOPDIR/SPECS/$SPECNAME" ] || '
            'SPECNAME="$(basename "$(ls "$RPMTOPDIR"/SPECS/kernel*.spec 2>/dev/null | head -1)")"\n\t\t')

s = open(PATH).read()
if MARKER in s:
    print("kpatch-build already patched")
    sys.exit(0)
if ANCHOR not in s:
    print("ANCHOR not found; kpatch-build not patched", file=sys.stderr)
    sys.exit(1)
s = s.replace(ANCHOR, FALLBACK + ANCHOR, 1)
open(PATH, "w").write(s)
print("patched kpatch-build spec fallback")
