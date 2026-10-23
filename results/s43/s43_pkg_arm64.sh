#!/usr/bin/env bash
# S43 AArch64 reference recipe = S39b per-package step, with GCCPIN releasever "current" meaning the current
# repositories. Run with XCFLAGS=-I/work/kpatch-inc (kpatch headers on the include path, B1) and GCCPIN from
# s43_gccpin.sh. S39b header follows.
# S39b per-package step (S39 + every patch in the source tar, per-file make logs kept, optional gcc pin).
# S39 per-package step (runs in native aarch64 AL2023 container). For one livepatch package: fetch shipped
# modules, prep the exact kernel source via rpmbuild -bp (applies AL2023's downstream patches), build one
# reference object per changed file per CVE patch, and fetch the kernel vmlinux for the sympos check.
# Outputs under /work/out/<pkg>/{ko,ref/<cve>,vmlinux}.
set -u
PKG=$1
OUT=/work/${OUTROOT:-out39b}/$PKG; rm -rf "$OUT"; mkdir -p "$OUT/ko" "$OUT/ref"
log(){ echo "[$(date -u +%H:%M:%S)] S39b $PKG $*"; }
# GCCPIN=<releasever>:<gcc nvr>, e.g. 2023.1.20230628:11.3.1-4.amzn2023.0.3, pins the compiler the module records
if [ -n "${GCCPIN:-}" ]; then
  RV=${GCCPIN%%:*}; GV=${GCCPIN#*:}
  RVOPT=(); [ "$RV" != "current" ] && RVOPT=(--releasever="$RV")
  dnf -q "${RVOPT[@]}" install -y --allowerasing "gcc-$GV" "cpp-$GV" >/tmp/pin.log 2>&1 || { log "gcc-pin-fail"; tail -3 /tmp/pin.log; exit 5; }
fi
log "gcc: $(gcc --version | head -1)"
rm -rf ~/rpmbuild; WT=$(mktemp -d); cd "$WT"

log "download shipped binary rpm"
dnf download -q "$PKG" >/dev/null 2>&1 || { log "ko-rpm-fail"; exit 3; }
rpm2cpio "$PKG"-*.aarch64.rpm 2>/dev/null | cpio -idm 2>/dev/null
find . -name "livepatch-*.ko" -exec cp {} "$OUT/ko/" \; 2>/dev/null
nko=$(ls "$OUT/ko"/*.ko 2>/dev/null | wc -l); log "shipped modules: $nko"
[ "$nko" -eq 0 ] && { log "no-ko"; exit 3; }

log "download livepatch source rpm (patches + bundled kernel srpm)"
dnf download -q --source --enablerepo='*-source' "$PKG" >/dev/null 2>&1 || { log "srpm-fail"; exit 3; }
rpm2cpio "$PKG"-*.src.rpm 2>/dev/null | cpio -idm 2>/dev/null
tar xf "$PKG"*.tar 2>/dev/null   # holds the CVE-*.patch files
KV=$(echo "$PKG" | sed "s/kernel-livepatch-//")
# AL2023 6.1: kernel-$KV*.src.rpm; 6.12/6.18: kernel6.12-$KV / kernel6.18-$KV
KSRPM=$(ls kernel-"$KV"*.src.rpm kernel6.12-"$KV"*.src.rpm kernel6.18-"$KV"*.src.rpm 2>/dev/null | head -1)
[ -z "$KSRPM" ] && KSRPM=$(ls kernel*.src.rpm 2>/dev/null | grep -v livepatch | head -1)
[ -z "$KSRPM" ] && { log "no-kernel-srpm"; ls -la; exit 3; }
log "ksrpm=$KSRPM"

log "prep kernel source via rpmbuild -bp (applies downstream patches)"
rpm -ivh --nodeps "$KSRPM" >/tmp/rpminst.log 2>&1
SPEC=$(ls ~/rpmbuild/SPECS/*.spec 2>/dev/null | head -1); [ -z "$SPEC" ] && { log "no-spec"; exit 4; }
rpmbuild -bp --nodeps --target aarch64 "$SPEC" >/tmp/bp.log 2>&1   # trailing %prep step may rc!=0; tree is produced
KDIR=$(find ~/rpmbuild/BUILD -maxdepth 4 -type d -name "linux-*" 2>/dev/null | while read d; do [ -f "$d/Makefile" ] && [ -d "$d/arch/arm64" ] && { echo "$d"; break; }; done)
[ -z "$KDIR" ] && { log "no-prepped-kdir"; tail -4 /tmp/bp.log; exit 4; }
log "kdir=$KDIR"
cd "$KDIR"
CFG=$(find ~/rpmbuild/SOURCES "$WT" -name "config-aarch64" ! -name "*debug*" 2>/dev/null | head -1)
[ -z "$CFG" ] && CFG=$(find ~/rpmbuild/SOURCES "$WT" -name "config-aarch64*" 2>/dev/null | head -1)
[ -z "$CFG" ] && { log "no-config"; exit 4; }
cp "$CFG" .config; make olddefconfig >/tmp/cfg.log 2>&1
make -j"$(nproc)" prepare modules_prepare >/tmp/prep.log 2>&1 || { log "prepare-fail"; tail -3 /tmp/prep.log; exit 4; }
log "prepare ok"

PATCHDIR=$(find "$WT" -maxdepth 2 -name "*.patch" -printf "%h\n" 2>/dev/null | sort -u | head -1)
[ -z "$PATCHDIR" ] && { log "no-patchdir"; exit 4; }
built_total=0; cves=0
mkdir -p "$OUT/mklog"
for p in "$PATCHDIR"/*.patch; do
  [ -f "$p" ] || continue
  cve=$(basename "$p" .patch)   # S26 rule: ref dir = patch basename
  files=$(lsdiff "$p" 2>/dev/null | grep -E "\.c$" | sed -E "s#^[ab]/##" | sort -u)
  patch -p1 --fuzz=3 < "$p" >/dev/null 2>&1 || { log "$cve apply-fail"; continue; }
  mkdir -p "$OUT/ref/$cve"; b=0
  for f in $files; do
    o="${f%.c}.o"
    if make KCFLAGS="-ffunction-sections -fdata-sections ${XCFLAGS:-}" "$o" >/tmp/mk.log 2>&1 && [ -f "$o" ]; then
      mkdir -p "$OUT/ref/$cve/$(dirname "$f")"; cp "$o" "$OUT/ref/$cve/$f.o" 2>/dev/null; b=$((b+1)); built_total=$((built_total+1))
    else
      cp /tmp/mk.log "$OUT/mklog/$cve.$(echo "$f" | tr / _).log"
    fi
  done
  patch -p1 -R --fuzz=3 < "$p" >/dev/null 2>&1
  [ "$b" -gt 0 ] && cves=$((cves+1))
done
log "refs: $built_total objects over $cves patches"

cd /; rm -rf "$WT" ~/rpmbuild
touch "$OUT/PKG-DONE"
log "PKG DONE ko=$nko refobjs=$built_total vmlinux=$([ -f "$OUT/vmlinux" ] && echo yes || echo no)"
