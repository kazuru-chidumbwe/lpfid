#!/usr/bin/env bash
# S40 per-package (runs in the matching openEuler container; native toolchain). For one SysCare hotpatch:
# fetch the shipped patch-kernel .ko, prep the kernel source (rpmbuild -bp on kernel.spec), apply the whole
# .syscare.tar.gz CVE patch set, and compile one reference object per changed file. Outputs /work/out/<tag>/.
#   args: <nvr-acc tag, e.g. kernel-6.6.0-28.0.0.34.oe2403-ACC-1-7> <arch> <repo-base-url>
set -u
TAG=$1; ARCH=$2; BASE=$3
OUT=/work/${OUTROOT:-out}/$TAG.$ARCH; rm -rf "$OUT"; mkdir -p "$OUT/ko" "$OUT/ref"
log(){ echo "[$(date -u +%H:%M:%S)] S40 $TAG.$ARCH $*"; }
for t in curl rpm2cpio cpio patch lsdiff rpmbuild make gcc readelf; do
  command -v "$t" >/dev/null || { log "missing-tool $t"; exit 5; }
done
rm -rf ~/rpmbuild; WT=$(mktemp -d); cd "$WT"

# derive the shipped binary (patch-kernel-...) and source (kernel-...src.rpm) names
MOD="patch-${TAG}.$ARCH.rpm"
log "download shipped module $MOD"
curl -sL -o mod.rpm "$BASE/hotpatch_update/$ARCH/Packages/$MOD" || { log "mod-dl-fail"; exit 3; }
[ "$(stat -c%s mod.rpm)" -lt 1000 ] && { log "mod-404"; exit 3; }
rpm2cpio mod.rpm 2>/dev/null | cpio -idm 2>/dev/null
find . -name "*.ko" -exec cp {} "$OUT/ko/" \; 2>/dev/null
nko=$(ls "$OUT/ko"/*.ko 2>/dev/null | wc -l); log "shipped .ko: $nko"; [ "$nko" -eq 0 ] && { log "no-ko"; exit 3; }
echo "$MOD" > "$OUT/module_name.txt"; (readelf -p .comment "$OUT/ko"/*.ko 2>/dev/null | grep -i gcc | head -1) > "$OUT/toolchain.txt"

log "download source rpm"
curl -sL -o src.rpm "$BASE/hotpatch_update/source/Packages/${TAG}.src.rpm" || { log "src-dl-fail"; exit 3; }
[ "$(stat -c%s src.rpm)" -lt 100000 ] && { log "src-404"; exit 3; }
rpm2cpio src.rpm 2>/dev/null | cpio -idm 2>/dev/null
ls .syscare.tar.gz kernel.spec >/dev/null 2>&1 || { log "no-syscare-or-spec"; ls | head; exit 3; }

log "install src.rpm + rpmbuild -bp (prep kernel source)"
rpm -ivh --nodeps src.rpm >/tmp/inst.log 2>&1
SPEC=$(ls ~/rpmbuild/SPECS/kernel.spec 2>/dev/null | head -1); [ -z "$SPEC" ] && SPEC=$(ls ~/rpmbuild/SPECS/*.spec | head -1)
rpmbuild -bp --nodeps "$SPEC" >/tmp/bp.log 2>&1   # trailing %prep step may rc!=0
KDIR=$(find ~/rpmbuild/BUILD -maxdepth 4 -type d -name "kernel*" -o -maxdepth 4 -type d -name "linux-*" 2>/dev/null | while read d; do [ -f "$d/Makefile" ] && [ -d "$d/arch" ] && { echo "$d"; break; }; done)
[ -z "$KDIR" ] && { log "no-kdir"; tail -5 /tmp/bp.log; exit 4; }
log "kdir=$KDIR"; cd "$KDIR"
# config: the vendor's own build config from the exact binary kernel rpm, else the in-tree openeuler_defconfig.
# Never fall back to a generic defconfig (no ftrace/dynamic debug there, so every function would diverge).
KNVR=${TAG%%-ACC-*}; CFGSRC=""
for repo in OS everything update; do
  curl -sfL -o "$WT/kbin.rpm" "$BASE/$repo/$ARCH/Packages/$KNVR.$ARCH.rpm" && [ "$(stat -c%s "$WT/kbin.rpm")" -gt 1000000 ] && { CFGSRC="vendor-rpm:$repo"; break; }
  rm -f "$WT/kbin.rpm"
done
if [ -n "$CFGSRC" ]; then
  mkdir -p "$WT/kbin"; (cd "$WT/kbin" && rpm2cpio ../kbin.rpm | cpio -idm './boot/config-*' './lib/modules/*/config' 2>/dev/null)
  C=$(find "$WT/kbin" -type f -name "config*" | head -1); if [ -n "$C" ]; then cp "$C" .config; else CFGSRC=""; fi
fi
if [ -z "$CFGSRC" ]; then
  KA=$ARCH; [ "$ARCH" = x86_64 ] && KA=x86; [ "$ARCH" = aarch64 ] && KA=arm64
  [ -f "arch/$KA/configs/openeuler_defconfig" ] && cp "arch/$KA/configs/openeuler_defconfig" .config && CFGSRC="openeuler_defconfig"
fi
[ -z "$CFGSRC" ] && { log "no-config"; exit 4; }
make olddefconfig >/tmp/cfg.log 2>&1
echo "$CFGSRC $(sha256sum .config | cut -c1-16) $(grep -cE '^CONFIG_(FUNCTION_TRACER|DYNAMIC_DEBUG|LIVEPATCH)=y' .config)/3" > "$OUT/config.txt"
log "config=$(cat "$OUT/config.txt")"
make -j"$(nproc)" prepare modules_prepare >/tmp/prep.log 2>&1 || { log "prepare-fail"; tail -3 /tmp/prep.log; exit 4; }

# the shipped ACC build disables hot/cold partitioning when its module carries no .cold function; match it
XF=""; readelf -sW "$OUT"/ko/*.ko 2>/dev/null | grep -q '\.cold' || XF="-fno-reorder-blocks-and-partition"
echo "xflags=${XF:-none}" >> "$OUT/config.txt"
log "apply .syscare patch set (cumulative) + compile changed files (xflags=${XF:-none})"
tar xzf "$WT/.syscare.tar.gz" -C "$WT/syscare" 2>/dev/null || { mkdir -p "$WT/syscare"; tar xzf "$WT/.syscare.tar.gz" -C "$WT/syscare" 2>/dev/null; }
mkdir -p "$OUT/ref/cumulative"; files=""; built=0
for p in $(find "$WT/syscare" -name "*.patch" | sort | grep -v -E "${EXCLUDE:-^$}"); do
  patch -p1 --fuzz=3 < "$p" >/dev/null 2>&1 || log "apply-skip $(basename $p)"
  files="$files $(lsdiff "$p" 2>/dev/null | grep -E '\.c$' | sed -E 's#^[ab]/##')"
done
for f in $(echo "$files" | tr ' ' '\n' | sort -u); do
  [ -z "$f" ] && continue; o="${f%.c}.o"
  if make KCFLAGS="-ffunction-sections -fdata-sections $XF" "$o" >/tmp/mk.log 2>&1 && [ -f "$o" ]; then
    mkdir -p "$OUT/ref/cumulative/$(dirname "$f")"; cp "$o" "$OUT/ref/cumulative/$f.o" 2>/dev/null; built=$((built+1))
  fi
done
log "ref objects: $built"

# vmlinux from the exact kernel-debuginfo, so the scorer runs the sympos check on the positioned klp bindings
DBG="$BASE/debuginfo/$ARCH/Packages/${KNVR/kernel-/kernel-debuginfo-}.$ARCH.rpm"
if curl -sfL -o "$WT/dbg.rpm" "$DBG"; then
  mkdir -p "$WT/dbg"; (cd "$WT/dbg" && rpm2cpio ../dbg.rpm | cpio -idm '*/vmlinux' 2>/dev/null)
  V=$(find "$WT/dbg" -type f -name vmlinux | head -1); [ -n "$V" ] && cp "$V" "$OUT/vmlinux"
  # target kernel modules the hotpatch binds into (.klp.rela.<obj>.*): their debug objects, saved as <obj>.ko
  objs=$(readelf -SW "$OUT"/ko/*.ko 2>/dev/null | grep -o '\.klp\.rela\.[^. ]*' | sed 's/\.klp\.rela\.//' | grep -vx vmlinux | sort -u)
  mkdir -p "$OUT/modules"
  pats=$(for o in $objs; do echo "*/$(echo "$o" | sed 's/_/[-_]/g').ko*.debug"; done)   # drm.ko.debug or drm.ko-<ver>.debug
  [ -n "$pats" ] && (set -f; cd "$WT/dbg" && rpm2cpio ../dbg.rpm | cpio -idm $pats 2>/dev/null)
  for o in $objs; do
    D=$(find "$WT/dbg" -type f -name "*.debug" | grep -E "/$(echo "$o" | sed 's/_/[-_]/g')\.ko(-[^/]*)?\.debug$" | head -1)
    [ -n "$D" ] && cp "$D" "$OUT/modules/$o.ko"
  done
  log "target modules: $(echo $objs | wc -w) wanted, $(ls "$OUT/modules" | wc -l) found"
fi
log "vmlinux: $([ -f "$OUT/vmlinux" ] && echo yes || echo no)"
cd /; rm -rf "$WT" ~/rpmbuild
chmod -R a+rX "$OUT" 2>/dev/null   # so the host scorer (non-root) can read the root-written outputs
touch "$OUT/PKG-DONE"
log "PKG DONE ko=$nko refobjs=$built"
