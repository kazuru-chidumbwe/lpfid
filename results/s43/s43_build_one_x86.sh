#!/bin/bash
# S43 x86-64 reference recipe = the S26 builder with the S41 pass-2 name filter (unused when ONLY is empty), keeping
# the exact-build debuginfo vmlinux in /work/<pkg>/vmlinux for the sympos check. S26 header follows.
# S26 per-package reference build, run inside the s26-builder container (amazonlinux:2023 + kpatch-build).
# Arg: livepatch package name. Mounts /work. Steps:
#   1. download the binary + source RPMs
#   2. extract the shipped .ko (the subjects) from the binary rpm  -> /work/<pkg>/ko
#   3. install the livepatch src.rpm; Source0 is a tar of the .patch files, Source1 the kernel src.rpm
#   4. per patch, build the independent reference with the vendor's own invocation
#        kpatch-build -R -r <kernel.src.rpm> --skip-cleanup -o <out> <patch>
#      (-R/--non-replace matches livepatch.spec; -r builds the kernel from source = independent compile)
#   5. collect the plain-compiled patched objects kpatch-build leaves under $CACHEDIR/tmp/patched -> /work/<pkg>/ref
#      (those gcc-compiled objects are the generator-independent reference the oracle scores against; the
#       klp symbol rewriting under test happens later, in the shipped .ko)
# Kernel is built once and the cache reused across this package's patches; cache + downloads are dropped at
# the end so the orchestrator only has to keep ko/ + ref/ for scoring. Heavy logging: this is the S26 gate.
set -u
PKG="$1"
W="/work/$PKG"
rm -rf "$W"; mkdir -p "$W/dl" "$W/ko" "$W/ref" "$W/built"
cd "$W/dl" || exit 2

echo "== fetch $PKG =="
dnf -q download "$PKG" 2>&1 | tail -2
dnf -q download --source "$PKG" 2>&1 | tail -2

echo "== extract shipped .ko from binary rpm =="
for r in "$PKG"*.x86_64.rpm; do [ -e "$r" ] && rpm2cpio "$r" | cpio -idm 2>/dev/null; done
find . -name '*.ko' -exec cp {} "$W/ko/" \; 2>/dev/null
# decompress any compressed shipped modules
find . -name '*.ko.xz'  -exec cp {} "$W/ko/" \; 2>/dev/null
find . -name '*.ko.zst' -exec cp {} "$W/ko/" \; 2>/dev/null
find . -name '*.ko.gz'  -exec cp {} "$W/ko/" \; 2>/dev/null
for k in "$W/ko"/*.ko.*; do [ -e "$k" ] || continue; case "$k" in
  *.xz)  xz  -d -f "$k";; *.zst) zstd -d -f --rm "$k";; *.gz) gzip -d -f "$k";; esac; done
echo "shipped ko: $(ls "$W/ko"/*.ko 2>/dev/null | wc -l)"

echo "== install livepatch src.rpm: Source0 tar (patches) + Source1 kernel src.rpm =="
rpmdev-setuptree 2>/dev/null
rpm -i "$PKG"*.src.rpm 2>/dev/null
SRC="$HOME/rpmbuild/SOURCES"
# 6.1 ships Source1 as kernel-<ver>.src.rpm; 6.12/6.18 as kernel<basever>-<ver>.src.rpm
KSRPM="$(ls "$SRC"/kernel*-*.src.rpm 2>/dev/null | head -1)"
mkdir -p "$SRC/patches"
for t in "$SRC"/kernel-livepatch-*.tar; do [ -e "$t" ] && tar xf "$t" -C "$SRC/patches"; done
mapfile -t PATCHES < <(find "$SRC/patches" -name '*.patch' | sort)
if [ -n "${ONLY:-}" ]; then mapfile -t PATCHES < <(for p in "${PATCHES[@]}"; do b=$(basename "$p" .patch | tr . -); tr . - <<< "$ONLY" | grep -qxF "$b" && echo "$p"; done); fi
echo "kernel srpm: $KSRPM ; patches: ${#PATCHES[@]}"
if [ -z "$KSRPM" ] || [ "${#PATCHES[@]}" -eq 0 ]; then echo "MISSING_SOURCES"; exit 0; fi

# Amazon's kpatch-build -r mode needs the matching kernel-debuginfo (reference vmlinux); the
# debuginfo repo is disabled by default. Install the exact version and pass -v, as livepatch.spec does.
# Kernel package base (kernel OR kernel6.12/kernel6.18) and version from the srpm name.
KBASE="$(basename "$KSRPM" | sed -E 's/^(kernel[0-9.]*)-.*/\1/')"            # kernel | kernel6.12 | kernel6.18
KVER="$(basename "$KSRPM" | sed -E 's/^kernel[0-9.]*-(.*)\.src\.rpm$/\1/')"  # e.g. 6.12.20-23.97.amzn2023
echo "== install ${KBASE}-debuginfo $KVER =="
dnf install -y --enablerepo='*debuginfo*' "${KBASE}-debuginfo-$KVER" > "$W/debuginfo-install.log" 2>&1 \
  || echo "  debuginfo install rc=$? (tail:)" && tail -3 "$W/debuginfo-install.log"
VMLINUX="/usr/lib/debug/lib/modules/${KVER}.x86_64/vmlinux"
# S43: the exact-build vmlinux is kept in /work/<pkg>/vmlinux for the sympos check
if [ -e "$VMLINUX" ]; then echo "  vmlinux OK: $VMLINUX"; cp "$VMLINUX" "$W/vmlinux"; else echo "  VMLINUX MISSING: $VMLINUX"; echo NO_VMLINUX; exit 0; fi
# S43: debug objects of the kernel modules the livepatches bind into (.klp.sym.<obj>.*), for the sympos check
mkdir -p "$W/klpobj"
for obj in $(for k in "$W/ko"/*.ko; do readelf -sW "$k" 2>/dev/null; done | grep -o -E "\.klp\.sym\.[A-Za-z0-9_-]+\." | sed -E 's/^\.klp\.sym\.//; s/\.$//' | grep -v -x vmlinux | sort -u); do
  f=$(find "/usr/lib/debug/lib/modules/${KVER}.x86_64" \( -name "${obj}.ko*.debug" -o -name "$(echo "$obj" | tr _ -).ko*.debug" \) 2>/dev/null | head -1)
  if [ -n "$f" ]; then cp "$f" "$W/klpobj/${obj}.ko"; echo "  klp target $obj: $f"; else echo "  klp target $obj: no debug object"; fi
done

# kpatch-build runs rpmbuild -bp on the kernel srpm, which needs the kernel's build deps.
echo "== install kernel build deps (dnf builddep $KVER) =="
dnf install -y dnf-plugins-core > "$W/builddep.log" 2>&1
dnf builddep -y "$KSRPM" >> "$W/builddep.log" 2>&1 || echo "  builddep rc=$? (tail:)"
tail -3 "$W/builddep.log"

# kpatch-build enforces that the build gcc matches the gcc the kernel was built with. Detect the
# kernel's gcc from the vmlinux .comment and install that exact amzn package; skip the check only
# if no matching package exists (documented in the Section 7.6 threats).
echo "== match kernel build gcc =="
GCCVER="$(readelf -p .comment "$VMLINUX" 2>/dev/null | grep -oE 'Red Hat [0-9]+\.[0-9]+\.[0-9]+-[0-9]+' | head -1 | awk '{print $3}')"
echo "  kernel gcc token: ${GCCVER:-unknown}"
CCHECK=""
if [ -n "$GCCVER" ]; then
  PKGVER="$(dnf -q list available --showduplicates gcc 2>/dev/null | awk -v v="$GCCVER" 'index($2,v)==1{print $2}' | tail -1)"
  if [ -n "$PKGVER" ]; then
    echo "  installing gcc-$PKGVER"
    dnf install -y --allowerasing "gcc-$PKGVER" "cpp-$PKGVER" > "$W/gcc-match.log" 2>&1 \
      || dnf downgrade -y "gcc-$PKGVER" "cpp-$PKGVER" >> "$W/gcc-match.log" 2>&1
  fi
  gcc --version 2>/dev/null | head -1
  if gcc --version 2>/dev/null | grep -q "Red Hat ${GCCVER}"; then
    echo "  gcc matched"
  else
    CCHECK="--skip-compiler-check"; echo "  gcc NOT matched -> --skip-compiler-check"
  fi
else
  CCHECK="--skip-compiler-check"; echo "  gcc token unknown -> --skip-compiler-check"
fi

# kpatch-build 0.9.10 looks for 'kernel.spec'; Amazon ships 'kernel<basever>.spec' for 6.12/6.18.
# Patch kpatch-build to fall back to the actual kernel*.spec the srpm installs (no effect on 6.1).
python3 /work/fix_kpatch.py || echo "  kpatch-build spec fallback not applied"

# Build once; kpatch-build reuses the cache across this package's patches.
export CACHEDIR="$W/kcache"
i=0
for p in "${PATCHES[@]}"; do
  i=$((i+1)); name="$(basename "$p" .patch)"
  echo "== kpatch-build [$i/${#PATCHES[@]}] $name =="
  mkdir -p "$W/built/$name"   # kpatch-build -o requires the output dir to pre-exist
  if kpatch-build -R -r "$KSRPM" -v "$VMLINUX" $CCHECK --skip-cleanup -o "$W/built/$name" "$p" > "$W/kpatch-$name.log" 2>&1; then
    echo "  built OK"
  else
    rc=$?; echo "  kpatch rc=$rc (tail:)"; tail -4 "$W/kpatch-$name.log"
  fi
  find "$W/built/$name" -name '*.ko' -exec cp {} "$W/built/" \; 2>/dev/null
  # the independent reference: gcc-compiled patched objects (namespaced + flat for the orchestrator glob)
  mkdir -p "$W/ref/$name"
  find "$CACHEDIR" -path '*patched*' -name '*.o' -exec cp {} "$W/ref/$name/" \; 2>/dev/null
done

# bound disk: keep only ko/ + ref/ for the host scorer
rm -rf "$CACHEDIR" "$W/dl"
echo "DONE $PKG shippedko=$(ls "$W/ko"/*.ko 2>/dev/null | wc -l) builtko=$(ls "$W/built"/*.ko 2>/dev/null | wc -l) ref=$(ls "$W/ref"/*.o 2>/dev/null | wc -l)"
