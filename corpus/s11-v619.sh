#!/usr/bin/env bash
# S11 after Deviation 1 (S11-PREREG-2026-10-09.md, 9 Oct 2026): pin Linux 6.19, fixes from linux-6.19.y after
# v6.19 (6.19.1 to 6.19.14). kpatch-build v0.9.11 and the pin's in-tree klp-build on the same fixes.
# 1. pin: kernel.org tarball checked against sha256sums.asc, same recipe as tb-newpins.sh
# 2. selection, canary, kpatch, klp-build, S22 references, scoring (as s11.sh)
# Stop with: kill $(cat /opt/atlas/s12/s11.pid)
set -u
cd /opt/atlas/s12
echo $$ > s11.pid
C=/opt/atlas/livepatch-corpus; V=6.19; T=$C/linux-$V; SRC=$C/src; LOG=$C/build-logs; IN=$C/inputs
st() { echo "[$(date -u +%H:%M:%S)] S11 $*" | tee -a /opt/atlas/s12/build-progress.txt; }
st "start (Deviation 1: pin $V)"

# ---- 1. the 6.19 pin
if [ ! -f $T/vmlinux ]; then
  (cd $SRC && curl -sSfL https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc -o sums-v6.asc \
     && { [ -f linux-$V.tar.xz ] || curl -sSfLO https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$V.tar.xz; })
  want=$(grep " linux-$V.tar.xz$" $SRC/sums-v6.asc | cut -d" " -f1); got=$(sha256sum $SRC/linux-$V.tar.xz | cut -d" " -f1)
  [ -n "$want" ] && [ "$want" = "$got" ] || { st "pin tarball SHA MISMATCH or missing: stop"; exit 1; }
  st "pin tarball sha OK $got"
  [ -d $T ] || tar xJf $SRC/linux-$V.tar.xz -C $C
  (cd $T && cp $IN/pilot-work_linux.config .config \
     && ./scripts/config --enable LIVEPATCH --enable DEBUG_INFO --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT \
     && make -j12 CC=gcc-13 HOSTCC=gcc-13 olddefconfig > $LOG/$V-olddefconfig.log 2>&1 && cp .config $IN/linux-$V.config)
  [ -e $T/scripts/livepatch/klp-build ] || { st "pin $V has no klp-build: stop"; exit 1; }
  (cd $T && nice -n 5 make -j12 CC=gcc-13 HOSTCC=gcc-13 > $LOG/$V-build.log 2>&1) || { st "pin $V BUILD_FAIL: stop"; exit 1; }
  (cd $T && sha256sum arch/x86/boot/bzImage vmlinux > $LOG/$V-sha256.txt)
  st "pin $V built: $(cut -c1-16 $LOG/$V-sha256.txt | tr '\n' ' ')"
fi

# pristine tree from the verified tarball, and the pin tree checked against it
mkdir -p pristine
[ -d pristine/linux-$V ] || tar xJf $SRC/linux-$V.tar.xz -C pristine
left=$(rsync -rlc --dry-run --itemize-changes pristine/linux-$V/ $T/ | grep -cE "^(>f|cd|cL|>L)")
st "pin tree vs tarball: files_differing=$left"
[ "$left" = "0" ] || { st "PIN_DIFFERS_FROM_TARBALL: stop"; exit 1; }

# ---- 2. stable history after v6.19 (a fresh repository: the one of the invalid run is kept aside, with its outputs)
mkdir -p invalid-s11-1102; for d in results/*/6.19 oracle/s11-*; do [ -e "$d" ] && mv "$d" invalid-s11-1102/$(echo $d | tr / _); done
[ -d stable619 ] && mv stable619 stable619-invalid-1102
git init -q stable619; git -C stable619 remote add origin https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
for i in 1 2 3; do git -C stable619 fetch -q --shallow-exclude=v$V origin +refs/heads/linux-6.19.y:refs/heads/linux-6.19.y && break; sleep 30; done
n=$(git -C stable619 rev-list --count linux-6.19.y 2>/dev/null || echo 0)
st "6.19 fetched $n commits"
[ "$n" -gt 0 ] || { st "no 6.19.y history after v$V: stop"; exit 1; }
python3 s12select.py vulns stable619 out 6.19=$V=$T > select619.log 2>&1 || { st "selection failed: stop"; exit 1; }
st "selection $(tail -1 select619.log)"
python3 -c "import json,sys; d=json.loads(open('select619.log').read().splitlines()[-1].split(' ',1)[1]); sys.exit(0 if d.get('8_main_sample',0)>0 else 1)" \
  || { st "main sample empty: stop"; exit 1; }

# canary on 6.19 with kpatch, as for S12 and the 5.15 arm (fix A, fix B, fix A on one worker)
python3 canary515.py 6.19 >> s11-canary.out 2>&1
if tail -1 canary619.log 2>/dev/null | grep -q '"pass": true'; then
  st "canary 6.19 passed"
  python3 s12build.py v0.9.11 4 --branches 6.19 --set main >> campaign.log 2>&1
  st "kpatch 6.19 done"
else
  st "canary 6.19 FAILED: kpatch 6.19 builds skipped, see s11-canary.out"
fi
python3 /opt/atlas/s12/s11klp.py 4 --set main >> campaign.log 2>&1
st "klp-build 6.19 done"
python3 s22refs.py 4 --offset 0 --branches 6.19 --set main >> campaign.log 2>&1
st "S22 6.19 done"
for k in v0.9.11 klp; do
  nice -n 19 python3 s21oracle.py $k gcc-13 --workers 4 --branches 6.19 > oracle/s11-$k-gcc-13-6.19.log 2>&1
done
st "S11 ALL DONE"
