#!/usr/bin/env bash
# S40 runner: every unit of one architecture in s40_units.txt. Per release, load the openEuler image and pin the
# compiler the module records; check it before the refbuild; then refbuild (container) and score (host).
#   usage: nohup bash s40_run.sh <arch> <python> > s40.<arch>.run.log 2>&1 &
set -u; DOCKER=${DOCKER:-docker}
ARCH=$1; PY=$2; cd ~/s40
M=https://repo.openeuler.org; RES=s40.$ARCH.results.jsonl
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }
grep -v '^#' s40_units.txt | awk -v a="$ARCH" '$2==a' | while read REL A TAG; do
  img=s40-$(echo "$REL" | tr 'A-Z' 'a-z')
  case $REL in
    openEuler-24.03-LTS) PIN=gcc-12.3.1-30.oe2403; WANT="12.3.1-30.oe2403";;
    openEuler-24.03-LTS-SP1) PIN=gcc-12.3.1-62.oe2403sp1; WANT="12.3.1-62.oe2403sp1";;
    openEuler-20.03-LTS-SP4) PIN=gcc; WANT="7.3.0";;
    *) PIN=gcc; WANT="10.3.1";;
  esac
  if ! $DOCKER image inspect "$img" >/dev/null 2>&1; then
    log "$REL image build ($PIN)"
    curl -sfL -o "img-$REL.tar.xz" "$M/$REL/docker_img/$ARCH/openEuler-docker.$ARCH.tar.xz" || { log "$REL img-dl-fail"; continue; }
    base=$($DOCKER load -i "img-$REL.tar.xz" | sed -n 's/^Loaded image: //p' | tail -1)
    printf 'FROM %s\nRUN dnf install -y --setopt=strict=0 make flex bison bc elfutils-libelf-devel openssl-devel rpm-build patchutils tar cpio xz findutils gawk perl hostname dwarves; dnf install -y --allowerasing %s; dnf clean all\n' \
      "$base" "$PIN" > "Dockerfile.$REL"
    ctx=$(mktemp -d); cp "Dockerfile.$REL" "$ctx/Dockerfile"   # empty build context: out/ holds root-owned files
    $DOCKER build -t "$img" "$ctx" > "build.$REL.$ARCH.log" 2>&1 || { log "$REL image-build-fail"; rm -rf "$ctx"; continue; }
    rm -rf "$ctx"
  fi
  have=$($DOCKER run --rm "$img" gcc --version | head -1)
  log "$TAG gcc: $have (want $WANT)"
  echo "$have" | grep -q -- "$WANT" || { log "$TAG GCC-MISMATCH, refbuild anyway (oracle gate decides)"; }
  $DOCKER run --rm -v ~/s40:/work "$img" bash /work/s40_pkg.sh "$TAG" "$ARCH" "$M/$REL" > "refbuild.$TAG.$ARCH.log" 2>&1
  tail -1 "refbuild.$TAG.$ARCH.log"
  if [ -f "out/$TAG.$ARCH/PKG-DONE" ]; then
    "$PY" s40_score.py blind-reloc-oracle-v1.7.py "$PY" "out/$TAG.$ARCH" "$RES"
  else
    echo "{\"tag\": \"$TAG.$ARCH\", \"status\": \"REFBUILD_FAIL\", \"reason\": \"$(tail -1 refbuild.$TAG.$ARCH.log | tr -d '"')\"}" >> "$RES"
  fi
done
log "S40 $ARCH DONE"; touch "S40-$ARCH-DONE"
