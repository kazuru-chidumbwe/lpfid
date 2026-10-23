#!/usr/bin/env bash
# S40 sensitivity arm (pre-reg A1 item 4): the ACC packages opened before scoring, built and scored with the same
# rules as the counted units (6.6: the exact compiler rebuild the module records; 4.19/5.10: the release's
# OS-repository compiler, addendum A3), into out-sens/. Never part of the primary count.
# usage: nohup bash s40_run_sens.sh <arch> <python> > s40.sens.<arch>.run.log 2>&1 &   (DOCKER="sudo docker" on the t4g)
set -u; DOCKER=${DOCKER:-docker}; ARCH=$1; PY=$2; cd ~/s40
M=https://repo.openeuler.org
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }
grep -v '^#' s40_units.sens.txt | awk -v a="$ARCH" '$2==a' | while read REL A TAG; do
  base=s40-$(echo "$REL" | tr 'A-Z' 'a-z')
  case $REL in *24.03*) img=$base;; *) img=$base-osgcc;; esac
  $DOCKER image inspect "$img" >/dev/null 2>&1 || { log "$TAG no image $img"; continue; }
  log "$TAG compiler: $($DOCKER run --rm "$img" rpm -q gcc)"
  $DOCKER run --rm -e OUTROOT=out-sens -v ~/s40:/work "$img" bash /work/s40_pkg_excl.sh "$TAG" "$ARCH" "$M/$REL" > "refbuild.sens.$TAG.$ARCH.log" 2>&1
  $DOCKER run --rm -v ~/s40:/work "$img" chmod -R a+rX "/work/out-sens/$TAG.$ARCH" >/dev/null 2>&1
  log "$(tail -1 refbuild.sens.$TAG.$ARCH.log)"
done
"$PY" s40_score18.py blind-reloc-oracle-v1.8.py out-sens "s40-v18-sens.$ARCH.jsonl" opened-before-scoring
log "SENS $ARCH DONE"; touch "S40-SENS-$ARCH-DONE"
