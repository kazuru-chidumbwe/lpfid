#!/usr/bin/env bash
# S40 addendum A3: rebuild and score the 4.19 and 5.10 units with the release's OS-repository compiler.
# usage: nohup bash s40_run_a3.sh <arch> > s40.a3.<arch>.run.log 2>&1 &   (DOCKER="sudo docker" on the t4g)
set -u; DOCKER=${DOCKER:-docker}; ARCH=$1; cd ~/s40
M=https://repo.openeuler.org
log(){ echo "[$(date -u +%H:%M:%S)] $*"; }
grep -v '^#' s40_units.full.txt | awk -v a="$ARCH" '$2==a && $1 !~ /24\.03/' | while read REL A TAG; do
  base=s40-$(echo "$REL" | tr 'A-Z' 'a-z'); img=$base-osgcc
  if ! $DOCKER image inspect "$img" >/dev/null 2>&1; then
    ctx=$(mktemp -d)
    printf 'FROM %s\nRUN dnf -y --allowerasing --disablerepo="update*" distro-sync gcc cpp libgcc libgomp libstdc++ 2>&1 | tail -3; rpm -q gcc\n' "$base" > "$ctx/Dockerfile"
    $DOCKER build -t "$img" "$ctx" > "build.a3.$REL.$ARCH.log" 2>&1 || { log "$REL a3-image-fail"; rm -rf "$ctx"; continue; }
    rm -rf "$ctx"
  fi
  log "$TAG compiler: $($DOCKER run --rm "$img" rpm -q gcc)"
  $DOCKER run --rm -e OUTROOT=out-a3 -v ~/s40:/work "$img" bash /work/s40_pkg_excl.sh "$TAG" "$ARCH" "$M/$REL" > "refbuild.a3.$TAG.$ARCH.log" 2>&1
  $DOCKER run --rm -v ~/s40:/work "$img" chmod -R a+rX "/work/out-a3/$TAG.$ARCH" >/dev/null 2>&1
  log "$(tail -1 refbuild.a3.$TAG.$ARCH.log)"
done
log "A3 $ARCH DONE"; touch "S40-A3-$ARCH-DONE"
