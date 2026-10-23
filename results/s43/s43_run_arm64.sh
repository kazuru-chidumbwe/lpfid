#!/usr/bin/env bash
# S43 AArch64 arm (t4g). For each drawn package: compiler pin (s43_gccpin.sh), reference build (s43_pkg_arm64.sh,
# kpatch headers on the include path), score with s43_score.py (oracle v2.0, registered operators). No vmlinux on
# AArch64: sympos NOT_CHECKED. Status ~/s43/STATUS, results ~/s43/results-aarch64.jsonl, flag ~/s43/S43-AARCH64-DONE.
set -u
H=~/s43; W=~/s39; cd $W
st(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a $H/STATUS; }
PKGS=$(python3 -c "import json; d=json.load(open('$H/draw.json')); [print(p) for s in ('6.1','6.12','6.18') for p in d['draw']['aarch64'][s]]")
st "start aarch64: $(echo $PKGS | wc -w) packages; oracle $(sha256sum $H/blind-reloc-oracle-v2.0.py | cut -c1-16), operators $(sha256sum $H/lpfid-mutate.py | cut -c1-16)"
n=0
for p in $PKGS; do
  n=$((n+1))
  pin=$(timeout 3600 sudo docker run --rm -v $W:/work s39-builder bash /work/s43_gccpin.sh "$p" 2>>$H/gccpin.log)
  [ "$pin" = "NOTFOUND" ] && pin=""
  st "[$n] $p gcc pin: '${pin:-none}'"
  timeout 7200 sudo docker run --rm -e OUTROOT=out43 -e XCFLAGS="-I/work/kpatch-inc" -e GCCPIN="$pin" -v $W:/work s39-builder \
    bash /work/s43_pkg_arm64.sh "$p" >> $H/refbuild-aarch64.log 2>&1
  sudo chmod -R a+rX "$W/out43/$p" 2>/dev/null; sudo chown -R ubuntu:ubuntu "$W/out43/$p" 2>/dev/null
  if [ -f "$W/out43/$p/PKG-DONE" ]; then
    $W/venv/bin/python $H/s43_score.py $H/blind-reloc-oracle-v2.0.py $H/lpfid-mutate.py "$W/out43/$p" $H/results-aarch64.jsonl >> $H/score-aarch64.log 2>&1
    st "[$n] $p scored: $(tail -1 $H/score-aarch64.log)"
  else
    echo "{\"pkg\": \"$p\", \"status\": \"REFBUILD_FAIL\", \"reason\": \"$(grep "S39b $p" $H/refbuild-aarch64.log | tail -1 | tr -d '"')\"}" >> $H/results-aarch64.jsonl
    st "[$n] $p REFBUILD_FAIL"
  fi
done
st "S43 aarch64 DONE"; touch $H/S43-AARCH64-DONE
