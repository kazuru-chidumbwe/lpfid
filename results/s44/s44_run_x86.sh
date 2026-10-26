#!/usr/bin/env bash
# S44 x86-64 census (Testbed B), internal/S44-PREREG-2026-10-24.md: the S43 runner with oracle v2.1, operators v2.1 and the
# census list in place of the draw. S43 header follows.
# S43 x86-64 arm (Testbed B). Waits for ~/s42/TB-QUEUE-DONE, then for each drawn package (three at a time): reference
# build in the s26-builder container (s43_build_one_x86.sh, exact-build vmlinux and target-module debug objects
# kept), score with s43_score.py (oracle v2.0, registered operators, sympos and clonerb-klp with the vmlinux).
# Status ~/s43/STATUS, results ~/s43/results-x86_64.jsonl, flag ~/s43/S43-X86-DONE.
set -u
H=~/s44; W=~/s44/x86; mkdir -p $W; cp $H/s43_build_one_x86.sh $H/fix_kpatch.py $W/
st(){ echo "[$(date -u +%FT%TZ)] $*" | tee -a $H/STATUS; }
PKGS=$(cat $H/census-x86_64-2026-10-24.txt)
st "start x86_64: $(echo $PKGS | wc -w) packages; oracle $(sha256sum $H/blind-reloc-oracle-v2.1.py | cut -c1-16), operators $(sha256sum $H/lpfid-mutate-v2.1.py | cut -c1-16)"
one(){ p=$1
  docker run --rm -v $W:/work s26-builder bash /work/s43_build_one_x86.sh "$p" > $W/$p.build.log 2>&1
  docker run --rm -v $W:/work s26-builder chmod -R a+rwX "/work/$p" >/dev/null 2>&1
  if [ -d "$W/$p/ko" ] && ls $W/$p/ref/*/*.o >/dev/null 2>&1; then
    # pairing reads ref/<patch>; target-module debug objects in klpobj/ are found by the sympos check under the pkg dir
    /opt/atlas/venvs/lpfid-oracle-v11/bin/python $H/s44_score.py $H/blind-reloc-oracle-v2.1.py $H/lpfid-mutate-v2.1.py "$W/$p" $H/results-x86_64.jsonl >> $H/score-x86_64.log 2>&1
    st "$p scored: $(grep "^$p " $H/score-x86_64.log | tail -1)"
  else
    echo "{\"pkg\": \"$p\", \"status\": \"REFBUILD_FAIL\", \"reason\": \"$(tail -1 $W/$p.build.log | tr -d '"')\"}" >> $H/results-x86_64.jsonl
    st "$p REFBUILD_FAIL: $(tail -1 $W/$p.build.log)"
  fi; }
for p in $PKGS; do
  while [ "$(jobs -rp | wc -l)" -ge 3 ]; do sleep 30; done
  one "$p" &
  sleep 5
done
wait
st "S44 x86_64 DONE"; touch $H/S44-X86-DONE
