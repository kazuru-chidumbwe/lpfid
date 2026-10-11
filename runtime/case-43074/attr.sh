#!/usr/bin/env bash
# Which kpatch commit fixes the pwq_cache binding of CVE-2026-43074 (6.6)? (9 Oct 2026)
# Two candidates lie between v0.9.10 and v0.9.11 and touch symbol lookup: c608faf "Fix sympos for gcc-14" and
# 0f0294a "lookup: fix local bind check". Four kpatch builds, each used once on the fix, same tree restore and
# compiler as the campaign (s12build.build, workers 10 and 11):
#   A = v0.9.10 + c608faf   B = v0.9.10 + 0f0294a   C = v0.9.11 - c608faf   D = v0.9.11 - 0f0294a
# Output: /opt/atlas/s12/attr/<variant>-gcc-13/6.6/CVE-2026-43074 and attr-result.txt
set -u
K=/opt/atlas/tools/kp
SRC=/opt/atlas/tools/kpatch
cd /opt/atlas/s12
log() { echo "[$(date -u +%H:%M:%S)] ATTR $*" | tee -a attr-result.txt; }
mk() {   # name base op commit
  local n=$1 base=$2 op=$3 c=$4 d=$K/src-$1
  rm -rf $d; git clone -q $SRC $d && cd $d && git checkout -q $base && git config user.email x@x && git config user.name attr
  if [ "$op" = pick ]; then git cherry-pick -x $c >/dev/null 2>&1 || { log "$n: cherry-pick $c conflicts"; git cherry-pick --abort; cd /opt/atlas/s12; return 1; }
  else git revert --no-edit $c >/dev/null 2>&1 || { log "$n: revert $c conflicts"; git revert --abort; cd /opt/atlas/s12; return 1; }; fi
  make -j8 >build.log 2>&1 && make install PREFIX=$K/$n DESTDIR= >>build.log 2>&1 || { log "$n: kpatch build failed"; cd /opt/atlas/s12; return 1; }
  log "$n: $base $op $c -> $(git rev-parse --short HEAD)"
  cd /opt/atlas/s12
}
mk attr-A v0.9.10 pick c608faf
mk attr-B v0.9.10 pick 0f0294a
mk attr-C v0.9.11 revert c608faf
mk attr-D v0.9.11 revert 0f0294a
S12_RESULTS=/opt/atlas/s12/attr python3 - <<'EOF'
import json, os, sys
sys.argv = [sys.argv[0]]
import importlib.util
spec = importlib.util.spec_from_file_location("b", "/opt/atlas/s12/s12build.py"); b = importlib.util.module_from_spec(spec); spec.loader.exec_module(b)
sel = json.loads(open("/opt/atlas/s12/out/6.6/selection.json").read())
job = next(j for j in sel["main"] + sel["overcap"] if j["cve"] == "CVE-2026-43074")
from concurrent.futures import ThreadPoolExecutor
variants = [v for v in ("attr-A", "attr-B", "attr-C", "attr-D") if os.path.isdir(f"/opt/atlas/tools/kp/{v}/bin")]
def run(iv):
    i, v = iv
    for vv in variants[i::2]:
        b.build({**job, "branch": "6.6", "set": "attr"}, 10 + i, vv, "gcc-13")
with ThreadPoolExecutor(2) as ex:
    list(ex.map(run, enumerate(variants[:2])))
EOF
for v in attr-A attr-B attr-C attr-D; do
  ko=$(ls /opt/atlas/s12/attr/$v-gcc-13/6.6/CVE-2026-43074/build/*.ko 2>/dev/null | head -1)
  if [ -z "$ko" ]; then log "$v: no module"; continue; fi
  log "$v: $(readelf -sW $ko | grep -o '\.klp\.sym\.vmlinux\.pwq_cache,[0-9]*' | sort -u | tr '\n' ' ') sha256 $(sha256sum $ko | cut -c1-16)"
done
log "ATTR DONE"
