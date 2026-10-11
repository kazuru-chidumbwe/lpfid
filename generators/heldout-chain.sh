#!/usr/bin/env bash
# S16 Deviation 4: score the held-out set H once its builds are done and only if the v1.4 validation passed.
cd /opt/atlas/s12
st() { echo "[$(date -u +%H:%M:%S)] $*" >> build-progress.txt; }
until grep -q "HELDOUT BUILD DONE" s11-heldout.log; do sleep 300; done
until [ -s /opt/atlas/lpfid/oracle-v14-validation.json ]; do sleep 300; done
if python3 -c "import json,sys; sys.exit(0 if json.load(open('/opt/atlas/lpfid/oracle-v14-validation.json'))['summary']['pass'] is True else 1)"; then
  st "S16 Dev4: v1.4 validation PASS; held-out scoring start"
  nice -n 19 /opt/atlas/venvs/lpfid-oracle-v11/bin/python s11_heldout_score.py --workers 6 > oracle/s11-heldout-score.log 2>&1
  st "S16 Dev4: held-out scoring done"
else
  st "S16 Dev4: v1.4 validation FAILED; held-out scoring not run"
fi
