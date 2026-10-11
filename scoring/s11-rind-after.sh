#!/usr/bin/env bash
# S11: score the klp-build modules against the independent compile (R-ind, S22 6.19) after the R-kp scoring.
cd /opt/atlas/s12
until grep -q "S11 ALL DONE" build-progress.txt; do sleep 300; done
echo "[$(date -u +%H:%M:%S)] S11 R-ind scoring start" >> build-progress.txt
nice -n 19 python3 s21oracle.py klp gcc-13 --workers 4 --branches 6.19 --reference ind > oracle/s11-klp-gcc-13-6.19-rind.log 2>&1
echo "[$(date -u +%H:%M:%S)] S11 R-ind scoring done" >> build-progress.txt
