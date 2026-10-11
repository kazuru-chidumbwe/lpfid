#!/usr/bin/env bash
# Loader baseline (TODO item 9; manuscript 6.6.1) on the runtime host.
# Same method as lab/s12/load-check.sh: boot the module's pin under KVM with a minimal busybox initramfs
# that holds only the module, insmod it, wait up to 60 s for enabled=1 and transition=0.
# Input: a TSV list "id<TAB>pin<TAB>module.ko" (one mutant or parent per line).
# Outcomes: LOADED_ENABLED (accepted), LOADED_NOT_LIVEPATCH (accepted: insmod rc 0 for a module whose
#           .modinfo has no livepatch=Y, i.e. a target or test module of the fixture corpus, which never
#           appears under /sys/kernel/livepatch), LOAD_FAIL, NOT_ENABLED, TIMEOUT (transition never completes),
#           CRASH (oops, BUG, panic or general protection fault in the serial log), BOOT_FAIL.
# A mutant counts as detected by the loader for every outcome except the two accepted ones (loud failure).
# Usage: loader-baseline.sh LIST.tsv OUTDIR [PAR]
set -uo pipefail
LIST=$1; OUT=$2; PAR=${3:-6}
PINS=/opt/atlas/s12-eval/pins
BB=/usr/bin/busybox
mkdir -p "$OUT/logs" "$OUT/work" "$OUT/rows"
log() { echo "[$(date -u +%H:%M:%S)] $*" >> "$OUT/progress.txt"; }

one() {
  local id=$1 pin=$2 ko=$3
  local safe; safe=$(echo "$id" | tr '/' '_')
  [ -f "$OUT/rows/$safe.row" ] && return 0   # resumable
  local w="$OUT/work/$safe"; rm -rf "$w"; mkdir -p "$w/tree"/{bin,proc,sys,dev}
  cp "$BB" "$w/tree/bin/busybox"
  for a in sh mount cat ls dmesg poweroff insmod sleep grep echo; do ln -sf busybox "$w/tree/bin/$a"; done
  cp "$ko" "$w/tree/m.ko"
  cat > "$w/tree/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
echo LC_BOOTED
insmod /m.ko
echo "LC_INSMOD_RC=$?"
n=0; en=; tr=
while [ $n -lt 60 ]; do
  for d in /sys/kernel/livepatch/*; do
    [ -d "$d" ] || continue
    en=$(cat $d/enabled 2>/dev/null); tr=$(cat $d/transition 2>/dev/null)
  done
  if [ "$en" = "1" ] && [ "$tr" = "0" ]; then break; fi
  sleep 1; n=$((n+1))
done
echo "LC_ENABLED=$en"
echo "LC_TRANSITION=$tr"
echo "LC_WAITED=$n"
dmesg | grep -i -E "livepatch|kpatch|klp|module|magic|disagrees|lp[0-9]|BUG|Oops|general protection|panic" | sed 's/^/LC_DMESG /'
echo LC_DONE
poweroff -f
INIT
  chmod +x "$w/tree/init"
  (cd "$w/tree" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "$w/initrd.gz"
  local serial="$OUT/logs/$safe.log"
  timeout 180 qemu-system-x86_64 -enable-kvm -m 768 -smp 2 -nographic -no-reboot \
    -kernel "$PINS/$pin/bzImage" -initrd "$w/initrd.gz" \
    -append "console=ttyS0 panic=-1 nokaslr init=/init" > "$serial" 2>&1
  local rc en trn outcome lp
  lp=$(objcopy -O binary --only-section=.modinfo "$ko" /dev/stdout 2>/dev/null | tr '\000' '\n' | grep -c -x 'livepatch=Y')
  rc=$(grep -a -o 'LC_INSMOD_RC=[0-9]*' "$serial" | head -1 | cut -d= -f2)
  en=$(grep -a -o 'LC_ENABLED=[0-9]*' "$serial" | head -1 | cut -d= -f2)
  trn=$(grep -a -o 'LC_TRANSITION=[0-9]*' "$serial" | head -1 | cut -d= -f2)
  if ! grep -aq LC_BOOTED "$serial"; then outcome=BOOT_FAIL
  elif grep -aqE "BUG:|Oops|general protection fault|Kernel panic" "$serial"; then outcome=CRASH
  elif [[ "$rc" != "0" ]]; then outcome=LOAD_FAIL
  elif [[ "$lp" == "0" ]]; then outcome=LOADED_NOT_LIVEPATCH
  elif [[ "$en" == "1" && "$trn" == "0" ]]; then outcome=LOADED_ENABLED
  elif [[ "$en" == "1" ]]; then outcome=TIMEOUT
  elif grep -aq LC_DONE "$serial"; then outcome=NOT_ENABLED
  else outcome=TIMEOUT; fi
  local reason
  reason=$(grep -a 'LC_DMESG' "$serial" | grep -a -v -i -E "command line|PCI: " | grep -a -i -E "fail|error|unknown|invalid|refus|denied|not found|magic|disagrees|BUG:|Oops|Kernel panic|-[0-9]+" | head -3 | sed 's/.*LC_DMESG //; s/"/'"'"'/g; s/\\/\//g' | tr '\n' ';' | tr -d '\r')
  printf '{"id":"%s","pin":"%s","module_sha256":"%s","outcome":"%s","insmod_rc":"%s","enabled":"%s","transition":"%s","reason":"%s"}\n' \
    "$id" "$pin" "$(sha256sum "$ko" | cut -d' ' -f1)" "$outcome" "$rc" "$en" "$trn" "$reason" > "$OUT/rows/$safe.row"
  rm -rf "$w"
  [[ "$outcome" == LOADED_ENABLED || "$outcome" == LOADED_NOT_LIVEPATCH ]] && rm -f "$serial"   # keep serial logs only for non-accepted runs
  log "$id $pin $outcome"
}
export -f one log
export OUT PINS BB

log "START list=$LIST n=$(wc -l < "$LIST")"
tr '\t' '\n' < "$LIST" | xargs -d '\n' -n 3 -P "$PAR" bash -c 'one "$@"' _
python3 - "$OUT" <<'PY'
import json, sys, glob, collections
out = sys.argv[1]
rows = [json.loads(l) for f in sorted(glob.glob(out + "/rows/*.row")) for l in open(f)]
summary = {"runs": len(rows), "by_outcome": dict(collections.Counter(r["outcome"] for r in rows)),
           "by_pin_outcome": {f"{p} {o}": n for (p, o), n in
                              sorted(collections.Counter((r["pin"], r["outcome"]) for r in rows).items())}}
json.dump({"summary": summary, "rows": rows}, open(out + "/loader-baseline.json", "w"), indent=1)
print(json.dumps(summary))
PY
log "DONE"
