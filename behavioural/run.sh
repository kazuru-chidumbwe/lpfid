#!/usr/bin/env bash
# S5 behavioural check runner (internal/S5-PREREG-2026-10-11.md). One VM boot per module on the runtime host.
# Phase 1: probe x3 before loading. Phase 2: insmod, wait enabled=1 and transition=0, probe x3. Phase 3: disable,
# wait transition=0, probe x3. Serial lines tagged S5_P<phase> carry the probe output.
# Input TSV: id<TAB>pin<TAB>module.ko<TAB>probe-binary. Output: OUT/rows.tsv (raw phase outputs) and serial logs.
# Usage: s5run.sh LIST.tsv OUTDIR [PAR]
set -uo pipefail
LIST=$1; OUT=$2; PAR=${3:-6}
PINS=/opt/atlas/s12-eval/pins
BB=/usr/bin/busybox
mkdir -p "$OUT/logs" "$OUT/work" "$OUT/rows"

one() {
  local id=$1 pin=$2 ko=$3 probe=$4
  local safe; safe=$(echo "$id" | tr '/:#' '___')
  [ -f "$OUT/rows/$safe.row" ] && return 0
  local w="$OUT/work/$safe"; rm -rf "$w"; mkdir -p "$w/tree"/{bin,proc,sys,dev}
  cp "$BB" "$w/tree/bin/busybox"
  for a in sh mount cat ls sleep echo insmod poweroff; do ln -sf busybox "$w/tree/bin/$a"; done
  cp "$ko" "$w/tree/m.ko"; cp "$probe" "$w/tree/probe"
  cat > "$w/tree/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
for i in 1 2 3; do /probe >> /p1; done
insmod /m.ko; echo "S5_INSMOD_RC=$?"
n=0; d=
while [ $n -lt 60 ]; do
  d=$(ls -d /sys/kernel/livepatch/* 2>/dev/null | head -1)
  [ -n "$d" ] && [ "$(cat $d/enabled)" = 1 ] && [ "$(cat $d/transition)" = 0 ] && break
  sleep 1; n=$((n+1))
done
echo "S5_ENABLED=$(cat $d/enabled 2>/dev/null) TRANSITION=$(cat $d/transition 2>/dev/null)"
for i in 1 2 3; do /probe >> /p2; done
echo 0 > $d/enabled 2>/dev/null
n=0
while [ $n -lt 60 ]; do
  [ "$(cat $d/transition 2>/dev/null)" = 0 ] && [ "$(cat $d/enabled 2>/dev/null)" != 1 ] && break
  sleep 1; n=$((n+1))
done
echo "S5_DISABLED=$(cat $d/enabled 2>/dev/null) TRANSITION=$(cat $d/transition 2>/dev/null)"
for i in 1 2 3; do /probe >> /p3; done
sleep 2
for ph in 1 2 3; do while read -r l; do echo "S5_P$ph $l"; done < /p$ph; done
echo S5_DONE
poweroff -f
INIT
  chmod +x "$w/tree/init"
  (cd "$w/tree" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "$w/initrd.gz"
  local log="$OUT/logs/$safe.log"
  timeout 300 qemu-system-x86_64 -enable-kvm -cpu host -m 1024 -smp 2 -nographic -no-reboot \
    -kernel "$PINS/$pin/bzImage" -initrd "$w/initrd.gz" \
    -append "console=ttyS0 panic=-1 nokaslr init=/init" > "$log" 2>&1 < /dev/null
  local crash; crash=$(grep -a -c -E "Oops|BUG:|general protection|Kernel panic" "$log")
  {
    printf "%s\t%s\t%s\t%s\t" "$id" "$pin" "$(sha256sum "$ko" | cut -c1-64)" "$crash"
    printf "%s\t" "$(grep -a -o 'S5_INSMOD_RC=[0-9]*' "$log" | head -1 | cut -d= -f2)"
    printf "%s\t" "$(grep -a -o 'S5_ENABLED=[^ ]* TRANSITION=[0-9]*' "$log" | head -1)"
    for ph in P1 P2 P3; do printf "%s\t" "$(grep -a -o -E "S5_$ph PROBE [a-z]+=-?[0-9]+( errno=[0-9]+)?" "$log" | sed "s/^S5_$ph //" | paste -sd '|')"; done
    printf "%s\n" "$(grep -a -c S5_DONE "$log")"
  } > "$OUT/rows/$safe.row"
}
export -f one; export OUT PINS BB
tr -d '\r' < "$LIST" | xargs -P "$PAR" -d '\n' -I{} bash -c 'IFS=$'"'"'\t'"'"' read -r a b c d <<< "{}"; one "$a" "$b" "$c" "$d"'
printf "id\tpin\tmodule_sha256\tcrash_lines\tinsmod_rc\tenable_state\tP1\tP2\tP3\tdone\n" > "$OUT/rows.tsv"
cat "$OUT"/rows/*.row >> "$OUT/rows.tsv"
echo "S5 RUN DONE"
