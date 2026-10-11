#!/usr/bin/env bash
# S6b independent check 1 (S6B-PREREG amendment, 11 Oct 2026): the kernel's own view of atomic replace.
# For each module: boot its pin under KVM with a busybox initramfs holding only the module, insmod it (with optional
# parameters), wait up to 60 s for enabled=1 and transition=0, then read /sys/kernel/livepatch/<patch>/replace.
# Input: TSV "id<TAB>pin<TAB>module.ko<TAB>params" (params may be empty). Output: OUT/replace.tsv and serial logs.
# Usage (runtime host): runtime_replace.sh LIST.tsv OUTDIR
set -uo pipefail
LIST=$1; OUT=$2
PINS=/opt/atlas/s12-eval/pins
BB=/usr/bin/busybox
mkdir -p "$OUT/logs" "$OUT/work"
printf "id\tpin\tparams\tinsmod_rc\tenabled\ttransition\treplace\tmodule_sha256\n" > "$OUT/replace.tsv"
while IFS=$'\t' read -r id pin ko params; do
  [ -z "$id" ] && continue
  safe=$(echo "$id" | tr '/:' '__')
  w="$OUT/work/$safe"; rm -rf "$w"; mkdir -p "$w/tree"/{bin,proc,sys,dev}
  cp "$BB" "$w/tree/bin/busybox"
  for a in sh mount cat ls sleep echo insmod poweroff; do ln -sf busybox "$w/tree/bin/$a"; done
  cp "$ko" "$w/tree/m.ko"
  cat > "$w/tree/init" <<INIT
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
insmod /m.ko $params
echo "RR_INSMOD_RC=\$?"
n=0; d=
while [ \$n -lt 60 ]; do
  d=\$(ls -d /sys/kernel/livepatch/* 2>/dev/null | head -1)
  [ -n "\$d" ] && [ "\$(cat \$d/enabled)" = 1 ] && [ "\$(cat \$d/transition)" = 0 ] && break
  sleep 1; n=\$((n+1))
done
echo "RR_ENABLED=\$(cat \$d/enabled 2>/dev/null)"
echo "RR_TRANSITION=\$(cat \$d/transition 2>/dev/null)"
echo "RR_REPLACE=\$(cat \$d/replace 2>/dev/null)"
poweroff -f
INIT
  chmod +x "$w/tree/init"
  (cd "$w/tree" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "$w/initrd.gz"
  log="$OUT/logs/$safe.log"
  timeout 180 qemu-system-x86_64 -enable-kvm -m 768 -smp 2 -nographic -no-reboot \
    -kernel "$PINS/$pin/bzImage" -initrd "$w/initrd.gz" \
    -append "console=ttyS0 panic=-1 nokaslr init=/init" > "$log" 2>&1 < /dev/null
  g() { grep -a -o "$1=[0-9]*" "$log" | head -1 | cut -d= -f2; }
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" "$id" "$pin" "$params" "$(g RR_INSMOD_RC)" "$(g RR_ENABLED)" \
    "$(g RR_TRANSITION)" "$(g RR_REPLACE)" "$(sha256sum "$ko" | cut -c1-64)" >> "$OUT/replace.tsv"
done < "$LIST"
echo "RUNTIME REPLACE DONE"
