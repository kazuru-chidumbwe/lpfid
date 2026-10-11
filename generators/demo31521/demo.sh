#!/usr/bin/env bash
# S11 run-time demonstration of the klp-build string-pointer fault (objtool elf_add_data, fixed in 6.19.9).
# Boots the 6.19 pin under KVM three times with the same busybox initramfs; the only difference is the
# livepatch applied first: none (baseline), lp2026_31521.ko as built in the S11 campaign (faulty objtool), or
# lp2026_31521.ko rebuilt with only fa31c5b01 in objtool (fixed). Then the same four insmods hit the patched
# load_module paths: a second livepatch module, a module with an unknown symbol, a non-GPL module, and a
# module stripped of its symbol table. Serial logs keep every kernel message.
# Usage (runtime host): demo.sh DIR   (DIR holds faulty.ko fixed.ko lp2.ko unknownsym.ko nongpl.ko stripped.ko)
set -uo pipefail
D=$(readlink -f "$1"); PIN=/opt/atlas/s12-eval/pins/6.19/bzImage; BB=/usr/bin/busybox
mkdir -p "$D/logs"
for variant in baseline faulty fixed; do
  w="$D/work-$variant"; rm -rf "$w"; mkdir -p "$w/tree"/{bin,proc,sys,dev}
  cp "$BB" "$w/tree/bin/busybox"
  for a in sh mount cat ls dmesg poweroff insmod sleep echo; do ln -sf busybox "$w/tree/bin/$a"; done
  for m in lp2 unknownsym nongpl stripped; do cp "$D/$m.ko" "$w/tree/$m.ko"; done
  [ "$variant" != baseline ] && cp "$D/$variant.ko" "$w/tree/lp.ko"
  cat > "$w/tree/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev 2>/dev/null
echo DEMO_BOOTED
if [ -f /lp.ko ]; then
  insmod /lp.ko; echo "DEMO_LP_RC=$?"
  n=0
  while [ $n -lt 60 ]; do
    d=$(ls -d /sys/kernel/livepatch/* 2>/dev/null | head -1)
    [ -n "$d" ] && [ "$(cat $d/enabled)" = 1 ] && [ "$(cat $d/transition)" = 0 ] && break
    sleep 1; n=$((n+1))
  done
  echo "DEMO_LP_ENABLED=$(cat $d/enabled 2>/dev/null) TRANSITION=$(cat $d/transition 2>/dev/null) WAITED=$n"
fi
for m in lp2 unknownsym nongpl stripped; do
  echo "DEMO_STEP $m" > /dev/kmsg
  insmod /$m.ko; echo "DEMO_RC $m=$?" > /dev/kmsg
done
echo DEMO_DMESG_BEGIN
dmesg
echo DEMO_DMESG_END
poweroff -f
INIT
  chmod +x "$w/tree/init"
  (cd "$w/tree" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "$w/initrd.gz"
  timeout 240 qemu-system-x86_64 -enable-kvm -m 768 -smp 2 -nographic -no-reboot \
    -kernel "$PIN" -initrd "$w/initrd.gz" \
    -append "console=ttyS0 panic=-1 nokaslr init=/init loglevel=7" > "$D/logs/$variant.log" 2>&1
  echo "$variant rc=$? $(grep -a -c -E 'Oops|BUG:|general protection|Kernel panic' "$D/logs/$variant.log") crash-lines"
done
sha256sum "$D"/*.ko "$PIN" > "$D/logs/inputs.sha256"
