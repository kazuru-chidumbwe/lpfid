#!/usr/bin/env bash
# S21 case study: CVE-2026-43074 (fs/eventpoll.c) on the 6.6.47 pin, runtime host.
# Arms: none (no module), v0.9.11 module (pwq_cache,1 = eventpoll.c copy), v0.9.10 module (pwq_cache,2 =
# workqueue.c copy). Boot with slub_debug=F (consistency checks on every slab free), load the module, wait for
# enabled=1 and transition=0, run epoll-free (64 rounds of add-then-close), dump the kernel log.
# Each arm runs 3 times. Usage: case-43074.sh OUTDIR
set -uo pipefail
OUT=$1; mkdir -p "$OUT"
EVAL=/opt/atlas/s12-eval
K=$EVAL/pins/6.6.47/bzImage
BB=/usr/bin/busybox
declare -A MOD=( [none]="" [v0.9.11]="$EVAL/results/v0.9.11-gcc-13/6.6/CVE-2026-43074/build/lp2026_43074.ko"
                 [v0.9.10]="$EVAL/sweep/v0910-6.6-CVE-2026-43074.ko" )
gcc -static -O1 -o "$OUT/epoll-free" "$(dirname "$0")/epoll-free.c" || exit 1
for arm in none v0.9.11 v0.9.10; do
  for rep in 1 2 3; do
    w=$(mktemp -d); mkdir -p "$w"/{bin,proc,sys,dev}
    cp "$BB" "$w/bin/busybox"; for a in sh mount cat dmesg poweroff insmod sleep grep echo; do ln -sf busybox "$w/bin/$a"; done
    cp "$OUT/epoll-free" "$w/epoll-free"
    [ -n "${MOD[$arm]}" ] && cp "${MOD[$arm]}" "$w/m.ko"
    cat > "$w/init" <<'INIT'
#!/bin/sh
mount -t proc proc /proc; mount -t sysfs sysfs /sys; mount -t devtmpfs devtmpfs /dev 2>/dev/null
echo CS_BOOTED
if [ -f /m.ko ]; then
  insmod /m.ko; echo "CS_INSMOD_RC=$?"
  n=0; while [ $n -lt 60 ]; do
    for d in /sys/kernel/livepatch/*; do en=$(cat $d/enabled 2>/dev/null); tr=$(cat $d/transition 2>/dev/null); done
    [ "$en" = 1 ] && [ "$tr" = 0 ] && break; sleep 1; n=$((n+1)); done
  echo "CS_ENABLED=$en CS_TRANSITION=$tr"
fi
/epoll-free
sleep 2
dmesg | grep -i -E "wrong slab cache|BUG|Oops|corrupt|general protection|WARNING" | sed 's/^/CS_DMESG /'
echo CS_DONE
poweroff -f
INIT
    chmod +x "$w/init"
    (cd "$w" && find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > "$w.gz"
    timeout 240 qemu-system-x86_64 -enable-kvm -m 1024 -smp 2 -nographic -no-reboot -kernel "$K" -initrd "$w.gz" \
      -append "console=ttyS0 panic=-1 nokaslr slub_debug=F init=/init" > "$OUT/$arm-$rep.log" 2>&1
    rm -rf "$w" "$w.gz"
    echo "$arm $rep: $(grep -a -c 'CS_DMESG' "$OUT/$arm-$rep.log") kernel lines; $(grep -a -o 'EPOLL_TEST_DONE[^\r]*' "$OUT/$arm-$rep.log" | head -1); $(grep -a -o 'CS_ENABLED=[0-9]* CS_TRANSITION=[0-9]*' "$OUT/$arm-$rep.log" | head -1)" | tee -a "$OUT/summary.txt"
  done
done
