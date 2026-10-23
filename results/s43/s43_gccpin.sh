#!/usr/bin/env bash
# S43 compiler pin (runs in the Amazon Linux 2023 builder container). Prints one line: empty when the container's gcc
# is the release the shipped modules record, "<releasever>:<gcc nvr>" when that release is found in the current
# repositories (releasever "current") or in an AL2023 release listed in releasemd.xml (newest first), or "NOTFOUND".
# The banners read are echoed to stderr. usage: s43_gccpin.sh <package>
set -u
PKG=$1; WT=$(mktemp -d); cd "$WT"
dnf download -q "$PKG" >/dev/null 2>&1 || { echo "NOTFOUND"; echo "download failed" >&2; exit 0; }
rpm2cpio "$PKG"-*.rpm 2>/dev/null | cpio -idm 2>/dev/null
REL=$(find . -name "livepatch-*.ko" -exec readelf -p .comment {} \; 2>/dev/null | grep -o -E "Red Hat [0-9]+\.[0-9]+\.[0-9]+-[0-9]+" | sort -u | awk '{print $3}')
echo "module gcc releases: $(echo $REL)" >&2
N=$(echo "$REL" | grep -c .)
[ "$N" -ne 1 ] && { echo "NOTFOUND"; echo "expected one gcc release, found $N" >&2; exit 0; }
CUR=$(rpm -q gcc)
case "$CUR" in gcc-"$REL".*) echo ""; exit 0;; esac
GV=$(dnf -q --showduplicates list available gcc 2>/dev/null | awk -v r="$REL" 'index($2, r ".")==1 {print $2}' | tail -1)
[ -n "$GV" ] && { echo "current:$GV"; exit 0; }
for RV in $(curl -s https://cdn.amazonlinux.com/al2023/core/releasemd.xml | grep -o -E "2023\.[0-9]+\.[0-9]{8}" | sort -u -r); do
  GV=$(dnf -q --releasever="$RV" --showduplicates list available gcc 2>/dev/null | awk -v r="$REL" 'index($2, r ".")==1 {print $2}' | tail -1)
  [ -n "$GV" ] && { echo "$RV:$GV"; exit 0; }
done
echo "NOTFOUND"
