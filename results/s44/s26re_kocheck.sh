#!/bin/sh
# S26 rebuild control, module side: the 58 kept S26 modules carry debug sections, the modules extracted again from the
# binary rpm do not. Compare every section that is not debug information, byte for byte, and the disassembly.
# usage: s26re_kocheck.sh > s26re-kocheck.txt
same=0; diff=0
for k in ~/s26/results/*/keep/*/*.ko; do
  pkg=$(echo "$k" | sed 's|.*/results/||; s|/keep/.*||')
  n=~/s44/s26re/keep/$pkg/ko/$(basename "$k")
  bad=""
  secs=$(readelf -S -W "$n" | sed -n 's/^ *\[ *[0-9]*\] \([^ ]*\) .*/\1/p' | grep -v '^$')
  ksecs=$(readelf -S -W "$k" | sed -n 's/^ *\[ *[0-9]*\] \([^ ]*\) .*/\1/p' | grep -v '^\.debug\|^\.rela\.debug\|^$')
  [ "$(echo "$secs" | sort)" = "$(echo "$ksecs" | sort)" ] || bad="$bad section-list"
  for s in $secs; do
    [ "$s" = ".symtab" ] || [ "$s" = ".strtab" ] || [ "$s" = ".shstrtab" ] && continue
    cmp -s <(objcopy -O binary --only-section="$s" "$k" /dev/stdout 2>/dev/null) \
           <(objcopy -O binary --only-section="$s" "$n" /dev/stdout 2>/dev/null) || bad="$bad $s"
  done
  a=$(objdump -dr "$k" | grep -v 'file format' | md5sum); b=$(objdump -dr "$n" | grep -v 'file format' | md5sum)
  [ "$a" = "$b" ] || bad="$bad disasm"
  a=$(readelf -sW "$k" | awk 'NR>3{print $2,$3,$4,$5,$7,$8}' | md5sum); b=$(readelf -sW "$n" | awk 'NR>3{print $2,$3,$4,$5,$7,$8}' | md5sum)
  [ "$a" = "$b" ] || bad="$bad symbols"
  if [ -z "$bad" ]; then same=$((same+1)); echo "SAME $pkg $(basename "$k")"; else diff=$((diff+1)); echo "DIFF $pkg $(basename "$k"):$bad"; fi
done
echo "modules same $same diff $diff (non-debug sections, symbols, disassembly)"
