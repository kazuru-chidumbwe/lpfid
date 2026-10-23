#!/usr/bin/env bash
# Print the relocations (offset, type, target) of one function's section in an ELF file, in offset order,
# merging .rela.text.<fn> and .klp.rela.*..text.<fn>. usage: relocs_fn.sh <elf> <function>
f=$1; fn=$2
readelf -rW "$f" | awk -v fn="$fn" '
  /^Relocation section/ { p = ($0 ~ ("\.text\." fn "\047")) ; next }
  p && NF >= 5 && $1 ~ /^[0-9a-f]+$/ { print $1, $3, $5, $6, $7 }' | sort
