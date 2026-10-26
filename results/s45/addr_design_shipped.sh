#!/bin/sh
# Address check on the design-draw CVE-2023-5090 module as shipped (extracted from the rpm), and on the kept file for
# comparison; the S26 keep step had overwritten the shipped module with the local build.
P=kernel-livepatch-6.1.56-82.125
K=$HOME/s44/s26re/keep/$P
PY=/opt/atlas/venvs/lpfid-oracle-v11/bin/python
R=$(grep -l svm_set_x2apic_msr_interception "$K"/ref/CVE-2023-5090*/*.o | head -1)
cd "$HOME/s45"
$PY addr_equiv.py x86_64 svm_set_x2apic_msr_interception "$K/ko/livepatch-CVE-2023-5090.ko" "$R" "design-shipped:$P"
$PY addr_equiv.py x86_64 svm_set_x2apic_msr_interception "$HOME/s26/results/$P/keep/CVE-2023-5090/livepatch-CVE-2023-5090.ko" "$R" "design-keep:$P"
