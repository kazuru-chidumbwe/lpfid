// S11 demo: references a symbol the kernel does not export (unknown-symbol path in load_module)
#include <linux/module.h>
extern void lpfid_no_such_symbol(void);
static int __init unknownsym_init(void) { lpfid_no_such_symbol(); return 0; }
module_init(unknownsym_init);
MODULE_LICENSE("GPL");
