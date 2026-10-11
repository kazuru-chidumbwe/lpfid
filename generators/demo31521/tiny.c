// S11 demo: a plain GPL module (control load, and stripped copy for the no-symbols path)
#include <linux/module.h>
static int __init tiny_init(void) { return 0; }
static void __exit tiny_exit(void) { }
module_init(tiny_init);
module_exit(tiny_exit);
MODULE_LICENSE("GPL");
