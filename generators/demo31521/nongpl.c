// S11 demo: non-GPL licence (licence taint warning in load_module)
#include <linux/module.h>
static int __init nongpl_init(void) { return 0; }
static void __exit nongpl_exit(void) { }
module_init(nongpl_init);
module_exit(nongpl_exit);
MODULE_LICENSE("Proprietary");
