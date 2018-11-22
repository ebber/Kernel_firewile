#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Erik Beitel");
MODULE_DESCRIPTION("A skeleton Linux module for a firewall.");
MODULE_VERSION("0.01");
static int __init mod_init(void) {
 	printk(KERN_INFO "Hello, World!\n");
 	return 0;
}

static void __exit mod_exit(void) {
	printk(KERN_INFO "Goodbye, World!\n");
}

module_init(mod_init);
module_exit(mod_exit);
