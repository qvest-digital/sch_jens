/* hack because Linux fails at exposing this value */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/jiffies.h>

int SHOW_HZ_before = 0;
int SHOW_HZ_hz = HZ;
int SHOW_HZ_after = 0;

MODULE_LICENSE("GPL");
