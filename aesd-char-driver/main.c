/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include "aesdchar.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("isch4196");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

/**
 * aesd_open() - Initialize anything in preparation for later operations
 * @inode: pointer to file data (simply contains information about a file)
 * @filp: pointer to a file structure, representing an open file
 *
 * Return: success
 */
int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;

    PDEBUG("open");
    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    // private_data preserves state information across system calls
    filp->private_data = dev; 
    
    return 0;
}

/**
 * aesd_release()
 * @inode: pointer to file data (simply contains information about a file)
 * @filp: pointer to a file structure, representing an open file
 * 
 * Deallocate anything that open allocated in filp->private_data. Because we
 * don't allocate anything, do nothing.
 * 
 * Return: success
 */
int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = 0;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    /**
     * TODO: handle read
     */
    return retval;
}

/**
 * aesd_write()
 * @filp: 
 * @buf:
 * @count:
 *
 * Return: num bytes written, or error status
 */
ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    ssize_t retval = -ENOMEM;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry entry;
    const char *buff_to_del;
    char *usr_str = (char *)kmalloc(count, GFP_KERNEL);
    if(NULL == usr_str)
	goto out;
    
    if(copy_from_user(usr_str, buf, count)) { // returns num bytes not copied
	retval = -EFAULT;
	goto out;
    }
    retval = count;
    PDEBUG("%zu bytes with offset %lld, copied string: %s\n", count, *f_pos, usr_str);
    
    entry.buffptr = usr_str;
    entry.size = count;
    buff_to_del = aesd_circular_buffer_add_entry(&dev->buffer, &entry);
    if(buff_to_del) {
	PDEBUG("write: deleting entry: %s\n", buff_to_del);
	kfree(buff_to_del);
    }

 out: 
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

/**
 * aesd_setup_cdev() - init cdev struct
 * @dev: pointer to aesd_dev struct containing cdev struct
 *
 * cdev is the kernel's internal structure that represents char devices
 *
 * Return: zero on success, else fail
 */
static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}

int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;

    PDEBUG("init");
    // dynamically choose a major number
    result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    
    // Initialize the AESD specific portion of the device
    // so.. initialize locking primitive here, as video says...
    
    result = aesd_setup_cdev(&aesd_device);
    if (result) {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

void aesd_cleanup_module(void)
{
    uint8_t index;
    struct aesd_buffer_entry *entry;
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    
    PDEBUG("cleanup");
    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, index) {
	PDEBUG("kfree: %s\n", entry->buffptr);
	kfree(entry->buffptr);
    }
    
    cdev_del(&aesd_device.cdev);
    unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
