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
#include <linux/mutex.h>
#include <linux/slab.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"

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
    PDEBUG("open: %lld", filp->f_pos);
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
 * Deallocate anything that open allocated in filp->private_data, but because we
 * don't allocate anything, do nothing.
 * 
 * Return: success
 */
int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release: %lld", filp->f_pos);
    return 0;
}

/**
 * aesd_read()
 * @filp: pointer to a file structure, representing an open file
 * @buf: buffer containing user's string
 * @count: num characters in buf
 * @f_pos: represents current file position
 *
 * Return: size of bytes read.
 *         return == count: then request num bytes transferred
 *         0 < return < count: only portion has been returned
 *         0: end of file
 */
ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
		  loff_t *f_pos)
{
    ssize_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    struct aesd_buffer_entry *entry = NULL;
    size_t entry_offset = 0; // no use of entry_offset right now?
    unsigned long num_bytes_not_copied = 0;
    
    if(mutex_lock_interruptible(&dev->lock)) {
	retval = -ERESTARTSYS;
	goto out;
    }
    
    PDEBUG("read %zu bytes with offset %lld, or %lld", count, *f_pos, filp->f_pos);
    entry = aesd_circular_buffer_find_entry_offset_for_fpos(&dev->buffer, *f_pos, &entry_offset);
    if (!entry) {
	PDEBUG("Empty entry!\n");
	retval = 0;
	goto out;
    }

    PDEBUG("entry->size: %ld, entry_offset: %ld, entry->buffptr: %s\n", entry->size, entry_offset, entry->buffptr);
    num_bytes_not_copied = copy_to_user(buf, entry->buffptr+entry_offset, entry->size-entry_offset);
    if (num_bytes_not_copied) {
	PDEBUG("Lingering bytes from copy_to_user\n");
	retval = -EFAULT;
	goto out;
    }

    retval = entry->size - num_bytes_not_copied - entry_offset;
    *f_pos += retval;
    PDEBUG("retval: %ld, num_bytes_not_copied: %ld\n", retval, num_bytes_not_copied);
 out:
    mutex_unlock(&dev->lock);
    return retval;
}

/**
 * aesd_write()
 * @filp: pointer to a file structure, representing an open file
 * @buf: buffer containing user's string
 * @count: num characters in buf
 *
 * TODO: Yes, this function can be refactored by always appending string to char ptr first.
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
    char *usr_str = NULL;
    
    if(mutex_lock_interruptible(&dev->lock)) {
	retval = -ERESTARTSYS;
	goto out;
    }
    
#warning need to add +1 to count in order for multiples of 8 bytes to work properly else garbage??
    usr_str = (char *)kmalloc(count*sizeof(char)+1, GFP_KERNEL); 
    if (NULL == usr_str) {
	retval = -ENOMEM;
	goto out;
    }

    if (copy_from_user(usr_str, buf, count)) { // returns num bytes not copied
	retval = -EFAULT;
	goto out;
    }
    retval = count;
    PDEBUG("%zu bytes with offset %lld, copied string: %s\n", count, *f_pos, usr_str);

    if (usr_str[count-1] == '\n') {
	// newline exists, directly store in aesd_circular_buffer
	PDEBUG("aesd_write newline exists\n");
	if (dev->entry.temp_buffer) {
	    // append to string received before that didn't have newline
	    PDEBUG("aesd_write write_buffer exists\n");
	    dev->entry.temp_buffer = krealloc(dev->entry.temp_buffer, dev->entry.size+count, GFP_KERNEL);
	    if (NULL == dev->entry.temp_buffer) {
		retval = -ENOMEM;
		goto out;
	    }
	    dev->entry.temp_buffer[dev->entry.size] = '\0'; // make sure null terminator exists for strcat
	    strcat(dev->entry.temp_buffer, usr_str);
	    PDEBUG("dev->entry.temp_buffer: %s\n", dev->entry.temp_buffer);
	    kfree(usr_str);
	    usr_str = dev->entry.temp_buffer;
	    dev->entry.temp_buffer = NULL;

	    entry.size = dev->entry.size+count;
	} else {
	    entry.size = count;
	}
	entry.buffptr = usr_str;
	*f_pos += entry.size;
	PDEBUG("add_entry: %ld, %s\n", entry.size, entry.buffptr);
	buff_to_del = aesd_circular_buffer_add_entry(&dev->buffer, &entry);
	if (buff_to_del) {
	    PDEBUG("write: deleting entry: %s\n", buff_to_del);
	    kfree(buff_to_del);
	}
    } else {
	// newline !exist, store for now
	PDEBUG("aesd_write newline does not exist\n");
	if (dev->entry.temp_buffer) {
	    // append to string received before that didn't have newline either
	    PDEBUG("aesd_write write_buffer exists\n");
	    dev->entry.temp_buffer = krealloc(dev->entry.temp_buffer, dev->entry.size+count, GFP_KERNEL);
	    if (NULL == dev->entry.temp_buffer) {
		retval = -ENOMEM;
		goto out;
	    }
	    dev->entry.temp_buffer[dev->entry.size] = '\0'; // make sure null terminator exists for strcat
	    strcat(dev->entry.temp_buffer, usr_str);
	    dev->entry.size += count;
	    PDEBUG("dev->entry.size: %ld, dev->entry.temp_buffer: %s\n", dev->entry.size, dev->entry.temp_buffer);
	    kfree(usr_str);
	} else {
	    dev->entry.temp_buffer = usr_str;
	    dev->entry.size = count;
	    PDEBUG("dev->entry.size: %ld, dev->entry.temp_buffer: %s\n", dev->entry.size, dev->entry.temp_buffer);
	}
    }
 out:
    mutex_unlock(&dev->lock);
    return retval;
}

/**
 * aesd_llseek()
 * @filp:   file structure to seek on
 * @off:    file offset to seek to 
 * @whence: type of seek
 *
 * Return: new position
 */
loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    loff_t retval = 0;
    struct aesd_dev *dev = filp->private_data;
    
    size_t buffer_size = aesd_total_buffer_size(&dev->buffer);
    PDEBUG("aesd_llseek: off: %lld, whence: %d, buffer size: %ld\n", off, whence, buffer_size);
    if(mutex_lock_interruptible(&dev->lock)) {
	retval = -ERESTARTSYS;
	goto out;
    }
    retval = fixed_size_llseek(filp, off, whence, buffer_size);
    PDEBUG("aesd_llseek: retval: %lld\n", retval);
 out:
    mutex_unlock(&dev->lock);
    return retval;
}

/**
 * aesd_adjust_file_offset()
 * @filp:
 * @write_cmd:
 * @write_cmd_offset 
 *
 * Adjust the file offset (f_pos) parameter of @filp based on location specified
 * by @write_cmd (the zero referenced command to locate) and @write_cmd_offset
 * (the zero referenced offset into the command)
 *
 * Return: 0 if successful, negative if error occured:
 *     -ERESTARTSYS if mutex could not be obtained
 *     -EINVAL if write command or write_cmd_offset was out of range
 */
static long aesd_adjust_file_offset(struct file *filp, unsigned int write_cmd, unsigned int write_cmd_offset)
{
    unsigned int offset = 0, i = 0;
    long retval = 0;
    struct aesd_dev *dev = filp->private_data;
    
    // error checking
    if (write_cmd > AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED-1) {
	retval = -EINVAL;
	goto out;
    }
    if (write_cmd_offset > dev->buffer.entry[write_cmd].size-1) {
	retval = -EINVAL;
	goto out;
    }

    // now obtain the offset
    offset += write_cmd_offset;
    while (i++ < write_cmd) {
	offset += dev->buffer.entry[i].size;
    }
    filp->f_pos = offset;
    retval = 0;
    PDEBUG("aesd_adjust_file_offset: %lld\n", filp->f_pos);
 out:
    return retval;
}

/**
 * aesd_ioctl()
 * @filp: pointer to file structure
 * @cmd:
 * @arg:
 *
 *
 */
long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    long retval = 0;
    struct aesd_seekto seekto;
    
    if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

    switch(cmd) {
    case AESDCHAR_IOCSEEKTO:
	if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto))) {
	    retval = -EFAULT;
	    break;
	}
	PDEBUG("aesd_ioctl %d, %d\n", seekto.write_cmd, seekto.write_cmd_offset);
	retval = aesd_adjust_file_offset(filp, seekto.write_cmd, seekto.write_cmd_offset);
	break;
    default:
	PDEBUG("aesd_ioctl default case\n");
	retval = -ENOTTY;
	break;
    }
    PDEBUG("aesd_ioctl: %lld, retval: %ld\n", filp->f_pos, retval);
    return retval;
}

struct file_operations aesd_fops = {
    .owner	    = THIS_MODULE,
    .open	    = aesd_open,
    .write	    = aesd_write,
    .unlocked_ioctl = aesd_ioctl,
    .read	    = aesd_read,
    .llseek	    = aesd_llseek,
    .release	    = aesd_release,
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
    mutex_init(&aesd_device.lock);
    // on need init circular buffer, memset already takes care of that since its part of struct
    
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
