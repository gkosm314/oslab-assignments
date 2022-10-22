/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * Surname: 	Stamatis
 * Name: 	Apostolos
 *
 * Surname: 	Kosmas
 * Name: 	Georgios
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>

#include <linux/mm.h>
#include <asm/page.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"
#include <linux/capability.h>
/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	WARN_ON ( !(sensor = state->sensor));

	if(sensor->msr_data[state->type]->last_update > state->buf_timestamp) return 1;
	else return 0;
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;

	uint16_t raw_data;
	long formatted_lab, xx, yyy;

	WARN_ON ( !(sensor = state->sensor));
	
	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	spin_lock(&sensor->lock);
	/*
	 * Any new data available?
	 */
	if(lunix_chrdev_state_needs_refresh(state)){

		raw_data = sensor->msr_data[state->type]->values[0];
		state->buf_timestamp = sensor->msr_data[state->type]->last_update;
	}
	else{
		spin_unlock(&sensor->lock);
		return -EAGAIN;
	}

	spin_unlock(&sensor->lock);
	
	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
	if(state->needsFormat) {
		/*
		 * Default behaviour, the data should be formatted
		 */
		if(state->type == 0) formatted_lab =  lookup_voltage[raw_data];
		else if(state->type == 1) formatted_lab =  lookup_temperature[raw_data];
		else if(state->type == 2) formatted_lab =  lookup_light[raw_data];

		/* Copy the long to the char array */
		//memcpy(state->buf_data, &formatted_lab,sizeof(formatted_lab));
		
		xx = formatted_lab/1000;
		yyy = formatted_lab%1000;

		memset(state->buf_data,'\0', LUNIX_CHRDEV_BUFSZ*sizeof(char));
		sprintf(state->buf_data, "%ld.%ld\n", xx, yyy);
		state->buf_lim = sizeof(formatted_lab)+1;
	}
	else {
		/*
		 * Return the raw data if ioctl has requested so
		 */

		/* Copy the long to the char array */


		memset(state->buf_data,'\0', LUNIX_CHRDEV_BUFSZ*sizeof(char));
		sprintf(state->buf_data, "%u\n", raw_data);
		state->buf_lim = sizeof(raw_data)+1;	
	}
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/


static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	struct lunix_chrdev_state_struct *new_state;

	unsigned int major_number = imajor(inode);
	unsigned int minor_number = iminor(inode);
	unsigned int type_bits;
	unsigned int sensor_bits;
	int ret;

	//Check if someone uses your driver for a non-lunix device
	if(major_number != LUNIX_CHRDEV_MAJOR){
		ret = -ENODEV;
		goto out;
	}

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	
	/*
	 * Maximum measurements that Lunix driver supports = 8 => only the last 3 bits are relevant
	 * Throw away the last 3 digits, since they are measurement related. Then only keep the bits that are relevant to the sensor id
	 */
	sensor_bits = (minor_number >> 3) & (LUNIX_SENSOR_CNT-1);
	//Keep the last 3 digits
	type_bits = minor_number & 7;
	
	/* Allocate a new Lunix character device private state structure */
	new_state = kzalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);
	new_state->needsFormat = 1;
	new_state->type = type_bits;
	new_state->sensor = &lunix_sensors[sensor_bits];
	new_state->buf_timestamp = 0;
	
	sema_init(&new_state->lock, 1);
	
	filp->private_data = new_state;
	if(!filp->private_data){
		kfree(new_state);
		ret = -ENOMEM;
		goto out;
	}
	ret = 0;

out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct lunix_chrdev_state_struct *state;
	int ret;
	switch(cmd) {
		case LUNIX_COOKEDCMD:
			state = filp->private_data;
			if (! capable(CAP_SYS_RAWIO)) {
				ret = -EPERM;
				break;
			}
			if (arg != 0 && arg != 1) {
				ret = -EINVAL;
				break;
			}

			state->needsFormat = (int) arg;
			break;
		default:
 			ret = -ENOTTY;
	}
	return ret;
}


static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	/* Lock */
	if (down_interruptible(&state->lock))
		return -ERESTARTSYS;
	
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			up(&state->lock);
			if (filp->f_flags & O_NONBLOCK)
				return -EAGAIN;
			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state)))
				return -ERESTARTSYS;
			if(down_interruptible(&state->lock))
				return -ERESTARTSYS;
		}
	}

	/* End of file */
	/* Determine the number of cached bytes to copy to userspace */
	ret = min(cnt, (size_t)(state->buf_lim-(*f_pos)));
	if (copy_to_user(usrbuf, &state->buf_data[(*f_pos)], ret)) {
		ret = -EFAULT;
		goto out;
	}

	/* Auto-rewind on EOF mode? */
	*f_pos += ret;
	if(*f_pos == state->buf_lim) *f_pos = 0;

out:
	/* Unlock*/
	up(&state->lock);
	return ret;
}

static vm_fault_t lunix_vma_fault(struct vm_fault *vmf){
	struct lunix_chrdev_state_struct *state;
	struct lunix_sensor_struct *sensor;
	struct page *page;
	struct lunix_msr_data_struct *pageptr;	//pointer to the start of a measurement page

	struct vm_area_struct *target_vma;	
	target_vma = vmf->vma;

	state = target_vma->vm_private_data;
	sensor = state->sensor;
	page = VM_FAULT_SIGBUS;
	pageptr = NULL;							/* default to "missing" */

	down(&state->lock);						
	pageptr = sensor->msr_data[state->type];

	//takes a kernel logical address and returns its associated struct page pointer and updates it reference counter
	if (!pageptr) goto out;
	page = virt_to_page(pageptr);
	debug("lunix_vma_fault: page: ");			
	vmf->page = page;
	get_page(vmf->page);

out:
	up(&state->lock);
	return 0;
}


static struct vm_operations_struct lunix_mmap_vm_ops = {
	.fault = lunix_vma_fault
};

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	vma->vm_private_data = filp->private_data;	//private data of this VMA == state of chrdev
	vma->vm_flags |= VM_IO;				//memory management should not to attempt to swap out this VMA
	vma->vm_ops = &lunix_mmap_vm_ops;			//operations regarding this vma
	return 0;
}

static struct file_operations lunix_chrdev_fops = 
{
    .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);

	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");

	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	

	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);

	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
}
