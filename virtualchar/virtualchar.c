#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <linux/gpio.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/notifier.h>
#include <linux/switch.h>
#include <linux/delay.h>

#include <linux/mutex.h>

#include <linux/workqueue.h>
#include <linux/time.h>
#include <linux/kthread.h>

#include <linux/wait.h>

#include <linux/string.h>
#include <linux/poll.h>

#include "virtualchar.h"

#define VERSION	"v1.0"

#define VIRTUALCHAR_DEBUG_ON	1

static int virtualchar_debug = 1;
module_param(virtualchar_debug,int,0644);

struct proc_dir_entry *virtualchar_proc = NULL;
#define VIRTUALCHARDEV_PROC_NAME	"virtualchar"

#define VIRTUALCHAR_DEBUG(fmt,arg...)	do{\
									if(virtualchar_debug)\
										printk(">>>>>>virtual char dev debug<<<<<<"fmt"\n",##arg);\
								}while(0)
#define VIRTUALCHAR_ERROR(fmt,arg...)	do{\
									if(virtualchar_debug)\
										printk(">>>>>>virtual char dev error<<<<<<"fmt"\n",##arg);\
								}while(0)
									
									
							
static struct virtualchar_dev *g_virtualchar_dev = NULL;

							
static int virtualchar_open(struct inode *inode, struct file *file)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	#if 1
	struct virtualchar_dev *dev = container_of(inode->i_cdev, struct virtualchar_dev,cdev);
	#else
	struct virtualchar_dev *dev = g_virtualchar_dev;
	#endif
	file->private_data = dev;

	if(!atomic_read(&dev->user)){ 
		
	}
	atomic_inc(&dev->user);
	
	return 0;
}

static int virtualchar_release(struct inode *inode, struct file *file)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	struct virtualchar_dev *dev = file->private_data;
	//if(atomic_dec_and_test(&dev->user))
	//	;
	
	return 0;
}
static long virtualchar_read(struct file *file, char *buf,size_t count,loff_t *f_ops)
{
	int ret = 0;
	struct virtualchar_dev *dev = file->private_data;
	
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	
	DEFINE_WAIT(wait); //autoremove wake(current process)
	
	while(1){
		//1.add to waite queue  2.set current state:TASK_INTERRUPTIBLE
		prepare_to_wait(&dev->r_wait, &wait, TASK_INTERRUPTIBLE);
		mutex_lock(&dev->mutex);
		ret = (dev->current_len == 0);
		mutex_unlock(&dev->mutex);
		if(!ret)
			break;
		if (file->f_flags & O_NONBLOCK) { //open with flags:O_NONBLOCK
			ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) { //ctrl+C, signal interrupt
			ret = -EINTR;
			break;
		}

		schedule(); //switch to other process
	}
	
	finish_wait(&dev->r_wait, &wait); //remove wait queue form wait
	if (ret)
		goto out;
	
	mutex_lock(&dev->mutex);
	if(count > dev->current_len)
		count = dev->current_len;
	
	if(copy_to_user(buf,dev->buffer,count)){
		#ifdef SUPPORT_CAT
		ret = count;
		#else
		ret = -EFAULT;
		#endif
		mutex_unlock(&dev->mutex);
		goto out;
	}else{
		memcpy(dev->buffer,dev->buffer+count,dev->current_len-count);
		dev->current_len -= count;
		VIRTUALCHAR_DEBUG("read %d bytes current_len %d ",count,dev->current_len);
		#ifdef SUPPORT_CAT
		ret = 0;
		#else
		ret = count;
		#endif
	}
	mutex_unlock(&dev->mutex);
	wake_up_interruptible(&dev->w_wait);

out:
	
	return ret;
}
static long virtualchar_write(struct file *file, char *buf,size_t count,loff_t *f_ops)
{
	int ret = 0;
	struct virtualchar_dev *dev = file->private_data;
	
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	
	DEFINE_WAIT(wait); //autoremove wake(current process)
	
	for(;;){
		//1.add to waite queue  2.set current state:TASK_INTERRUPTIBLE
		prepare_to_wait(&dev->w_wait, &wait, TASK_INTERRUPTIBLE);
		mutex_lock(&dev->mutex);
		ret = (dev->current_len == VIRTUALCHAR_BUFFER_SIZE);
		mutex_unlock(&dev->mutex);
		if(!ret)
			break;
		
		if (file->f_flags & O_NONBLOCK) { //open with flags:O_NONBLOCK
			ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) { //ctrl+C, signal interrupt
			ret = -EINTR;
			break;
		}

		schedule(); //switch to other process
	}
	
	finish_wait(&dev->w_wait, &wait); //remove wait queue form wait
	if (ret)
		goto out;
	
	mutex_lock(&dev->mutex);
	if(count > VIRTUALCHAR_BUFFER_SIZE - dev->current_len)
		count = VIRTUALCHAR_BUFFER_SIZE - dev->current_len;
	
	if(copy_from_user(dev->buffer+dev->current_len,buf,count)){
		ret = -EFAULT;
		mutex_unlock(&dev->mutex);
		goto out;
	}else{
		
		dev->current_len += count;

		VIRTUALCHAR_DEBUG("write %d bytes current_len %d ",count,dev->current_len);
		ret = count;
	}
	mutex_unlock(&dev->mutex);
	wake_up_interruptible(&dev->r_wait);
out:
	
	return ret;
}
static unsigned int virtualchar_poll(struct file *file, struct poll_table_struct *pt)
{
	unsigned int mask = 0;
	struct virtualchar_dev *dev = file->private_data;
	
	mutex_lock(&dev->mutex);
	poll_wait(file, &dev->w_wait, pt);
	poll_wait(file, &dev->r_wait, pt);
	if(dev->current_len != VIRTUALCHAR_BUFFER_SIZE)
		mask |= POLLOUT | POLLWRNORM; //write
	if(dev->current_len)
		mask |= POLLIN  | POLLRDNORM; //read
	mutex_unlock(&dev->mutex);	
	VIRTUALCHAR_DEBUG("%s mask:0x%x\n", __func__, mask);
	return mask;
}
static long virtualchar_unlocked_ioctl(struct file *file, unsigned int cmd,unsigned long arg)
{
	int ret = 0;
	struct virtualchar_dev *dev = file->private_data;
	int tmp;
	
	mutex_lock(&dev->mutex);
	switch(cmd)
	{
		case VIRTUALCHAR_MEM_CLEAR:
			if(dev->share_mem.mem){
				memset(dev->share_mem.mem,0,dev->share_mem.size);
				VIRTUALCHAR_DEBUG("virtualchar memory is set to zero");
			}else{
				ret = -EINVAL;
			}
			break;
		case VIRTUALCHAR_MEM_SET_SIZE:
			if(copy_from_user(&dev->share_mem.size,(int __user *)arg,sizeof(int))){
				ret =  -EFAULT;
				break;
			}

			if(dev->share_mem.mem)
				kfree(dev->share_mem.mem);
			dev->share_mem.mem = kzalloc(dev->share_mem.size,GFP_KERNEL);
			if(!dev->share_mem.mem){
				VIRTUALCHAR_DEBUG("virtualchar share memory size set error");
				ret =  -EFAULT;
			}
			break;
		case VIRTUALCHAR_MEM_GET_SIZE:
			if(copy_to_user((int __user *)arg,&dev->share_mem.size,sizeof(int)))
				ret =  -EFAULT;
			break;
		case VIRTUALCHAR_MEM_SET_OFFSET:
			if(copy_from_user(&dev->share_mem.offset,(int __user *)arg,sizeof(int)))
				ret =  -EFAULT;
			break;
		case VIRTUALCHAR_MEM_GET_OFFSET:
			if(copy_to_user((int __user *)arg,&dev->share_mem.offset,sizeof(int)))
				ret =  -EFAULT;
			break;
		case VIRTUALCHAR_MEM_SET_NUM:
			if(copy_from_user(&dev->share_mem.offset,(int __user *)arg,sizeof(int)))
				ret =  -EFAULT;
			break;
		case VIRTUALCHAR_MEM_GET_NUM:
			if(copy_to_user((int __user *)arg,&dev->share_mem.offset,sizeof(int)))
				ret =  -EFAULT;
			break;
		case VIRTUALCHAR_MEM_SET_VAL:
			if(dev->share_mem.num == 0 || (dev->share_mem.num + dev->share_mem.offset > dev->share_mem.size)){
				ret =  -EFAULT;
				break;
			}
			if(dev->share_mem.mem){
				if(copy_from_user(&dev->share_mem.mem,(int __user *)arg,dev->share_mem.num))
					ret =  -EFAULT;
			}else{
				ret = -EINVAL;
			}
			break;
		case VIRTUALCHAR_MEM_GET_VAL:
			if(dev->share_mem.num == 0 || (dev->share_mem.num + dev->share_mem.offset > dev->share_mem.size)){
				ret =  -EFAULT;
				break;
			}
			if(dev->share_mem.mem){
				if(copy_to_user((int __user *)arg,&dev->share_mem.mem,dev->share_mem.num))
					ret =  -EFAULT;
			}else{
				ret = -EINVAL;
			}
			break;
		default:
			ret = -EINVAL;
			break;	
	}
	mutex_unlock(&dev->mutex);
	
	return 0;
}


static struct file_operations virtualchar_fops = {
	.owner = THIS_MODULE,
	.open = virtualchar_open,
	.release = virtualchar_release,
	.unlocked_ioctl = virtualchar_unlocked_ioctl,
	.read = virtualchar_read,
	.write = virtualchar_write,
	.poll = virtualchar_poll,
};
									
static size_t virtualchar_status_show(struct device *dev,struct device_attribute *attr,char *buf)
{
	
	return sprintf(buf,"virtualchar->user = %d\n",atomic_read(&g_virtualchar_dev->user));
}
static size_t virtualchar_status_store(struct device *dev,struct device_attribute *attr,char *buf,size_t count)
{
	u32 tmp;
	
	tmp = simple_strtoul(buf,NULL,10);
	atomic_set(&g_virtualchar_dev->user,tmp);
	return count;
}
DEVICE_ATTR(status,0755,virtualchar_status_show,virtualchar_status_store);
static void virtualchar_work_wakeup(void);
static void virtualchar_delayedwork_wakeup(void);
static size_t virtualchar_workon_show(struct device *dev,struct device_attribute *attr,char *buf)
{
	
	return sprintf(buf,"virtualchar->workon = %d\n",atomic_read(&g_virtualchar_dev->workon));
}
static size_t virtualchar_workon_store(struct device *dev,struct device_attribute *attr,char *buf,size_t count)
{
	u32 tmp;
	
	tmp = simple_strtoul(buf,NULL,10);
	atomic_set(&g_virtualchar_dev->workon,tmp);
	virtualchar_delayedwork_wakeup();
	
	return count;
}
DEVICE_ATTR(workon,0755,virtualchar_workon_show,virtualchar_workon_store);
#if ATTRINUTE_ARRAY
static struct attribute * virtualchardev_attrs[] = {
	&dev_attr_status.attr,
	&dev_attr_workon.attr,
	NULL,
};

static struct attribute_group virtualchardev_attr_group = {
	.attrs = virtualchardev_attrs,
};

#endif	

static int virtualchar_write_proc(struct file *file, const char *buffer, unsigned long count, void *data)
{
	char tmp[512];
	
	if(count > 512){
		VIRTUALCHAR_ERROR("%s count error:%d ",__func__,count);
		return -EFAULT;
	}
	if(copy_from_user(tmp,buffer,count)){
		VIRTUALCHAR_ERROR("%s  copy_from_user fail",__func__);
		return -EFAULT;
	}
	VIRTUALCHAR_DEBUG("%s sucess",__func__);
	
	
	return count;
}
static int virtualchar_read_proc(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	char *ptr = page;
	
	ptr += sprintf(ptr,"\nvirtual char dev version:");
	ptr += sprintf(ptr,VERSION);
	ptr += sprintf(ptr,"\n");
	
	*eof = 1;
	return (ptr - page);
}


static enum hrtimer_restart virtualchar_work_hrtimer_func(struct hrtimer *timer)
{
    
    virtualchar_work_wakeup();
    return HRTIMER_NORESTART;
}
static void virtualchar_work_timer_init(struct virtualchar_dev *dev)
{
	ktime_t ktime;
	
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	ktime = ktime_set(1,0);
	hrtimer_init(&dev->work_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
    dev->work_timer.function = virtualchar_work_hrtimer_func;    
    hrtimer_start(&dev->work_timer, ktime, HRTIMER_MODE_REL);
} 
static void virtualchar_work_timer_exit(struct virtualchar_dev *dev)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	hrtimer_cancel(&dev->work_timer);
} 

static void virtualchar_delayedwork_wakeup(void)
{
	#if ENABLE_USER_WORKQUEUE
	queue_delayed_work(g_virtualchar_dev->wq, &g_virtualchar_dev->delayed_work,1*HZ);
	#else
	schedule_delayed_work(&g_virtualchar_dev->delayed_work);
	#endif
}
static void virtualchar_work_wakeup(void)
{
	#if ENABLE_USER_WORKQUEUE
	queue_work(g_virtualchar_dev->wq, &g_virtualchar_dev->work);
	#else
	schedule_work(&g_virtualchar_dev->work);
	#endif
}

static void virtualchar_workqueue(struct work_struct *work)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	struct virtualchar_dev *dev = container_of(work, struct virtualchar_dev,work);
	
	VIRTUALCHAR_DEBUG("workon: %d ",atomic_read(&dev->workon));
	
	ktime_t ktime = ktime_set(1, 0);
	hrtimer_start(&dev->work_timer, ktime, HRTIMER_MODE_REL);
}
static void virtualchar_delayed_workqueue(struct work_struct *work)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	struct virtualchar_dev *dev = container_of(work, struct virtualchar_dev,delayed_work.work);
	
	VIRTUALCHAR_DEBUG("workon: %d ",atomic_read(&dev->workon));
	
	
}

static void virtualchar_create_workqueue(struct virtualchar_dev *dev)
{
	#if ENABLE_USER_WORKQUEUE
	dev->wq = create_workqueue("virchar_wq");
	if(dev->wq){
		INIT_WORK(&dev->work, virtualchar_workqueue);
		INIT_DELAYED_WORK(&dev->delayed_work, virtualchar_delayed_workqueue);
	}
	#else
	INIT_WORK(&dev->work, virtualchar_workqueue);
	INIT_DELAYED_WORK(&dev->delayed_work, virtualchar_delayed_workqueue);
	#endif
	atomic_set(&dev->workon,0);
	
	virtualchar_work_timer_init(dev);
}
static void virtualchar_destroy_workqueue(struct virtualchar_dev *dev)
{
	virtualchar_work_timer_exit(dev);
	cancel_delayed_work_sync(&dev->delayed_work);
	cancel_work_sync(&dev->work);
	#if ENABLE_USER_WORKQUEUE
	destroy_workqueue(dev->wq);
	dev->wq = NULL;
	#endif
}

static void virtualchar_kthread_timer_func(unsigned long arg)
{
    
    g_virtualchar_dev->kthread_timeout = true;
    
    wake_up_interruptible(&g_virtualchar_dev->kthrea_wq);    
}

static void virtualchar_kthread_timer_init(struct virtualchar_dev *dev)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	init_timer(&dev->kthread_timer);
	dev->kthread_timer.expires = jiffies + 1*HZ;
	dev->kthread_timer.data = 0;
	dev->kthread_timer.function = virtualchar_kthread_timer_func;
	add_timer(&dev->kthread_timer);
	
} 
static void virtualchar_kthread_timer_exit(struct virtualchar_dev *dev)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	del_timer_sync(&dev->kthread_timer);
}


static int virtualchar_notifier_call_chain(struct virtualchar_dev *dev,unsigned long val,void *v)
{
	return blocking_notifier_call_chain(&dev->notifier_list,val,v);
}
int virtualchar_notifier_chain_register(struct virtualchar_dev *dev,struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&dev->notifier_list,nb);
}
EXPORT_SYMBOL(virtualchar_notifier_chain_register);
int virtualchar_notifier_chain_unregister(struct virtualchar_dev *dev,struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&dev->notifier_list,nb);
}
EXPORT_SYMBOL(virtualchar_notifier_chain_unregister);

static int virtualchar_notifier_handler(struct notifier_block *this, unsigned long event, void *ptr)
{
	VIRTUALCHAR_DEBUG(" %s : event:%d",__func__,event);
	
	return 0;
}
static struct notifier_block virtualchar_notifier=
{
	.notifier_call = virtualchar_notifier_handler,
};
static void virtualchar_notifier_init(struct virtualchar_dev *dev)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	BLOCKING_INIT_NOTIFIER_HEAD(&(dev->notifier_list));
	virtualchar_notifier_chain_register(dev,&virtualchar_notifier);
}
static void virtualchar_notifier_exit(struct virtualchar_dev *dev)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	virtualchar_notifier_chain_unregister(dev,&virtualchar_notifier);
}



static int virtualchar_kthread(void *arg)
{
	int val = 0;
	int time = 0;
    
	VIRTUALCHAR_DEBUG("enter: %s \n",__func__);
	while(1)
	{
		if(kthread_should_stop())
			break;
		
		
		wait_event_interruptible(g_virtualchar_dev->kthrea_wq,g_virtualchar_dev->kthread_timeout == true);
		mutex_lock(&g_virtualchar_dev->kthread_mutex);
		g_virtualchar_dev->kthread_timeout = false;
		g_virtualchar_dev->kthread_timer.expires = jiffies + 1*HZ;
		add_timer(&g_virtualchar_dev->kthread_timer);
		mutex_unlock(&g_virtualchar_dev->kthread_mutex);
		virtualchar_notifier_call_chain(g_virtualchar_dev,time++,NULL);
		VIRTUALCHAR_DEBUG(" run: %s \n",__func__);
	}
	
	return 0;
}
static void virtualchar_kthread_init(struct virtualchar_dev *dev)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	mutex_init(&dev->kthread_mutex);
	
	
	mutex_lock(&dev->kthread_mutex);
	dev->kthread_task = NULL;
	
	init_waitqueue_head(&dev->kthrea_wq);
	virtualchar_notifier_init(dev);
	virtualchar_kthread_timer_init(dev);
	
	dev->kthread_task = kthread_create(virtualchar_kthread,NULL,"virtualchar_kthread");
	if(IS_ERR(dev->kthread_task)){
		VIRTUALCHAR_DEBUG(" thread create fail  \n");
		PTR_ERR(dev->kthread_task);
		dev->kthread_task = NULL;
		mutex_unlock(&dev->kthread_mutex);
		return;
	}
	wake_up_process(dev->kthread_task);
	mutex_unlock(&dev->kthread_mutex);
	
} 
static void virtualchar_kthread_exit(struct virtualchar_dev *dev)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	
	
	if(dev->kthread_task)
    {
        kthread_stop(dev->kthread_task);
		mutex_lock(&dev->kthread_mutex);
		g_virtualchar_dev->kthread_timeout = true;
		mutex_unlock(&dev->kthread_mutex);
		wake_up_interruptible(&g_virtualchar_dev->kthrea_wq);
    }
	virtualchar_kthread_timer_exit(dev);
	virtualchar_notifier_exit(dev);
	
}



static int __init virtualchar_init(void)
{
	int ret = 0;
	dev_t devno;
	
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	
	g_virtualchar_dev = (struct virtualchar_dev *)kzalloc(sizeof(struct virtualchar_dev),GFP_KERNEL);
	if(!g_virtualchar_dev){
		ret = -ENOMEM;
		goto err;
	}
	g_virtualchar_dev->name = VIRTUALCHAR_NAME;
	g_virtualchar_dev->major = VIRTUALCHAR_MAJOR;
	g_virtualchar_dev->minor = VIRTUALCHAR_MINOR;
	atomic_set(&g_virtualchar_dev->user,0);
	mutex_init(&g_virtualchar_dev->mutex);
	
	
	
	if(g_virtualchar_dev->major){
		devno = MKDEV(g_virtualchar_dev->major,g_virtualchar_dev->minor);
		ret = register_chrdev_region(devno, 1, g_virtualchar_dev->name);
	}else{
		ret = alloc_chrdev_region(&devno,0,1,g_virtualchar_dev->name);
		g_virtualchar_dev->major = MAJOR(devno);
		g_virtualchar_dev->minor = MINOR(devno);
	}
	if(ret){
		goto err;
	}

	g_virtualchar_dev->cdev.owner = THIS_MODULE;
	cdev_init(&g_virtualchar_dev->cdev,&virtualchar_fops);
	
	ret = cdev_add(&g_virtualchar_dev->cdev,devno,1);
	if(ret){
		goto cdev_err;
	}
	
	g_virtualchar_dev->class = class_create(THIS_MODULE,"virtualchar");
	if(IS_ERR(g_virtualchar_dev->class)){
		ret = PTR_ERR(g_virtualchar_dev->class);
		goto class_err;
	}
	
	g_virtualchar_dev->device = device_create(g_virtualchar_dev->class,NULL,\
										devno,NULL,"%s",g_virtualchar_dev->name);
	if(IS_ERR(g_virtualchar_dev->device)){
		ret = PTR_ERR(g_virtualchar_dev->device);
		goto device_err;
	}
	
	#if ATTRINUTE_ARRAY
	sysfs_create_group(&g_virtualchar_dev->device->kobj,&virtualchardev_attr_group);
	#else
	device_create_file(g_virtualchar_dev->device,&dev_attr_status);	
	#endif
	
	virtualchar_proc = create_proc_entry(VIRTUALCHARDEV_PROC_NAME,0666,NULL);
	if(virtualchar_proc == NULL){
		VIRTUALCHAR_DEBUG("create_proc_entry %s fail","virtualchar");
	}else{
		virtualchar_proc->read_proc = virtualchar_read_proc;
		virtualchar_proc->write_proc = virtualchar_write_proc;
	}
	
	// create workqueue
	virtualchar_create_workqueue(g_virtualchar_dev);
	
	// kthread init
	virtualchar_kthread_init(g_virtualchar_dev);
	
	init_waitqueue_head(&g_virtualchar_dev->w_wait);
	init_waitqueue_head(&g_virtualchar_dev->r_wait);
	
	VIRTUALCHAR_DEBUG(" %s init ok",__func__);
	return 0;
device_err:
	device_destroy(g_virtualchar_dev->class,devno);
	g_virtualchar_dev->device = NULL;
class_err:
	class_destroy(g_virtualchar_dev->class);
	g_virtualchar_dev->class = NULL;
cdev_err:
	unregister_chrdev_region(devno,1);
	cdev_del(&g_virtualchar_dev->cdev);
err:		
	kfree(g_virtualchar_dev);
	g_virtualchar_dev = NULL;
	return ret;
}

static void __exit virtualchar_exit(void)
{
	VIRTUALCHAR_DEBUG("enter: %s ",__func__);
	dev_t devno;
	
	if(g_virtualchar_dev == NULL){
		return;
	}
	virtualchar_kthread_exit(g_virtualchar_dev);
	
	virtualchar_destroy_workqueue(g_virtualchar_dev);
	
	
	devno = MKDEV(g_virtualchar_dev->major,g_virtualchar_dev->minor);
	remove_proc_entry(VIRTUALCHARDEV_PROC_NAME,NULL);
	#if ATTRINUTE_ARRAY
	sysfs_remove_group(&g_virtualchar_dev->device->kobj,&virtualchardev_attr_group);
	#else
	device_remove_file(g_virtualchar_dev->device,&dev_attr_status);
	#endif
	device_destroy(g_virtualchar_dev->class,devno);
	class_destroy(g_virtualchar_dev->class);
	unregister_chrdev_region(devno,1);
	cdev_del(&g_virtualchar_dev->cdev);
	
	kfree(g_virtualchar_dev->share_mem.mem);
	kfree(g_virtualchar_dev);
	g_virtualchar_dev = NULL;
}

module_init(virtualchar_init);
module_exit(virtualchar_exit);
MODULE_LICENSE("GPL");
