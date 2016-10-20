#ifndef _VIRTUAL_CHAR_H_
#define _VIRTUAL_CHAR_H_

#define ATTRINUTE_ARRAY	1
#define ENABLE_USER_WORKQUEUE	1 	// enable create user work queue
#define SUPPORT_CAT

#define VIRTUALCHAR_IOC_MAGIC	'V'
#define VIRTUALCHAR_MEM_CLEAR	_IOWR(VIRTUALCHAR_IOC_MAGIC,0x00,int)
#define VIRTUALCHAR_MEM_SET_SIZE		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x01,int)
#define VIRTUALCHAR_MEM_GET_SIZE		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x02,int)
#define VIRTUALCHAR_MEM_SET_OFFSET		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x03,int)
#define VIRTUALCHAR_MEM_GET_OFFSET		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x04,int)
#define VIRTUALCHAR_MEM_SET_NUM		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x05,int)
#define VIRTUALCHAR_MEM_GET_NUM		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x06,int)
#define VIRTUALCHAR_MEM_SET_VAL		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x07,int)
#define VIRTUALCHAR_MEM_GET_VAL		_IOWR(VIRTUALCHAR_IOC_MAGIC,0x08,int)

#define VIRTUALCHAR_MEM_SIZE_MAX	(1024*1024)
#define VIRTUALCHAR_BUFFER_SIZE 	(1024)

#define VIRTUALCHAR_NAME	"virtualchardev"
#define VIRTUALCHAR_MAJOR	0
#define VIRTUALCHAR_MINOR	0


struct share_mem
{
	unsigned char *mem;
	int size;
	int offset;
	int num;
};



struct virtualchar_dev
{
	const char *name;
	int major;
	int minor;
	struct cdev cdev;
	struct device *device;
	struct class *class;
	atomic_t	user; 
	struct share_mem share_mem;
	struct mutex mutex;
	unsigned char buffer[VIRTUALCHAR_BUFFER_SIZE];
	unsigned long current_len;
	
	wait_queue_head_t w_wait;// 阻塞写用的等待队列头
	wait_queue_head_t r_wait;// 阻塞读用的等待队列头
	
	#if ENABLE_USER_WORKQUEUE
	struct workqueue_struct *wq;
	#endif
	struct work_struct work;
	struct delayed_work delayed_work;
	struct hrtimer work_timer;
	atomic_t	workon;
	
	struct timer_list kthread_timer;
	wait_queue_head_t kthrea_wq;
	int kthread_timeout;
	struct mutex kthread_mutex;
	struct task_struct *kthread_task;
	
	struct blocking_notifier_head notifier_list;
};


#endif