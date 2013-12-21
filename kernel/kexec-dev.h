#ifndef __KEXEC_DEV_H
#define __KEXEC_DEV_H

#include <linux/types.h>
#include <linux/kexec.h>

struct kexec_param {
	void *entry;
	int nr_segments;
	struct kexec_segment *segment;
	unsigned long kexec_flags;
};

/* Ioctl defines */
#define KEXEC_IOC_MAGIC		'K'

#define KEXEC_IOC_LOAD		_IOW(KEXEC_IOC_MAGIC, 0, struct kexec_param)
#define KEXEC_IOC_REBOOT	_IOW(KEXEC_IOC_MAGIC, 1, int)
#define KEXEC_IOC_CHECK_LOADED  _IOR(KEXEC_IOC_MAGIC, 2, int)

#endif /* __KEXEC_DEV_H */

