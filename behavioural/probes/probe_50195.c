// S5 probe, CVE-2024-50195 (kernel/time/posix-clock.c, pc_clock_settime): an invalid timespec reaches the driver.
// clock_settime on the KVM PTP clock with tv_nsec = 2,000,000,000.
// Vulnerable kernel: the request reaches ptp_kvm, which refuses settime (EOPNOTSUPP).
// Fixed kernel: the timespec is rejected first (EINVAL).
// Revision 2 (11 Oct): raw syscall; glibc's clock_settime() rejects tv_nsec >= 1e9 itself, so revision 1 never reached the kernel.
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define FD_TO_CLOCKID(fd) ((~(clockid_t)(fd) << 3) | 3)

int main(void)
{
	int fd = open("/dev/ptp0", O_RDWR);
	if (fd < 0) {
		printf("PROBE error=open errno=%d\n", errno);
		return 1;
	}
	struct timespec ts = { .tv_sec = 0, .tv_nsec = 2000000000L };
	int r = syscall(__NR_clock_settime, FD_TO_CLOCKID(fd), &ts);
	printf("PROBE result=%d errno=%d\n", r, r ? errno : 0);
	return 0;
}
