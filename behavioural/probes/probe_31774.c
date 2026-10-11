// S5 probe, CVE-2026-31774 (io_uring/net.c, io_sendmsg_prep): a negative length is accepted.
// Submits one IORING_OP_SENDMSG on an AF_UNIX datagram pair with sqe->len = 0xffffffff (-1 as int).
// Vulnerable kernel: the request is prepared and the message is sent (cqe res = 5 bytes).
// Fixed kernel: preparation rejects it (cqe res = -EINVAL).
// Raw syscalls, no liburing, so it builds statically anywhere.
#include <errno.h>
#include <linux/io_uring.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <unistd.h>

int main(void)
{
	struct io_uring_params p;
	memset(&p, 0, sizeof(p));
	int ring = syscall(__NR_io_uring_setup, 4, &p);
	if (ring < 0) {
		printf("PROBE error=setup errno=%d\n", errno);
		return 1;
	}
	size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	size_t cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
	char *sq = mmap(0, sq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQ_RING);
	char *cq = mmap(0, cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_CQ_RING);
	struct io_uring_sqe *sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe), PROT_READ | PROT_WRITE,
					 MAP_SHARED | MAP_POPULATE, ring, IORING_OFF_SQES);
	if (sq == MAP_FAILED || cq == MAP_FAILED || sqes == MAP_FAILED) {
		printf("PROBE error=mmap errno=%d\n", errno);
		return 1;
	}
	int sv[2];
	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		printf("PROBE error=socketpair errno=%d\n", errno);
		return 1;
	}
	char payload[] = "hello";
	struct iovec iov = { .iov_base = payload, .iov_len = 5 };
	struct msghdr msg;
	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	unsigned tail = *(unsigned *)(sq + p.sq_off.tail);
	unsigned mask = *(unsigned *)(sq + p.sq_off.ring_mask);
	unsigned idx = tail & mask;
	struct io_uring_sqe *sqe = &sqes[idx];
	memset(sqe, 0, sizeof(*sqe));
	sqe->opcode = IORING_OP_SENDMSG;
	sqe->fd = sv[0];
	sqe->addr = (unsigned long)&msg;
	sqe->len = 0xffffffffu;
	((unsigned *)(sq + p.sq_off.array))[idx] = idx;
	__atomic_store_n((unsigned *)(sq + p.sq_off.tail), tail + 1, __ATOMIC_RELEASE);

	int n = syscall(__NR_io_uring_enter, ring, 1, 1, IORING_ENTER_GETEVENTS, NULL, 0);
	if (n < 0) {
		printf("PROBE error=enter errno=%d\n", errno);
		return 1;
	}
	unsigned head = *(unsigned *)(cq + p.cq_off.head);
	struct io_uring_cqe *cqe = (struct io_uring_cqe *)(cq + p.cq_off.cqes) + (head & *(unsigned *)(cq + p.cq_off.ring_mask));
	printf("PROBE result=%d\n", cqe->res);
	return 0;
}
