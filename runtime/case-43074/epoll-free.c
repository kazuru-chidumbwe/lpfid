/* Exercise the eventpoll paths of CVE-2026-43074's livepatch (S21 case study, 8 Oct 2026).
 * epoll_ctl(ADD) on a pipe allocates an eppoll_entry from fs/eventpoll.c's pwq_cache
 * (ep_ptable_queue_proc, not replaced by the module); closing the epoll fd frees it in
 * ep_clear_and_put (replaced by the module), through the module's binding of pwq_cache. */
#include <stdio.h>
#include <sys/epoll.h>
#include <unistd.h>

int main(void)
{
	int rounds = 64, freed = 0;
	for (int i = 0; i < rounds; i++) {
		int p[2];
		if (pipe(p) != 0) { perror("pipe"); return 1; }
		int ep = epoll_create1(0);
		if (ep < 0) { perror("epoll_create1"); return 1; }
		struct epoll_event ev = { .events = EPOLLIN, .data.fd = p[0] };
		if (epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) != 0) { perror("epoll_ctl"); return 1; }
		close(ep);             /* ep_clear_and_put -> ep_unregister_pollwait -> kmem_cache_free(pwq_cache) */
		close(p[0]); close(p[1]);
		freed++;
	}
	printf("EPOLL_TEST_DONE rounds=%d\n", freed);
	return 0;
}
