// S5 probe, CVE-2024-57903 (net/core/sock.c, sk_setsockopt): SO_REUSEPORT on a non-inet socket.
// Vulnerable kernel: setsockopt succeeds. Fixed kernel: it fails with EOPNOTSUPP.
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>

int main(void)
{
	int one = 1;
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if (s < 0) {
		printf("PROBE error=socket errno=%d\n", errno);
		return 1;
	}
	int r = setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
	printf("PROBE result=%d errno=%d\n", r, r ? errno : 0);
	return 0;
}
