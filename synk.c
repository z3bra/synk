#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "arg.h"

#define SERVER_HOST "127.0.0.1"
#define SERVER_PORT 9723

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-h HOST] [-p PORT] FILE\n", name),
	exit(1);
}

int
main(int argc, char *argv[])
{
	int cfd;
	char *argv0;
	size_t len = 0;
	uint16_t port = SERVER_PORT;
	uint32_t host = INADDR_LOOPBACK;
	struct sockaddr_in clt;
	char path[PATH_MAX] = "", ts[32] = "";

	ARGBEGIN{
	case 'h': host = atol(EARGF(usage(argv0))); break;
	case 'p': port = atoi(EARGF(usage(argv0))); break;
	}ARGEND;

	if (argc < 2)
		return 1;
	
	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return 1;
	}

	memset(&clt, 0, sizeof(clt));
	clt.sin_family        = AF_INET;
	clt.sin_addr.s_addr   = htonl(host);
	clt.sin_port          = htons(port);

	if (connect(cfd, (struct sockaddr *)&clt, sizeof(clt)) < 0) {
		perror("connect");
		return 1;
	}

	snprintf(path, PATH_MAX, "%s", argv[1]);
	len = strnlen(path, PATH_MAX);
	if (send(cfd, path, len, 0) < 0) {
		perror("send");
		return -1;
	}

	send(cfd, "\n", 1, 0);

	recv(cfd, ts, 32, 0);
	printf("%s: %s\n", path, ts);

	return 0;
}
