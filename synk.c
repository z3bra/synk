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
client(in_addr_t host, in_port_t port, const char *fn)
{
	int cfd;
	size_t len = 0;
	struct sockaddr_in clt;
	char path[PATH_MAX] = "", ts[PATH_MAX] = "";
	
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

	snprintf(path, PATH_MAX, "%s", fn);
	len = strnlen(path, PATH_MAX);
	printf("%s: %s\n", inet_ntoa(clt.sin_addr), path);
	if ((len = write(cfd, path, len)) < 0) {
		perror("write");
		return -1;
	}

	read(cfd, ts, PATH_MAX);
	printf("%s: %s\n", path, ts);

	close(cfd);

	return 0;
}

int
main(int argc, char *argv[])
{
	char *argv0;
	in_port_t port = SERVER_PORT;
	in_addr_t host = INADDR_LOOPBACK;

	ARGBEGIN{
	case 'h': host = inet_network(EARGF(usage(argv0))); break;
	case 'p': port = atoi(EARGF(usage(argv0))); break;
	}ARGEND;

	if (argc < 1)
		usage(argv0);

	client(host, port, argv[0]);
	return 0;
}
