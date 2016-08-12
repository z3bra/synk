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

#define LISTEN_PORT 9723
#define MAXCONN 10

struct client_t {
	int fd;
	struct in_addr in;	
};

void
usage(char *name) {
	fprintf(stderr, "usage: %s [-h HOST] [-p PORT]\n", name);
	exit(1);
}

void *
handle_client(void *arg)
{
	int i = 0;
	char buf, path[PATH_MAX] = "", ts[32] = "";
	size_t len = 0;
	struct stat sb;
	struct client_t *c = *(struct client_t **)arg;

	printf("%s: connected\n", inet_ntoa(c->in));
	while ((len = recv(c->fd, &buf, 1, 0)) > 0) {
		if (i > PATH_MAX) {
			printf("%s: filename too long (>%d)\n", inet_ntoa(c->in), PATH_MAX);
			break;
		}

		if (buf == '\n' || buf == '\0') {
			printf("%s: %s\n", inet_ntoa(c->in), path);
			stat(path, &sb);
			snprintf(ts, 32, "%lu", sb.st_mtim.tv_sec);
			len = strnlen(ts, 32);
			send(c->fd, ts, len, 0);
			memset(path, 0, PATH_MAX);
			i = 0;
		} else {
			path[i++] = buf;
		}
	}

	close(c->fd);
	len = 0;
	printf("%s: disconnected\n", inet_ntoa(c->in));
	free(c);
	pthread_exit((int *)&len);
}

int
loop(int sfd)
{
	int cfd;
	socklen_t len;
	struct sockaddr_in clt;
	struct client_t *c = NULL;
	pthread_t th;

	for (;;) {
		len = sizeof(clt);
		if ((cfd = accept(sfd, (struct sockaddr *)&clt, &len)) < 0) {
			perror("accept");
			return 1;
		}

		c = malloc(sizeof(struct client_t));
		c->fd = cfd;
		c->in = clt.sin_addr;

		pthread_create(&th, NULL, handle_client, &c);
	}
}

int
main(int argc, char *argv[])
{
	int sfd;
	char *argv0;
	uint16_t port = LISTEN_PORT;
	uint32_t host = INADDR_LOOPBACK;
	struct sockaddr_in srv;

	ARGBEGIN{
	case 'p':
		port = atoi(EARGF(usage(argv0)));
		break;
	}ARGEND;
	
	if ((sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return 1;
	}

	memset(&srv, 0, sizeof(srv));
	srv.sin_family        = AF_INET;
	srv.sin_addr.s_addr   = htonl(host);
	srv.sin_port          = htons(port);

	if (bind(sfd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
		perror("bind");
		return 1;
	}

	if (listen(sfd, MAXCONN) < 0) {
		perror("listen");
		return 1;
	}

	return loop(sfd);
}
