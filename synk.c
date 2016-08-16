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

#define SERVER_HOST    "127.0.0.1"
#define SERVER_PORT    9723
#define TIMESTAMP_MAX  32
#define CONNECTION_MAX 1

struct client_t {
        int fd;
        struct in_addr in;
};

enum {
	SYNK_CLIENT,
	SYNK_SERVER
};

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-s] [-h HOST] [-p PORT] [FILE..]\n", name),
	exit(1);
}

void *
handleclient(void *arg)
{
	int i = 0;
	char path[PATH_MAX] = "", ts[32] = "";
	size_t len = 0;
	struct stat sb;
	struct client_t *c = *(struct client_t **)arg;

	printf("%s: connected\n", inet_ntoa(c->in));
	while ((len = read(c->fd, &path, PATH_MAX)) > 0) {
		if (i > PATH_MAX) {
			printf("%s: filename too long (>%d)\n", inet_ntoa(c->in), PATH_MAX);
			break;
		}

		path[len] = '\0';
		printf("%s: %s\n", inet_ntoa(c->in), path);
		stat(path, &sb);
		snprintf(ts, 32, "%lu", sb.st_mtim.tv_sec);
		len = strnlen(ts, 32);
		write(c->fd, ts, len);
		memset(path, 0, PATH_MAX);
		i = 0;
	}

	close(c->fd);
	len = 0;
	printf("%s: disconnected\n", inet_ntoa(c->in));
	free(c);
	pthread_exit((int *)&len);
}

int
server(in_addr_t host, in_port_t port)
{
	int sfd;
	int cfd;
	socklen_t len;
	struct sockaddr_in clt;
	struct sockaddr_in srv;
	struct client_t *c = NULL;
	pthread_t th;

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

	if (listen(sfd, CONNECTION_MAX) < 0) {
		perror("listen");
		return 1;
	}

	for (;;) {
		len = sizeof(clt);
		if ((cfd = accept(sfd, (struct sockaddr *)&clt, &len)) < 0) {
			perror("accept");
			return 1;
		}

		c = malloc(sizeof(struct client_t));
		c->fd = cfd;
		c->in = clt.sin_addr;

		pthread_create(&th, NULL, handleclient, &c);
	}

	return 0;
}

int
client(in_addr_t host, in_port_t port, const char *fn)
{
	int cfd;
	ssize_t len = 0;
	struct sockaddr_in clt;
	char path[PATH_MAX] = "", ts[TIMESTAMP_MAX] = "";
	
	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return 1;
	}

	memset(&clt, 0, sizeof(clt));
	clt.sin_family        = AF_INET;
	clt.sin_addr.s_addr   = htonl(host);
	clt.sin_port          = htons(port);

	if (connect(cfd, (struct sockaddr *)&clt, sizeof(clt)) < 0) {
		perror(inet_ntoa(clt.sin_addr));
		return -1;
	}

	/* we first send a filename to the server ... */
	snprintf(path, PATH_MAX, "%s", fn);
	len = strnlen(path, PATH_MAX);
	printf("%s: %s\n", inet_ntoa(clt.sin_addr), path);
	if ((len = write(cfd, path, len)) < 0) {
		perror("write");
		return -1;
	}

	/* ... which should return the timestamp of this file */
	read(cfd, ts, TIMESTAMP_MAX);
	printf("%s: %s\n", path, ts);

	close(cfd);

	return 0;
}

int
main(int argc, char *argv[])
{
	char *argv0;
	uint8_t mode = SYNK_CLIENT;
	in_port_t port = SERVER_PORT;
	in_addr_t host = INADDR_LOOPBACK;

	ARGBEGIN{
	case 'h': host = inet_network(EARGF(usage(argv0))); break;
	case 'p': port = atoi(EARGF(usage(argv0))); break;
	case 's': mode = SYNK_SERVER; break;
	}ARGEND;

	if (mode == SYNK_CLIENT && argc < 1)
		usage(argv0);

	switch(mode) {
	case SYNK_CLIENT:
		client(host, port, argv[0]);
		break;
	case SYNK_SERVER:
		server(host, port);
		break; /* NOTREACHED */
	}
	return 0;
}
