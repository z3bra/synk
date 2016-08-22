#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "arg.h"
#include "sha512.h"

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

const char *rsync_cmd[] = { "rsync", "-azEq", "--delete", NULL };

long gettimestamp(const char *path);
int handleclient(int cfd, struct in_addr inet);
int server(in_addr_t host, in_port_t port);
int client(in_addr_t host, in_port_t port, const char *path);
int sha512(FILE *stream, unsigned char *hash);

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-s] [-h HOST] [-p PORT] [FILE..]\n", name),
	exit(1);
}

/*
 * Generate sha512 hash from stream, and store it in hash, which must
 * be able to store 64 bytes.
 */
int
sha512(FILE *stream, unsigned char *hash)
{
	sha512_state md;
	size_t len = 0;
	unsigned char buf[128];

	if (sha512_init(&md) != 0) {
		perror("sha512_init");
		return 1;
	}

	while ((len = fread(buf, 128, 1, stream)) > 0) {
		if (sha512_process(&md, buf, len) != 0) {
			return 1;
		}
	}

	return sha512_done(&md, hash);
}

/*
 * Returns the UNIX timestamp for the given file, or -1 in case stat(2)
 * is in error.
 */
long
gettimestamp(const char *path)
{
	struct stat sb;
	if (stat(path, &sb) < 0) {
		perror(path);
		return -1;
	}

	return sb.st_mtim.tv_sec;
}

/*
 * Read a path from a connected client, get the timestamp for this path and
 * send it back to the client. Close connection afterward.
 */
int
handleclient(int cfd, struct in_addr inet)
{
	char path[PATH_MAX] = "", ts[TIMESTAMP_MAX] = "";
	ssize_t len = 0;

	if ((len = read(cfd, &path, PATH_MAX)) < 0) {
		perror(inet_ntoa(inet));
		return -1;
	}

	path[len] = '\0';
	printf("%s: %s\n", inet_ntoa(inet), path);

	/* retrieve timestamp for received path.. */
	snprintf(ts, TIMESTAMP_MAX, "%lu", gettimestamp(path));
	len = strnlen(ts, TIMESTAMP_MAX);

	/* .. and send it to the client */
	write(cfd, ts, len);

	close(cfd);

	return 0;
}

/*
 * Server part: bind on given address/port and wait for a client connection.
 * Only one client is handled per server instance, and the server gets close
 * at the end.
 */
int
server(in_addr_t host, in_port_t port)
{
	int sfd;
	int cfd;
	socklen_t len;
	struct sockaddr_in clt;
	struct sockaddr_in srv;

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

	len = sizeof(clt);
	if ((cfd = accept(sfd, (struct sockaddr *)&clt, &len)) < 0) {
		perror("accept");
		return 1;
	}

	handleclient(cfd, clt.sin_addr);

	close(sfd);

	return 0;
}

/*
 * Client part: connect to the given address/port and send the given path to
 * the server. The server should return the timestamp for this file on the
 * socket. Connection is terminated after receiving the timestamp
 */
int
client(in_addr_t host, in_port_t port, const char *fn)
{
	int cfd;
	long ltim, rtim;
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
	ltim = gettimestamp(path);
	rtim = strtol(ts, NULL, 10);
	printf("%s:%s L:%lu R:%lu\n", path, ltim==rtim?"SYNKED":"TOSYNK",ltim, rtim);

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
