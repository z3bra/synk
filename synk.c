#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "arg.h"
#include "sha512.h"

#define SERVER_HOST    "127.0.0.1"
#define SERVER_PORT    9723

#define TIMESTAMP_MAX  19 /* length of LONG_MAX */
#define CONNECTION_MAX 1

/* hold a socket connection, used to pass a connection to a thread */
struct client_t {
        int fd;
        struct in_addr inet;
};

/* metadata informations about a file, to decide about the synkro state */
struct metadata_t {
	char path[PATH_MAX];
	unsigned char hash[64];
	long mtime;
};

/* singly-linked list for all the nodes that should be in synk */
struct node_t {
	struct metadata_t meta;
	struct sockaddr_in peer;
	SLIST_ENTRY(node_t) entries;
};

/* different operationnal mode for TCP connection */
enum {
	SYNK_CLIENT,
	SYNK_SERVER
};

void  usage(char *name);
long  gettimestamp(const char *path);
void *handleclient(void *arg);
int   server(in_addr_t, in_port_t);
int   client(struct metadata_t, struct node_t *);
int   synkronize(in_addr_t, in_port_t, FILE *, const char *fn);

SLIST_HEAD(head_node_t, node_t) head;
const char *rsync_cmd[] = { "rsync", "-azEq", "--delete", NULL };

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-s] [-h HOST] [-p PORT] [FILE..]\n", name),
	exit(1);
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
void *
handleclient(void *arg)
{
	ssize_t len = 0;
	FILE *f = NULL;
	struct metadata_t local, remote;
	struct client_t *c = (struct client_t *)arg;

	memset(&local, 0, sizeof(local));
	memset(&remote, 0, sizeof(remote));

	if ((len = read(c->fd, &remote, sizeof(remote))) < 0) {
		perror(inet_ntoa(c->inet));
		return NULL;
	}

	strncpy(local.path, remote.path, PATH_MAX);

	/* compute sha512 hash for the given file... */
	if ((f = fopen(local.path, "r")) != NULL) {
		sha512(f, local.hash);
		fclose(f);
	}

	local.mtime = gettimestamp(local.path);

	/* .. and send it to the client */
	write(c->fd, &local, sizeof(local));
	close(c->fd);

	free(c);

	pthread_exit(NULL);
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
	pthread_t th;
	struct sockaddr_in clt;
	struct sockaddr_in srv;
	struct client_t *c = NULL;

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
	for (;;) {
		if ((cfd = accept(sfd, (struct sockaddr *)&clt, &len)) < 0) {
			perror("accept");
			return 1;
		}

		c = malloc(sizeof(struct client_t));
		c->fd = cfd;
		c->inet = clt.sin_addr;

		pthread_create(&th, NULL, handleclient, c);
	}

	close(sfd); /* NOTREACHED */

	return 0;
}

/*
 * Client part: connect to the given address/port and send the given path to
 * the server. The server should return the timestamp for this file on the
 * socket. Connection is terminated after receiving the timestamp
 */
int
getpeerinfo(struct metadata_t local, struct node_t *clt)
{
	int cfd;
	ssize_t len = 0;

	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return 1;
	}

	if (connect(cfd, (struct sockaddr *) &(clt->peer), sizeof(clt->peer)) < 0) {
		perror(inet_ntoa(clt->peer.sin_addr));
		return -1;
	}

	if ((len = write(cfd, &local, sizeof(struct metadata_t))) < 0) {
		perror("write");
		return -1;
	}

	/* ... which should return the timestamp of this file */
	if ((len = read(cfd, &(clt->meta), sizeof(struct metadata_t))) < 0) {
		perror("write");
		return -1;
	}

	return close(cfd);
}

int
synkronize(in_addr_t host, in_port_t port, FILE *f, const char *fn)
{
	int cfd;
	struct metadata_t local;
	struct node_t *tmp = NULL;

	memset(&local, 0, sizeof(local));

	sha512(f, local.hash);
	snprintf(local.path, PATH_MAX, "%s", fn);
	local.mtime = gettimestamp(local.path);

	tmp = malloc(sizeof(struct node_t));

	memset(&tmp->meta, 0, sizeof(struct metadata_t));
	memset(&tmp->peer, 0, sizeof(struct sockaddr_in));

	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return 1;
	}

	tmp->peer.sin_family        = AF_INET;
	tmp->peer.sin_addr.s_addr   = htonl(host);
	tmp->peer.sin_port          = htons(port);

	SLIST_INIT(&head);
	SLIST_INSERT_HEAD(&head, tmp, entries);

	printf("localhost\t%s\t%7s\t%lu\n", local.path, sha512_format(local.hash), local.mtime);

	SLIST_FOREACH(tmp, &head, entries) {
		getpeerinfo(local, tmp);
		if (sha512_compare(local.hash, tmp->meta.hash) == 0) {
			printf("%s\tSYNKED\n", local.path);
		} else {
			printf("%s\t%s\t%7s\t%lu\n", inet_ntoa(tmp->peer.sin_addr),
			                            tmp->meta.path,
			                            sha512_format(tmp->meta.hash),
			                            tmp->meta.mtime);
		}
		SLIST_REMOVE(&head, tmp, node_t, entries);
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	char *argv0, *fn;
	FILE *f = NULL;
	uint8_t mode = SYNK_CLIENT;
	in_port_t port = SERVER_PORT;
	in_addr_t host = INADDR_LOOPBACK;

	ARGBEGIN{
	case 'h': host = inet_network(EARGF(usage(argv0))); break;
	case 'p': port = atoi(EARGF(usage(argv0))); break;
	case 's': mode = SYNK_SERVER; break;
	}ARGEND;

	if (mode == SYNK_CLIENT && argc == 0)
		usage(argv0);

	switch(mode) {
	case SYNK_CLIENT:
		while ((fn = *(argv++)) != NULL) {
			f = fopen(fn, "r");
			if (f) {
				synkronize(host, port, f, fn);
				fclose(f);
			}
		}
		break;
	case SYNK_SERVER:
		server(host, port);
		break;
	}
	return 0;
}
