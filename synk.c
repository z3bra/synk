#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
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

#define IS_LOOPBACK(p)	((p)->peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK))

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
struct peer_t {
	struct metadata_t meta;
	struct sockaddr_in peer;
	SLIST_ENTRY(peer_t) entries;
};
SLIST_HEAD(peers_t, peer_t);

/* different operationnal mode for TCP connection */
enum {
	SYNK_CLIENT,
	SYNK_SERVER
};

void usage(char *name);
void *sendmetadata(void *arg);
int serverloop(in_addr_t, in_port_t);

char *echo(char * []);
char **concat(int, ...);

struct peer_t *addpeer(struct peers_t *, in_addr_t, in_port_t);
long gettimestamp(const char *path);
int getpeermeta(struct peer_t *, struct metadata_t *);
struct peer_t *freshestpeer(struct peers_t *);
int syncfile(struct peers_t *, const char *);
int uptodate(struct peers_t *);
int flushpeers(struct peers_t *);
int syncwithmaster(struct peer_t *master, struct peers_t *plist);
int dosync(struct peer_t *master, struct peer_t *slave);

const char *rsync_cmd[] = { "rsync", "-azEq", "--delete", NULL };
const char *ssh_cmd[] = { "ssh", NULL };

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-s] [-h HOST] [-p PORT] [FILE..]\n", name),
	exit(1);
}

/*
 * Same as the echo(1) command as defined by POSIX. Takes a like of arguments
 * and return a string containing all args separated by white spaces.
 */
char *
echo(char *args[])
{
	size_t len = 0;
	char *str = NULL;
	char **p;

	str = malloc(_POSIX_ARG_MAX);
	memset(str, 0, _POSIX_ARG_MAX);

	for (p = args; *p || len > _POSIX_ARG_MAX; p++) {
		snprintf(str + len, _POSIX_ARG_MAX, "%s ", *p);
		len += strnlen(*p, _POSIX_ARG_MAX) + 1;
	}

	str[len-1] = 0;

	return str;
}

/*
 * Take a variable number of arrays, and concatenate them in a single array.
 * The first argument is the number of arrays passed
 * All arrays should be NULL terminated, or undefined behavior may occur.
 */
char **
concat(int n, ...)
{
	size_t i, len = 0;
	va_list args;
	char **p, **tmp, **cat = { NULL };

	va_start(args, n);
	while (n --> 0)	{
		p = va_arg(args, char * []);

		/* count args in the given array */
		for (i=0; p[i]; ++i);

		/* Leave room for a NULL arg at the end */
		i += n ? 0 : 1;

		tmp = realloc(cat, (len + i) * sizeof(char *));
		if (!tmp) {
			perror("realloc");
			free(cat);
			va_end(args);
			return NULL;
		}
		cat = tmp;
		memcpy(cat + len, p, i*sizeof(char *));
		len += i;
	}

	va_end(args);
	return cat;
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
 * Retrieve metadata about a filename and store it in the given pointer.
 * The pointer must be already allocated
 */
struct metadata_t *
getmetadata(const char *fn)
{
	FILE *f = NULL;
	struct metadata_t *meta = NULL;

	if ((meta = malloc(sizeof(struct metadata_t))) == NULL) {
		perror("malloc");
		return NULL;
	}

	if ((f = fopen(fn, "r")) == NULL) {
		perror(fn);
		return NULL;
	}

	memset(meta, 0, sizeof(struct metadata_t));
	sha512(f, meta->hash);
	snprintf(meta->path, PATH_MAX, "%s", fn);
	meta->mtime = gettimestamp(meta->path);

	fclose(f);

	return meta;
}


/*
 * Read a path from a connected client, get the timestamp for this path and
 * send it back to the client. Close connection afterward.
 */
void *
sendmetadata(void *arg)
{
	ssize_t len = 0;
	struct metadata_t *local, remote;
	struct client_t *c = (struct client_t *)arg;

	memset(&remote, 0, sizeof(remote));

	if ((len = read(c->fd, &remote, sizeof(remote))) < 0) {
		perror(inet_ntoa(c->inet));
		pthread_exit(NULL);
	}

	local = getmetadata(remote.path);

	/* .. and send it to the client */
	write(c->fd, local, sizeof(struct metadata_t));
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
serverloop(in_addr_t host, in_port_t port)
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
		return -1;
	}

	memset(&srv, 0, sizeof(srv));
	srv.sin_family        = AF_INET;
	srv.sin_addr.s_addr   = htonl(host);
	srv.sin_port          = htons(port);

	if (bind(sfd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
		perror("bind");
		return -1;
	}

	if (listen(sfd, CONNECTION_MAX) < 0) {
		perror("listen");
		return -1;
	}

	len = sizeof(clt);
	for (;;) {
		if ((cfd = accept(sfd, (struct sockaddr *)&clt, &len)) < 0) {
			perror("accept");
			return -1;
		}

		c = malloc(sizeof(struct client_t));
		c->fd = cfd;
		c->inet = clt.sin_addr;

		pthread_create(&th, NULL, sendmetadata, c);
	}

	close(sfd); /* NOTREACHED */

	return 0;
}

/*
 * Add a peer to the singly-linked list referencing peers.
 * metadata structure will be zeroed for future use.
 */
struct peer_t *
addpeer(struct peers_t *plist, in_addr_t host, in_port_t port)
{
	int cfd = 0;
	struct peer_t *entry = NULL;

	entry = malloc(sizeof(struct peer_t));
	memset(&entry->meta, 0, sizeof(struct metadata_t));
	memset(&entry->peer, 0, sizeof(struct sockaddr_in));

	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return NULL;
	}

	entry->peer.sin_family        = AF_INET;
	entry->peer.sin_addr.s_addr   = htonl(host);
	entry->peer.sin_port          = htons(port);

	SLIST_INSERT_HEAD(plist, entry, entries);

	return entry;
}

/*
 * Empty the linked-list containing all peers
 */
int
flushpeers(struct peers_t *plist)
{
	struct peer_t *tmp = NULL;
	while (!SLIST_EMPTY(plist)) {
		tmp = SLIST_FIRST(plist);
		SLIST_REMOVE_HEAD(plist, entries);
		free(tmp);
	}

	return 0;
}

/*
 * Check the synchronisation status between all peers. If at least 2 hashes
 * differ, it returns with a non-zero status.
 */
int
uptodate(struct peers_t *plist)
{
	struct peer_t *tmp = NULL;
	unsigned char *hash = NULL;

	SLIST_FOREACH(tmp, plist, entries) {
		if (hash == NULL) {
			hash = tmp->meta.hash;
		} else {
			if (!sha512_compare(hash, tmp->meta.hash))
				return 0;
		}
	}

	return 1;
}

/*
 * Client part: connect to the given address/port and send the given path to
 * the server. The server should return the timestamp for this file on the
 * socket. Connection is terminated after receiving the timestamp
 */
int
getpeermeta(struct peer_t *clt, struct metadata_t *local)
{
	int cfd;
	ssize_t len = 0;

	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		perror("socket");
		return -1;
	}

	if (connect(cfd, (struct sockaddr *) &(clt->peer), sizeof(clt->peer)) < 0) {
		perror(inet_ntoa(clt->peer.sin_addr));
		return -1;
	}

	if ((len = write(cfd, local, sizeof(struct metadata_t))) < 0) {
		perror("write");
		return -1;
	}

	/* ... which should return the metadata for this file */
	if ((len = read(cfd, &(clt->meta), sizeof(struct metadata_t))) < 0) {
		perror("read");
		return -1;
	}

	return close(cfd);
}

/*
 * return a pointer to the peer having the highest timestamp.
 * NULL is returned in case the local file is the most recent
 */
struct peer_t *
freshestpeer(struct peers_t *plist)
{
	long ts = -1;
	struct peer_t *tmp = NULL;
	struct peer_t *freshest = NULL;

	SLIST_FOREACH(tmp, plist, entries) {
		if (tmp->meta.mtime > ts) {
			freshest = tmp;
			ts = tmp->meta.mtime;
		}
	}

	return freshest;
}

/*
 * Logic to synchronize a remote peer with all the slaves if they differ
 */
int
syncwithmaster(struct peer_t *master, struct peers_t *plist)
{
	int ret = 0;
	struct peer_t *slave = NULL;
	SLIST_FOREACH(slave, plist, entries) {
		if (slave == master)
			continue;
		if (!sha512_compare(master->meta.hash, slave->meta.hash))
			continue;

		ret += dosync(master, slave);
	}
	return ret;
}

int
dosync(struct peer_t *master, struct peer_t *slave)
{
	char **cmd = NULL;
	char *args[] = { NULL, NULL, NULL };
	char source[_POSIX_ARG_MAX] = "";
	char destination[_POSIX_ARG_MAX] = "";

	if (IS_LOOPBACK(slave)) {
		snprintf(source, _POSIX_ARG_MAX, "%s:%s", inet_ntoa(master->peer.sin_addr), slave->meta.path);
		snprintf(destination, _POSIX_ARG_MAX, "%s", master->meta.path);
	} else {
		snprintf(source, _POSIX_ARG_MAX, "%s", master->meta.path);
		snprintf(destination, _POSIX_ARG_MAX, "%s:%s", inet_ntoa(slave->peer.sin_addr), slave->meta.path);
	}

	args[0] = source;
	args[1] = destination;

	cmd = concat(2, rsync_cmd, args);

	if (!IS_LOOPBACK(master) && !IS_LOOPBACK(slave)) {
		cmd = concat(2, ssh_cmd, (char *[]){ inet_ntoa(master->peer.sin_addr), echo(cmd), NULL });
	}

	puts(echo(cmd));
	free(cmd);

	return 0;
}

/*
 * Check the synchronisation state of a file between mutliple peers, and
 * synchronise them if they differ
 */
int
syncfile(struct peers_t *plist, const char *fn)
{
	int ret = 0;
	struct metadata_t *local;
	struct peer_t *tmp    = NULL;
	struct peer_t *master = NULL;

	local = getmetadata(fn);

	if (!local)
		return -1;

	SLIST_FOREACH(tmp, plist, entries) {
		if (getpeermeta(tmp, local) != 0) {
			printf("%s: couldn't retrieve metadata\n", inet_ntoa(tmp->peer.sin_addr));
			return -1;
		}
	}

	addpeer(plist, INADDR_LOOPBACK, 0);
	tmp = SLIST_FIRST(plist);
	tmp->meta = *local;

	if (!uptodate(plist)) {
		master = freshestpeer(plist);
		ret = syncwithmaster(master, plist);
	}

	flushpeers(plist);
	free(local);

	return ret;
}

int
main(int argc, char *argv[])
{
	char *argv0, *fn;
	uint8_t mode = SYNK_CLIENT;
	in_port_t port = SERVER_PORT;
	in_addr_t host = INADDR_LOOPBACK;
	struct peers_t plist;

	SLIST_INIT(&plist);

	ARGBEGIN{
	case 'h':
		host = inet_network(EARGF(usage(argv0)));
		if (mode == SYNK_CLIENT)
			addpeer(&plist, host, port);
		break;
	case 'p': port = atoi(EARGF(usage(argv0))); break;
	case 's': mode = SYNK_SERVER; break;
	}ARGEND;


	switch(mode) {
	case SYNK_CLIENT:
		while ((fn = *(argv++)) != NULL) {
			syncfile(&plist, fn);
		}
		break;
	case SYNK_SERVER:
		serverloop(host, port);
		break;
	}
	return 0;
}
