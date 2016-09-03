#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "arg.h"
#include "sha512.h"

#define IS_LOOPBACK(p)	((p)->peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
#define log(l,...) if(verbose>=l){printf(__VA_ARGS__);}

#define SERVER_HOST    "127.0.0.1"
#define SERVER_PORT    9723

#define TIMESTAMP_MAX  19 /* length of LONG_MAX */
#define CONNECTION_MAX 1
#define RECVSIZ        512
#define TIMEOUT        5
#define RETRY          8

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
	char host[HOST_NAME_MAX];
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

enum {
	LOG_NONE = 0,
	LOG_ERROR = 1,
	LOG_VERBOSE = 2,
	LOG_DEBUG = 3,
};

void usage(char *name);
int sendmetadata(struct client_t *);
int serverloop(in_addr_t, in_port_t);

char *echo(char * []);
char **concat(int, ...);
struct in_addr *resolve(char *);

struct peer_t *addpeer(struct peers_t *, char *, in_port_t);
long gettimestamp(const char *path);
int getpeermeta(struct peer_t *, struct metadata_t *);
struct peer_t *freshestpeer(struct peers_t *);
int syncfile(struct peers_t *, const char *);
int uptodate(struct peers_t *);
int flushpeers(struct peers_t *);
int syncwithmaster(struct peer_t *master, struct peers_t *plist);
int dosync(struct peer_t *master, struct peer_t *slave);
int spawnremote(struct peers_t *);

const char *rsync_cmd[] = { "rsync", "-azEq", "--delete", NULL };
const char *ssh_cmd[] = { "ssh", NULL };

int verbose = LOG_ERROR;

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-qvs] [-p PORT] -h HOST [FILE..]\n", name),
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
			log(LOG_ERROR, "realloc: %s\n", strerror(errno));;
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
 * Put an hostname, get an in_addr!
 * This is intended to be consumed directly, as gethostbyname() might
 * return a pointer to a static buffer
 */
struct in_addr *
resolve(char *hostname)
{
	struct hostent *he;
	
	if (!(he = gethostbyname(hostname))) {
		herror(hostname);
		return NULL;
	}
	
	return ((struct in_addr **)he->h_addr_list)[0];
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
		log(LOG_ERROR, "%s: %s\n", path, strerror(errno));;
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
		log(LOG_ERROR, "malloc: %s\n", strerror(errno));;
		return NULL;
	}

	memset(meta, 0, sizeof(struct metadata_t));
	snprintf(meta->path, PATH_MAX, "%s", fn);
	if ((f = fopen(fn, "r")) == NULL)
		return meta;

	sha512(f, meta->hash);
	meta->mtime = gettimestamp(meta->path);

	fclose(f);

	return meta;
}


/*
 * Read a path from a connected client, get the timestamp for this path and
 * send it back to the client. Close connection afterward.
 */
int
sendmetadata(struct client_t *c)
{
	ssize_t len = 0;
	struct metadata_t *local, remote;

	memset(&remote, 0, sizeof(remote));

	if ((len = read(c->fd, &remote, sizeof(remote))) < 0) {
		log(LOG_ERROR, "%s: %s\n", inet_ntoa(c->inet), strerror(errno));;
		return -1;
	}

	local = getmetadata(remote.path);

	/* .. and send it to the client */
	write(c->fd, local, sizeof(struct metadata_t));
	close(c->fd);

	free(c);

	return -1;
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
	struct sockaddr_in clt;
	struct sockaddr_in srv;
	struct client_t *c = NULL;

	if ((sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log(LOG_ERROR, "socket: %s\n", strerror(errno));;
		return -1;
	}

	memset(&srv, 0, sizeof(srv));
	srv.sin_family        = AF_INET;
	srv.sin_addr.s_addr   = host;
	srv.sin_port          = htons(port);

	if (bind(sfd, (struct sockaddr *)&srv, sizeof(srv)) < 0) {
		log(LOG_ERROR, "bind: %s\n", strerror(errno));;
		return -1;
	}

	if (listen(sfd, CONNECTION_MAX) < 0) {
		log(LOG_ERROR, "listen: %s\n", strerror(errno));;
		return -1;
	}

	len = sizeof(clt);
	if ((cfd = accept(sfd, (struct sockaddr *)&clt, &len)) < 0) {
		log(LOG_ERROR, "accept: %s\n", strerror(errno));;
		return -1;
	}

	alarm(0); /* cancel previously set SIGALRM */

	c = malloc(sizeof(struct client_t));
	c->fd = cfd;
	c->inet = clt.sin_addr;

	sendmetadata(c);

	return close(sfd);
}

/*
 * Add a peer to the singly-linked list referencing peers.
 * metadata structure will be zeroed for future use.
 */
struct peer_t *
addpeer(struct peers_t *plist, char *hostname, in_port_t port)
{
	int cfd = 0;
	struct peer_t *entry = NULL;
	struct in_addr *host;

	entry = malloc(sizeof(struct peer_t));
	memset(&entry->meta, 0, sizeof(struct metadata_t));
	memset(&entry->peer, 0, sizeof(struct sockaddr_in));

	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log(LOG_ERROR, "socket: %s\n", strerror(errno));;
		return NULL;
	}

	strncpy(entry->host, hostname, HOST_NAME_MAX);
	host = resolve(hostname);

	entry->peer.sin_family        = AF_INET;
	entry->peer.sin_addr.s_addr   = host->s_addr;
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
	struct peer_t *tmp, *ref;

	ref = SLIST_FIRST(plist);
	SLIST_FOREACH(tmp, plist, entries) {
		if (!sha512_compare(ref->meta.hash, tmp->meta.hash))
			return 0;
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
	int i, cfd;
	ssize_t r, len = 0;

	if ((cfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		log(LOG_ERROR, "socket: %s\n", strerror(errno));;
		return -1;
	}

	for (i=0; i<RETRY; i++) {
		if (!connect(cfd, (struct sockaddr *) &(clt->peer), sizeof(clt->peer)))
			break;

		if (errno != ECONNREFUSED || i+1 >= RETRY) {
			log(LOG_ERROR, "%s: %s\n", inet_ntoa(clt->peer.sin_addr), strerror(errno));;
			return -1;
		}
		usleep(250000);
	}

	if (write(cfd, local, sizeof(struct metadata_t)) < 0) {
		log(LOG_ERROR, "write: %s\n", strerror(errno));;
		return -1;
	}

	/* ... which should return the metadata for this file */
	len = 0;
	while (len < (ssize_t)sizeof(struct metadata_t)) {
		if ((r = read(cfd, (unsigned char *)&(clt->meta) + len, RECVSIZ)) < 0) {
			log(LOG_ERROR, "read: %s\n", strerror(errno));;
			return -1;
		}
		len += r;
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
		snprintf(destination, _POSIX_ARG_MAX, "%s", master->meta.path);
		snprintf(source, _POSIX_ARG_MAX, "%s:%s", master->host, slave->meta.path);
	} else {
		snprintf(source, _POSIX_ARG_MAX, "%s", master->meta.path);
		snprintf(destination, _POSIX_ARG_MAX, "%s:%s", slave->host, slave->meta.path);
	}

	args[0] = source;
	args[1] = destination;

	cmd = concat(2, rsync_cmd, args);

	if (!IS_LOOPBACK(master) && !IS_LOOPBACK(slave)) {
		cmd = concat(2, ssh_cmd, (char *[]){
			master->host, echo(cmd), NULL });
	}

	if (!fork()) {
		log(LOG_VERBOSE, "%s\n", echo(cmd));
		execvp(cmd[0], cmd);
		log(LOG_ERROR, "%s: %s\n", cmd[0], strerror(errno));;
		return -1;
	}
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
		if (getpeermeta(tmp, local) != 0)
			return -1;
	}

	addpeer(plist, "localhost", 0);
	tmp = SLIST_FIRST(plist);
	tmp->meta = *local;

	if (!uptodate(plist)) {
		master = freshestpeer(plist);
		ret = syncwithmaster(master, plist);
	}

	flushpeers(plist);
	free(local);

	wait(NULL);

	return ret;
}

int
spawnremote(struct peers_t *plist)
{
	char **cmd = NULL;
	char synk_cmd[_POSIX_ARG_MAX];

	struct peer_t *tmp;

	SLIST_FOREACH(tmp, plist, entries) {
		snprintf(synk_cmd, _POSIX_ARG_MAX, "synk -s -h %s",
			inet_ntoa(tmp->peer.sin_addr));
		cmd = concat(2, ssh_cmd, (char *[]){ tmp->host, synk_cmd, NULL });
		if (!fork()) {
			log(LOG_VERBOSE, "%s\n", echo(cmd));
			execvp(cmd[0], cmd);
			log(LOG_ERROR, "%s: %s\n", cmd[0], strerror(errno));;
			return -1;
		}
	}
	return 0;
}

int
main(int argc, char *argv[])
{
	char *argv0, *fn;
	char *hostname = NULL;
	in_port_t port = SERVER_PORT;
	uint8_t mode = SYNK_CLIENT;
	struct peers_t plist;

	SLIST_INIT(&plist);

	ARGBEGIN{
	case 'h':
		hostname = EARGF(usage(argv0));
		if (mode == SYNK_CLIENT)
			addpeer(&plist, hostname, port);
		break;
	case 'p': port = atoi(EARGF(usage(argv0))); break;
	case 's': mode = SYNK_SERVER; break;
	case 'v': verbose++; break;
	case 'q': verbose = LOG_NONE; break;
	}ARGEND;

	if (hostname == NULL)
		usage(argv0);

	switch(mode) {
	case SYNK_CLIENT:
		while ((fn = *(argv++)) != NULL) {
			spawnremote(&plist);
			syncfile(&plist, fn);
		}
		break;
	case SYNK_SERVER:
		alarm(TIMEOUT);
		serverloop(resolve(hostname)->s_addr, port);
		break;
	}
	return 0;
}
