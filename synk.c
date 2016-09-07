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
#include "synk.h"

#define IS_LOOPBACK(p)	((p)->peer.sin_addr.s_addr == htonl(INADDR_LOOPBACK))

static void usage(char *name);
static char *echo(char * []);
static char **concat(int, ...);

static long gettimestamp(const char *path);
static struct in_addr *getinetaddr(char *);
static struct metadata_t *getmetadata(const char *);
static struct peer_t *freshestpeer(struct peers_t *);
static int getpeermeta(struct peer_t *, struct metadata_t *);
static int flushpeers(struct peers_t *);
static int spawnremote(struct peers_t *);
static int uptodate(struct peers_t *);
static int dosync(struct peer_t *master, struct peer_t *slave);
static int syncwithmaster(struct peer_t *master, struct peers_t *plist);
static int syncfile(struct peers_t *, const char *);
static int sendmetadata(struct client_t *);
static int waitclient(in_addr_t, in_port_t);

const char *rsync_cmd[] = { "rsync", "-azEq", "--delete", NULL };
const char *ssh_cmd[] = { "ssh", NULL };

int verbose = LOG_ERROR;

void
usage(char *name)
{
	fprintf(stderr, "usage: %s [-qvs] [-f FILE] [-p PORT] -h HOST [FILE..]\n", name);
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
 * Put an hostname, get an in_addr!
 * This is intended to be consumed directly, as gethostbyname() might
 * return a pointer to a static buffer
 */
struct in_addr *
getinetaddr(char *hostname)
{
	struct hostent *he;

	if (!(he = gethostbyname(hostname))) {
		herror(hostname);
		return NULL;
	}

	return ((struct in_addr **)he->h_addr_list)[0];
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
	host = getinetaddr(hostname);

	entry->peer.sin_family        = AF_INET;
	entry->peer.sin_addr.s_addr   = host->s_addr;
	entry->peer.sin_port          = htons(port);

	SLIST_INSERT_HEAD(plist, entry, entries);

	return entry;
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

	log(LOG_VERBOSE, "master: %s\n", freshest->host);
	return freshest;
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

	for (i=0; i<MAXRETRY; i++) {
		if (!connect(cfd, (struct sockaddr *) &(clt->peer), sizeof(clt->peer)))
			break;

		if (errno != ECONNREFUSED || i+1 >= MAXRETRY) {
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
		if ((r = read(cfd, (unsigned char *)&(clt->meta) + len, RCVBUFSZ)) < 0) {
			log(LOG_ERROR, "read: %s\n", strerror(errno));;
			return -1;
		}
		len += r;
	}

	return close(cfd);
}

/*
 * Load peers from a file
 */
int
loadpeers(struct peers_t *plist, const char *fn)
{
	char host[HOST_NAME_MAX], *lf;
	FILE *f = NULL;

	f = fopen(fn, "r");
	if (!f) {
		perror(fn);
		return -1;
	}

	while (fgets(host, HOST_NAME_MAX, f)) {
		if ((lf = strchr(host, '\n')) != NULL)
			*lf = '\0';

		log(LOG_VERBOSE, "config: %s\n", host);
		addpeer(plist, host, SERVER_PORT);
	}

	fclose(f);
	return 0;
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
waitclient(in_addr_t host, in_port_t port)
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

	if (listen(sfd, MAXCONNECT) < 0) {
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
 * Connect via ssh to a remote and spawn an instance running in server-mode
 */
int
spawnremote(struct peers_t *plist)
{
	char **cmd = NULL;
	char synk_cmd[_POSIX_ARG_MAX];

	struct peer_t *tmp;

	SLIST_FOREACH(tmp, plist, entries) {
		if (IS_LOOPBACK(tmp))
			continue;
		snprintf(synk_cmd, _POSIX_ARG_MAX, "synk -s -h %s",
			inet_ntoa(tmp->peer.sin_addr));
		cmd = concat(2, ssh_cmd, (char *[]){ tmp->host, synk_cmd, NULL });
		if (!fork()) {
			execvp(cmd[0], cmd);
			log(LOG_ERROR, "%s: %s\n", cmd[0], strerror(errno));;
			return -1;
		}
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
		if (sha512_compare(ref->meta.hash, tmp->meta.hash)) {
			log(LOG_DEBUG, "+ sha512 mismatch: %s / %s)\n", ref->host, tmp->host);
			return 0;
		}
	}

	log(LOG_DEBUG, "+ no difference found: %s\n", ref->meta.path);
	return 1;
}

/*
 * Given a master and a slave, create the appropriate rsync(1) command to
 * get the slave in sync with the master, from localhost (this might involve
 * using ssh to spawn the rsync process on a remote master)
 */
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
		log(LOG_VERBOSE, "synk: %s\n", echo(cmd));
		execvp(cmd[0], cmd);
		log(LOG_ERROR, "%s: %s\n", cmd[0], strerror(errno));;
		return -1;
	}
	free(cmd);

	return 0;
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
		if (IS_LOOPBACK(tmp)) {
			memcpy(&tmp->meta, local, sizeof(struct metadata_t));
		} else {
			if (getpeermeta(tmp, local) != 0)
				return -1;
		}

		log(LOG_VERBOSE, "peer: %s\t%s\t%.7s\t%lu\n",
			tmp->host,
			tmp->meta.path,
			sha512_format(tmp->meta.hash),
			tmp->meta.mtime);
	}

	if (!uptodate(plist)) {
		master = freshestpeer(plist);
		ret = syncwithmaster(master, plist);
	}

	free(local);

	while (waitpid(-1, NULL, WNOHANG) > 0);

	return ret;
}

int
main(int argc, char *argv[])
{
	char *argv0, *fn;
	char config[PATH_MAX] = PATHCONFIG;
	char *hostname = NULL;
	in_port_t port = DEFPORT;
	uint8_t mode = SYNK_CLIENT;
	struct peers_t plist;

	SLIST_INIT(&plist);
	addpeer(&plist, "localhost", 0);

	ARGBEGIN{
	case 'f':
		strncpy(config, EARGF(usage(argv0)), PATH_MAX);
		break;
	case 'h':
		hostname = EARGF(usage(argv0));
		if (mode == SYNK_CLIENT)
			addpeer(&plist, hostname, port);
		break;
	case 'p': port = atoi(EARGF(usage(argv0))); break;
	case 'q': verbose = LOG_NONE; break;
	case 's': mode = SYNK_SERVER; break;
	case 'v': verbose++; break;
	}ARGEND;

	if (hostname == NULL)
		loadpeers(&plist, config);

	switch(mode) {
	case SYNK_CLIENT:
		while ((fn = *(argv++)) != NULL) {
			spawnremote(&plist);
			syncfile(&plist, fn);
		}
		flushpeers(&plist);
		break;
	case SYNK_SERVER:
		alarm(SERVERTIMEO);
		waitclient(getinetaddr(hostname)->s_addr, port);
		break;
	}
	return 0;
}
