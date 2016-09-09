#include <arpa/inet.h>
#include <sys/queue.h>
#include <limits.h>

#define DEFADDR      "127.0.0.1"
#define DEFPORT      9723
#define SERVERTIMEO  5 /* in seconds */
#define RCVBUFSZ     512
#define UTSLEN       19
#define MAXCONNECT   1
#define MAXRETRY     8
#define PATHCONFIG   "/etc/synk.conf"

/* hold a socket connection, used to pass a connection to a thread */
struct client_t {
        int fd;
        struct in_addr inet;
};

/* metadata informations about a file, to decide about the synkro state */
struct metadata_t {
	char path[_POSIX_PATH_MAX];
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

struct peer_t *addpeer(struct peers_t *, char *, in_port_t);
int parseconf(struct peers_t *, const char *);
