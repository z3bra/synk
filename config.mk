VERSION = 0.0

CC = cc
LD = ${CC}

PREFIX = /usr/local
MANDIR = ${PREFIX}/man

CPPFLAGS = -DVERSION=\"${VERSION}\"
CFLAGS = ${CPPFLAGS} -Wall -Wextra -pedantic -g
LDFLAGS =
LIBS = -lpthread
