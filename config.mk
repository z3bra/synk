VERSION = 1.1

CC = cc
LD = ${CC}
YACC = yacc

PREFIX = /usr/local
MANDIR = ${PREFIX}/man

CPPFLAGS = -DVERSION=\"${VERSION}\"
CFLAGS = ${CPPFLAGS} -Wall -Wextra -pedantic -g
LDFLAGS =
LIBS =
