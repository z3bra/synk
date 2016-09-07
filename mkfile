<config.mk

synk: y.tab.o synk.o sha512.o
	$LD -o $target $prereq $LDFLAGS $LIBS

%.o: %.c synk.h
	$CC $CFLAGS -c $stem.c -o $stem.o

y.tab.c: parse.y
	$YACC $prereq

clean:V:
	rm -f *.o synk y.tab.c

install:V: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp synk ${DESTDIR}${PREFIX}/bin/synk
	chmod 755 ${DESTDIR}${PREFIX}/bin/synk

uninstall:V:
	rm ${DESTDIR}${PREFIX}/bin/synk
