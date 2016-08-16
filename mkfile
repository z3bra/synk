<config.mk

synk: synk.o
	$LD -o $target $prereq $LDFLAGS $LIBS

%.o: %.c
	$CC $CFLAGS -c $stem.c -o $stem.o

clean:V:
	rm -f *.o synk

install:V: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp synk ${DESTDIR}${PREFIX}/bin/synk
	chmod 755 ${DESTDIR}${PREFIX}/bin/synk

uninstall:V:
	rm ${DESTDIR}${PREFIX}/bin/synk
