include config.mk

synk: y.tab.o synk.o sha512.o
	$(LD) -o $@ $^ $(LDFLAGS) $(LIBS)

y.tab.c: parse.y
	$(YACC) $^

clean:
	rm -f *.o synk y.tab.c

install: synk synk.1 synk.conf.5
	mkdir -p ${DESTDIR}${PREFIX}/bin
	mkdir -p ${DESTDIR}${MANDIR}/man1
	mkdir -p ${DESTDIR}${MANDIR}/man5
	cp synk ${DESTDIR}${PREFIX}/bin/synk
	cp synk.1 ${DESTDIR}${MANDIR}/man1/synk.1
	cp synk.conf.5 ${DESTDIR}${MANDIR}/man5/synk.conf.5
	chmod 755 ${DESTDIR}${PREFIX}/bin/synk
	chmod 644 ${DESTDIR}${MANDIR}/man1/synk.1
	chmod 644 ${DESTDIR}${MANDIR}/man5/synk.conf.5

uninstall:
	rm ${DESTDIR}${PREFIX}/bin/synk
	rm ${DESTDIR}${MANDIR}/man1/synk.1
	rm ${DESTDIR}${MANDIR}/man5/synk.conf.5
