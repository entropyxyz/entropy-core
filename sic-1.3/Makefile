.POSIX:

NAME = sic
VERSION = 1.3

# paths
PREFIX = /usr/local
MANPREFIX = ${PREFIX}/share/man

# use system flags.
SIC_CFLAGS = ${CFLAGS}
SIC_LDFLAGS = ${LDFLAGS}
SIC_CPPFLAGS = ${LDFLAGS} -DVERSION=\"${VERSION}\" -D_GNU_SOURCE

BIN = sic
SRC = ${BIN:=.c}
OBJ = ${SRC:.c=.o}
MAN1 = ${BIN:=.1}

all: ${BIN}

${BIN}: ${@:=.o}

${OBJ}: config.h strlcpy.c util.c

.o:
	${CC} -o $@ $< ${SIC_LDFLAGS}

.c.o:
	${CC} -c ${SIC_CFLAGS} ${SIC_CPPFLAGS} -o $@ -c $<

config.h:
	cp config.def.h $@

clean:
	rm -f ${BIN} ${OBJ} "${NAME}-${VERSION}.tar.gz"

dist:
	mkdir -p "${NAME}-${VERSION}"
	cp -fR LICENSE Makefile README arg.h config.def.h \
		${MAN1} ${SRC} util.c strlcpy.c "${NAME}-${VERSION}"
	tar -cf - "${NAME}-${VERSION}" | \
		gzip -c > "${NAME}-${VERSION}.tar.gz"
	rm -rf "${NAME}-${VERSION}"

install: all
	mkdir -p ${DESTDIR}${PREFIX}/bin
	cp -f ${BIN} "${DESTDIR}${PREFIX}/bin"
	chmod 755 "${DESTDIR}${PREFIX}/bin/${BIN}"
	mkdir -p "${DESTDIR}${MANPREFIX}/man1"
	sed "s/VERSION/${VERSION}/g" < ${MAN1} > "${DESTDIR}${MANPREFIX}/man1/${MAN1}"
	chmod 644 "${DESTDIR}${MANPREFIX}/man1/${MAN1}"

uninstall:
	rm -f \
		"${DESTDIR}${PREFIX}/bin/${BIN}"\
		"${DESTDIR}${MANPREFIX}/man1/${MAN1}"

.PHONY: all clean dist install uninstall
