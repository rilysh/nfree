# For Distro's that only ship Clang.
CC?=	clang
PROG=	nfree
DEST=	/usr/local/bin
CFLAGS=	-O2 -s

nfree: ${PROG}.c
	${CC} ${CFLAGS} -o ${PROG} $^

install:
	cp ${PROG} ${DEST}/

uninstall:
	rm -f ${DEST}/${PROG}

clean:
	rm -f ${PROG}
