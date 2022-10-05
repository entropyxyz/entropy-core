/* See LICENSE file for license details. */
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

static void
eprint(const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(bufout, sizeof bufout, fmt, ap);
	va_end(ap);
	fprintf(stderr, "%s", bufout);
	if(fmt[0] && fmt[strlen(fmt) - 1] == ':')
		fprintf(stderr, " %s\n", strerror(errno));
	exit(1);
}

static int
dial(char *host, char *port) {
	struct addrinfo hints;
	struct addrinfo *res, *r;
	int fd;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if(getaddrinfo(host, port, &hints, &res) != 0)
		eprint("error: cannot resolve hostname '%s':", host);
	for(r = res; r; r = r->ai_next) {
		if((fd = socket(r->ai_family, r->ai_socktype, r->ai_protocol)) == -1)
			continue;
		if(connect(fd, r->ai_addr, r->ai_addrlen) == 0)
			break;
		close(fd);
	}
	freeaddrinfo(res);
	if(!r)
		eprint("error: cannot connect to host '%s'\n", host);
	return fd;
}

static char *
eat(char *s, int (*p)(int), int r) {
	while(*s != '\0' && p((unsigned char)*s) == r)
		s++;
	return s;
}

static char*
skip(char *s, char c) {
	while(*s != c && *s != '\0')
		s++;
	if(*s != '\0')
		*s++ = '\0';
	return s;
}

static void
trim(char *s) {
	char *e;

	for (e = s + strlen(s); e > s && isspace((unsigned char)*(e - 1)); e--)
		;
	*e = '\0';
}
