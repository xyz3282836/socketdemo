#include "apue.h"
#include <netdb.h>
#include <errno.h>
#include <syslog.h>
#include <sys/socket.h>

#define BUFLEN 128
#define QLEN 10

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

int main(int argc, char const *argv[])
{
	struct addrinfo *ailist, *aip;
	struct addrinfo hint;
	int sockfd, err, n;
	char *host;
	if ((n = sysconf(_SC_HOST_NAME_MAX)) < 0)
			n = HOST_NAME_MAX;
	if (gethostname(host, n) < 0)
		err_sys("gethostname error");

	printf("gethostname: host: %s\n", host);

	memset(&hint, 0, sizeof(hint));
	hint.ai_flags = AI_CANONNAME;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_canonname = NULL;
	hint.ai_addr = NULL;
	hint.ai_next = NULL;
	if ((err = getaddrinfo(host, "ruptime", &hint, &ailist)) != 0)
	{
		printf("ruptimed: getaddrinfo error: %s\n", gai_strerror(err));
		exit(1);
	}
	printf("ruptimed: getaddrinfo addr: %d %d %s\n ", aip->ai_socktype,SOCK_STREAM,aip->ai_addr->sa_data);
	// for (aip = ailist; aip != NULL; aip = aip->ai_next)
	// {
	// 	printf("ruptimed: getaddrinfo addr: %c\n", aip->ai_addr->sa_data);
	// }
	printf("end\n");
	exit(1);
}