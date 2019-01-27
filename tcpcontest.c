/*
   tcpcontest
 */

#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#define close closesocket
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define SOCKET int
#define gai_strerrorA gai_strerror
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static const char *me;
static int
usage (int retcode)
{
        FILE *out = retcode ? stderr : stdout;
        fprintf(out, "Usage: %s HOST PORT\n", me);
        fprintf(out, "Invoke connect() on HOST:PORT and return call value\n");
        exit(retcode);
}

int
main (int argc, char *argv[])
{
        me = argv[0];
        if (argc != 3)
        {
                usage(EXIT_FAILURE);
        }
#ifdef _WIN32
        WSADATA wsaData;
        int err;
        err = WSAStartup(MAKEWORD(2,2), &wsaData);
        if (err != 0)
        {
                fprintf(stderr, "WSAStartup: %d\n", err);
                exit(err);
        }
#endif
        struct addrinfo hints;
        struct addrinfo *result, *rp;
        memset (&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = 0;
        hints.ai_protocol = IPPROTO_TCP;

        int addr = getaddrinfo(argv[1], argv[2], &hints, &result);
        int rc = EXIT_FAILURE;

        if (addr != 0)
        {
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerrorA(addr));
                exit(rc);
        }
        for (rp = result; rp != NULL; rp = rp->ai_next)
        {
                SOCKET s = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
                if (s==-1)
                {
                        continue;
                }
                char str[INET6_ADDRSTRLEN];
                void *sinaddr = NULL;
                if(rp->ai_family == AF_INET)
                {
                        struct sockaddr_in *sinp = (struct sockaddr_in *) rp->ai_addr;
                        sinaddr = &sinp->sin_addr;
                }
                else
                {
                        struct sockaddr_in6 *sin6p = (struct sockaddr_in6 *) rp->ai_addr;
                        sinaddr = &sin6p->sin6_addr;
                }
                if (inet_ntop(rp->ai_family, sinaddr, str, INET6_ADDRSTRLEN) == NULL) {
                        perror("inet_ntop");
                        exit(EXIT_FAILURE);
                }
                rc = connect(s, rp->ai_addr, (int) rp->ai_addrlen);
                if(rc == 0)
                {
                        close(s);
                        printf("Connect to %s is OK\n", str);
                        break;
                }
                else if (rc== -1)
                {
#ifndef _WIN32
                        printf ("Connect to %s is error: errno is %d (%s)\n", str, errno, strerror(errno));
#else
                        printf("Connect to %s is error: errno is %d\n", str, WSAGetLastError());
 #endif
                        close(s);
                }
                else
                {
                        printf("Connecto to %s is error: return code is %d\n", str, rc);
                        close(s);
                }
        }
        freeaddrinfo(result);
#ifdef _WIN32
        WSACleanup();
#endif
        exit(rc);
}
