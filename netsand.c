/*
   network sandbox simple for every -- block unwanted connect() calls.
 */

#define _GNU_SOURCE

#ifndef _WIN32
#include <arpa/inet.h>
#include <dlfcn.h>
#include <fnmatch.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <resolv.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <syslog.h>
#define SOCKET int
#define HOOK(fn) fn
#define WSAAPI /* nothing */
#else
#define _CRT_SECURE_NO_WARNINGS
#include <SDKDDKVer.h>
#define WIN32_LEAN_AND_MEAN
#ifdef SAND_EXPORTS
#define SAND_API __declspec(dllexport)
#else
#define SAND_API __declspec(dllimport)
#endif
#define HOOK(fn) SAND_API __stdcall hook_ ## fn
#include <windows.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>
#include <Shlwapi.h>
#include <iphlpapi.h>
#include "sys_queue.h"
#include "inject.h"
#include "MinHook.h"
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "IPHLPAPI.lib")
#ifdef _M_X64
#ifdef _DEBUG
#pragma comment(lib, "libMinHook-x64-v140-mtd.lib")
#else
#pragma comment(lib, "libMinHook-x64-v140-mt.lib")
#endif
#elif defined _M_IX86
#ifdef _DEBUG
#pragma comment(lib, "libMinHook-x86-v140-mtd.lib")
#else
#pragma comment(lib, "libMinHook-x86-v140-mt.lib")
#endif
#endif
#endif

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#ifdef _WIN32
typedef uint16_t in_port_t;
#define MISSING_STRNDUP
#define MAXNS 30
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_INFO 6
#define LOG_DEBUG 7
#define vsyslog(l,f,a) /* Not supported */
#define pthread_testcancel() /* Not supported */
#define localtime_r(ti,tm) localtime_s(tm, ti)
#define fnmatch(p,s,f) (!PathMatchSpecA(s,p))
#endif

#if defined(__APPLE__) && defined(__MACH__)
#include <AvailabilityMacros.h>
#if __MAC_OS_X_VERSION_MAX_ALLOWED < 1070
#define MISSING_STRNDUP
#endif
#endif

#ifdef __SunOS_5_11
#undef MISSING_STRNDUP
#endif

#if defined(__unix__) || (defined(__APPLE__) && defined(__MACH__))
#include <sys/param.h>
#if defined(BSD)
#define HAVE_GETPROGNAME
#endif
#endif

#if (defined(sun) || defined(__sun)) && (defined(__SVR4) || defined(__svr4__))
#define HAVE_GETEXECNAME
#include <libgen.h>
#endif

typedef enum SAND_address_type
{
        SAND_IPV4_ADDR = 1 << 0, /* 1 */
        SAND_IPV6_ADDR = 1 << 1, /* 2 */
        SAND_GLOB_ADDR = 1 << 2 /* 4 */
} SAND_address_type_t;

#define SAND_HOST_ADDR (1 << 3)  /* 8 */

typedef enum SAND_log_level
{
        SAND_SILENT_LOG_LEVEL = -1, /* mapped from 0. */
        SAND_ERROR_LOG_LEVEL = LOG_ERR, /* mapped from 1 (to 3). */
        SAND_BLOCK_LOG_LEVEL = LOG_WARNING, /* mapped from 2 (to 4). */
        SAND_ALLOW_LOG_LEVEL = LOG_INFO, /* mapped from 3 (to 6). */
        SAND_DEBUG_LOG_LEVEL = LOG_DEBUG /* mapped from 4 (to 7). */
} SAND_log_level_t;

typedef enum SAND_log_target
{
        SAND_STDERR_LOG = 1 << 0, /* 1 */
        SAND_SYSLOG_LOG = 1 << 1, /* 2 */
        SAND_FILE_LOG = 1 << 2 /* 4 */
} SAND_log_target_t;

typedef enum SAND_rule_type
{
        SAND_ALLOW = 0,
        SAND_BLOCK = 1
} SAND_rule_type_t;

static const char *rule_type_name[] = {
        "ALLOW",
        "BLOCK"
};

static const char *address_type_name[] = {
        [SAND_IPV4_ADDR] = "IPv4",
        [SAND_IPV6_ADDR] = "IPv6",
        [SAND_GLOB_ADDR] = "glob",
        [SAND_HOST_ADDR] = "host"
};

typedef struct SAND_entry {
        union {
                struct in_addr ipv4;
                struct in6_addr ipv6;
                char *glob;
        } addr;
        union {
                struct in_addr ipv4;
                struct in6_addr ipv6;
        } netmask;
        in_port_t port;
        SAND_address_type_t addr_type;
        SAND_rule_type_t rule_type;
        SLIST_ENTRY(SAND_entry) entries;
        bool is_subnet;
} SAND_entry_t;

static inline
SAND_entry_t *
SAND_entry_alloc (void)
{
        return (SAND_entry_t *) malloc (sizeof(SAND_entry_t));
}

SLIST_HEAD(SAND_list, SAND_entry) SAND_list_head = { NULL };

#define SAND_ALLOW_ENV_VAR_NAME "SAND_ALLOW"
#define SAND_BLOCK_ENV_VAR_NAME "SAND_BLOCK"
#define SAND_LOG_LEVEL_ENV_VAR_NAME "SAND_LOG_LEVEL"
#define SAND_LOG_PATH_ENV_VAR_NAME "SAND_LOG_PATH"
#define SAND_LOG_TARGET_ENV_VAR_NAME "SAND_LOG_TARGET"
#if defined(__APPLE__) && defined(__MACH__)
#define SAND_PRELOAD_ENV_VAR_NAME "DYLD_INSERT_LIBRARIES"
#else
#define SAND_PRELOAD_ENV_VAR_NAME "LD_PRELOAD"
#endif

#if defined(HAVE_GETEXECNAME)
static inline const char *
getprogname ()
{
        const char *fullpath = getexecname ();
        return basename ((char *) fullpath);
}

#elif !defined(HAVE_GETPROGNAME)
#ifdef _WIN32
char __progname[_MAX_FNAME];
#else
extern char *__progname;
#endif

static inline const char *
getprogname ()
{
#ifdef _WIN32
        char szThisModule[MAX_PATH] = { 0 };
        GetModuleFileNameA(NULL, szThisModule, MAX_PATH);
        _splitpath(szThisModule, NULL, NULL, __progname, NULL);
#endif
        return __progname;
}
#endif

static const char version[] = "netsand v1.0.0";
static volatile bool initialized = false;
static bool needs_dns_lookup = false;
static SAND_log_level_t log_level = SAND_BLOCK_LOG_LEVEL;
static SAND_log_target_t log_target = SAND_STDERR_LOG;
static char *log_file_name = NULL;

#ifdef __GNUC__
static void
SAND_log (SAND_log_level_t level, const char *format, ...)
__attribute__ ((__format__ (__printf__, 2, 3)));
#endif

static void
SAND_log (SAND_log_level_t level, const char *format, ...)
{
        if (log_level >= level)
        {
                struct tm now_tm;
                time_t now;
                char buffer[sizeof ("YYYY-MM-DDTHH:MM:SS ")];
                time (&now);
                localtime_r (&now, &now_tm);
                strftime (buffer, sizeof (buffer), "%Y-%m-%dT%H:%M:%S ", &now_tm);

                if ((log_target & SAND_FILE_LOG) == SAND_FILE_LOG)
                {
                        va_list ap;
                        va_start (ap, format);
                        FILE *log_stream = fopen (log_file_name, "a");

                        if (!log_stream)
                        {
                                fprintf (stderr, "Unable to create log file %s; discarding file logs\n", log_file_name);
                                log_target &= ~SAND_FILE_LOG;
                        }
                        else
                        {
                                fprintf (log_stream, "%s", buffer);
                                vfprintf (log_stream, format, ap);
                                fclose (log_stream);
                        }

                        va_end (ap);
                }

                if ((log_target & SAND_STDERR_LOG) == SAND_STDERR_LOG)
                {
                        va_list ap;
                        va_start (ap, format);
                        fprintf (stderr, "%s", buffer);
                        vfprintf (stderr, format, ap);
                        fflush (stderr);
                        va_end (ap);
                }

                if ((log_target & SAND_SYSLOG_LOG) == SAND_SYSLOG_LOG)
                {
                        va_list ap;
                        va_start (ap, format);
                        /*
                         * syslog will be automatically opened at first invocation.
                         *
                         * We do not change anything to this because:
                         *  - we know that syslog will not be used during initialization
                         *    of our library
                         *  - the program that will be invoked after our library is
                         *    preloaded can use syslog with non default settings. So
                         *    we reuse these in order not to interfere with the
                         *    program.
                         */
                        vsyslog (level, format, ap);
                        va_end (ap);
                }
        }
}

#define DIE(...) do { \
                SAND_log (SAND_ERROR_LOG_LEVEL,"ERROR " __VA_ARGS__); \
                exit (EXIT_FAILURE); \
} while (0)

#ifdef MISSING_STRNDUP
static inline char *
strndup (const char *s, size_t n)
{
        size_t len = strlen (s);

        if (len > n)
        {
                len = n;
        }

        char *ns = (char *) malloc (len + 1);

        if (ns != NULL)
        {
                ns[len] = '\0';
                memcpy (ns, s, len);
        }

        return ns;
}
#endif


static inline void
mask_ipv4 (struct in_addr *addr, const struct in_addr *netmask)
{
        addr->s_addr &= netmask->s_addr;
}

static inline void
mask_ipv6 (struct in6_addr *addr, const struct in6_addr *netmask)
{
        uint32_t *_addr = (uint32_t *) addr;
        const uint32_t *_netmask = (uint32_t *) netmask;

        int i;
        for (i = 0; i < 4; i++)
        {
                _addr[i] &= _netmask[i];
        }
}

static void
make_ipv4_netmask (struct in_addr *netmask, uint8_t cidr_prefix_length)
{
        memset (netmask, 0, sizeof(struct in_addr));

        if (cidr_prefix_length > 0)
        {
                netmask->s_addr = htonl (0xFFFFFFFFu << (32u - cidr_prefix_length));
        }
}

static void
make_ipv6_netmask (struct in6_addr *netmask, uint8_t cidr_prefix_length)
{
        memset (netmask, 0, sizeof(struct in6_addr));

        uint8_t *p_netmask = netmask->s6_addr;
        while (8 < cidr_prefix_length)
        {
                *p_netmask = 0xFFu;
                p_netmask++;
                cidr_prefix_length -= 8;
        }
        if (cidr_prefix_length > 0)
        {
                *p_netmask = (0xFFu << (8u - cidr_prefix_length));
        }
}

static int
SAND_rule_add (const char * const str, const size_t len, const size_t rule_type)
{
        int type = SAND_IPV4_ADDR | SAND_IPV6_ADDR | SAND_GLOB_ADDR | SAND_HOST_ADDR;
        const char *p = str;
        const char *service = NULL;
        const char *cidr_prefix_length_start = NULL;
        enum
        {
                IPV6_SB_NONE,
                IPV6_SB_OPEN,
                IPV6_SB_CLOSE
        } sb = IPV6_SB_NONE;
        size_t colon_count = 0;
        size_t ipv4_segment = 1;
        uint16_t segment = 0; /* IPv4 or IPv6 */

        while (p < str + len)
        {
                unsigned char c = *p;

                /* `*' allowed only for glob. Let's go on to check for errors. */
                if (c == '*')
                {
                        /* `*' not allowed if only remaining choices are IPv4 or IPv6. */
                        if (!(type & ~(SAND_IPV4_ADDR | SAND_IPV6_ADDR)))
                        {
                                DIE ("`*' not allowed for IPv4 or IPv6, aborting\n");
                        }
                        else
                        {
                                type = SAND_GLOB_ADDR;
                        }
                }

                /* `[' allowed only at beginning of address for IPv6. */
                else if (c == '[')
                {
                        if (p == str)
                        {
                                type = SAND_IPV6_ADDR;
                                sb = IPV6_SB_OPEN;
                        }
                        else
                        {
                                DIE ("`[' allowed only once for IPv6, aborting\n");
                        }
                }

                else if (c == ']')
                {
                        if (type == SAND_IPV6_ADDR && sb == IPV6_SB_OPEN)
                        {
                                sb = IPV6_SB_CLOSE;
                        }
                        else
                        {
                                DIE ("`]' unexpected, aborting\n");
                        }
                }

                else if (c == ':')
                {
                        /* IPv6 uses `:' as a segment separator. So we count them.
                         * Validation for IPv6 is done later with inet_pton. */
                        colon_count++;
                        /* Assume `:' precedes port. We will check if not empty later. */
                        service = p + 1;

                        if (colon_count > 1)
                        {
                                if ((type & SAND_IPV6_ADDR) == SAND_IPV6_ADDR)
                                {
                                        type = SAND_IPV6_ADDR;
                                }

                                if (type != SAND_IPV6_ADDR ||
                                    ((sb == IPV6_SB_OPEN && colon_count > 7) ||
                                     colon_count > 8))
                                {
                                        DIE ("Extra `:' unexpected, aborting\n");
                                }

                                if (colon_count == 8 || sb == IPV6_SB_CLOSE)
                                {
                                        break;
                                }
                                else
                                {
                                        service = NULL;
                                }
                        }

                        else
                        {
                                /* If so far IPv4 was still a valid choice, then it is it now. */
                                if (p != str && ((type & SAND_IPV4_ADDR) == SAND_IPV4_ADDR))
                                {
                                        type = SAND_IPV4_ADDR;

                                        if (ipv4_segment == 4)
                                        {
                                                break;
                                        }
                                }
                        }
                }

                /* We can see dots for IPv4, glob, or hostnames.  We can rule
                 * out IPv4 when we have a segment that does not fit what is
                 * expected (e.g. higher than 255).
                 */
                else if (c == '.')
                {
                        if (type == SAND_IPV6_ADDR)
                        {
                                DIE ("`.' not allowed for IPv6, aborting\n");
                        }

                        type &= ~SAND_IPV6_ADDR;

                        segment = 0;
                        ipv4_segment++;

                        if (ipv4_segment > 4)
                        {
                                if (type == SAND_IPV4_ADDR) /* not possible for now. */
                                {
                                        DIE ("Extra `.' unexpected, aborting\n");
                                }
                                else
                                {
                                        type &= ~SAND_IPV4_ADDR;
                                }
                        }
                }

                else if (isdigit (c))
                {
                        if ((type & SAND_IPV4_ADDR) == SAND_IPV4_ADDR && cidr_prefix_length_start == NULL)
                        {
                                /* INT30-C */
                                if ((segment > UINT16_MAX / 10) ||
                                    (UINT16_MAX - (c - '0') < segment * 10))
                                {
                                        DIE ("Invalid IPv4 segment, aborting\n");
                                }
                                else
                                {
                                        segment = segment * 10 + (c - '0');
                                }

                                if (segment > 255)
                                {
                                        if (type == SAND_IPV4_ADDR) /* not possible */
                                        {
                                                DIE ("Invalid IPv4 address, aborting\n");
                                        }
                                        else
                                        {
                                                SAND_log (SAND_DEBUG_LOG_LEVEL,
                                                          "DEBUG %hd... is not an IPv4 segment\n",
                                                          segment);
                                                type &= ~SAND_IPV4_ADDR;
                                        }
                                }
                        }
                }

                else if (isxdigit (c)) /* and not a digit */
                {
                        if (type == SAND_IPV4_ADDR) /* not possible */
                        {
                                DIE ("Invalid IPv4 address, aborting\n");
                        }
                        else
                        {
                                type &= ~SAND_IPV4_ADDR;
                        }
                }

                else if (isalnum (c)) /* not a digit nor an xdigit */
                {
                        if (!(type & ~(SAND_IPV4_ADDR | SAND_IPV6_ADDR)))
                        {
                                DIE ("`%c' unexpected, aborting\n", c);
                        }
                        else
                        {
                                type &= ~(SAND_IPV4_ADDR | SAND_IPV6_ADDR);
                        }
                }

                else if (c == '-' || c == '_')
                {
                        if (!(type & ~(SAND_IPV4_ADDR | SAND_IPV6_ADDR)) || p == str)
                        {
                                DIE ("`%c' unexpected, aborting\n", c);
                        }
                        else
                        {
                                type &= ~(SAND_IPV4_ADDR | SAND_IPV6_ADDR);
                        }
                }

                else if (c == '/')
                {
                        if (!(type & (SAND_IPV4_ADDR | SAND_IPV6_ADDR)) || cidr_prefix_length_start != NULL)
                        {
                                DIE ("`%c' unexpected, aborting\n", c);
                        }
                        else
                        {
                                cidr_prefix_length_start = p + 1;
                                type &= (SAND_IPV4_ADDR | SAND_IPV6_ADDR);
                        }
                }

                else
                {
                        /* We may revisit this later for UTF-8 */
                        DIE ("`%c' unexpected here, aborting\n", c);
                }

                p++;
        }

        /* If so far IPv4 was still a valid choice, then it is it now. */
        if ((type & SAND_IPV4_ADDR) == SAND_IPV4_ADDR)
        {
                type = SAND_IPV4_ADDR;
        }

        /* If so far host was still a valid choice, then it is it now. */
        else if ((type & SAND_HOST_ADDR) == SAND_HOST_ADDR)
        {
                type = SAND_HOST_ADDR;
        }

        if (type == SAND_IPV6_ADDR && sb == IPV6_SB_OPEN)
        {
                DIE ("`]' missing, aborting\n");
        }

        assert (type == SAND_IPV4_ADDR ||
                type == SAND_IPV6_ADDR ||
                type == SAND_HOST_ADDR || type == SAND_GLOB_ADDR);

        in_port_t port = 0;
        /* If we have a port here, check if everything after that port is valid. */
        if (service != NULL)
        {
                const char *t = service;
                bool getservbyname_needed = false;

                if (t == str + len)
                {
                        DIE ("No port specified after `:', aborting\n");
                }

                while (t < str + len)
                {
                        unsigned char u = *t;

                        if (isdigit (u))
                        {
                                /* INT30-C */
                                if ((port > UINT16_MAX / 10) ||
                                    (UINT16_MAX - (u - '0') < port * 10))
                                {
                                        DIE ("Invalid port number, aborting\n");
                                }
                                else
                                {
                                        port = port * 10 + (u - '0');
                                }
                        }

                        else if (isalnum (u) || u == '-')
                        {
                                getservbyname_needed = true;
                        }

                        else
                        {
                                DIE ("`%c' unexpected for port, aborting\n", u);
                        }

                        t++;
                }

                if (getservbyname_needed)
                {
#ifdef _WIN32
                        /* We need to initialize WinSock. It's safe to do so. */
                        WSADATA wsaData;
                        int iWSErr = WSAStartup(MAKEWORD(2, 2), &wsaData);

                        if (iWSErr != 0)
                        {
                                DIE("Cannot initialize WinSock 2 API, aborting\n");
                        }
#endif

                        char *svc = strndup (service, len - (service - str));
                        struct servent *svt = getservbyname (svc, "tcp");

                        if (svt != NULL)
                        {
                                port = ntohs (svt->s_port);
                                free (svc);
#ifdef _WIN32
                                WSACleanup();
#endif
                        }
                        else
                        {
                                fprintf (stderr, "service `%s' not found, aborting\n", svc);
                                free (svc);
#ifdef _WIN32
                                WSACleanup();
#endif
                                exit (EXIT_FAILURE);
                        }
                }

                if (port == 0)
                {
                        DIE ("`0' not allowed for port, aborting\n");
                }
        }

        uint8_t cidr_prefix_length = 0;
        if (cidr_prefix_length_start != NULL)
        {
                const char *p_end = str + len;

                if (service != NULL)
                {
                        p_end = service - 1;
                }
                if (sb == IPV6_SB_CLOSE)
                {
                        p_end--;
                }

                if (p_end - cidr_prefix_length_start <= 0)
                {
                        DIE ("No CIDR prefix length specified after `/', aborting\n");
                }
                else if (p_end - cidr_prefix_length_start > 3)
                {
                        DIE ("Too long CIDR prefix length, aborting\n");
                }

                const char *t;
                for (t = cidr_prefix_length_start; t < p_end; t++)
                {
                        unsigned char u = *t;

                        if (!isdigit (u))
                        {
                                DIE ("`%c' unexpected for CIDR prefix length, aborting\n", u);
                        }

                        cidr_prefix_length = cidr_prefix_length * 10 + (u - '0');
                }

                if ((type == SAND_IPV4_ADDR && cidr_prefix_length > 32) ||
                    (type == SAND_IPV6_ADDR && cidr_prefix_length > 128))
                {
                        DIE ("`%u' not allowed for CIDR prefix length, aborting\n", cidr_prefix_length);
                }
        }

        const char *host_start = str;
        const char *host_end = host_start + len;

        if (service != NULL)
        {
                host_end = service - 1;
        }
        if (sb == IPV6_SB_CLOSE)
        {
                host_start++;
                host_end--;
        }
        if (cidr_prefix_length_start != NULL)
        {
                host_end = cidr_prefix_length_start - 1;
        }

        size_t host_len = host_end - host_start;
        char *host = strndup (host_start, host_len);

        SAND_log (SAND_DEBUG_LOG_LEVEL,
                  "DEBUG Adding %s rule for %s connection to %s:%hu\n",
                  rule_type_name[rule_type], address_type_name[type], host, port);

        switch (type)
        {
        case SAND_IPV6_ADDR:
        {
                SAND_entry_t *e = SAND_entry_alloc ();
                e->rule_type = rule_type;
                e->addr_type = SAND_IPV6_ADDR;
                e->port = htons (port);
                e->is_subnet = cidr_prefix_length_start != NULL;

                if (inet_pton (AF_INET6, host, &e->addr.ipv6) != 1)
                {
                        DIE ("Invalid IPv6 address: `%s', aborting\n", host);
                }

                if (e->is_subnet)
                {
                        make_ipv6_netmask (&e->netmask.ipv6, cidr_prefix_length);
                        mask_ipv6 (&e->addr.ipv6, &e->netmask.ipv6);
                }

                SLIST_INSERT_HEAD (&SAND_list_head, e, entries);
                free (host);
                break;
        }

        case SAND_IPV4_ADDR:
        {
                SAND_entry_t *e = SAND_entry_alloc ();
                e->rule_type = rule_type;
                e->addr_type = SAND_IPV4_ADDR;
                e->port = htons (port);
                e->is_subnet = cidr_prefix_length_start != NULL;

                if (inet_pton (AF_INET, host, &e->addr.ipv4) != 1)
                {
                        DIE ("Invalid IPv4 address: `%s', aborting\n", host);
                }

                if (e->is_subnet)
                {
                        make_ipv4_netmask (&e->netmask.ipv4, cidr_prefix_length);
                        mask_ipv4 (&e->addr.ipv4, &e->netmask.ipv4);
                }

                SLIST_INSERT_HEAD (&SAND_list_head, e, entries);
                free (host);
                break;
        }

        case SAND_GLOB_ADDR:
        {
                SAND_entry_t *e = SAND_entry_alloc ();
                e->rule_type = rule_type;
                e->addr_type = SAND_GLOB_ADDR;
                e->port = htons (port);
                e->is_subnet = false;
                /* Here we transfer ownership of `host' to the entry. */
                e->addr.glob = host;
                SLIST_INSERT_HEAD (&SAND_list_head, e, entries);

                /* Do not perform DNS lookups for '*' rules. We don't need to. */
                if (host[0] != '*' || host[1] != '\0')
                {
                        needs_dns_lookup = true;
                }
                break;
        }

        case SAND_HOST_ADDR:
        {
                struct addrinfo *ailist, *aip;
                struct addrinfo hints;
                int err;
                memset (&hints, 0, sizeof(struct addrinfo));
#ifdef AI_ADDRCONFIG
                hints.ai_flags |= AI_ADDRCONFIG;
#endif
                hints.ai_family = AF_UNSPEC; /* IPv4 or IPv6 or others */
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_protocol = IPPROTO_TCP;

#ifdef _WIN32
                /* We need to initialize WinSock. It's safe to do so. */
                WSADATA wsaData;
                int iWSErr = WSAStartup(MAKEWORD(2, 2), &wsaData);

                if (iWSErr != 0)
                {
                        DIE("Cannot initialize WinSock 2 API, aborting\n");
                }
#endif

                if ((err = getaddrinfo (host, NULL, &hints, &ailist)) != 0)
                {
                        DIE ("%s, aborting\n", gai_strerror (err));
                }

                for (aip = ailist; aip != NULL; aip = aip->ai_next)
                {
                        if (aip->ai_family == AF_INET)
                        {
                                struct sockaddr_in *sa = (struct sockaddr_in *) aip->ai_addr;
                                SAND_entry_t *e = SAND_entry_alloc ();
                                e->rule_type = rule_type;
                                e->addr_type = SAND_IPV4_ADDR;
                                e->port = htons (port);
                                e->is_subnet = false;
                                e->addr.ipv4 = sa->sin_addr;
                                SLIST_INSERT_HEAD (&SAND_list_head, e, entries);
                        }

                        else if (aip->ai_family == AF_INET6)
                        {
                                struct sockaddr_in6 *sa =
                                        (struct sockaddr_in6 *) aip->ai_addr;
                                SAND_entry_t *e = SAND_entry_alloc ();
                                e->rule_type = rule_type;
                                e->addr_type = SAND_IPV6_ADDR;
                                e->port = htons (port);
                                e->is_subnet = false;
                                e->addr.ipv6 = sa->sin6_addr;
                                SLIST_INSERT_HEAD (&SAND_list_head, e, entries);
                        }
                }

                freeaddrinfo (ailist);
                free (host);

#ifdef _WIN32
                WSACleanup();
#endif

                break;
        }
        }

        return 0;
}

static size_t
SAND_rules_add (const char *rules, size_t rule_type)
{
        size_t count = 0;

        if (rules)
        {
                const char *p = rules + strlen (rules);
                size_t len = 0;

                while (p >= rules)
                {
                        if (*p == ';')
                        {
                                if (len > 1)
                                {
                                        SAND_rule_add (p + 1, len - 1, rule_type);
                                }

                                len = 1;
                                count++;
                        }
                        else
                        {
                                len++;
                        }

                        p--;
                }

                if (len - 1 > 0)
                {
                        SAND_rule_add (p + 1, len - 1, rule_type);
                        count++;
                }
        }

        return count;
}

static long
SAND_long_value (const char *name, const char *value, long lower_bound,
                 long upper_bound)
{
        char *endptr;
        errno = 0;
        long v = strtol (value, &endptr, 10);
        if ((errno == ERANGE && (v == LONG_MAX || v == LONG_MIN)) ||
            (errno != 0 && value == 0L) ||
            *endptr != '\0' || (v < lower_bound || v > upper_bound))
        {
                DIE ("`%s' not valid for %s (should be between `%ld' and `%ld')\n",
                     value, name, lower_bound, upper_bound);
        }

        return v;
}


/* The real connect function. WARNING: cancellation point. */
static int (WSAAPI *real_connect)(SOCKET fd, const struct sockaddr * addr,
                                  socklen_t addrlen);

typedef struct SAND_resolver {
        union {
                struct in_addr ipv4;
                struct in6_addr ipv6;
        } addr;
        bool isv6;
} SAND_resolver_t;

static void
SAND_read_resolv (SAND_resolver_t * out, size_t * index)
{
        *index = 0;

#ifndef _WIN32
#define NS "nameserver "

        char buffer[1024];
        FILE *resolv = fopen ("/etc/resolv.conf", "r");

        if (!resolv)
        {
                DIE ("Could not read /etc/resolv.conf, aborting\n");
        }

        while (fgets(buffer, sizeof(buffer), resolv) && *index < MAXNS)
        {
                if (!strncmp(buffer, NS, sizeof(NS) - 1))
                {
                        char *ns = buffer + sizeof(NS) - 1;
                        size_t len = strlen(ns);

                        if (ns[len - 1] == '\n')
                        {
                                ns[len - 1] = '\0';
                        }

                        SAND_log(SAND_DEBUG_LOG_LEVEL, "DEBUG Found nameserver: %s\n", ns);

                        if (inet_pton(AF_INET, ns, &out[*index].addr.ipv4) == 1)
                        {
                                out[(*index)++].isv6 = false;
                        }
                        else if (inet_pton(AF_INET6, ns, &out[*index].addr.ipv6) == 1)
                        {
                                out[(*index)++].isv6 = true;
                        }
                        else
                        {
                                DIE("Cannot process nameserver: `%s'\n", ns);
                        }
                }
        }

        fclose(resolv);

#else
        /* We rely on GetAdaptersAddresses:
         *   https://msdn.microsoft.com/en-us/library/windows/desktop/aa365915(v=vs.85).aspx
         * to retrieve IPv4 and IPv6 DNS server addresses.
         */
        DWORD dwRetVal = 0;

        // Set the flags to pass to GetAdaptersAddresses
        ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_UNICAST;

        LPVOID lpMsgBuf = NULL;

        PIP_ADAPTER_ADDRESSES pAddresses = NULL;
        ULONG outBufLen = 0;
        ULONG iterations = 0;

        PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;
        IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;

#define WORKING_BUFFER_SIZE 15000
#define MAX_TRIES 3

        // Allocate a 15 KB buffer to start with.
        outBufLen = WORKING_BUFFER_SIZE;

        do {
                pAddresses = (IP_ADAPTER_ADDRESSES *) malloc (outBufLen);
                if (pAddresses == NULL)
                {
                        DIE ("Cannot allocate memory for IP_ADAPTER_ADDRESSES, aborting\n");
                }

                dwRetVal = GetAdaptersAddresses (AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);

                if (dwRetVal == ERROR_BUFFER_OVERFLOW)
                {
                        free (pAddresses);
                        pAddresses = NULL;
                }
                else
                {
                        break;
                }

                iterations++;

        } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (iterations < MAX_TRIES));

        if (dwRetVal == NO_ERROR) {
                // If successful, output some information from the data we received
                pCurrAddresses = pAddresses;

                while (pCurrAddresses) {
                        pDnServer = pCurrAddresses->FirstDnsServerAddress;

                        while (pDnServer && *index < MAXNS) {
                                ADDRESS_FAMILY family = pDnServer->Address.lpSockaddr->sa_family;

                                if (family == AF_INET6)
                                {
                                        out[*index].addr.ipv6 = ((struct sockaddr_in6 *) pDnServer->Address.lpSockaddr)->sin6_addr;
                                        out[*index].isv6 = true;
                                }
                                else if (family == AF_INET)
                                {
                                        out[*index].addr.ipv4 = ((struct sockaddr_in *) pDnServer->Address.lpSockaddr)->sin_addr;
                                        out[*index].isv6 = false;
                                }

                                (*index)++;
                                pDnServer = pDnServer->Next;
                        }

                        pCurrAddresses = pCurrAddresses->Next;
                }
        }
        else {
                if (dwRetVal == ERROR_NO_DATA)
                        DIE("Cannot find any DNS server, aborting\n");
                else {
                        if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                          FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                          NULL, dwRetVal, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                                          (LPTSTR)&lpMsgBuf, 0, NULL)) {
                                SAND_log(SAND_ERROR_LOG_LEVEL, "ERROR %s\n", lpMsgBuf);
                                LocalFree(lpMsgBuf);
                                free (pAddresses);
                                exit(1);
                        }
                }
        }
#endif
}

const char *
SAND_version (void)
{
        return version;
}

#ifdef _WIN32

int HOOK(connect(SOCKET fd, const struct sockaddr *addr, socklen_t addrlen));
void SAND_init(void);
pfnCreateProcess real_CreateProcess;
BOOL HOOK(CreateProcess(
                  LPCTSTR lpApplicationName,
                  LPTSTR lpCommandLine,
                  LPSECURITY_ATTRIBUTES lpProcessAttributes,
                  LPSECURITY_ATTRIBUTES lpThreadAttributes,
                  BOOL bInheritHandles,
                  DWORD dwCreationFlags,
                  LPVOID lpEnvironment,
                  LPCTSTR lpCurrentDirectory,
                  LPSTARTUPINFO lpStartupInfo,
                  LPPROCESS_INFORMATION lpProcessInformation))
{
        stCreateProcess cpArgs = {
                .fn = real_CreateProcess,
                .lpApplicationName = lpApplicationName,
                .lpCommandLine = lpCommandLine,
                .lpProcessAttributes = lpProcessAttributes,
                .lpThreadAttributes = lpThreadAttributes,
                .bInheritHandles = bInheritHandles,
                .dwCreationFlags = dwCreationFlags,
                .lpEnvironment = lpEnvironment,
                .lpCurrentDirectory = lpCurrentDirectory,
                .lpStartupInfo = lpStartupInfo,
                .lpProcessInformation = lpProcessInformation
        };

        BOOL isConsole;

        return CreateProcessThenInject(&cpArgs, &isConsole);
}

#endif

static inline void
SAND_sym_connect (void)
{
        if (real_connect == NULL)
        {
#ifdef _WIN32
                if (MH_Initialize() != MH_OK)
                {
                        DIE("Cannot initialize MinHook, aborting\n");
                }

                if (MH_CreateHookApiEx(L"ws2_32", "connect", &hook_connect, (LPVOID *) &real_connect, NULL) != MH_OK)
                {
                        DIE("Cannot hook connect(), aborting\n");
                }

                /* TODO: add WSAConnect, ConnectEx */
                if (MH_CreateHook(&CreateProcess, &hook_CreateProcess, (LPVOID *) &real_CreateProcess) != MH_OK)
                {
                        DIE("Cannot hook CreateProcess, aborting\n");
                }

                if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
                {
                        DIE("Cannot enable hooks, aborting\n");
                }
#else
                real_connect =
                        (int (*)(int, const struct sockaddr *, socklen_t))dlsym (RTLD_NEXT,
                                                                                 "connect");

                if (real_connect == NULL)
                {
                        char *error = dlerror ();

                        if (error == NULL)
                        {
                                error = "connect is NULL";
                        }

                        DIE ("%s\n", error);
                }
#endif
        }
}

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved
                      )
{
        switch (ul_reason_for_call)
        {
        case DLL_PROCESS_ATTACH:
                SAND_init ();
                break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
                break;
        }
        return TRUE;
}
#endif

/* Called by dynamic linker when library is loaded. */
#ifdef __SUNPRO_C
#pragma init (SAND_init)
#elif defined(__GNUC__)
void SAND_init (void) __attribute__ ((constructor));
#endif

void
SAND_init (void)
{
        SAND_sym_connect ();

        char *level = getenv (SAND_LOG_LEVEL_ENV_VAR_NAME);
        if (level)
        {
                static const SAND_log_level_t map[] = {
                        SAND_SILENT_LOG_LEVEL,
                        SAND_ERROR_LOG_LEVEL,
                        SAND_BLOCK_LOG_LEVEL,
                        SAND_ALLOW_LOG_LEVEL,
                        SAND_DEBUG_LOG_LEVEL
                };

                long lvl = SAND_long_value (SAND_LOG_LEVEL_ENV_VAR_NAME, level,
                                            0,
                                            sizeof (map) / sizeof (map[0]) - 1);

                log_level = map[(size_t) lvl];
        }

        char *target = getenv (SAND_LOG_TARGET_ENV_VAR_NAME);
        if (target)
        {
                log_target = SAND_long_value (SAND_LOG_TARGET_ENV_VAR_NAME,
                                              target, SAND_STDERR_LOG,
                                              SAND_STDERR_LOG | SAND_SYSLOG_LOG |
                                              SAND_FILE_LOG);

                if ((log_target & SAND_FILE_LOG) == SAND_FILE_LOG)
                {
                        const char *progname = getprogname ();
                        const char *log_path = getenv (SAND_LOG_PATH_ENV_VAR_NAME);
                        if (!log_path)
                        {
                                log_path = ".";
                        }
#ifdef _WIN32
#define SAND_PATH_SEP "\\"
#else
#define SAND_PATH_SEP "/"
#endif
                        log_file_name = malloc (strlen (log_path) + strlen (progname) + 6);
                        sprintf (log_file_name, "%s" SAND_PATH_SEP "%s.sand", log_path, progname);
                }
        }

        /* Initialize our singly-linked list. */
        SLIST_INIT (&SAND_list_head);

        char *block = getenv (SAND_BLOCK_ENV_VAR_NAME);
        SAND_rules_add (block, SAND_BLOCK);

        char *allow = getenv (SAND_ALLOW_ENV_VAR_NAME);
        SAND_rules_add (allow, SAND_ALLOW);

        if (allow != NULL && block == NULL && needs_dns_lookup)
        {
                DIE ("Glob specified for ALLOW rule but no rule for BLOCK; aborting\n");
        }

        /* Fail if there is a glob and DNS is not allowed. */
        if (needs_dns_lookup)
        {
#ifdef _WIN32
                /* We need to initialize WinSock. It's safe to do so. */
                WSADATA wsaData;
                int iWSErr = WSAStartup (MAKEWORD(2, 2), &wsaData);

                if (iWSErr != 0)
                {
                        DIE("Cannot initialize WinSock 2 API, aborting\n");
                }
#endif
                bool dns_server_found = false;

                /* Read nameserver entries in /etc/resolv.conf */
                SAND_resolver_t dns[MAXNS] = { 0 };
                size_t dns_count;
                SAND_read_resolv (dns, &dns_count);

                /* Cycle in all allowed IP entries to check if we have one of these */
                SAND_entry_t *e;
                SLIST_FOREACH (e, &SAND_list_head, entries)
                {
                        if (dns_server_found)
                        {
                                break;
                        }

                        if (e->rule_type == SAND_ALLOW &&
                            e->addr_type != SAND_GLOB_ADDR &&
                            (!e->port || e->port == htons (53)))
                        {
                                size_t i;
                                for (i = 0; i < dns_count; i++)
                                {
                                        if ((e->addr_type == SAND_IPV4_ADDR &&
                                             !dns[i].isv6 &&
                                             e->addr.ipv4.s_addr == dns[i].addr.ipv4.s_addr) ||
                                            (e->addr_type == SAND_IPV6_ADDR &&
                                             dns[i].isv6 &&
                                             IN6_ARE_ADDR_EQUAL (&e->addr.ipv6, &dns[i].addr.ipv6)))
                                        {
                                                dns_server_found = true;
                                                break;
                                        }
                                }
                        }
                }

                if (!dns_server_found)
                {
                        DIE ("No DNS allowed while some glob rule need one, aborting\n");
                }

#ifdef _WIN32
                WSACleanup ();
#endif

        }

        initialized = true;
}

#define INET4_FMLY(a) (a->sa_family == AF_INET)
#define INET4_CAST(a) ((const struct sockaddr_in *) a)
#define INET6_CAST(a) ((const struct sockaddr_in6 *) a)
#define INET4_PORT(a) (INET4_CAST (a)->sin_port)
#define INET6_PORT(a) (INET6_CAST (a)->sin6_port)
#define INETX_PORT(a) (INET4_FMLY (a) ? INET4_PORT (a) : INET6_PORT (a))
#define INET4_ADDR(a) (&INET4_CAST (a)->sin_addr)
#define INET6_ADDR(a) (&INET6_CAST (a)->sin6_addr)
#define INETX_ADDR(a) (INET4_FMLY (a) ? (void *) INET4_ADDR (a) : (void *) INET6_ADDR (a))
#define INET4_IN_6(i) ((struct in_addr *) ((i)->s6_addr + 12))

static inline
bool
SAND_rule_match_ipv4 (const struct in_addr *rule_addr, in_port_t rule_port, const struct in_addr *addr, in_port_t port, bool rule_is_subnet, const struct in_addr *netmask)
{
        struct in_addr masked_addr;
        if (rule_is_subnet)
        {
                masked_addr = *addr;
                mask_ipv4 (&masked_addr, netmask);
                addr = &masked_addr;
        }
        return (rule_addr->s_addr == addr->s_addr &&
                (!rule_port || rule_port == port));
}

static inline
bool
SAND_rule_match_ipv6 (const struct in6_addr *rule_addr, in_port_t rule_port, const struct in6_addr *addr, in_port_t port, bool rule_is_subnet, const struct in6_addr *netmask)
{
        struct in6_addr masked_addr;
        if (rule_is_subnet)
        {
                masked_addr = *addr;
                mask_ipv6 (&masked_addr, netmask);
                addr = &masked_addr;
        }
        return (IN6_ARE_ADDR_EQUAL (rule_addr, addr) &&
                (!rule_port || rule_port == port));
}

static inline
bool
SAND_rule_match (SAND_entry_t *e, const struct sockaddr *addr, const char *buf)
{
        switch (e->addr_type)
        {
        case SAND_IPV6_ADDR:
                if (addr->sa_family == AF_INET6)
                {
                        return SAND_rule_match_ipv6 (
                                       &e->addr.ipv6,
                                       e->port,
                                       INET6_ADDR (addr),
                                       INET6_PORT (addr),
                                       e->is_subnet,
                                       &e->netmask.ipv6);
                }
                else if (addr->sa_family == AF_INET)
                {
                        if (IN6_IS_ADDR_V4MAPPED (&e->addr.ipv6))
                        {
                                return SAND_rule_match_ipv4 (
                                               INET4_IN_6 (&e->addr.ipv6),
                                               e->port,
                                               INET4_ADDR (addr),
                                               INET4_PORT (addr),
                                               e->is_subnet,
                                               INET4_IN_6 (&e->netmask.ipv6));
                        }
                }
                break;

        case SAND_IPV4_ADDR:
                if (addr->sa_family == AF_INET)
                {
                        return SAND_rule_match_ipv4 (
                                       &e->addr.ipv4,
                                       e->port,
                                       INET4_ADDR (addr),
                                       INET4_PORT (addr),
                                       e->is_subnet,
                                       &e->netmask.ipv4);
                }
                else if (addr->sa_family == AF_INET6)
                {
                        if (IN6_IS_ADDR_V4MAPPED (INET6_ADDR (addr)))
                        {
                                return SAND_rule_match_ipv4 (
                                               &e->addr.ipv4,
                                               e->port,
                                               INET4_IN_6 (INET6_ADDR (addr)),
                                               INET6_PORT (addr),
                                               e->is_subnet,
                                               &e->netmask.ipv4);
                        }
                }
                break;

        case SAND_GLOB_ADDR:
                return (((e->addr.glob[0] == '*' && e->addr.glob[1] == '\0')
                         || !fnmatch (e->addr.glob, buf, 0))
                        && (!e->port || e->port == INETX_PORT (addr)));
        }

        return false;
}

/*
 * Real work happens here.
 *
 * We don't do anything except for AF_INET and AF_INET6.
 */
int
HOOK(connect(SOCKET fd, const struct sockaddr *addr, socklen_t addrlen))
{
        if (!initialized)
        {
                /* With SELinux enabled `connect' gets called for audit purpose
                   _before_ `SAND_init' so we ensure we have the real `connect'
                   symbol address here to avoid segfaulting. */
                SAND_sym_connect ();

                /* Do not check connections if initialization is not complete. */
                return real_connect (fd, addr, addrlen);
        }

        if (addr != NULL &&
            (addr->sa_family == AF_INET || addr->sa_family == AF_INET6))
        {
                char str[INET6_ADDRSTRLEN];
                in_port_t port = INETX_PORT (addr);
                inet_ntop (addr->sa_family, INETX_ADDR (addr), str, INET6_ADDRSTRLEN);

                char hbuf[NI_MAXHOST] = "*";

                bool dns_lookup_done = !needs_dns_lookup;

                /* We have access to IP address and port where the
                 * connection is requested.
                 *
                 * Logic:
                 *  1. check if this address appears in our ALLOW rules:
                 *     - if so, proceed to the real connect call
                 *  2. If not, check if it's in the BLOCK rules:
                 *     - if so, call pthread_testcancel, then return EACCES
                 *  3. Otherwise proceed with regular connect call. */
                SAND_entry_t *e;
                SLIST_FOREACH (e, &SAND_list_head, entries)
                {
                        if (e->addr_type == SAND_GLOB_ADDR)
                        {
                                if (!dns_lookup_done)
                                {
                                        int rc = getnameinfo (addr, addrlen, hbuf, sizeof (hbuf),
                                                              NULL, 0, NI_NUMERICSERV);

                                        if (rc)
                                        {
                                                SAND_log (SAND_BLOCK_LOG_LEVEL, "ERROR resolving name: %s\n",
                                                          gai_strerror (rc));
                                                continue;
                                        }
                                        else
                                        {
                                                dns_lookup_done = true;
                                        }
                                }
                        }

                        SAND_log (SAND_DEBUG_LOG_LEVEL,
                                  "DEBUG Checking %s rule for %s connection to %s:%hu\n",
                                  rule_type_name[e->rule_type],
                                  address_type_name[e->addr_type],
                                  str, ntohs (e->port));

                        if (SAND_rule_match(e, addr, hbuf))
                        {
                                if (e->rule_type == SAND_ALLOW)
                                {
                                        SAND_log (SAND_ALLOW_LOG_LEVEL, "ALLOW connection to %s:%hu\n", str,
                                                  ntohs (port));
                                        return real_connect (fd, addr, addrlen);
                                }
                                else
                                {
                                        pthread_testcancel ();
                                        SAND_log (SAND_BLOCK_LOG_LEVEL, "BLOCK connection to %s:%hu\n", str,
                                                  ntohs (port));
#ifdef _WIN32
                                        WSASetLastError(WSAEACCES);
#else
                                        errno = EACCES;
#endif
                                        return -1;
                                }
                        }
                }

                SAND_log (SAND_ALLOW_LOG_LEVEL, "ALLOW connection to %s:%hu\n", str,
                          ntohs (port));
        }

        return real_connect (fd, addr, addrlen);
}
