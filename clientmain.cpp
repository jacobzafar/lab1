#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include "protocol.h"

// Included to get the support library (template convention; not otherwise used).
#include <calcLib.h>

// Enable to send debug output to STDERR (STDOUT stays clean either way).
// Alternatively: make CFLAGS=-DDEBUG
// #define DEBUG

#ifdef DEBUG
#define DBG(...) fprintf(stderr, __VA_ARGS__)
#else
#define DBG(...) do { } while (0)
#endif

#define RESULT_SUCCESS 0
#define RESULT_TRANSPORT_FAILED 1

/* The assignment mandates a 2 second timeout for UDP. */
#define UDP_TIMEOUT_SEC 2
/* Extra retransmissions on UDP timeout (assignment permits 2). */
#define UDP_RETRIES 2
/* TCP is reliable, but we still bound waits so a silent (echo-like) or
 * garbage-spewing (chargen-like) "wrong" server cannot hang us forever. */
#define TCP_TIMEOUT_SEC 5
/* Bound on connect() itself, for a host that resolves but is unreachable
 * at the network level (as opposed to actively refusing). */
#define CONNECT_TIMEOUT_SEC 5
/* Safety cap on handshake lines read before giving up (a chargen-style
 * server would otherwise stream forever). */
#define MAX_HANDSHAKE_LINES 200

static int handle_tcp(const char *protoLabel, const char *Desthost, const char *Destport, const char *Destpath, int reportTransport);
static int handle_udp(const char *protoLabel, const char *Desthost, const char *Destport, const char *Destpath, int reportTransport);

/* 1 if the string is all upper-case or all lower-case letters; 0 if it
 * mixes the two (e.g. "Tcp"). The assignment forbids case combinations. */
static int is_consistent_case(const char *s) {
    int sawUpper = 0, sawLower = 0;
    for (const char *p = s; *p; ++p) {
        if (*p >= 'A' && *p <= 'Z') sawUpper = 1;
        else if (*p >= 'a' && *p <= 'z') sawLower = 1;
    }
    return !(sawUpper && sawLower);
}

/* Strip trailing \r / \n from a NUL-terminated string, in place. */
static void strip_eol(char *s) {
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r')) {
        s[--len] = '\0';
    }
}

/* Read one '\n'-terminated line from a TCP socket, byte-by-byte, so we
 * are correct regardless of how the stream is split across segments.
 * The trailing '\n' (and '\r') is stripped. Returns the line length
 * (>=0), or -1 on error/timeout/orderly-close-with-no-data. */
static int read_line_tcp(int sock, char *out, size_t outsize) {
    size_t i = 0;
    for (;;) {
        if (i >= outsize - 1) {
            out[outsize - 1] = '\0';
            return (int)(outsize - 1);
        }
        char c;
        ssize_t r = recv(sock, &c, 1, 0);
        if (r == 0) {
            if (i == 0) return -1;
            break;
        }
        if (r < 0) return -1;
        if (c == '\n') break;
        out[i++] = c;
    }
    out[i] = '\0';
    strip_eol(out);
    return (int)i;
}

/* Receive exactly `want` bytes over TCP into `buf` (capacity `cap`),
 * but stop early if the first read already delivered a complete,
 * smaller protocol message (sizeof(calcMessage)). Returns the number
 * of bytes now in `buf`, 0 on orderly close, -1 on error/timeout. */
static ssize_t recv_struct_tcp(int sock, void *buf, size_t cap, size_t want) {
    ssize_t n = recv(sock, buf, cap, 0);
    if (n <= 0) return n;
    while ((size_t)n < want && (size_t)n != sizeof(struct calcMessage)) {
        ssize_t r = recv(sock, (char *)buf + n, cap - (size_t)n, 0);
        if (r <= 0) break;
        n += r;
    }
    return n;
}

/* Send a datagram on a connected UDP socket and wait for the reply,
 * retransmitting up to UDP_RETRIES extra times on timeout. Returns
 * bytes received (>0), 0 if every attempt timed out, -1 on a hard
 * error (e.g. ICMP port unreachable -> ECONNREFUSED). */
static ssize_t udp_send_recv(int sock, const void *sbuf, size_t slen,
                             void *rbuf, size_t rcap) {
    for (int attempt = 0; attempt <= UDP_RETRIES; ++attempt) {
        if (send(sock, sbuf, slen, 0) < 0) return -1;
        ssize_t r = recv(sock, rbuf, rcap, 0);
        if (r > 0) return r;
        if (r == 0) return 0;
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
            DBG("UDP timeout, retransmitting (%d/%d)\n", attempt + 1, UDP_RETRIES);
            continue;
        }
        return -1;
    }
    return 0;
}

/* connect() with a bounded wait via a temporarily non-blocking socket +
 * select(). Restores blocking mode before returning. 0 on success, -1
 * on failure/timeout. */
static int connect_with_timeout(int sock, const struct sockaddr *addr, socklen_t addrlen, int timeout_sec) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(sock, addr, addrlen);
    if (rc == 0) {
        fcntl(sock, F_SETFL, flags);
        return 0;
    }
    if (errno != EINPROGRESS) {
        fcntl(sock, F_SETFL, flags);
        return -1;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    rc = select(sock + 1, NULL, &wfds, NULL, &tv);
    fcntl(sock, F_SETFL, flags);
    if (rc <= 0) {
        errno = ETIMEDOUT;
        return -1;
    }

    int soerr = 0;
    socklen_t slen = sizeof(soerr);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0) {
        errno = soerr ? soerr : EIO;
        return -1;
    }
    return 0;
}

/* Resolve host/port (AF_UNSPEC -> IPv4 or IPv6) and return a socket
 * that is connected (TCP) or has its peer recorded (UDP). Tries every
 * address getaddrinfo returns. On failure prints the required error to
 * STDERR and returns -1. On success *outRes holds the addrinfo list
 * (caller frees) and *outFamily the address family that worked. */
static int resolve_connect(const char *host, const char *port, int socktype,
                           struct addrinfo **outRes, int *outFamily) {
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socktype;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0 || res == NULL) {
        fprintf(stderr, "ERROR: RESOLVE ISSUE\n");
        return -1;
    }

    int sock = -1;
    int family = AF_UNSPEC;
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock == -1) continue;
        if (socktype == SOCK_STREAM) {
            if (connect_with_timeout(sock, rp->ai_addr, rp->ai_addrlen, CONNECT_TIMEOUT_SEC) == 0) {
                family = rp->ai_family;
                break;
            }
        } else {
            /* UDP connect() only records the peer locally. */
            if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) {
                family = rp->ai_family;
                break;
            }
        }
        close(sock);
        sock = -1;
    }

    if (sock == -1) {
        fprintf(stderr, "ERROR: CANT CONNECT TO %s\n", host);
        freeaddrinfo(res);
        return -1;
    }

    char ipstr[INET6_ADDRSTRLEN] = "0.0.0.0";
    getnameinfo(rp->ai_addr, rp->ai_addrlen, ipstr, sizeof(ipstr), NULL, 0, NI_NUMERICHOST);
    DBG("Connected to %s:%s (%s)\n", ipstr, port, family == AF_INET6 ? "IPv6" : "IPv4");

    *outRes = res;
    if (outFamily) *outFamily = family;
    return sock;
}

static int compute(const char *op, int v1, int v2, int *result) {
    if (strcmp(op, "add") == 0) { *result = v1 + v2; return 0; }
    if (strcmp(op, "sub") == 0) { *result = v1 - v2; return 0; }
    if (strcmp(op, "mul") == 0) { *result = v1 * v2; return 0; }
    if (strcmp(op, "div") == 0) {
        if (v2 == 0) { *result = 0; return 0; }
        *result = v1 / v2;              /* integer division truncates toward zero */
        return 0;
    }
    return -1;
}

static const char *arith_name(uint32_t arith) {
    switch (arith) {
        case 1: return "add";
        case 2: return "sub";
        case 3: return "mul";
        case 4: return "div";
        default: return "unknown";
    }
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s protocol://server:port/path\n", argv[0]);
        return EXIT_FAILURE;
    }

    char protocolstring[8], hoststring[2000], portstring[8], pathstring[16];
    char *input = argv[1];

    if (strstr(input, "///") != NULL) {
        fprintf(stderr, "ERROR: INVALID FORMAT: %s\n", input);
        return EXIT_FAILURE;
    }

    char *proto_end = strstr(input, "://");
    if (!proto_end) {
        fprintf(stderr, "ERROR: INVALID FORMAT, MISSING '://'\n");
        return EXIT_FAILURE;
    }

    size_t proto_len = (size_t)(proto_end - input);
    if (proto_len == 0 || proto_len >= sizeof(protocolstring)) {
        fprintf(stderr, "ERROR: PROTOCOL STRING INVALID LENGTH\n");
        return EXIT_FAILURE;
    }
    strncpy(protocolstring, input, proto_len);
    protocolstring[proto_len] = '\0';

    if (!is_consistent_case(protocolstring)) {
        fprintf(stderr, "ERROR: PROTOCOL MUST NOT MIX UPPER/LOWER CASE\n");
        return EXIT_FAILURE;
    }

    char *host_start = proto_end + 3;

    char *port_start = strchr(host_start, ':');
    if (!port_start || port_start == host_start) {
        fprintf(stderr, "ERROR: PORT IS MISSING OR ':' IS MISPLACED\n");
        return EXIT_FAILURE;
    }

    size_t host_len = (size_t)(port_start - host_start);
    if (host_len == 0 || host_len >= sizeof(hoststring)) {
        fprintf(stderr, "ERROR: HOST STRING INVALID LENGTH\n");
        return EXIT_FAILURE;
    }
    strncpy(hoststring, host_start, host_len);
    hoststring[host_len] = '\0';

    char *path_start = strchr(host_start, '/');
    if (!path_start || *(path_start + 1) == '\0') {
        fprintf(stderr, "ERROR: PATH IS MISSING OR INVALID\n");
        return EXIT_FAILURE;
    }

    size_t path_len = strlen(path_start + 1);
    if (path_len == 0 || path_len >= sizeof(pathstring)) {
        fprintf(stderr, "ERROR: PATH STRING INVALID LENGTH\n");
        return EXIT_FAILURE;
    }
    strcpy(pathstring, path_start + 1);

    if (!is_consistent_case(pathstring)) {
        fprintf(stderr, "ERROR: PATH MUST NOT MIX UPPER/LOWER CASE\n");
        return EXIT_FAILURE;
    }

    if (port_start >= path_start) {
        fprintf(stderr, "ERROR: PORT IS MISSING OR MISPLACED\n");
        return EXIT_FAILURE;
    }
    size_t port_len = (size_t)(path_start - port_start - 1);
    if (port_len == 0 || port_len >= sizeof(portstring)) {
        fprintf(stderr, "ERROR: PORT STRING INVALID LENGTH\n");
        return EXIT_FAILURE;
    }
    strncpy(portstring, port_start + 1, port_len);
    portstring[port_len] = '\0';

    for (size_t i = 0; i < strlen(portstring); ++i) {
        if (portstring[i] < '0' || portstring[i] > '9') {
            fprintf(stderr, "ERROR: PORT MUST BE NUMERIC\n");
            return EXIT_FAILURE;
        }
    }

    const char *protocol = protocolstring;
    const char *Desthost = hoststring;
    const char *Destport = portstring;
    const char *Destpath = pathstring;

    long port = strtol(Destport, NULL, 10);
    if (port < 1 || port > 65535) {
        fprintf(stderr, "ERROR: PORT IS OUT OF SERVER SCOPE\n");
        return EXIT_FAILURE;
    }

    if (!(strcasecmp(Destpath, "text") == 0 || strcasecmp(Destpath, "binary") == 0)) {
        fprintf(stderr, "ERROR: UNKNOWN PATH: %s\n", Destpath);
        return EXIT_FAILURE;
    }

    DBG("Parsed: protocol=%s host=%s port=%ld path=%s\n", protocol, Desthost, port, Destpath);

    if (strcasecmp(protocol, "tcp") == 0) {
        return handle_tcp(protocol, Desthost, Destport, Destpath, 0) == RESULT_SUCCESS
                   ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcasecmp(protocol, "udp") == 0) {
        return handle_udp(protocol, Desthost, Destport, Destpath, 0) == RESULT_SUCCESS
                   ? EXIT_SUCCESS : EXIT_FAILURE;
    }
    else if (strcasecmp(protocol, "any") == 0) {
        /* Try TCP first; if that transport does not work at all, fall
         * back to UDP. If both fail, give up. */
        if (handle_tcp("tcp", Desthost, Destport, Destpath, 1) == RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }
        fprintf(stderr, "NOTE: ANY -> TCP did not work, trying UDP.\n");
        if (handle_udp("udp", Desthost, Destport, Destpath, 1) == RESULT_SUCCESS) {
            return EXIT_SUCCESS;
        }
        fprintf(stderr, "ERROR: ANY -> NEITHER TCP NOR UDP REACHED %s\n", Desthost);
        return EXIT_FAILURE;
    }
    else {
        fprintf(stderr, "ERROR: UNKNOWN PROTOCOL: %s\n", protocol);
        return EXIT_FAILURE;
    }
}

/* Read the server's version list (one protocol per line, ended by a
 * blank line). Returns 1 if `wanted` appeared as a complete line, 0 if
 * the list ended without it, -1 on timeout/connection error. */
static int read_handshake_and_check(int sock, const char *wanted) {
    char line[512];
    int found = 0;
    for (int i = 0; i < MAX_HANDSHAKE_LINES; ++i) {
        int n = read_line_tcp(sock, line, sizeof(line));
        if (n < 0) return -1;
        if (n == 0) return found;              /* blank line: end of list */
        DBG("Handshake line: '%s'\n", line);
        if (strcmp(line, wanted) == 0) found = 1;
    }
    return 0;
}

static int handle_tcp(const char *protoLabel, const char *Desthost, const char *Destport, const char *Destpath, int reportTransport) {
    printf("Protocol: %s, Host %s, port %s and path %s.\n", protoLabel, Desthost, Destport, Destpath);

    struct addrinfo *res = NULL;
    int sock = resolve_connect(Desthost, Destport, SOCK_STREAM, &res, NULL);
    if (sock < 0) return RESULT_TRANSPORT_FAILED;

    struct timeval tv;
    tv.tv_sec = TCP_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    int isBinary = (strcasecmp(Destpath, "binary") == 0);
    char wanted[32];
    snprintf(wanted, sizeof(wanted), "%s TCP 1.1", isBinary ? "BINARY" : "TEXT");

    int matched = read_handshake_and_check(sock, wanted);
    if (matched < 0) {
        fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
        close(sock); freeaddrinfo(res);
        return RESULT_TRANSPORT_FAILED;
    }
    if (matched == 0) {
        fprintf(stderr, "ERROR: MISSMATCH PROTOCOL\n");
        close(sock); freeaddrinfo(res);
        return RESULT_TRANSPORT_FAILED;
    }

    char reply[64];
    snprintf(reply, sizeof(reply), "%s OK\n", wanted);
    if (send(sock, reply, strlen(reply), 0) <= 0) {
        fprintf(stderr, "ERROR: CANT CONNECT TO %s\n", Desthost);
        close(sock); freeaddrinfo(res);
        return RESULT_TRANSPORT_FAILED;
    }
    DBG("Sent handshake reply: %s", reply);

    if (reportTransport) printf("Reached server using TCP.\n");

    if (!isBinary) {
        char line[256];
        int n = read_line_tcp(sock, line, sizeof(line));
        if (n < 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        printf("ASSIGNMENT: %s\n", line);

        char op[16];
        int v1 = 0, v2 = 0;
        if (sscanf(line, "%15s %d %d", op, &v1, &v2) != 3) {
            fprintf(stderr, "ERROR: MALFORMED ASSIGNMENT\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        int result = 0;
        if (compute(op, v1, v2, &result) != 0) {
            fprintf(stderr, "ERROR: UNKNOWN OPERATION %s\n", op);
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        DBG("Calculated the result to %d\n", result);

        char answer[32];
        snprintf(answer, sizeof(answer), "%d\n", result);
        send(sock, answer, strlen(answer), 0);

        char verdict[256];
        int m = read_line_tcp(sock, verdict, sizeof(verdict));
        if (m < 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        printf("%s (myresult=%d)\n", verdict, result);

        close(sock); freeaddrinfo(res);
        return RESULT_SUCCESS;
    }
    else {
        unsigned char raw[sizeof(struct calcProtocol) + 16];
        ssize_t n = recv_struct_tcp(sock, raw, sizeof(raw), sizeof(struct calcProtocol));
        if (n <= 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if ((size_t)n == sizeof(struct calcMessage)) {
            fprintf(stderr, "ERROR: SERVER SENT NOT OK, PROTOCOL NOT SUPPORTED\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if ((size_t)n != sizeof(struct calcProtocol)) {
            fprintf(stderr, "ERROR: WRONG SIZE OR INCORRECT PROTOCOL\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        struct calcProtocol task;
        memcpy(&task, raw, sizeof(task));

        uint32_t arith = ntohl(task.arith);
        int32_t v1 = (int32_t)ntohl((uint32_t)task.inValue1);
        int32_t v2 = (int32_t)ntohl((uint32_t)task.inValue2);
        const char *opname = arith_name(arith);

        int result = 0;
        if (compute(opname, v1, v2, &result) != 0) {
            fprintf(stderr, "ERROR: UNKNOWN OPERATION CODE %u\n", arith);
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        printf("ASSIGNMENT: %s %d %d\n", opname, v1, v2);
        DBG("Calculated the result to %d\n", result);

        task.type = htons(2);
        task.inResult = (int32_t)htonl((uint32_t)result);

        if (send(sock, &task, sizeof(task), 0) <= 0) {
            fprintf(stderr, "ERROR: FAILED TO SEND REPLY TO %s\n", Desthost);
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        unsigned char rbuf[sizeof(struct calcMessage) + 16];
        ssize_t m = recv_struct_tcp(sock, rbuf, sizeof(rbuf), sizeof(struct calcMessage));
        if (m <= 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if ((size_t)m != sizeof(struct calcMessage)) {
            fprintf(stderr, "ERROR: WRONG SIZE OR INCORRECT PROTOCOL\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        struct calcMessage response;
        memcpy(&response, rbuf, sizeof(response));
        uint32_t message = ntohl(response.message);

        if (message == 1) {
            printf("OK (myresult=%d)\n", result);
        } else if (message == 2) {
            printf("NOT OK (myresult=%d)\n", result);
        } else {
            fprintf(stderr, "ERROR: UNKNOWN RESPONSE\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        close(sock); freeaddrinfo(res);
        return RESULT_SUCCESS;
    }
}

static int handle_udp(const char *protoLabel, const char *Desthost, const char *Destport, const char *Destpath, int reportTransport) {
    printf("Protocol: %s, Host %s, port %s and path %s.\n", protoLabel, Desthost, Destport, Destpath);

    struct addrinfo *res = NULL;
    int sock = resolve_connect(Desthost, Destport, SOCK_DGRAM, &res, NULL);
    if (sock < 0) return RESULT_TRANSPORT_FAILED;

    struct timeval tv;
    tv.tv_sec = UDP_TIMEOUT_SEC;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

    int isBinary = (strcasecmp(Destpath, "binary") == 0);

    if (isBinary) {
        struct calcMessage first;
        memset(&first, 0, sizeof(first));
        first.type          = htons(22);   /* client-to-server, binary */
        first.message       = htonl(0);    /* N/A */
        first.protocol      = htons(17);   /* UDP */
        first.major_version = htons(1);
        first.minor_version = htons(1);    /* protocol.h documents 1.1 as the supported version */

        unsigned char raw[sizeof(struct calcProtocol) + 16];
        ssize_t n = udp_send_recv(sock, &first, sizeof(first), raw, sizeof(raw));
        if (n < 0) {
            fprintf(stderr, "ERROR: CANT CONNECT TO %s\n", Desthost);
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if (n == 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if ((size_t)n == sizeof(struct calcMessage)) {
            fprintf(stderr, "ERROR: SERVER SENT NOT OK, PROTOCOL NOT SUPPORTED\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if ((size_t)n != sizeof(struct calcProtocol)) {
            fprintf(stderr, "ERROR: WRONG SIZE OR INCORRECT PROTOCOL\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        if (reportTransport) printf("Reached server using UDP.\n");

        struct calcProtocol task;
        memcpy(&task, raw, sizeof(task));

        uint32_t arith = ntohl(task.arith);
        int32_t v1 = (int32_t)ntohl((uint32_t)task.inValue1);
        int32_t v2 = (int32_t)ntohl((uint32_t)task.inValue2);
        const char *opname = arith_name(arith);

        int result = 0;
        if (compute(opname, v1, v2, &result) != 0) {
            fprintf(stderr, "ERROR: UNKNOWN OPERATION CODE %u\n", arith);
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        printf("ASSIGNMENT: %s %d %d\n", opname, v1, v2);
        DBG("Calculated the result to %d\n", result);

        task.type = htons(2);
        task.inResult = (int32_t)htonl((uint32_t)result);

        struct calcMessage response;
        ssize_t m = udp_send_recv(sock, &task, sizeof(task), &response, sizeof(response));
        if (m <= 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if ((size_t)m != sizeof(struct calcMessage)) {
            fprintf(stderr, "ERROR: WRONG SIZE OR INCORRECT PROTOCOL\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        uint32_t message = ntohl(response.message);
        if (message == 1) {
            printf("OK (myresult=%d)\n", result);
        } else if (message == 2) {
            printf("NOT OK (myresult=%d)\n", result);
        } else {
            fprintf(stderr, "ERROR: UNKNOWN RESPONSE\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        close(sock); freeaddrinfo(res);
        return RESULT_SUCCESS;
    }
    else {
        const char *first = "TEXT UDP 1.1\n";

        char buffer[1024];
        ssize_t n = udp_send_recv(sock, first, strlen(first), buffer, sizeof(buffer) - 1);
        if (n < 0) {
            fprintf(stderr, "ERROR: CANT CONNECT TO %s\n", Desthost);
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        if (n == 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        buffer[n] = '\0';
        strip_eol(buffer);

        if (reportTransport) printf("Reached server using UDP.\n");
        printf("ASSIGNMENT: %s\n", buffer);

        char op[16];
        int v1 = 0, v2 = 0;
        if (sscanf(buffer, "%15s %d %d", op, &v1, &v2) != 3) {
            fprintf(stderr, "ERROR: MALFORMED ASSIGNMENT\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }

        int result = 0;
        if (compute(op, v1, v2, &result) != 0) {
            fprintf(stderr, "ERROR: UNKNOWN OPERATION %s\n", op);
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        DBG("Calculated the result to %d\n", result);

        char answer[32];
        snprintf(answer, sizeof(answer), "%d\n", result);

        char verdict[256];
        ssize_t m = udp_send_recv(sock, answer, strlen(answer), verdict, sizeof(verdict) - 1);
        if (m <= 0) {
            fprintf(stderr, "ERROR: MESSAGE LOST (TIMEOUT)\n");
            close(sock); freeaddrinfo(res);
            return RESULT_TRANSPORT_FAILED;
        }
        verdict[m] = '\0';
        strip_eol(verdict);

        printf("%s (myresult=%d)\n", verdict, result);

        close(sock); freeaddrinfo(res);
        return RESULT_SUCCESS;
    }
}
