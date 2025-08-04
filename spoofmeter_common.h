#ifndef SPOOFMETER_COMMON_H
#define SPOOFMETER_COMMON_H

// This is the common header file for SpoofMeter,
// shared between both the client and the server.

// Exactly 16 bytes in length
#define SPOOFMETER_GREETING "SpoofMeter 1.0\r\n"

// TODO: greeting for each incoming TCP connection
// TODO: echo back for each UDP packet successfully received

// The following are general utilities,
// not necessarily specific to SpoofMeter.

#include <cstring>
#include <string>

// Deal with Windows differences
#ifdef _WIN32
    // Windows
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>

    #ifndef sa_family_t
        typedef ADDRESS_FAMILY sa_family_t;
    #endif
#else
    // POSIX (Linux, macOS, etc.)
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/ip6.h>
    #include <netinet/tcp.h>
    #include <netinet/udp.h>
    #include <arpa/inet.h>
#endif

// Useful utility functions

// These should be called first and last in your program
// These are no-op on Linux
bool sockets_init();
void sockets_cleanup();

// Closes a file descriptor, if not already -1, and sets it to -1
void fd_close_ptr(/*INOUT*/ int *pfd);

// Makes a file descriptor become non-blocking
// Returns true if success, false if error
bool fd_become_nonblocking(int fd);

// Prints a sockaddr (either IPv4 or IPv6) as a human-readable string
// Returns empty string on error
std::string sockaddr_to_string(const struct sockaddr *addr);

#endif // SPOOFMETER_COMMON_H
