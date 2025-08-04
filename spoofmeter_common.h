#ifndef SPOOFMETER_COMMON_H
#define SPOOFMETER_COMMON_H

// This is the common header file for SpoofMeter,
// shared between both the client and the server.

#include <cstring>
#include <string>

// Deal with Windows differences
#ifdef _WIN32
    // Windows
    #include <winsock2.h>
    #include <ws2tcpip.h>
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

// Exactly 16 bytes in length
#define SPOOFMETER_GREETING "SpoofMeter 1.0\r\n"

// TODO: greeting for each incoming TCP connection
// TODO: echo back for each UDP packet successfully received

// Useful utility functions

// Closes a file descriptor, if not already -1, and sets it to -1
void fd_close_ptr(/*INOUT*/ int *pfd);

// Makes a file descriptor become non-blocking
// Returns true if success, false if error
bool fd_become_nonblocking(int fd);

// Prints a sockaddr (either IPv4 or IPv6) as a human-readable string
// Returns empty string on error
std::string sockaddr_to_string(const struct sockaddr *addr);

#endif // SPOOFMETER_COMMON_H
