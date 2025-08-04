// This is the common header file for SpoofMeter,
// shared between both the client and the server.

#ifndef SPOOFMETER_COMMON_H
#define SPOOFMETER_COMMON_H

// Exactly 16 bytes in length
#define SPOOFMETER_GREETING "SpoofMeter 1.0\r\n"

// TODO: greeting for each incoming TCP connection
// TODO: echo back for each UDP packet successfully received

// Useful utility functions

#include <string>
#include <sys/types.h>
#include <sys/socket.h>

// Closes a file descriptor, if not already -1, and sets it to -1
void fd_close_ptr(/*INOUT*/ int *pfd);

// Makes a file descriptor become non-blocking
// Returns true if success, false if error
bool fd_become_nonblocking(int fd);

// Prints a sockaddr (either IPv4 or IPv6) as a human-readable string
// Returns empty string on error
std::string sockaddr_to_string(const struct sockaddr *addr);

#endif // SPOOFMETER_COMMON_H
