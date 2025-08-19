#ifndef SOCKET_HELPER_H
#define SOCKET_HELPER_H

// Headers common to both Windows and POSIX
#include <string>

// Deal with Windows differences in network header files
#ifdef _WIN32
    // Windows
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #include <errhandlingapi.h>

    #ifndef sa_family_t
        typedef ADDRESS_FAMILY sa_family_t;
    #endif

    typedef SOCKET socket_t;
#else
    // Standard POSIX (Linux, MacOS, etc.)
    #include <sys/types.h>
    #include <sys/socket.h>

    typedef int socket_t;
#endif

// These should be called first and last in your program
// These are no-op on Linux
bool sockets_init();
void sockets_cleanup();

// Windows uses different error handling, can't just use perror()
void socket_error(const std::string& msg);

// Windows requires different closer for sockets, can't just use close()
bool socket_close(socket_t socket);

// If given socket is not already -1, closes it, and sets it to -1
bool socket_close_ptr(/*INOUT*/ socket_t *pSocket);

// Makes a socket become non-blocking
bool socket_become_nonblocking(socket_t socket);

// Makes a socket become reusable (SO_REUSEADDR and SO_REUSEPORT)
bool socket_become_reusable(socket_t socket);

// Makes an IPv6 socket become IPv6-only (SO_V6ONLY)
bool socket_become_v6only(socket_t socket);

// Raw socket helper, sets IP_HDRINCL for both IPv4 and IPv6
bool socket_raw_set_hdrincl(socket_t socket, sa_family_t family);

// Raw socket helper, sets SO_BINDTODEVICE or Windows equivalent
// Takes the interface index, not the device name
bool socket_raw_bind_to_interface(socket_t socket, sa_family_t family, int ifindex);

// Returns true if addresses match
// Port number, and anything else, is ignored
bool sockaddr_addresses_match(const struct sockaddr *a, const struct sockaddr *b);

// Prettyprints a sockaddr (either IPv4 or IPv6) as a human-readable string
// Returns empty string on error
std::string sockaddr_to_string(const struct sockaddr *addr);

// Looks up interface name, and interface number, for given sockaddr
// It matches by address (either IPv4 or IPv6) so sockaddr must be local (not remote)
// Returns empty string (and sets ifindex to -1) on error
std::string sockaddr_to_interface_name(const struct sockaddr *addr, /*OUT*/ int *ifindex);

#endif // SOCKET_HELPER_H
