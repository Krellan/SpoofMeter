#include "spoofmeter_common.h"

#include <stdio.h>
#include <fcntl.h>

bool sockets_init() {
#ifdef _WIN32
	WSADATA wsaData;
	uint8_t byHiExp = 2;
	uint8_t byLoExp = 2;

	// Winsock 2.2 is the standard version number these days
	if (WSAStartup(MAKEWORD(byHiExp, byLoExp), &wsaData) != 0) {
		// Initialization failed
		fprintf(stderr, "Failed to initialize Winsock: %d\n",
			WSAGetLastError()
		);
		
		return false;
	}

	uint8_t byHiRec = HIBYTE(wsaData.wVersion);
	uint8_t byLoRec = LOBYTE(wsaData.wVersion);
	if ((byHiRec != byHiExp) || (byLoRec != byLoExp)) {
		fprintf(stderr, "Winsock incompatible! Version expected %u.%u received %u.%u\n",
			(unsigned int)byHiExp, (unsigned int)byLoExp,
			(unsigned int)byHiRec, (unsigned int)byLoRec
		);
		
		return false;
	}

	printf("Winsock initialized: version %u.%u\n",
		(unsigned int)byHiRec, (unsigned int)byLoRec
	);
	
	return true;
#else
	// As Linux is more reliable than Windows, network initialization will always succeed
	return true;
#endif
}

void sockets_cleanup() {
#ifdef _WIN32
	WSACleanup();
#endif
}

void fd_close_ptr(/*INOUT*/ int *pfd) {
	int fd = *pfd;
	
    // If fd is already -1, this function harmlessly does nothing
	if (fd != -1) {

		if (close(fd) != 0) {
            // Just a warning, as we are closing anyway
            // and there is not much we can do about it.
            // This should not normally happen.
            perror("Failed to close file descriptor");
        }

		*pfd = -1;
	}
}

bool fd_become_nonblocking(int fd) {
	int flags;
	
	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		perror("Failed to get file descriptor flags");

		return false;
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		perror("Failed to set file descriptor to non-blocking");

		return false;
	}

	return true;
}

std::string sockaddr_to_string(const struct sockaddr *addr) {
	sa_family_t family = addr->sa_family;
	socklen_t addrlen;

	char hostbuf[NI_MAXHOST + 1];
	char servbuf[NI_MAXSERV + 1];

	switch(family) {
		case AF_INET:
			addrlen = sizeof(struct sockaddr_in);
			break;

		case AF_INET6:
			addrlen = sizeof(struct sockaddr_in6);
			break;
		
		default:
			fprintf(stderr, "Unsupported address family: %d\n", (int)family);

            return std::string();
	}

	int result;
	int flags = NI_NUMERICHOST | NI_NUMERICSERV;

	// Make sure NUL-terminated even at max length
	hostbuf[NI_MAXHOST] = '\0';
	servbuf[NI_MAXSERV] = '\0';

	result = getnameinfo(addr, addrlen, hostbuf, NI_MAXHOST, servbuf, NI_MAXSERV, flags);
	if (result != 0)
	{
		// Compensate for getnameinfo() using its own error namespace above errno
		if (result == EAI_SYSTEM) {
			// Fall through to errno
			perror("Failed getnameinfo");
		} else {
			fprintf(stderr, "Failed getnameinfo: %s\n", gai_strerror(result));
		}

        return std::string();
	}

	switch(family) {
		case AF_INET:
			return std::string(hostbuf) + ":" + std::string(servbuf);

		case AF_INET6:
			return std::string("[") + std::string(hostbuf) + std::string("]:") + std::string(servbuf);

		default:
			break;
	}

	// This was already checked above and should not happen here
	fprintf(stderr, "Unsupported address family: %d\n", (int)family);

    return std::string();
}
