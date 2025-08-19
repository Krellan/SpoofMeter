#include "socket_helper.h"

// Headers common to both Windows and POSIX
#include <fcntl.h>

#include <cstring>

// Additional headers needed only during this internal implementation
#ifdef _WIN32
	// Windows
#else
    // Standard POSIX (Linux, MacOS, etc.)
	#include <netinet/in.h>
	#include <net/if.h>
	#include <netdb.h>
	#include <unistd.h>
	#include <ifaddrs.h>

	#include <cerrno>
#endif

bool sockets_init() {
#ifdef _WIN32
	WSADATA wsaData;
	uint8_t byHiExp = 2;
	uint8_t byLoExp = 2;

	// Winsock 2.2 is the standard version number these days
	if (WSAStartup(MAKEWORD(byHiExp, byLoExp), &wsaData) != 0) {
		// Initialization failed
		socket_error("Winsock failed to initialize");
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
#else
	// As Linux was built on the Internet from day one,
	// and networking was not bolted on as an afterthought,
	// network initialization will always succeed.
	printf("LinuxSock initialized :)\n");
#endif
	return true;
}

void sockets_cleanup() {
#ifdef _WIN32
	WSACleanup();
#endif
}

void socket_error(const std::string& msg) {
#ifdef _WIN32
	DWORD dwCode = (DWORD)WSAGetLastError();

	// If no Winsock error, fall back to general Windows GetLastError()
	if (dwCode == ERROR_SUCCESS) {
		dwCode = GetLastError();
	}

	char *szBuffer = NULL;

	DWORD result = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwCode,
		0,
		(LPSTR)&szBuffer,
		0,
		NULL
	);

	if (szBuffer != NULL && result != 0) {
		fprintf(stderr, "%s: %s (%u)\n",
			msg.c_str(),
			szBuffer,
			(unsigned int)dwCode
		);
	} else {
		fprintf(stderr, "%s: Error (%u)\n",
			msg.c_str(),
			(unsigned int)dwCode
		);
	}

	// Always free the buffer if allocated, even if lookup failed
	if (szBuffer != NULL) {
		LocalFree(szBuffer);
	}
#else
	int code = errno;

	fprintf(stderr, "%s: %s (%u)\n",
		msg.c_str(),
		strerror(code),
		(unsigned int)code
	);
#endif
}

bool socket_close(socket_t socket) {
	int result;

#ifdef _WIN32
	result = closesocket(socket);
#else
	result = close(socket);
#endif

	if (result != 0) {
		// Just a warning, as we are closing anyway
		// and there is not much we can do about it.
		socket_error("Failed to close socket");
		return false;
	}

	return true;
}

bool socket_close_ptr(/*INOUT*/ socket_t *pSocket) {
	socket_t socket = *pSocket;

    // If socket is already -1, harmlessly do nothing successfully
	if (socket == (socket_t)-1) {
		return true;
	}

	bool result = socket_close(socket);

	*pSocket = (socket_t)-1;

	return result;
}

bool socket_become_nonblocking(socket_t fd) {
#ifdef _WIN32
	// Windows uses ioctlsocket() instead of fcntl()
	u_long mode = 1; // 1 = non-blocking, 0 = blocking

	if (ioctlsocket(fd, FIONBIO, &mode) != 0) {
		socket_error("Failed to set socket to non-blocking");
		return false;
	}
#else
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1) {
		socket_error("Failed to get file descriptor flags");
		return false;
	}

	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) == -1) {
		socket_error("Failed to set file descriptor to non-blocking");
		return false;
	}
#endif

	return true;
}

bool socket_become_reusable(socket_t fd) {
	int one = 1;
	socklen_t optlen = sizeof(one);

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&one, optlen) != 0) {
		socket_error("Failed to set SO_REUSEADDR");
		return false;
	}

#ifndef _WIN32
	// SO_REUSEPORT not available and not needed on Windows
	// Windows SO_REUSEADDR is more permissive and already does this too
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (const char *)&one, optlen) != 0) {
		socket_error("Failed to set SO_REUSEPORT");
		return false;
	}
#endif

	return true;
}

bool socket_become_v6only(socket_t fd) {
	int one = 1;
	socklen_t optlen = sizeof(one);

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&one, optlen) != 0) {
		socket_error("Failed to set IPV6_V6ONLY");
		return false;
	}

	return true;
}

bool socket_raw_set_hdrincl(socket_t socket, sa_family_t family) {
	int opt_level;
	int opt_name;

	if (family == AF_INET) {
		opt_level = IPPROTO_IP;
		opt_name = IP_HDRINCL;
	}
	else if (family == AF_INET6) {
		opt_level = IPPROTO_IPV6;
		opt_name = IPV6_HDRINCL;
	}
	else {
		fprintf(stderr, "Unsupported address family for raw socket: %d\n", (int)family);
		return false;
	}

	int one = 1;
	socklen_t len = sizeof(one);

	if (setsockopt(socket, opt_level, opt_name, (const char *)&one, len) == 0) {
		return true;
	}

	socket_error("Failed to set IP_HDRINCL option");
	return false;
}

bool socket_raw_bind_to_interface(socket_t socket, sa_family_t family, int ifindex) {
#ifdef _WIN32
	// Windows takes the interface index, not name,
	// and it is at IP level, not SOL_SOCKET, so it cares what family it is,
	// and it applies only to unicast (which is good enough for us).
	int opt_level;
	int opt_name;

	if (family == AF_INET) {
		opt_level = IPPROTO_IP;
		opt_name = IP_UNICAST_IF;
	}
	else if (family == AF_INET6) {
		opt_level = IPPROTO_IPV6;
		opt_name = IPV6_UNICAST_IF;
	}
	else {
		fprintf(stderr, "Unsupported address family for raw socket: %d\n", (int)family);
		return false;
	}

	// Windows requires the interface index in network byte order,
	// if it is IPv4, but host byte order if it is IPv6!
	u_long ulIfIndex = (u_long)ifindex;
	DWORD dwIfIndex;
	if (family == AF_INET) {
		dwIfIndex = htonl(ulIfIndex);
	} else {
		dwIfIndex = ulIfIndex;
	}
	socklen_t len = sizeof(dwIfIndex);

	if (setsockopt(socket, opt_level, opt_name, (const char *)&dwIfIndex, len) == 0) {
		return true;
	}

	socket_error("Failed to set IP_UNICAST_IF option");
#else
	char namebuf[IF_NAMESIZE + 1];

	// Linux does not require address family in order to bind to device
	(void)family;

	// Linux uses SO_BINDTODEVICE, which takes device name, not index
	if (if_indextoname(ifindex, namebuf) == NULL) {
		socket_error("Failed to look up interface name");
		return false;
	}

	// Ensure NUL-terminated
	namebuf[IF_NAMESIZE] = '\0';

	socklen_t len = strlen(namebuf);

	int result = setsockopt(socket, SOL_SOCKET, SO_BINDTODEVICE, namebuf, len);
	if (result == 0) {
		return true;
	}

	socket_error("Failed to set SO_BINDTODEVICE");
#endif
	return false;
}

bool sockaddr_addresses_match(const struct sockaddr *a, const struct sockaddr *b) {
	if (a == NULL) {
		printf("No match: first address nonexistent\n");
		return false;
	}
	if (b == NULL) {
		printf("No match: second address nonexistent\n");
		return false;
	}

	sa_family_t famA = a->sa_family;
	sa_family_t famB = b->sa_family;

	if (famA != famB) {
		printf("No match on address family: %d != %d\n", (int)famA, (int)famB);
		return false;
	}

	// Compare only the address field, ignore everything else.
	// In particular, there is actually a Linux bug, in getifaddrs(),
	// the port number is filled in with uninitialized garbage.
	if (famA == AF_INET) {
		struct sockaddr_in *addrA = (struct sockaddr_in *)a;
		struct sockaddr_in *addrB = (struct sockaddr_in *)b;
		if (memcmp(&addrA->sin_addr, &addrB->sin_addr, sizeof(struct in_addr)) == 0) {
			printf("Match IPv4: %s == %s\n", sockaddr_to_string(a).c_str(), sockaddr_to_string(b).c_str());
			return true;
		}
	}

	if (famA == AF_INET6) {
		struct sockaddr_in6 *addrA = (struct sockaddr_in6 *)a;
		struct sockaddr_in6 *addrB = (struct sockaddr_in6 *)b;
		if (memcmp(&addrA->sin6_addr, &addrB->sin6_addr, sizeof(struct in6_addr)) == 0) {
			printf("Match IPv6: %s == %s\n", sockaddr_to_string(a).c_str(), sockaddr_to_string(b).c_str());
			return true;
		}
	}

	printf("No match: %s != %s\n", sockaddr_to_string(a).c_str(), sockaddr_to_string(b).c_str());
	return false;
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
#ifdef _WIN32
		socket_error("Failed getnameinfo");
#else
		// Compensate for getnameinfo() using its own error namespace above errno
		if (result != EAI_SYSTEM) {
			fprintf(stderr, "Failed getnameinfo: %s (%u)\n",
				gai_strerror(result),
				(unsigned int)result
			);
		} else {
			// Fall through to errno
			socket_error("Failed getnameinfo");
		}
#endif

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

// Using struct sockaddr so it works for both IPv4 and IPv6
std::string sockaddr_to_interface_name(const struct sockaddr *addr, /*OUT*/ int *ifindex) {
	// Initialize output parameter
	*ifindex = -1;

	sa_family_t family = addr->sa_family;

	if (family != AF_INET && family != AF_INET6) {
		fprintf(stderr, "Unsupported address family: %d\n", (int)family);
		return std::string();
	}

	std::string result;

	printf("Looking up interface of IP address: %s\n", sockaddr_to_string(addr).c_str());
#ifdef _WIN32
	ULONG bufferSize = 0;
	PIP_ADAPTER_ADDRESSES pAdapters = NULL;
	ULONG flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

	// First call to get the required buffer size
	if (GetAdaptersAddresses(family, flags, NULL, pAdapters, &bufferSize) != ERROR_BUFFER_OVERFLOW) {
		socket_error("Failed to query adapter addresses");
		return std::string();
	}

	pAdapters = (PIP_ADAPTER_ADDRESSES)malloc(bufferSize);
	if (pAdapters == NULL) {
		socket_error("Failed to allocate memory");
		return std::string();
	}

	if (GetAdaptersAddresses(family, flags, NULL, pAdapters, &bufferSize) != ERROR_SUCCESS) {
		free(pAdapters);
		socket_error("Failed to get adapter addresses");
		return std::string();
	}

	PIP_ADAPTER_ADDRESSES pIterAdapter = pAdapters;

	// Two layers of linked lists to walk through
	while(pIterAdapter != NULL) {
		PIP_ADAPTER_UNICAST_ADDRESS pIterUnicast = pIterAdapter->FirstUnicastAddress;

		bool match = false;

		// Consider only unicast addresses, as that is what IP_UNICAST_IF wants
		while(pIterUnicast != NULL) {
			struct sockaddr *pIterAddr = pIterUnicast->Address.lpSockaddr;

			if (pIterAddr != NULL) {
				if (sockaddr_addresses_match(addr, pIterAddr)) {
					match = true;
					printf("Match found on adapter %s\n", pIterAdapter->AdapterName);

					break;
				}
			}

			pIterUnicast = pIterUnicast->Next;
		}

		if (match) {
			result = pIterAdapter->AdapterName;

			// This is for IPv4 (and perhaps others)
			IF_INDEX ifIndex = pIterAdapter->IfIndex;

			// IPv6 is in a separate field
			if (family == AF_INET6) {
				IF_INDEX ifIndex_v6 = pIterAdapter->Ipv6IfIndex;

				// Prefer it only if it was correctly filled in
				if (ifIndex_v6 > 0) {
					ifIndex = ifIndex_v6;
				}
			}

			// 0 indicates error here, so if this happens leave output at -1
			if (ifIndex > 0) {
				int nIndex = (int)ifIndex;

				*ifindex = nIndex;
			}

			break;
		}

		pIterAdapter = pIterAdapter->Next;
	}

	free(pAdapters);
#else
	// Linux uses getifaddrs()
	struct ifaddrs *if_list = NULL;
	if (getifaddrs(&if_list) != 0) {
		socket_error("Failed to get interface addresses");
		return std::string();
	}
	if (if_list == NULL) {
		fprintf(stderr, "Failed to get interface addresses!\n");
		return std::string();
	}

	// At this point, we are now responsible for freeing the ifaddrs list
	// Walk through the list
	for(struct ifaddrs *if_iter = if_list; if_iter != NULL; if_iter = if_iter->ifa_next) {
		// Skip over interfaces that have no local address
		if (if_iter->ifa_addr == NULL) {
			continue;
		}

		if (sockaddr_addresses_match(addr, if_iter->ifa_addr)) {
			printf("Match found on interface %s\n", if_iter->ifa_name);
			result = if_iter->ifa_name;

			unsigned int index = if_nametoindex(result.c_str());

			// 0 indicates error here, so if this happens leave output at -1
			if (index > 0) {
				*ifindex = (int)index;
			}

			break;
		}
	}

	freeifaddrs(if_list);
#endif

	printf("IP address %s matched to interface %s (index %d)\n",
		sockaddr_to_string(addr).c_str(),
		result.c_str(),
		*ifindex
	);
	return result;
}
