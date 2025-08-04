#include "spoofmeter_common.h"

// This is the SpoofMeter server.
// It is designed to be talked to by a SpoofMeter client.

//   Usage: spoofmeter-server <port>
// Example: spoofmeter-server 12345

// Mandatory command line arguments:
// <port>: The port number (applies to both TCP and UDP) of this server

// Optional command line arguments:
// TODO

// Unlike the SpoofMeter client, operation is not sequential.
// The SpoofMeter server is stateless, and will remain up indefinitely,
// until manually terminated by the user.

// The given port number will be claimed, for both TCP and UDP.
// The server will accept incoming TCP connections,
// and keep them open for as long as the client remains connected.
// The server will accept incoming UDP packets.
// Each UDP packet successfully received will be echoed back,
// to all currently connected TCP clients.

// This operation all runs as a normal user.
// No root privileges are needed.


// TODO: rough implementation details are below here, in comments and pseudocode, and these comments are not intended to be in the final product


// TODO: figure out how to bind to a given interface
// take this as the --interface argument
// either a number (the interface index ID) or a string is OK here
// default is "" (empty string) to bind to all interfaces by default

// TODO: require only the port number on the command line
// as the --port argument
// we of course want to bind to the "from anybody" address

// open a UDP socket and keep it open
// if both IPv4 and IPv6 are available, open two UDP sockets, one for each
// be sure to make it IPv6 only (set the option to avoid IPv4-mapped addresses)

// whenever we receive UDP packet
// echo the UDP content back down to all currently open TCP sockets
// UDP content will also include a standardized header
// so the client can know how we received it when we received it
// include the protocol we received it on (IPv4 or IPv6) as this will influence the length of subsequent fields in our reply
// reply includes:
// 1 byte protocol (0x04 or 0x06)
// X bytes source IP, 4 if IPv4, 16 if IPv6
// 2 bytes source UDP port
// X bytes destination IP (should be our own IP)
// 2 bytes destination IP port
// 2 bytes payload length
// X bytes payload

// should we have a timestamp? feature creep
// anything else that we can reveal here that might be useful?

// all of this is in network byte order (big endian)

// each TCP socket gets its own buffer in case one is slower than the others
// close the TCP socket forcefully if it is helpless (buffer gets over a certain size)
// this is 1MB, a number I just made up, user config with --max_buffer_size arg

// unlike the client, the server must not run as root
// a warning message should be printed if it is run as root

// one nice thing is that we always have 2 UDP sockets open at all times,
// so even if there are zero TCP clients connected,
// we still have a way to block our event loop, and avoid bug of 100% CPU upon zero connections.

// all sockets need to be made nonblocking, including newly spawned sockets from accept()

static int udp_ipv4_socket = -1;
static int udp_ipv6_socket = -1;

static int tcp_ipv4_listen_socket = -1;
static int tcp_ipv6_listen_socket = -1;

void close_sockets() {
	fd_close_ptr(&udp_ipv4_socket);
	fd_close_ptr(&udp_ipv6_socket);
	fd_close_ptr(&tcp_ipv4_listen_socket);
	fd_close_ptr(&tcp_ipv6_listen_socket);
}

bool socket_become_reusable(int fd) {
	int one = 1;
	socklen_t optlen = sizeof(one);

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, optlen) != 0) {
		perror("Failed to set SO_REUSEADDR");
		return false;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, optlen) != 0) {
		perror("Failed to set SO_REUSEPORT");
		return false;
	}

	return true;
}

bool socket_become_v6only(int fd) {
	int one = 1;
	socklen_t optlen = sizeof(one);

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, optlen) != 0) {
		perror("Failed to set IPV6_V6ONLY");
		return false;
	}

	return true;
}

// All sockets, TCP and UDP, are at the same port number
bool open_sockets(uint16_t port) {
	// Create UDP IPv4 socket
	udp_ipv4_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_ipv4_socket == -1) {
		perror("Failed to create IPv4 UDP socket");
		return false;
	}

	if (!fd_become_nonblocking(udp_ipv4_socket)) {
		return false;
	}
	if (!socket_become_reusable(udp_ipv4_socket)) {
		return false;
	}

	struct sockaddr_in addr_v4;
	memset(&addr_v4, 0, sizeof(addr_v4));
	addr_v4.sin_family = AF_INET;
	addr_v4.sin_port = htons(port);
	addr_v4.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(udp_ipv4_socket, (struct sockaddr *)&addr_v4, sizeof(addr_v4)) != 0) {
		perror("Failed to bind IPv4 UDP socket");
		return false;
	}
	
	// Create UDP IPv6 socket
	udp_ipv6_socket = socket(AF_INET6, SOCK_DGRAM, 0);
	if (udp_ipv6_socket == -1) {
		perror("Failed to create IPv6 UDP socket");
		return false;
	}

	if (!fd_become_nonblocking(udp_ipv6_socket)) {
		return false;
	}
	if (!socket_become_reusable(udp_ipv6_socket)) {
		return false;
	}

	// IPv6 needs V6ONLY because we already have a separate socket for IPv4
	if (!socket_become_v6only(udp_ipv6_socket)) {
		return false;
	}

	struct sockaddr_in6 addr_v6;
	memset(&addr_v6, 0, sizeof(addr_v6));
	addr_v6.sin6_family = AF_INET6;
	addr_v6.sin6_port = htons(port);
	addr_v6.sin6_addr = in6addr_any;

	if (bind(udp_ipv6_socket, (struct sockaddr *)&addr_v6, sizeof(addr_v6)) != 0) {
		perror("Failed to bind IPv6 UDP socket");
		return false;
	}

	// Create TCP IPv4 socket
	tcp_ipv4_listen_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_ipv4_listen_socket < 0) {
		perror("Failed to create IPv4 TCP socket");
		return false;
	}

	if (!fd_become_nonblocking(tcp_ipv4_listen_socket)) {
		return false;
	}
	if (!socket_become_reusable(tcp_ipv4_listen_socket)) {
		return false;
	}

	// TCP socket binds to same port as UDP socket
	if (bind(tcp_ipv4_listen_socket, (struct sockaddr *)&addr_v4, sizeof(addr_v4)) != 0) {
		perror("Failed to bind IPv4 TCP socket");
		return false;
	}

	if (listen(tcp_ipv4_listen_socket, SOMAXCONN) != 0) {
		perror("Failed to listen on IPv4 TCP socket");
		return false;
	}

	// Create TCP IPv6 socket
	tcp_ipv6_listen_socket = socket(AF_INET6, SOCK_STREAM, 0);
	if (tcp_ipv6_listen_socket < 0) {
		perror("Failed to create IPv6 TCP socket");
		return false;
	}

	if (!fd_become_nonblocking(tcp_ipv6_listen_socket)) {
		return false;
	}
	if (!socket_become_reusable(tcp_ipv6_listen_socket)) {
		return false;
	}

	// IPv6 needs V6ONLY because we already have a separate socket for IPv4
	if (!socket_become_v6only(tcp_ipv6_listen_socket)) {
		return false;
	}

	// TCP socket binds to same port as UDP socket
	if (bind(tcp_ipv6_listen_socket, (struct sockaddr *)&addr_v6, sizeof(addr_v6)) != 0) {
		perror("Failed to bind IPv6 TCP socket");
		return false;
	}

	if (listen(tcp_ipv6_listen_socket, SOMAXCONN) != 0) {
		perror("Failed to listen on IPv6 TCP socket");
		return false;
	}

	printf("Successfully bound IPv4: %s\n", sockaddr_to_string((struct sockaddr *)&addr_v4).c_str());
	printf("Successfully bound IPv6: %s\n", sockaddr_to_string((struct sockaddr *)&addr_v6).c_str());

	return true;
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	if (!sockets_init()) {
		fprintf(stderr, "Failed to initialize sockets!\n");
		return 1;
	}

	// TODO: warn if user runs this as root

	// TODO: Get command line arguments

	// port number is mandatory
	// the others are optional
	uint16_t port = 12345; // TODO: replace with actual command line argument

	if (!open_sockets(port)) {
		fprintf(stderr, "Failed to open sockets!\n");
		return 2;
	}

	printf("SpoofMeter server hello world!\n");

	close_sockets();

	sockets_cleanup();
	
	return 0;
}
