// This is the SpoofMeter client.
// It is designed to talk to a SpoofMeter server.

//   Usage: spoofmeter-client <host> <port>
// Example: spoofmeter-client 127.0.0.1 12345

// Mandatory command line arguments:
// <host>: The host name (or IP address) of the SpoofMeter server
// <port>: The port number (applies to both TCP and UDP) of that server

// Optional command line arguments:
// TODO

// Here's what is done:

// 1) The client will first connect to the SpoofMeter server,
// using TCP, as a normal user (not root),
// to verify existence and reachability of the server.
// The client will then send a UDP packet to the server,
// also as an unprivileged user,
// using the same port number as the TCP connection.
// The server will echo back the contents of the received UDP packet,
// over the established TCP connection,
// allowing the client to verify successful reception of the UDP packet.

// 2) After this is proven, more interesting operation begins.
// Using root privileges, raw UDP packets will be crafted,
// each with a different spoofed source IP address,
// and these will also be sent to the SpoofMeter server.
// The server will echo back these UDP packets similarly, if received,
// over the originally established TCP connection,
// allowing the client to verify which packets were successfully received,
// and which were dropped.

// 3) After a variety of these spoofed UDP packets are sent,
// the client will then analyze the received results,
// and print out the spoofability of the source IP address,
// indicating which bits of the source IP address were successfully spoofed,
// and how reliable this spoofability appears to be.


// TODO: rough implementation details are below here, in comments and pseudocode, and these comments are not intended to be in the final product


// Optional command line arguments:
// TODO: getopt

// TODO: figure out how to open a raw socket
// so I can send raw packets
// on Linux (only) I can use IPV6_HDRINCL
// it is standard for IPv4 so I can use IP_HDRINCL anywhere

// TODO: drop root privs after opening raw sockets
// find the original user name/ID who executed this program, assuming sudo or su was used
// restore that user name/ID
// optional command line argument --user that will specify who to become
// this takes a string or number, if it is a number that is a raw UID number directly
// become that user before continuing program execution
// problem: argument parsing needs to be done first, however,
// argument parsing is the most risky to do as root.
// is there any way we can minimize this? maybe do not have the --user option at all,
// and just hardcode behavior of always returning to original user if possible?

// TODO: connect with either IPv4 or IPv6
// take -4 or -6 arguments
// important if user gives hostname instead of a raw IP address
// as hostname will be ambiguous
// Mandatory options for client include --host and --port
// --host is server hostname or raw IPv4 or IPv6 address
// if hostname we look it up with DNS and use the first address we get back
// optionally take -4 or -6 arguments to constrain the results to IPv4 only or IPv6 only
// it is an error if no suitable IP address can be found for given hostname
// --port is port number (both TCP and UDP will be used)
// if port is a string then we look it up in that old fashioned /etc/services way
// a port number of 0 is actually acceptable since we are building raw packets anyway
// optional arguments
// --source_port for our UDP packets we will be sending, default is same port number as outbound
// --ttl for our UDP packets we will be sending, default is 255
// --interface to bind to a specific interface, default is empty string which means "any" interface
// interface takes name or number, if numeric then it is a raw interface ID number

// TODO: our startup sequence
// first, client will connect to the server with TCP as a normal user
// once established, and we verify that it is our SpoofMeter server on the other side,
// the client will be receiving a greeting from the server
// that shows the server's point of view of our TCP connection
// including our local (their remote) IP/port, and their local (our remote) IP/port
// at a minimum.
// Exactly "SpoofMeter 1.0\r\n" (16 bytes) will be sent first.
// Client will close connection immediately and exit with error if these 16 bytes no match.

// Then, normal execution begins
// client will send a series of UDP packets to the server.
// These UDP packets are addressed to the
// same destination IP and port, except now it is UDP instead of TCP.
// the server will echo back the received UDP packet,
// including source IP/port and received IP/port again,
// and perhaps anything else useful we can get out of it.
// This echo-back takes place over the TCP connection.
// This allows us to use TCP's built-in reliability features to verify correct
// reception of the UDP packets received.

// change the bits of the source address
// leave other bits unchanged (ports and so on)
// the goal is to see how much of the IP address we can vary and still get through to the server

// the server will echo back the UDP packet, so we can see how it appeared
// and if it was even received at all

// after flipping each bit in the IP address at least once,
// see how many of these packets were successfully echoed back by the server
// indicating correct reception, and which were dropped.
// the first and the last packet in this sequence will be unchanged, honest IP address,
// which should be guaranteed to always get echoed back to us.

// this should take 32 packets back and forth (or 128 if IPv6) to account for each bit in the IP address
// maybe --repeat option from command line (default is 1) to do this multiple times
// all we need is one successful round trip of a bit flipped, to let us know this bit can be flipped
// these bits do not need to be repeated

// after building up a bitmask of bits that we can successfully flip around and still get through,
// randomize these bits, send UDP packets to the server this way, see what gets echoed back
// all of these should get back if consistent
// this gives us our confidence level (from 0% to 100%) of how much of the IP address we can vary and still get through to the server
// special case, if bitmask is all zeroes (no bits were successfully flipped), then we are done, 100% confident.

// the results will then be printed to the output

// the server must be capable of accepting more than one TCP client at a time
// received UDP packets will be echoed back to all of these connected TCP clients
// this implies needing a per-client outbound buffer
// to take into account that some clients may be slower than others
// the server will have a command line option --max_buffer_size to specify how large this buffer can get
// default is 1 MB (just a hardcoded number that I brainstormed)

// the UDP payload of the packets we send to the server:
// 8 bytes 64-bit session ID (randomly generated at client startup)
// 8 bytes 64-bit packet sequence number (starting at 1 and incrementing by 1 for each packet sent)
// this reserves packet sequence number 0 for future use
// should we have a timestamp? feature creep
// byte order in our payload will be big endian (network byte order)

// if UDP payload is 18 bytes, it will equal the minimum Ethernet size of 64 bytes
// 14 bytes Ethernet header (dest MAC, source MAC, EtherType)
// 20 bytes IPv4 header
//  8 bytes UDP header
// 18 bytes UDP payload, this is the size that is changeable
//  4 bytes Ethernet CRC

// I wonder if i could think of something 2-byte just to pad it out to exactly this minimum
// maybe ASCII "SM" for SpoofMeter
// this makes our payload exactly 18 bytes which fits the Ethernet minimum of 64 bytes perfectly

// the random key will be algorithmic and reproducible
// --seed command line argument for random seed
// otherwise we take the timestamp at the start of the run
// simply adding together seconds and subseconds (whatever it is, milli or micro or nano) is good enough
// we print the random seed we used, so user has the opportunity to repeat the run with the same seed if desired
// the RNG will be something simple but fully under our control, so it is reproducible

// in my handcrafted IP packets, the IPv4 IP ID, and the IPv6 flow label,
// will be set to this value: (session_ID XOR sequence_number) then masked off,
// taking lower bits only, to however many bits will fit in the field, 16 if IPv4, 20 if IPv6
// IPv4 fragment allowed bit will always be set to 1 (don't fragment), to conform with IPv6 which has no fragments by design
// all other fragment related fields will be set to 0
// IPv4 TOS and IPv6 traffic class will be set to 0
// IPV6 hop limit is same as TTL

// IP checksum and UDP checksum will be calculated by client and filled in manually
// as we are providing raw IP packets, we can not trust kernel to get it right

// minimize use of libraries, even if it means more code locally
// avoid libpcap and libnet, because although these are good libraries,
// they defeat the point of learning how to do this ourselves.
// and i want my program to compile with no non-already-included-on-system libraries.

// all sockets need to be made nonblocking

// optional command line argument --delay to insert a delay between UDP packets sent out
// default is 0 to enforce no minimum delay (as soon as server echoes it back, we know we can send another)
// optional command line argument --timeout to bound how long we will wait for echoed packets to reply to us before being assumed lost
// default is 1.0 seconds, this might be too fast, maybe make it 2.0 seconds
// each of these take seconds, in decimal, subseconds are perfectly OK here

// send with sendmsg() so we can specify which interface it will be going out of
// using PKTINFO structure
// and we also have to specify the spoofed source IP address here again in the PKTINFO structure just to be sure
// hopefully the kernel will not reject it or override it going outbound
// do this always, as we are spoofing source IP, we don't want kernel routing it out the wrong interface

// TODO: how do we look up which interface will be used, by default, for an outbound packet?
// need to learn this information, so we can default it correctly

// send a clean, unspoofed, UDP packet to the server first
// make sure it comes back
// for each bit in the IP address, 32 if IPv4, 128 if IPv6
// flip that bit, send another UDP packet, see if it comes back
// if it comes back, add it to our successful spoofability bitmask
// once done with all bits, show this bitmask to the user
// if bitmask is all 0, we are done, nothing at all can be spoofed, confidence 100% here special case

// otherwise, for a sequence of 100 packets (configurable),
// randomize the bits in the IP address that are allowed to be spoofed
// all other bits must remain truthful and unchanged
// send these to the server, see how many come back
// this builds up our confidence level, from 0% to 100%, based on how many of these packets came back
// the --count option will specify how many of these packets to send
// a count of 0 is valid and will just skip this step entirely, if user does not want to run it

// print the results to the user
// including the confidence level percentage (unless user skipped this step with --count 0)

// to aid in exactly reproducing a previous run, the random seed used will be printed out
// and that random seed will be used to set the 8-byte session ID that we will be using
// as well as all other randomness decisions we will be making


#include "spoofmeter_common.h"

#include "socket_helper.h"

#include <cstdio>
#include <cstring>

// Additional headers needed on Linux
#ifndef _WIN32
	#include <unistd.h>
	#include <grp.h>
	#include <arpa/inet.h>
	#include <netinet/in.h>
	#include <netinet/ip.h>
	#include <netinet/ip6.h>
#endif


static socket_t raw_ipv4_socket = (socket_t)-1;
static socket_t raw_ipv6_socket = (socket_t)-1;

static socket_t udp_ipv4_socket = (socket_t)-1;
static socket_t udp_ipv6_socket = (socket_t)-1;

static socket_t tcp_socket = (socket_t)-1;

// TODO: these are just for testing
// in real life we will only be using one, selected from lookup, taken from command line
static socket_t tcp_ipv4_socket = (socket_t)-1;
static socket_t tcp_ipv6_socket = (socket_t)-1;

// TODO: global options structure

// TODO: globals structure, instead of individual declarations everywhere

// TODO: stuff learned from sockets

void close_sockets() {
	socket_close_ptr(&tcp_socket);
	socket_close_ptr(&tcp_ipv4_socket);
	socket_close_ptr(&tcp_ipv6_socket);
	socket_close_ptr(&udp_ipv4_socket);
	socket_close_ptr(&udp_ipv6_socket);
	socket_close_ptr(&raw_ipv4_socket);
	socket_close_ptr(&raw_ipv6_socket);
}

// Only the address portion of the remote_addr sockaddr is used
socket_t open_udp_socket(
	sa_family_t family,
	uint16_t local_port,
	uint16_t remote_port,
	const struct sockaddr *remote_addr,
	/*OUT*/ struct sockaddr_storage *out_local_addr,
	/*OUT*/ int *out_ifindex
) {
	socket_t sock;

	// Initialize output parameters
	memset(out_local_addr, 0, sizeof(*out_local_addr));
	*out_ifindex = -1;

	sock = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock == (socket_t)-1) {
		socket_error("Failed to create UDP socket");
		return (socket_t)-1;
	}

	if (!socket_become_nonblocking(sock)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	if (!socket_become_reusable(sock)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	if (family == AF_INET6) {
		if (!socket_become_v6only(sock)) {
			socket_close(sock);
			return (socket_t)-1;
		}
	}

	struct sockaddr *local_ptr = NULL;
	struct sockaddr_in local_ipv4;
	struct sockaddr_in6 local_ipv6;
	socklen_t local_len;

	// Local sockaddr is to the local port on any interface
	if (family == AF_INET) {
		memset(&local_ipv4, 0, sizeof(local_ipv4));

		local_ipv4.sin_family = AF_INET;
		local_ipv4.sin_port = htons(local_port);
		local_ipv4.sin_addr.s_addr = INADDR_ANY;
		
		local_ptr = (struct sockaddr *)&local_ipv4;
		local_len = sizeof(local_ipv4);
	}
	else if (family == AF_INET6) {
		memset(&local_ipv6, 0, sizeof(local_ipv6));
		
		local_ipv6.sin6_family = AF_INET6;
		local_ipv6.sin6_port = htons(local_port);
		local_ipv6.sin6_addr = in6addr_any;
		
		local_ptr = (struct sockaddr *)&local_ipv6;
		local_len = sizeof(local_ipv6);
	}
	else {
		fprintf(stderr, "Unsupported address family: %d\n", (int)family);
		socket_close(sock);
		return (socket_t)-1;
	}

	// Bind the UDP socket to the local port number on all interfaces
	if (bind(sock, local_ptr, local_len) != 0) {
		socket_error("Failed to bind UDP socket");
		socket_close(sock);
		return (socket_t)-1;
	}

	printf("UDP unbound local address: %s\n", sockaddr_to_string(local_ptr).c_str());

	struct sockaddr *remote_ptr = NULL;
	struct sockaddr_in remote_ipv4;
	struct sockaddr_in6 remote_ipv6;
	socklen_t remote_len;

	// Remote sockaddr is to only the given remote address and remote port
	if (family == AF_INET) {
		memset(&remote_ipv4, 0, sizeof(remote_ipv4));
		struct sockaddr_in *cast_ipv4 = (struct sockaddr_in *)remote_addr;

		remote_ipv4.sin_family = AF_INET;
		remote_ipv4.sin_port = htons(remote_port);
		memcpy(&remote_ipv4.sin_addr, &cast_ipv4->sin_addr, sizeof(remote_ipv4.sin_addr));

		remote_ptr = (struct sockaddr *)&remote_ipv4;
		remote_len = sizeof(remote_ipv4);
	}
	else if (family == AF_INET6) {
		memset(&remote_ipv6, 0, sizeof(remote_ipv6));
		struct sockaddr_in6 *cast_ipv6 = (struct sockaddr_in6 *)remote_addr;

		remote_ipv6.sin6_family = AF_INET6;
		remote_ipv6.sin6_port = htons(remote_port);
		memcpy(&remote_ipv6.sin6_addr, &cast_ipv6->sin6_addr, sizeof(remote_ipv6.sin6_addr));

		remote_ptr = (struct sockaddr *)&remote_ipv6;
		remote_len = sizeof(remote_ipv6);
	}
	else {
		fprintf(stderr, "Unsupported address family: %d\n", (int)family);
		socket_close(sock);
		return (socket_t)-1;
	}

	// Connect the UDP socket, which sends nothing on the network,
	// but causes the kernel to look up the route to the remote host.
	if (connect(sock, (struct sockaddr *)remote_ptr, remote_len) != 0) {
		socket_error("Failed to connect UDP socket");
		socket_close(sock);
		return (socket_t)-1;
	}

	printf("UDP remote address: %s\n", sockaddr_to_string((struct sockaddr *)remote_ptr).c_str());

	struct sockaddr_storage lookup_addr;
	socklen_t lookup_len = sizeof(lookup_addr);
	
	memset(&lookup_addr, 0, sizeof(lookup_addr));

	// Get the local IP address the kernel selected for this route
	if (getsockname(sock, (struct sockaddr *)&lookup_addr, &lookup_len) != 0) {
		socket_error("Failed to get local socket name");
		socket_close(sock);
		return (socket_t)-1;
	}
	if (lookup_len != local_len) {
		fprintf(stderr, "Unexpected socket name length: %d\n", (int)lookup_len);
		socket_close(sock);
		return (socket_t)-1;
	}

	printf("UDP bound local address: %s\n", sockaddr_to_string((struct sockaddr *)&lookup_addr).c_str());

	std::string interface_name;
	int interface_index = -1;

	interface_name = sockaddr_to_interface_name((struct sockaddr *)&lookup_addr, &interface_index);
	if (interface_index == -1) {
		fprintf(stderr, "Failed to determine interface name for local IP!\n");
		socket_close(sock);
		return (socket_t)-1;
	}

	printf("UDP bound interface: %s (index %d)\n", interface_name.c_str(), interface_index);

	// Populate out-parameters
	memcpy(out_local_addr, &lookup_addr, sizeof(*out_local_addr));
	*out_ifindex = interface_index;

	return sock;
}

socket_t open_raw_socket(sa_family_t family, int interface_index) {
	socket_t sock;
	
	// Tell the kernel we are attempting to spoof UDP protocol
	sock = socket(family, SOCK_RAW, IPPROTO_UDP);
	if (sock == (socket_t)-1) {
		socket_error("Failed to create raw socket");
		return (socket_t)-1;
	}

	if (!socket_become_nonblocking(sock)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	if (!socket_become_reusable(sock)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	// Linux gives an error if IPV6_V6ONLY used on raw socket
#ifdef _WIN32
	if (family == AF_INET6) {
		if (!socket_become_v6only(sock)) {
			socket_close(sock);
			return (socket_t)-1;
		}
	}
#endif

	if (!socket_raw_set_hdrincl(sock, family)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	if (!socket_raw_bind_to_interface(sock, family, interface_index)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	return sock;
}

// Only the address portion of the remote_addr sockaddr is used
// ### this code is very redundant with open_udp_socket()
// only the connect() call, what's after it needs to diverge
// because connect() will return EAGAIN/EWOULDBLOCK/Ewhatever given we are non-blocking
// ### error out if somehow the UDP and TCP got at a different ifindex, make this comparison in the caller
socket_t open_tcp_socket(
	sa_family_t family,
	uint16_t local_port,
	uint16_t remote_port,
	const struct sockaddr *remote_addr,
	/*OUT*/ struct sockaddr_storage *out_local_addr,
	/*OUT*/ int *out_ifindex
) {
	socket_t sock;

	// Initialize output parameters
	memset(out_local_addr, 0, sizeof(*out_local_addr));
	*out_ifindex = -1;

	// ### this should be the only divergence point between TCP and UDP initially here
	sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (sock == (socket_t)-1) {
		socket_error("Failed to create UDP socket");
		return (socket_t)-1;
	}

	if (!socket_become_nonblocking(sock)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	if (!socket_become_reusable(sock)) {
		socket_close(sock);
		return (socket_t)-1;
	}

	if (family == AF_INET6) {
		if (!socket_become_v6only(sock)) {
			socket_close(sock);
			return (socket_t)-1;
		}
	}

	struct sockaddr *local_ptr = NULL;
	struct sockaddr_in local_ipv4;
	struct sockaddr_in6 local_ipv6;
	socklen_t local_len;

	// Local sockaddr is to the local port on any interface
	if (family == AF_INET) {
		memset(&local_ipv4, 0, sizeof(local_ipv4));

		local_ipv4.sin_family = AF_INET;
		local_ipv4.sin_port = htons(local_port);
		local_ipv4.sin_addr.s_addr = INADDR_ANY;

		local_ptr = (struct sockaddr *)&local_ipv4;
		local_len = sizeof(local_ipv4);
	}
	else if (family == AF_INET6) {
		memset(&local_ipv6, 0, sizeof(local_ipv6));

		local_ipv6.sin6_family = AF_INET6;
		local_ipv6.sin6_port = htons(local_port);
		local_ipv6.sin6_addr = in6addr_any;

		local_ptr = (struct sockaddr *)&local_ipv6;
		local_len = sizeof(local_ipv6);
	}
	else {
		fprintf(stderr, "Unsupported address family: %d\n", (int)family);
		socket_close(sock);
		return (socket_t)-1;
	}

	// ### cosmetic divergence only TCP/UDP
	// Bind the UDP socket to the local port number on all interfaces
	if (bind(sock, local_ptr, local_len) != 0) {
		socket_error("Failed to bind TCP socket");
		socket_close(sock);
		return (socket_t)-1;
	}

	printf("TCP unbound local address: %s\n", sockaddr_to_string(local_ptr).c_str());

	struct sockaddr *remote_ptr = NULL;
	struct sockaddr_in remote_ipv4;
	struct sockaddr_in6 remote_ipv6;
	socklen_t remote_len;

	// Remote sockaddr is to only the given remote address and remote port
	if (family == AF_INET) {
		memset(&remote_ipv4, 0, sizeof(remote_ipv4));
		struct sockaddr_in *cast_ipv4 = (struct sockaddr_in *)remote_addr;

		remote_ipv4.sin_family = AF_INET;
		remote_ipv4.sin_port = htons(remote_port);
		memcpy(&remote_ipv4.sin_addr, &cast_ipv4->sin_addr, sizeof(remote_ipv4.sin_addr));

		remote_ptr = (struct sockaddr *)&remote_ipv4;
		remote_len = sizeof(remote_ipv4);
	}
	else if (family == AF_INET6) {
		memset(&remote_ipv6, 0, sizeof(remote_ipv6));
		struct sockaddr_in6 *cast_ipv6 = (struct sockaddr_in6 *)remote_addr;

		remote_ipv6.sin6_family = AF_INET6;
		remote_ipv6.sin6_port = htons(remote_port);
		memcpy(&remote_ipv6.sin6_addr, &cast_ipv6->sin6_addr, sizeof(remote_ipv6.sin6_addr));

		remote_ptr = (struct sockaddr *)&remote_ipv6;
		remote_len = sizeof(remote_ipv6);
	}
	else {
		fprintf(stderr, "Unsupported address family: %d\n", (int)family);
		socket_close(sock);
		return (socket_t)-1;
	}

	// Connect the UDP socket, which sends nothing on the network,
	// but causes the kernel to look up the route to the remote host.
	// ### True divergence here: treat EAGAIN/EINTR/Ewhatever as OK
	if (connect(sock, (struct sockaddr *)remote_ptr, remote_len) != 0) {
		// Error 115 is OK, that means the connection is in progress
		int err = errno;
		// TODO: look up proper constant and avoid hardcoding this
		if (err != 115) {
			socket_error("Failed to connect TCP socket");
			socket_close(sock);
			return (socket_t)-1;
		}
	}

	// ### TCP will not have this valid until connect() succeeds, most likely
	// split this into a separate function that can be called separately
	printf("TCP remote address: %s\n", sockaddr_to_string((struct sockaddr *)remote_ptr).c_str());

	struct sockaddr_storage lookup_addr;
	socklen_t lookup_len = sizeof(lookup_addr);

	memset(&lookup_addr, 0, sizeof(lookup_addr));

	// Get the local IP address the kernel selected for this route
	if (getsockname(sock, (struct sockaddr *)&lookup_addr, &lookup_len) != 0) {
		socket_error("Failed to get local socket name");
		socket_close(sock);
		return (socket_t)-1;
	}
	if (lookup_len != local_len) {
		fprintf(stderr, "Unexpected socket name length: %d\n", (int)lookup_len);
		socket_close(sock);
		return (socket_t)-1;
	}

	printf("TCP bound local address: %s\n", sockaddr_to_string((struct sockaddr *)&lookup_addr).c_str());

	std::string interface_name;
	int interface_index = -1;

	interface_name = sockaddr_to_interface_name((struct sockaddr *)&lookup_addr, &interface_index);
	if (interface_index == -1) {
		fprintf(stderr, "Failed to determine interface name for local IP!\n");
		socket_close(sock);
		return (socket_t)-1;
	}

	printf("TCP bound interface: %s (index %d)\n", interface_name.c_str(), interface_index);

	// Populate out-parameters
	memcpy(out_local_addr, &lookup_addr, sizeof(*out_local_addr));
	*out_ifindex = interface_index;

	return sock;
}

bool open_client_sockets() {
	// Open raw sockets for IPv4 and IPv6
	// Also open the UDP sockets at the same time

	// UDP sockets are needed to provide cover for the raw sockets,
	// by telling the kernel that these UDP ports really are in use,
	// this is why we need to know the UDP port number first.

	// FUTURE: perhaps accept arguments, in case user wants to use only one of these,
	// but that would require argument processing as root which we are trying to avoid.
	// FUTURE: we might also need SO_BINDTODEVICE before we lose root privs,
	// but that would also require getting the interface name from the command line.
	// TODO: do the privileged setsockopt stuff here also like IP_HDRINCL and IPV6_HDRINCL
	
	// sanitize the options during postprocessing
	// if IPv4 and IPv6 are both disabled, then enable both, as that should be the default

	// actually, as this is the client, only one will ever be opened at a time
	// need to do hostname lookup first to see if it is IPv4 or IPv6
	// and filtering by the options -4 and -6

	int ifindex_ipv4 = -1;
	int ifindex_ipv6 = -1;

	struct in_addr local_ipv4;
	struct in_addr remote_ipv4;

	struct in6_addr local_ipv6;
	struct in6_addr remote_ipv6;

	// TODO: this should be passed in from command line options
	// if testing by connecting to localhost, local and remote port numbers must differ
	uint16_t local_port = 12346;
	uint16_t remote_port = 12345;

	// TODO: these should come from hostname lookup earlier, from command line options
	inet_pton(AF_INET, "127.0.0.1", &remote_ipv4);
	inet_pton(AF_INET6, "::1", &remote_ipv6);
	
	struct sockaddr_in target_ipv4;
	struct sockaddr_in6 target_ipv6;

	struct sockaddr_storage local_ipv4_storage;
	struct sockaddr_storage local_ipv6_storage;

	// Fill in only the desired address, everything else is unused
	memset(&target_ipv4, 0, sizeof(target_ipv4));
	memcpy(&target_ipv4.sin_addr, &remote_ipv4, sizeof(remote_ipv4));

	memset(&target_ipv6, 0, sizeof(target_ipv6));
	memcpy(&target_ipv6.sin6_addr, &remote_ipv6, sizeof(remote_ipv6));

	// TODO: only if IPv4 is enabled in the options

	udp_ipv4_socket = open_udp_socket(AF_INET, local_port, remote_port, (struct sockaddr *)&target_ipv4, &local_ipv4_storage,&ifindex_ipv4);
	if (udp_ipv4_socket == (socket_t)-1) {
		fprintf(stderr, "Failed to open UDP IPv4 socket!\n");
		return false;
	}

	raw_ipv4_socket = open_raw_socket(AF_INET, ifindex_ipv4);
	if (raw_ipv4_socket == (socket_t)-1) {
		fprintf(stderr, "Failed to open raw IPv4 socket!\n");
		return false;
	}

	// TODO: only if IPv6 is enabled in the options

	udp_ipv6_socket = open_udp_socket(AF_INET6, local_port, remote_port, (struct sockaddr *)&target_ipv6, &local_ipv6_storage, &ifindex_ipv6);
	if (udp_ipv6_socket == (socket_t)-1) {
		fprintf(stderr, "Failed to open UDP IPv6 socket!\n");
		return false;
	}
	
	raw_ipv6_socket = open_raw_socket(AF_INET6, ifindex_ipv6);
	if (raw_ipv6_socket == (socket_t)-1) {
		fprintf(stderr, "Failed to open raw IPv6 socket!\n");
		return false;
	}

	// Copy back the obtained local addresses
	if (ifindex_ipv4 != -1) {
		struct sockaddr_in *ipv4_ptr = (struct sockaddr_in *)&local_ipv4_storage;
		char buffer[INET_ADDRSTRLEN + 1];
		memcpy(&local_ipv4, &ipv4_ptr->sin_addr, sizeof(local_ipv4));
		inet_ntop(AF_INET, &local_ipv4, buffer, INET_ADDRSTRLEN);
		buffer[INET_ADDRSTRLEN] = '\0';
		printf("Local address of IPv4 UDP: %s\n", buffer);
	}
	if (ifindex_ipv6 != -1) {
		struct sockaddr_in6 *ipv6_ptr = (struct sockaddr_in6 *)&local_ipv6_storage;
		char buffer[INET6_ADDRSTRLEN + 1];
		memcpy(&local_ipv6, &ipv6_ptr->sin6_addr, sizeof(local_ipv6));
		inet_ntop(AF_INET6, &local_ipv6, buffer, INET6_ADDRSTRLEN);
		buffer[INET6_ADDRSTRLEN] = '\0';
		printf("Local address of IPv6 UDP: %s\n", buffer);
	}

	// TODO: might have to bite the bullet and parse the command line as root
	// this allow us to take --user name (or UID) as target user to run as
	// if --user is numeric then use that for the target GID also
	// this allows us to take --localport (defaults to --port which is mandatory) for UDP
	// and thus bind to privileged local ports as needed
	// this allows us to take --interface name to SO_BINDTODEVICE and force a specific interface
	// the --host is mandatory

	// open UDP ports, both IPv4 and IPv6, locally
	// these will provide cover for the raw sockets
	// by telling the kernel that these UDP ports really are in use
	// this is why we need the UDP port number first

	// if interface name was not explicitly given
	// do the UDP connect() trick to learn the local IP
	// and look up the interface table to and find a local IP match
	// and use that as the device to bind to, if the user did not give --interface
	// error out if not found a local interface name
	// because we need to SO_BINDTODEVICE it
	// otherwise we can not force all future stuff to go out the same interface
	// when we are changing the source IP address!

	// set IP_HDRINCL for both IPv4 and IPv6
	// fill in interface name and sendmsg() with it and PACKETINFO (or whatever that option is called)
	// to ensure all sendings go out the desired interface

	// TODO: --user name has priority if that is given (it can be numeric also)
	// if it is numeric then use it as both UID and GID
	// next priority is SUDO_UID and SUDO_GID
	// both must exist and be numeric and be nonzero
	// next priority is SUDO_USER which is string

	// if --user name (or SUDO_USER) is a string,
	// look that up in passwd and get numeric UID and GID from there
	// error out unless both of these are found and numeric and nonzero

	// TODO: do the 4 operations in that recommended order to drop privs
	// setgroups()
	// setgid()
	// initgroups()
	// setuid()

	// ### call open_tcp_socket() here
	// open two TCP connections for now, just to test
	// one IPv4 and one IPv6
	// this also provides us a neat way to test the multiplexer on the server side of things
	// when done, we will only need to open one per client run

	// ### temporary for testing here only
	int ifindex_tcp_ipv4;
	int ifindex_tcp_ipv6;

	tcp_ipv4_socket = open_tcp_socket(AF_INET, local_port, remote_port, (struct sockaddr *)&target_ipv4, &local_ipv4_storage,&ifindex_tcp_ipv4);
	if (tcp_ipv4_socket == (socket_t)-1) {
		fprintf(stderr, "Failed to open TCP IPv4 socket!\n");
		return false;
	}

	tcp_ipv6_socket = open_tcp_socket(AF_INET6, local_port, remote_port, (struct sockaddr *)&target_ipv6, &local_ipv6_storage, &ifindex_tcp_ipv6);
	if (tcp_ipv6_socket == (socket_t)-1) {
		fprintf(stderr, "Failed to open TCP IPv6 socket!\n");
		return false;
	}

	// Copy back the obtained local addresses
	if (ifindex_tcp_ipv4 != -1) {
		struct sockaddr_in *ipv4_ptr = (struct sockaddr_in *)&local_ipv4_storage;
		char buffer[INET_ADDRSTRLEN + 1];
		memcpy(&local_ipv4, &ipv4_ptr->sin_addr, sizeof(local_ipv4));
		inet_ntop(AF_INET, &local_ipv4, buffer, INET_ADDRSTRLEN);
		buffer[INET_ADDRSTRLEN] = '\0';
		printf("Local address of IPv4 TCP: %s\n", buffer);
	}
	if (ifindex_tcp_ipv6 != -1) {
		struct sockaddr_in6 *ipv6_ptr = (struct sockaddr_in6 *)&local_ipv6_storage;
		char buffer[INET6_ADDRSTRLEN + 1];
		memcpy(&local_ipv6, &ipv6_ptr->sin6_addr, sizeof(local_ipv6));
		inet_ntop(AF_INET6, &local_ipv6, buffer, INET6_ADDRSTRLEN);
		buffer[INET6_ADDRSTRLEN] = '\0';
		printf("Local address of IPv6 TCP: %s\n", buffer);
	}

	// ### this should be an error and not a warning
	if (ifindex_ipv4 != ifindex_tcp_ipv4) {
		printf("Whoa, different ifindex for TCP versus UDP! IPv4 %d %d\n", ifindex_tcp_ipv4, ifindex_ipv4);
	}
	if (ifindex_ipv6 != ifindex_tcp_ipv6) {
		printf("Whoa, different ifindex for TCP versus UDP! IPv6 %d %d\n", ifindex_tcp_ipv6, ifindex_ipv6);
	}

	return true;
}

bool drop_privileges() {
#ifdef _WIN32
	fprintf(stderr, "Dropping privileges not supported on Windows yet!\n");
	return true;
#else
	// TODO: make sure all the special Linux header files are included in the ifdef at top of file
    uid_t effective_uid = geteuid();
	gid_t effective_gid = getegid();
	printf("Current effective UID: %d, GID: %d\n", (int)effective_uid, (int)effective_gid);

	uid_t real_uid = getuid();
	gid_t real_gid = getgid();
	printf("Current real UID: %d, GID: %d\n", (int)real_uid, (int)real_gid);

	// If UID already nonzero, we have no root privileges to drop
	if (effective_uid != 0 && effective_gid != 0)
	{
		// This is successful, not an error, as privs were evidently already dropped
		fprintf(stderr, "Already running as ordinary user, not root!\n");
		return true;
	}

	// Special case for recovering real UID/GID when running under sudo
	if (real_uid == 0) {
		const char *env_sudo_uid = getenv("SUDO_UID");
		if (env_sudo_uid != NULL) {
			real_uid = (uid_t)atoi(env_sudo_uid);
		}
	}
	if (real_gid == 0) {
		const char *env_sudo_gid = getenv("SUDO_GID");
		if (env_sudo_gid != NULL) {
			real_gid = (gid_t)atoi(env_sudo_gid);
		}
	}
	printf("After sudo special case, current real UID: %d, GID: %d\n", (int)real_uid, (int)real_gid);

	// This also catches any errors from atoi() above
	if (real_uid == 0 || real_gid == 0) {
		fprintf(stderr, "Unable to determine original non-root user!\n");
		return false;
	}
	
	// Drop all supplementary groups before changing GID
	if (setgroups(0, NULL) != 0) {
		perror("Failed to drop supplementary groups");
		return false;
	}

	// Change group before changing user, as non-root user no longer has privs to change group
	if (effective_gid != real_gid) {
		if (setgid(real_gid) != 0) {
			perror("Failed to setgid");
			return false;
		}
	}

	// TODO: initgroups() here
	// that requires user name, not just the GID, which we do not have yet

	// Change user, which will drop root privs
	if (effective_uid != real_uid) {
		if (setuid(real_uid) != 0) {
			perror("Failed to setuid");
			return false;
		}
	}

	// By demonstration, verify we no longer have root privileges
    if (setuid(0) != -1) {
        fprintf(stderr, "Still running with root privileges!\n");
		return false;
	}

	printf("Successfully dropped root privileges!\n");
	return true;
#endif
}

void await_tcp_connections(void) {
	// success is indicated by sockets becoming writable
	// not readable, because server might not have sent anything yet
	// ### also check for errors
	// perhaps use getsockopt SOL_SOCKET SO_ERROR to see if connect succeeded
	// or just by demonstration reading our greeting block back

	// ### we need to set TCP_NODELAY when opening TCP sockets
	// and in the server when accepting them also, in addition to nonblocking and so on

	// ### we should make a standard subroutine for setting socket options perhaps
	// then both the client connect, and the server accept, paths could use these
	// the server bind will also need to establish on these as well

	// ### TODO timeout, take the timeout from the command line
	// otherwise what is the point of the extra work to be non-blocking?
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	if (!sockets_init()) {
		fprintf(stderr, "Failed to initialize sockets!\n");
		return 1;
	}

	// This must be done as root
	if (!open_client_sockets()) {
		fprintf(stderr, "Failed to open raw sockets!\n");
		return 2;
	}

	// This should be done ASAP, even before option processing
	if (!drop_privileges()) {
		fprintf(stderr, "Failed to drop root privileges!\n");
		fprintf(stderr, "For safety, this program will not continue as root.\n");
		fprintf(stderr, "Please run as an ordinary user, using sudo or similar wrapper.\n");
		return 3;
	}

	printf("SpoofMeter client all set up!\n");
	printf("Attempting TCP connection....\n");

	await_tcp_connections();

	printf("SpoofMeter client hello world!\n");

	close_sockets();

	sockets_cleanup();

	// TODO: cleanup global variables here
	// any fatal error should return here, not exit, so we get a chance to do cleanup no matter what
	return 0;
}
