#include "spoofmeter_common.h"

#include <stdio.h>

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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static int raw_ipv4_socket = -1;
static int raw_ipv6_socket = -1;

static int udp_ipv4_socket = -1;
static int udp_ipv6_socket = -1;

static int tcp_socket = -1;

bool open_raw_sockets() {
	// Open raw sockets for IPv4 and IPv6
	// FUTURE: perhaps accept arguments, in case user wants to use only one of these,
	// but that would require argument processing as root which we are trying to avoid.
	// FUTURE: we might also need SO_BINDTODEVICE before we lose root privs,
	// but that would also require getting the interface name from the command line.
	// TODO: do the privileged setsockopt stuff here also like IP_HDRINCL and IPV6_HDRINCL	
	raw_ipv4_socket = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (raw_ipv4_socket < 0) {
		perror("Failed to open raw IPv4 socket");
		return false;
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

	raw_ipv6_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_UDP);
	if (raw_ipv6_socket < 0) {
		perror("Failed to open raw IPv6 socket");
		close(raw_ipv4_socket);
		return false;
	}

	// Open UDP sockets for IPv4 and IPv6
	udp_ipv4_socket = socket(AF_INET, SOCK_DGRAM, 0);
	if (udp_ipv4_socket < 0) {
		perror("Failed to open UDP IPv4 socket");
		close(raw_ipv4_socket);
		close(raw_ipv6_socket);
		return false;
	}

	udp_ipv6_socket = socket(AF_INET6, SOCK_DGRAM, 0);
	if (udp_ipv6_socket < 0) {
		perror("Failed to open UDP IPv6 socket");
		close(raw_ipv4_socket);
		close(raw_ipv6_socket);
		close(udp_ipv4_socket);
		return false;
	}

	// Open TCP socket
	tcp_socket = socket(AF_INET, SOCK_STREAM, 0);
	if (tcp_socket < 0) {
		perror("Failed to open TCP socket");
		close(raw_ipv4_socket);
		close(raw_ipv6_socket);
		close(udp_ipv4_socket);
		close(udp_ipv6_socket);
		return false;
	}

	return true;
}

bool drop_privileges() {
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

	// TODO: setgroups() here

	// Change group before changing user, as non-root user no longer has privs to change group
	if (effective_gid != real_gid) {
		if (setgid(real_gid) != 0) {
			perror("Failed to setgid");
			return false;
		}
	}

	// TODO: initgroups() here

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
}

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	// This should be done ASAP, even before option processing
	if (!drop_privileges()) {
		fprintf(stderr, "Failed to drop root privileges!\n");
		fprintf(stderr, "For safety, this program will not continue as root.\n");
		fprintf(stderr, "Please run as an ordinary user, using sudo or similar wrapper.\n");
		return 1;
	}

	// TODO: cleanup global variables here
	// any fatal error should return here, not exit, so we get a chance to do cleanup no matter what

	printf("SpoofMeter client hello world!\n");
	return 0;
}
