#include "spoofmeter_common.h"

#include <stdio.h>

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

int main(int argc, char **argv) {
	return 0;
}
