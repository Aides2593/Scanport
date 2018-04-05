#undef _WINSOCKAPI_
#define _WINSOCKAPI_

#include "Log.h"
#include <string.h>
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment (lib, "WS2_32.lib")

#define NUMBER_OF_PORT 65535
#define MAX_THREAD 5
#define TIME_OUT 3000
#define MAX_DATAGRAM 4096
#define SOURCE_PORT 12345

struct iphdr
{
	unsigned char  ip_ver : 4;
	unsigned char  ip_len: 4;        // 4-bit IPv4 version 4-bit header length (in 32-bit words)
	unsigned char  ip_tos;           // IP type of service
	unsigned short ip_totallength;   // Total length
	unsigned short ip_id;            // Unique identifier
	unsigned short ip_offset;        // Fragment offset field
	unsigned char  ip_ttl;           // Time to live
	unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
	unsigned short ip_checksum;      // IP checksum
	unsigned int   ip_srcaddr;       // Source address
	unsigned int   ip_destaddr;      // Source address

};

struct tcphdr
{
	unsigned short source_port;   // source port
	unsigned short dest_port;     // destination port
	unsigned int sequence;        // sequence number - 32 bits
	unsigned int acknowledge;     // acknowledgement number - 32 bits

	unsigned char ns : 1;          //Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; //according to rfc
	unsigned char data_offset : 4;    /*The number of 32-bit words
									  in the TCP header.
									  This indicates where the data begins.
									  The length of the TCP header
									  is always a multiple
									  of 32 bits.*/

	unsigned char fin : 1; //Finish Flag
	unsigned char syn : 1; //Synchronise Flag
	unsigned char rst : 1; //Reset Flag
	unsigned char psh : 1; //Push Flag
	unsigned char ack : 1; //Acknowledgement Flag
	unsigned char urg : 1; //Urgent Flag

	unsigned char ecn : 1; //ECN-Echo Flag
	unsigned char cwr : 1; //Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window; // window
	unsigned short checksum; // checksum
	unsigned short urgent_pointer; // urgent pointer
};

struct tmp_header
{
	unsigned int source_addr;
	unsigned int dest_addr;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_len;

	struct tcphdr tcp;
};

void scan_ip(CHAR ip[], int, int);
unsigned short checksum(unsigned short *ptr, int nbytes);
DWORD WINAPI sniffer(LPVOID param);
void process_packet(char* buffer, int size, char dest_ip[]);