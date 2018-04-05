#undef _WINSOCKAPI_
#define _WINSOCKAPI_
#include <Windows.h>
#include <WinSock2.h>
#include <iphlpapi.h>
#define HAVE_REMOTE
#include "pcap.h"
#include "Log.h"
#pragma comment (lib, "WS2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib,"wpcap.lib")

#define MAX_DUMP 0
#define SOURCE_PORT 59712
#define MAX_PORT    65535
#define MAX_TIMEOUT	10000
//Ethernet Header
typedef struct ethernet_header
{
	UCHAR dest[6]; //Total 48 bits
	UCHAR source[6]; //Total 48 bits
	USHORT type; //16 bits
}   ETHER_HDR, *PETHER_HDR, FAR * LPETHER_HDR, ETHERHeader;

//IP Header
typedef struct ip_hdr
{
	unsigned char  ip_header_len : 4;  // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char  ip_version : 4;  // 4-bit IPv4 version
	unsigned char  ip_tos;           // IP type of service
	unsigned short ip_total_length;  // Total length
	unsigned short ip_id;            // Unique identifier 

	unsigned char  ip_frag_offset : 5;        // Fragment offset field

	unsigned char  ip_more_fragment : 1;
	unsigned char  ip_dont_fragment : 1;
	unsigned char  ip_reserved_zero : 1;

	unsigned char  ip_frag_offset1;    //fragment offset

	unsigned char  ip_ttl;           // Time to live
	unsigned char  ip_protocol;      // Protocol(TCP,UDP etc)
	unsigned short ip_checksum;      // IP checksum
	unsigned int   ip_srcaddr;       // Source address
	unsigned int   ip_destaddr;      // Source address
}   IPV4_HDR, *PIPV4_HDR, FAR * LPIPV4_HDR, IPHeader;

// TCP header
typedef struct tcp_header
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
} TCP_HDR, *PTCP_HDR, FAR * LPTCP_HDR, TCPHeader, TCP_HEADER;

//PSEUDO_HEADER
typedef struct pseudo_header    //needed for checksum calculation
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	//char tcp[28];
	TCP_HDR tcp;
}   P_HDR, PSEUDO_HDR, PSEUDO_HEADER;

typedef struct input_param
{
	char localip[20];
	char destip[20];
	unsigned char local_mac[10];
	unsigned char dest_mac[10];
	pcap_t *fp;
	int port;
	bool *open_port;
} INPUT_PARAM;
void GetMacAddress(unsigned char *mac, CHAR destip[]);
void GetGateway(char srcip[], char gatewayip[]);
void InitWSA();
bool GetLocalIp(char localip[]);
bool BuildEthernetHeader(PETHER_HDR buffer, unsigned char local_mac[], unsigned char gateway_mac[]);
bool BuildIPHeader(PIPV4_HDR buffer, char srcip[], char destip[], int id);
bool BuildTCPHeader(PTCP_HDR buffer , int desport);
void ifprint(pcap_if_t *d);
unsigned short in_checksum(unsigned short *ptr, int nbytes);
int GetDevice(pcap_if_t * dev, int nod, char * local_ip);