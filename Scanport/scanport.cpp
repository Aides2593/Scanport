#include "scanport.h"

unsigned short checksum(unsigned short *ptr, int nbytes)
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes>1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return(answer);
}

void scan_ip(CHAR ip[], int start_port, int end_port)
{
	struct sockaddr_in client;
	SOCKET sock;
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock == INVALID_SOCKET)
	{
		Log("Create socket error!!");
		goto TAIL;
	}
	CHAR datagram[MAX_DATAGRAM];
	struct iphdr *iph = (struct iphdr *)datagram;
	struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(ip));

	struct sockaddr_in dest;
	struct hostent *host_entry;
	CHAR szHostName[255];
	tmp_header tmph;
	dest.sin_addr.s_addr = inet_addr(ip);
	gethostname(szHostName, 255);
	host_entry = gethostbyname(szHostName);
	char *szLocalIP;
	szLocalIP = inet_ntoa(*(struct in_addr *)*host_entry->h_addr_list);

	ZeroMemory(datagram, MAX_DATAGRAM);

	//Fill ip header
	iph->ip_ver = 4;
	iph->ip_len = 5;
	iph->ip_tos = 0;
	iph->ip_totallength = sizeof(struct iphdr) + sizeof(struct tcphdr);
	iph->ip_id = htons(54321);
	iph->ip_offset = htons(16384);
	iph->ip_ttl = 64;
	iph->ip_protocol = IPPROTO_TCP;
	iph->ip_srcaddr = inet_addr(szLocalIP);
	iph->ip_destaddr = inet_addr(ip);
	iph->ip_checksum = 0;
	
	iph->ip_checksum = checksum((unsigned short *)datagram, iph->ip_totallength >> 1);

	//Fill tcp header
	tcph->dest_port = htons(80);
	tcph->source_port = htons(1);
	tcph->sequence = htonl(1105024978);
	tcph->acknowledge = 0;
	tcph->data_offset = sizeof(struct tcphdr);
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(14600);
	tcph->urgent_pointer = 0;

	DWORD one = 1;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char *)&one, sizeof(one)) < 0)
	{
		int ret = WSAGetLastError();
		Log("Setsockopt error");
		goto TAIL;
	}
	DWORD thread_id;
	HANDLE thread_handle = 0;
	//start sniffer thread
	thread_handle = CreateThread(NULL, 0, sniffer, (LPVOID)ip, 0, &thread_id);

	//start scan port
	client.sin_family = AF_INET;
	client.sin_addr.s_addr = inet_addr(ip);
	client.sin_port = htons(50000);
	for (int i = start_port; i <= end_port; ++i)
	{
		tcph->dest_port = htons(i);
		tcph->checksum = 0;
		tmph.source_addr = inet_addr(szLocalIP);
		tmph.dest_addr = inet_addr(ip);
		tmph.protocol = IPPROTO_TCP;
		tmph.tcp_len = htons(sizeof(struct tcphdr));

		memcpy(&tmph.tcp, tcph, sizeof(struct tcphdr));

		if (sendto(sock, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr *)&client, sizeof(client)) == SOCKET_ERROR)
		{
			int ret = WSAGetLastError();
			Log("Sento error");

			goto TAIL;
		}
	}
TAIL:
	closesocket(sock);
	WSACleanup();
	if (!thread_id)
		WaitForSingleObject(thread_handle, INFINITE);
	return;
}

DWORD WINAPI sniffer(LPVOID param)
{
	SOCKET sock_raw;
	char * dest_ip = (char *)param;
	int saddr_size, data_size;
	struct sockaddr saddr;

	char *buffer = (char *)malloc(65536); 

	//Create a raw socket that shall sniff
	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (sock_raw < 0)
	{
		Log("Socket Error\n");
		return 1;
	}

	saddr_size = sizeof saddr;

	while (1)
	{
		//Receive a packet
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);

		if (data_size <0)
		{
			Log("Recvfrom error , failed to get packets\n");
			return 1;
		}

		//Now process the packet
		process_packet(buffer, data_size, dest_ip);
	}

	closesocket(sock_raw);
	return 0;
}

void process_packet(char* buffer, int size, char dest_ip[])
{
	//Get the IP Header part of this packet
	struct iphdr *iph = (struct iphdr*)buffer;
	struct sockaddr_in source, dest;
	unsigned short iphdrlen;

	if (iph->ip_protocol == 6)
	{
		struct iphdr *iph = (struct iphdr *)buffer;
		iphdrlen = iph->ip_len * 4;

		struct tcphdr *tcph = (struct tcphdr*)(buffer + iphdrlen);

		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->ip_srcaddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->ip_destaddr;

		if (tcph->syn == 1 && tcph->ack == 1 && source.sin_addr.s_addr == inet_addr(dest_ip))
		{
			Log("Port %d open \n", ntohs(tcph->source_port));
		}
	}
}