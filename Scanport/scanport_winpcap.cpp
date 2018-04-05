#include "scanport_winpcap.h"

void GetMacAddress(unsigned char *mac, CHAR ip[])
{
	DWORD ret;
	in_addr srcip;
	ULONG MACAddr[2];
	ULONG PhyAddr = 6;

	srcip.s_addr = 0;
	ret = SendARP((IPAddr)inet_addr(ip), (IPAddr)srcip.s_addr, &MACAddr, &PhyAddr);
	if (ret != NO_ERROR)
	{
		Log("clgt");
		return;
	}
	if (PhyAddr)
	{
		BYTE *bMacAddr = (BYTE *)&MACAddr;
		for (int i = 0; i < (int)PhyAddr; ++i)
			mac[i] = (char)bMacAddr[i];
	}
}

void GetGateway(char srcip[], char gatewayip[])
{
	IP_ADAPTER_INFO ip_adapter_info[100];
	PIP_ADAPTER_INFO p;
	ULONG bufferlen = sizeof(ip_adapter_info);
	if (GetAdaptersInfo(ip_adapter_info, &bufferlen) != NO_ERROR)
	{
		Log("Get adapter info fail!");
		return;
	}
	p = ip_adapter_info;
	while (p != NULL)
	{
		if (inet_addr(srcip) == inet_addr(p->IpAddressList.IpAddress.String))
			strcpy(gatewayip, p->GatewayList.IpAddress.String);
		p = p->Next;
	}

}
void InitWSA()
{
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != NO_ERROR)
	{
		Log("Init WSA fail. Error code %d", WSAGetLastError());
		return;
	}
}
bool GetLocalIp(char localip[])
{
	char host_name[MAX_HOSTNAME_LEN];
	hostent *host_entry;
	if (gethostname(host_name, MAX_HOSTNAME_LEN) != NO_ERROR)
	{
		Log("Cannot get host name. EC = %d", WSAGetLastError());
		return false;
	}
	host_entry = gethostbyname(host_name);
	if (host_entry == NULL)
	{
		Log("Cannot gethostbyname. EC = %d", WSAGetLastError());
		return false;
	}
	
	sprintf(localip, "%s", inet_ntoa(*(struct in_addr *)*host_entry->h_addr_list));
	return true;
}
bool BuildEthernetHeader(PETHER_HDR ethernet, unsigned char local_mac[], unsigned char gateway_mac[])
{
	memcpy(ethernet->source, local_mac, 6);
	memcpy(ethernet->dest, gateway_mac, 6);
	ethernet->type = htons(0x0800);
	return true;
}
bool BuildIPHeader(PIPV4_HDR iphdr, char srcip[], char destip[], int id)
{
	iphdr->ip_version = 4;
	iphdr->ip_header_len = 5;
	iphdr->ip_tos = 0;
	iphdr->ip_total_length = htons(sizeof(IPV4_HDR) +sizeof(TCP_HDR) + MAX_DUMP);
	iphdr->ip_id = htons(id);
	iphdr->ip_frag_offset = 0;
	iphdr->ip_reserved_zero = 0;
	iphdr->ip_dont_fragment = 1;
	iphdr->ip_more_fragment = 0;
	iphdr->ip_frag_offset1 = 0;
	iphdr->ip_ttl = 40;
	iphdr->ip_protocol = 6;
	iphdr->ip_srcaddr = inet_addr(srcip);
	iphdr->ip_destaddr = inet_addr(destip);
	iphdr->ip_checksum = 0;
	iphdr->ip_checksum = in_checksum((unsigned short*)iphdr, sizeof(IPV4_HDR));
	return true;
}

bool BuildTCPHeader(PTCP_HDR tcphdr, int desport)
{
	tcphdr->source_port = htons(SOURCE_PORT);
	tcphdr->dest_port = htons(desport);
	tcphdr->sequence = 0;
	tcphdr->acknowledge = 0;
	tcphdr->reserved_part1 = 0;
	tcphdr->data_offset = 5;
	tcphdr->fin = 0;
	tcphdr->syn = 1;
	tcphdr->rst = 0;
	tcphdr->psh = 0;
	tcphdr->ack = 0;
	tcphdr->urg = 0;
	tcphdr->ecn = 0;
	tcphdr->cwr = 0;
	tcphdr->window = htons(8196);
	tcphdr->checksum = 0;
	tcphdr->urgent_pointer = 0;
	return true;
}
void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;

	printf("%s\n", d->name);	//Name

	if (d->description)
	{
		printf("Description: %s\n", d->description);	//Description
	}

	// Loopback Address
	printf("Loopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "Yes" : "No");

	for (a = d->addresses; a; a = a->next)	//Now print the IP addresses etc of each device
	{
		printf("Address Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("Address Family Name: AF_INET\n");

			if (a->addr)
			{
				printf("Address: %s\n", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
			}

			if (a->netmask)
			{
				//If a valid netmask has been detected
				printf("Netmask: %s\n", inet_ntoa(((struct sockaddr_in *)a->netmask)->sin_addr));
			}

			if (a->broadaddr)
			{
				//If a valid Broadcast Address is detected
				printf("Broadcast Address: %s\n", inet_ntoa(((struct sockaddr_in *)a->broadaddr)->sin_addr));
			}

			if (a->dstaddr)
			{
				printf("Destination Address: %s\n", inet_ntoa(((struct sockaddr_in *)a->dstaddr)->sin_addr));
			}
			break;

		default:
			printf("Address Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}
unsigned short in_checksum(unsigned short *ptr, int nbytes)
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
	answer = (SHORT)~sum;

	return(answer);
}
int GetDevice(pcap_if_t * dev, int nod, char * localip)
{
	pcap_if_t *tmp;
	unsigned char gmac[10] = { 0, };
	char gatewayip[20];
	for (int i = 1; i < nod; ++i)
	{
		tmp = &dev[i];
		pcap_addr_t *a;
		bool flag = false;
		for (a = tmp->addresses; a; a = a->next)
		{
			if (a->addr->sa_family != AF_INET)
			{
				continue;
			}
			snprintf(localip, 20, "%s", inet_ntoa(((struct sockaddr_in *)a->addr)->sin_addr));
			GetGateway(localip, gatewayip);
			GetMacAddress(gmac, gatewayip);
			printf("%s: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", gatewayip, gmac[0], gmac[1], gmac[2], gmac[3], gmac[4], gmac[5]);
			if (gmac[0] | gmac[1] | gmac[2] | gmac[3] | gmac[4] | gmac[5] != 0)
				return i;
		}
	}
	return 0;
}
