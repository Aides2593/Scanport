//#include "scanport.h"
#include "scanport_winpcap.h"
#include <stdio.h>
bool open_port[MAX_PORT] = { false, };
DWORD WINAPI capture_thread(PVOID param)
{
	INPUT_PARAM ip = *(INPUT_PARAM *)param;

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int res;
	time_t local_tv_sec;
	struct tm ltime;
	char timestr[16];
	PETHER_HDR pehdr;
	PIPV4_HDR	piphdr;
	PTCP_HDR	ptcphdr;
	
	int threshold = sizeof(ETHER_HDR) + sizeof(PIPV4_HDR) + sizeof(TCP_HDR);
	while (res = pcap_next_ex(ip.fp, &header, &pkt_data))
	{
		if (res == 0)
			continue;
		if (res == -1)
			return -1;
		if (header->caplen < threshold)
		{
			printf("capture packet size < threshold");
			continue;
		}
		pehdr = (PETHER_HDR)pkt_data;
		piphdr = (PIPV4_HDR)(pkt_data + sizeof(ETHER_HDR));
		ptcphdr = (PTCP_HDR)(pkt_data + sizeof(ETHER_HDR) + sizeof(IPV4_HDR));
		//printf("Port %d:\n", ptcphdr->source_port);
		if (piphdr->ip_srcaddr == inet_addr(ip.destip) && piphdr->ip_destaddr == inet_addr(ip.localip) && htons(ptcphdr->dest_port) == SOURCE_PORT && ptcphdr->ack == 1 && ptcphdr->rst != 1)
			//printf("Port %d: is open\n", htons(ptcphdr->source_port));
			ip.open_port[htons(ptcphdr->source_port)] = true;
	}
	
}
int main()
{
	pcap_if_t *alldevs, *d, dev[100];
	pcap_t *fp;
	pcap_addr_t *a;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	int count = 1;

	char local_ip[20];
	unsigned char s_mac[10];
	char gatewayip[20];
	unsigned char g_mac[10];
	char packet[65536];
	char dest_ip[] = "107.113.169.17";
	PETHER_HDR pehdr = (PETHER_HDR)packet;
	PIPV4_HDR iphdr = (PIPV4_HDR)(packet + sizeof(ETHER_HDR));
	PTCP_HDR tcphdr = (PTCP_HDR)(packet + sizeof(ETHER_HDR) + sizeof(TCP_HDR));
	P_HDR pseudo_header;
	char *dump = "";


	//init WSA

	if (pcap_findalldevs_ex("rpcap://", NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	printf("Retrieved.\n");

	printf("The following devices found : \n\n");
	for (d = alldevs; d; d = d->next)	//Print the devices
	{
		printf("%d)\n", count);
		dev[count++] = *d;
		ifprint(d);
		
	}
	count = GetDevice(dev, count, local_ip);
	InitWSA();
	printf("Local ip = %s\n", local_ip);
	
	//Get LocalMac
	GetMacAddress(s_mac, local_ip);
	printf("Selected device has mac address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", s_mac[0], s_mac[1], s_mac[2], s_mac[3], s_mac[4], s_mac[5]);

	//Get default gateway ip & mac
	GetGateway(local_ip, gatewayip);
	GetMacAddress(g_mac, dest_ip);
	printf("gateway ip = %s mac address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",gatewayip, g_mac[0], g_mac[1], g_mac[2], g_mac[3], g_mac[4], g_mac[5]);
	if ((fp = pcap_open(dev[count].name,        // name of the device
		65536,						// portion of the packet to capture (only the first 100 bytes)
		PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
		2000,
		NULL, // read timeout
		errbuf						// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", dev[count].name);
		return 1;
	}
	printf("Opened");
	pcap_freealldevs(alldevs);
	BuildEthernetHeader(pehdr, s_mac, g_mac);

	//Create capture thread
	INPUT_PARAM ip;
	strcpy_s(ip.localip, 20, local_ip);
	strcpy_s(ip.destip, 20, dest_ip);
	memcpy_s(ip.local_mac, 10, s_mac, 10);
	memcpy_s(ip.dest_mac, 10, g_mac, 10);
	ip.fp = fp;
	ip.port = SOURCE_PORT;
	ip.open_port = open_port;
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)capture_thread, (LPVOID)&ip, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE)
	{
		printf("Cannot create thread!, error code = ", GetLastError());
		return -1;
	}

	for (int i = 100; i < 140; ++i)
	{
		BuildIPHeader(iphdr, local_ip, dest_ip, i);
		BuildTCPHeader(tcphdr, i);
		char *data;
		data = (char *)(packet + sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR));
		strcpy(data, dump);

		pseudo_header.source_address = inet_addr(local_ip);
		pseudo_header.dest_address = inet_addr(dest_ip);
		pseudo_header.placeholder = 0;
		pseudo_header.protocol = IPPROTO_TCP;
		pseudo_header.tcp_length = htons(sizeof(TCP_HDR) + strlen(dump));
		memcpy(&pseudo_header.tcp, tcphdr, sizeof TCP_HDR);
		unsigned char *seudo;
		seudo = new unsigned char[sizeof P_HDR + strlen(dump)];
		memcpy(seudo, &pseudo_header, sizeof P_HDR);
		memcpy(seudo + sizeof P_HDR, data, strlen(dump));

		tcphdr->checksum = in_checksum((unsigned short*)seudo, sizeof(P_HDR) + strlen(dump));

		//printf("\nSending Packet...");

		//Uncomment this line if you want to flood
		{
			pcap_sendpacket(fp, (u_char * )packet, sizeof(ETHER_HDR) + sizeof(IPV4_HDR) + sizeof(TCP_HDR) + strlen(dump));
			printf("Port %d Test\n", i);
		}
		Sleep(200);
	}
	WaitForSingleObject(hThread, MAX_TIMEOUT);
	TerminateThread(hThread, 0);
	for (int i = 0; i <= MAX_PORT; ++i)
		if (open_port[i])
			printf("port %d open\n", i);
	return 0;
}
