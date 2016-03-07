#ifndef __HANDLE_PKY_H__
#define __HANDLE_PKY_H__
#include "pkt_struct.cpp"

void tcp_protocol_packet_handle(
	u_char *argument,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_content
	) {
	struct tcp_header *tcp_protocol;
	u_short sport;
	u_short dport;
	int header_length;
	u_short windows;
	u_short urgent_pointer;
	u_int sequence;
	u_int acknowledgement;
	u_short checksum;
	u_char flags;

	printf("===========TCP Protocol===========\n");

	tcp_protocol = (struct tcp_header*)(packet_content + 14 + 20);
	sport = ntohs(tcp_protocol->sport);
	dport = ntohs(tcp_protocol->dport);
	header_length = tcp_protocol->offset * 4;
	sequence = ntohl(tcp_protocol->sequence);
	acknowledgement = ntohl(tcp_protocol->ack);
	windows = ntohs(tcp_protocol->windows);
	urgent_pointer = ntohs(tcp_protocol->urgent_pointer);
	flags = tcp_protocol->flags;
	checksum = ntohs(tcp_protocol->checksum);

	fprintf(stdout, "%d0%d%d%c%d", header_length, sport, dport, flags, windows);

	switch (dport) {
	default:
		break;
	}

	if (flags & 0x08) printf("PSH");
	if (flags & 0x10) printf("ACK");
	if (flags & 0x02) printf("SYN");
	if (flags & 0x20) printf("URG");
	if (flags & 0x01) printf("FIN");
	if (flags & 0x04) printf("RST");
	printf("\n");
}

void udp_protocol_packet_handle(
	u_char *argument,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_content
	) {
	struct udp_header* udp_protocol;
	u_short sport;
	u_short dport;
	u_short datalen;

	udp_protocol = (struct udp_header*)(packet_content + 14 + 20);
	sport = ntohs(udp_protocol->sport);
	dport = ntohs(udp_protocol->dport);
	datalen = ntohs(udp_protocol->datalen);

	fprintf(stdout, "0%d%d%d", datalen, sport, dport);
}

void arp_protocol_packet_handle(
	u_char *argument,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_content
	) {
	struct arp_header *arp_protocol;
	u_short protocol_type;
	u_short hardware_type;
	u_short operation_code;
	u_char hardware_length;
	u_char protocol_length;

	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = packet_header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);

	printf("--------   ARP协议    --------\n");
	arp_protocol = (struct arp_header*)(packet_content + 14);
	hardware_type = ntohs(arp_protocol->arp_hardware_type);
	protocol_type = ntohs(arp_protocol->arp_protocol_type);
	operation_code = ntohs(arp_protocol->arp_operation_code);
	hardware_length = arp_protocol->arp_hardware_length;
	protocol_length = arp_protocol->arp_protocol_length;

	fprintf(stdout, "%d%s", protocol_length, timestr);

	switch (operation_code)
	{
	case 1:
		printf("ARP请求协议\n");
		break;
	case 2:
		printf("ARP应答协议\n");
		break;
	case 3:
		printf("RARP请求协议\n");
		break;
	case 4:
		printf("RARP应答协议\n");
		break;
	default:
		break;
	}
}



void icmp_protocol_packet_handle(
	u_char *argument,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_content
	) {
	struct icmp_header *icmp_protocol;
	u_short type;
	u_short datalen;
	u_int init_time;
	u_int recv_time;
	u_int send_time;

	icmp_protocol = (struct icmp_header*)(packet_content + 14 + 20);
	datalen = sizeof(icmp_protocol);
	type = icmp_protocol->type;
	init_time = icmp_protocol->init_time;
	recv_time = icmp_protocol->recv_time;
	send_time = icmp_protocol->send_time;

	fprintf(stdout, "%d%c%d%d%d", datalen, type, init_time, recv_time, send_time);

	  printf("===========ICMP Protocol==========\n");  

	switch (icmp_protocol->type) {
	case 8:
		// 回显请求报文  
		break;
	case 0:
		// 回显应答报文  
		break;
	default:
		break;
	}
}

void ip_protocol_packet_handle(
	u_char *argument,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_content
	) {
	struct ip_header *ip_protocol;
	u_int header_length;
	u_char tos;
	u_short checksum;

	ip_address saddr;
	ip_address daddr;
	u_char ttl;
	u_short tlen;
	u_short identification;
	u_short offset;

	printf("===========IP Protocol===========\n");

	ip_protocol = (struct ip_header*)(packet_content + 14);
	header_length = ip_protocol->header_length * 4;
	checksum = ntohs(ip_protocol->checksum);
	tos = ip_protocol->tos;
	offset = ntohs(ip_protocol->offset);

	saddr = ip_protocol->saddr;
	daddr = ip_protocol->daddr;
	ttl = ip_protocol->ttl;
	identification = ip_protocol->identification;
	tlen = ip_protocol->tlen;
	offset = ip_protocol->offset;

	fprintf(stdout, "%d%d%c%d%d%d", saddr, daddr, ttl, identification, tlen, offset);

	switch (ip_protocol->proto) {
	case 6:
		tcp_protocol_packet_handle(argument, packet_header, packet_content);
		break;
	case 17:
		udp_protocol_packet_handle(argument, packet_header, packet_content);
		break;
	case 1:
		icmp_protocol_packet_handle(argument, packet_header, packet_content);
		break;
	default:
		break;
	}
}


void ethernet_protocol_packet_handle(
	u_char *argument,
	const struct pcap_pkthdr *packet_header,
	const u_char *packet_content
	) {
	u_short ethernet_type;      // 以太网类型  
	struct ether_header *ethernet_protocol;     // 以太网协议变量  
	u_char *mac_string;         // 以太网地址  

	ethernet_protocol = (struct ether_header*)packet_content;       // 获取以太网数据内容  
	printf("Ethernet type is : \n");
	ethernet_type = ntohs(ethernet_protocol->ether_type);    // 获取以太网类型  
	printf("    %04x\n", ethernet_type);



	switch (ethernet_type) {
	case 0x0800:
		printf("The network layer is IP protocol\n");
		break;
	case 0x0806:
		printf("The network layer is ARP protocol\n");
		break;
	default:
		break;
	}

	// 获取以太网源地址  
	//  printf("MAC Source Address is : \n");  
	mac_string = ethernet_protocol->ether_shost;

	
	fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
		);
	
	// 获取以太网目的地址  
	//  printf("MAC Target Address is : \n");  
	mac_string = ethernet_protocol->ether_dhost;
	
	fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x",
		*mac_string,
		*(mac_string + 1),
		*(mac_string + 2),
		*(mac_string + 3),
		*(mac_string + 4),
		*(mac_string + 5)
		);
	
	fprintf(stdout, "%d", sizeof(packet_content));

	switch (ethernet_type) {
	case 0x0800:
		struct ip_header *ip_protocol;
		u_int header_length;
		u_char tos;
		u_short checksum;

		ip_address saddr;
		ip_address daddr;
		u_char ttl;
		u_short tlen;
		u_short identification;
		u_short offset;

		printf("===========IP Protocol===========\n");

		ip_protocol = (struct ip_header*)(packet_content + 14);
		header_length = ip_protocol->header_length * 4;
		checksum = ntohs(ip_protocol->checksum);
		tos = ip_protocol->tos;
		offset = ntohs(ip_protocol->offset);

		saddr = ip_protocol->saddr;
		daddr = ip_protocol->daddr;
		ttl = ip_protocol->ttl;
		identification = ip_protocol->identification;
		tlen = ip_protocol->tlen;
		offset = ip_protocol->offset;

		fprintf(stdout, "%d%d%c%d%d%d", saddr, daddr, ttl, identification, tlen, offset);

		switch (ip_protocol->proto) {
		case 6:
			tcp_protocol_packet_handle(argument, packet_header, packet_content);
			break;
		case 17:
			udp_protocol_packet_handle(argument, packet_header, packet_content);
			break;
		case 1:
			icmp_protocol_packet_handle(argument, packet_header, packet_content);
			break;
		default:
			break;
		}

		break;
	default:
		break;
	}
}

#endif