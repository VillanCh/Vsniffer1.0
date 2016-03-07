#include "Dumper.h"
#include "pkt_struct.cpp"
#include "Handle_PKY.h"

Dumper::Dumper(char * dev_name)
{
	fp = pcap_open_live(dev_name, 65535, 1, 1000, errbuf);
}
Dumper::Dumper(char * dev_name, bool isPromiscuous)
{
	fp = pcap_open_live(dev_name, 65535, isPromiscuous ? 1 : 0, 1000, errbuf);
}
Dumper::Dumper(char * dev_name, bool isPromiscuous, int pkt_len, int read_timeout)
{
	fp = pcap_open_live(dev_name, pkt_len, isPromiscuous ? 1 : 0, read_timeout, errbuf);
}
Dumper::Dumper(char * dev_name, bool isPromiscuous, int pkt_len, int read_timeout, int open_flag)
{
	switch (open_flag)
	{
	case 1:
		fp = pcap_open_live(dev_name, pkt_len, isPromiscuous ? 1 : 0, read_timeout, errbuf);
		break;
	case 2:
		//TODO with pcap_open_offline

		break;
	case 3:
		/*
		TODO
		with a dead open interface!
		*/
		//fp = pcap_open_dead(dev_name, pkt_len, isPromiscuous ? 1 : 0, read_timeout, errbuf);
		break;
	}
	
	if (fp == NULL)
	{
		//TODO
	}
	
}

/**
Dumper::Dumper(char * dev_name, bool isPromiscucos, int pkt_len, int read_timeout, int open_flag, Filter *filter)
{
	Dumper(dev_name, isPromiscucos, pkt_len, read_timeout, open_flag);
	setFilter(fp, filter);
}
*/


/*
	initial the Dumper if necessary
		TBD ： 
			if you think it has no use , just delete it 
		and at the same time change the flag : isAlready
*/
int Dumper::init()
{
	if (fp == NULL)
	{
		//TODO
		//Throw a exception about that  the fp is NULL , need rebirth the Dumper
		isAlready = false;
		return -1;
	}

	isAlready = true;

	//TODO
}


/* 
	the file filename outputFile : OUTPUT_FILE or NOT_OUTPUT_FILE
	
	decide whether to output to a file
	and set param NULL on filename if you don't want to output to a file;
	start Capturepacket_header
*/
int Dumper::startCapture(bool outputFile, char *filename)
{
	startCapture(outputFile, filename, &filter);
	return 0;
}
/* 
	the file filename outputFile : OUTPUT_FILE or NOT_OUTPUT_FILE

	set a filter and decide if to output to a file 
	then begin !

	plus : it looks like a complex logic , so if you don' t understand enough , don't use the method !
*/
int Dumper::startCapture(bool outputFile, char *filename, Filter *filter)
{
	pcap_dumper_t *dumpfile = NULL;
	pcap_pkthdr* packet_header;
	u_char *packet_content;
	int res = 0;
	

	if (!isAlready)
	{
		//TBD
		//Throw an exception
		return -1;
	}

	if (outputFile)
	{
		char *ofilename = filename;

		if (ofilename != NULL)
		{
			dumpfile = pcap_dump_open(fp, ofilename);

			if (dumpfile == NULL)
			{
				fprintf(stderr, "\nError opening output file\n");

				pcap_close(fp);
				return -5;
			}
		}
	}


	/*
	Attention!!!
		acording to the outputFile
			there will be two while to chose insteading of in the one while block;
	*/
	while ((res = pcap_next_ex(fp, &packet_header, (const u_char **)&packet_content)) >= 0)
	{
		if (!isAlready)
		{
			//TBD
			//Throw an exception
			return -1;
		}
		if (res == 0)
		{
			continue;
		}

		if (outputFile)
		{
			//save the packet on the dump file
			pcap_dump((unsigned char *)dumpfile, packet_header, packet_content);
		}


		//printf(" i ' m working    catching the packets!");
		/*
		TBD:
		how to deal with packets???
			1. do a count with different types of packets 
			2. do a analysis with differen types of packets
		*/

		// 分析数据包  
		//ethernet_protocol_packet_handle(NULL, header, pkt_data);

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
			this->ip++;
			break;
		case 0x0806:
			printf("The network layer is ARP protocol\n");
			this->arp++;
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
				//tcp_protocol_packet_handle(argument, packet_header, packet_content);
				this->tcp++;
				break;
			case 17:
				//udp_protocol_packet_handle(argument, packet_header, packet_content);
				this->udp++;
				break;
			case 1:
				//icmp_protocol_packet_handle(argument, packet_header, packet_content);
				this->icmp++;
				break;
			default:
				break;
			}

			break;
		default:
			break;
		}







		time_t local_tv_sec;
		char timestr[16];
		ip_header *ih;
		struct tm *ltime;
		// 将时间戳转换成可识别的格式  
		local_tv_sec = packet_header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
		ih = (ip_header *)(packet_content + 14); //以太网头部长度  

		// 输出时间和IP信息  
		printf("%s.%.6d len:%d ", timestr, packet_header->ts.tv_usec, packet_header->len);

		printf("%d.%d.%d.%d -> %d.%d.%d.%d\n",
			ih->saddr.byte1,
			ih->saddr.byte2,
			ih->saddr.byte3,
			ih->saddr.byte4,
			ih->daddr.byte1,
			ih->daddr.byte2,
			ih->daddr.byte3,
			ih->daddr.byte4);

	}

}


/* set Filter */
int Dumper::setFilter(Filter *filter)
{
	char * fitSyntax = NULL;

	fitSyntax = filter->getFilterStr();

	setFilter(fitSyntax);

	return 0;
}
int Dumper::setFilter(Filter *filter, bpf_u_int32 NetMask)
{
	/*
	TBD:
	how to compile the Filter class
	and how to set a Filter

	with the two function :
	pcap_compile
	pcap_setfilter
	*/

	char * fitSyntax = NULL;

	fitSyntax = filter->getFilterStr();


	setFilter(fitSyntax, NetMask);

	return 0;
}
int Dumper::setFilter(char * std_syntax)
{
	bpf_u_int32 NetMask_default = 0xffffff;
	setFilter(std_syntax, NetMask_default);
	return 1;
}
int Dumper::setFilter(char * std_syntax, bpf_u_int32 NetMask)
{
	struct bpf_program fcode;

	if (pcap_compile(fp, &fcode, std_syntax, 1, NetMask) < 0)
	{
		fprintf(stderr, "\nError compiling filter: wrong syntax.\n");

		pcap_close(fp);
		return -3;
	}

	//set the filter
	if (pcap_setfilter(fp, &fcode)<0)
	{
		fprintf(stderr, "\nError setting the filter\n");

		pcap_close(fp);
		return -4;
	}
}
