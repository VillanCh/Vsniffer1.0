#ifndef __DUMPER_H__
#define __DUMPER_H__


#ifndef WINPCAP_BASIC
#include "winpcap_basic.h"
#endif

#include "Filter.h"

/* how to open the if ?*/
#define OPEN_ALIVE 1
#define OPEN_OFFLINE 2
#define OPEN_DEAD 3

/* how to store the packet? */
#define OUTPUT_FILE true
#define NOT_OUTPUT_FILE false

class Dumper
{
public :
//	Dumper(){};
	~Dumper(){};
	
	/* 构造器实现 */
	Dumper(char * dev_name);
	Dumper(char * dev_name, bool isPromiscuous);
	Dumper(char * dev_name, bool isPromiscuous, int pkt_len, int read_timeout);
	Dumper(char * dev_name, bool isPromiscucos, int pkt_len, int read_timeout, int open_flag);
	//Dumper(char * dev_name, bool isPromiscucos, int pkt_len, int read_timeout, int open_flag, Filter *filter);
	/* pcap 描述符 */
	pcap_t* fp; 

private:
	/* flag : 一切准备就绪?  */
	bool isAlready = false;
	/* errbuf : 错误缓存 */
	char errbuf[PCAP_ERRBUF_SIZE];

	Filter filter;
private:

public :
	int tcp = 0;
	int udp = 0;
	int icmp = 0;
	int ip = 0;
	int arp = 0;



	/* the basic methods to op the dumper*/
	int init();
	int startCapture(bool outputFile, char *filename);
	int startCapture(bool outputFile, char *filename, Filter *filter);

	/* DO with filter stuff	*/
	int setFilter(Filter *filter);
	int setFilter(Filter *filter, bpf_u_int32 NetMask);
	int setFilter(char* std_syntax);
	int setFilter(char * std_syntax, bpf_u_int32 NetMask);

	int stopCapture();

};


#endif