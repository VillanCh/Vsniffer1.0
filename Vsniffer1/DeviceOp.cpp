#include "DeviceOp.h"
#include "stdafx.h"
using namespace std;

char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

CString DeviceOp::showDevices()
{

	CString ret = CString("");
	char tmp[1024];
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE + 1] = {'\0'};

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "error in pcap_findalldevs ! : %s \n" ,errbuf);
	}

	d = alldevs;
	int i = 0;
	while (d != NULL)
	{
		this->dev_num++;
		pcap_addr_t *a;
		++i;
		mapdevs[i] = d->name;
		char ip6str[128];

		/* Name */
		sprintf_s(tmp,"%s\n", d->name);
		//strcat_s(ret, d->name);
		//strcat_s(ret, "\n\tDescription: ");
		ret.Append(CString(tmp));
		/* Description */
		if (d->description){
			sprintf_s(tmp,"\tDescription: %s\n", d->description);
			//strcat_s(ret, d->description);
			//ret.Append(CString(tmp));
		}
		//strcat_s(ret, "\n\rLoopback: ");
		/* Loopback Address*/
		sprintf_s(tmp,"\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
		//strcat_s(ret, (d->flags & PCAP_IF_LOOPBACK) ? "yes\n" : "no\n");
		//ret.Append(CString(tmp));
		/* IP addresses */
		for (a = d->addresses; a; a = a->next) {
			char s[1024];
			sprintf_s(s,"\tAddress Family: #%d\n", a->addr->sa_family);
			//strcat_s(ret,s);
			//ret.Append(CString(s));
			
			switch (a->addr->sa_family)
			{
			case AF_INET:
				sprintf_s(s, "\tAddress Family Name: AF_INET\n"); 
				//strcat_s(ret, s);
				//ret.Append(CString(s));

				if (a->addr){
					sprintf_s(s,"\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
					ret.Append(CString(s));

//					strcat_s(ret, s);
				}
				if (a->netmask){

					sprintf_s(s,"\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
					ret.Append(CString(s));

					//				strcat_s(ret, s);
				}
				if (a->broadaddr){
					sprintf_s(s,"\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
//					strcat_s(ret, s);
					//ret.Append(CString(s));

				}
				if (a->dstaddr){

					sprintf_s(s,"\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
					//strcat_s(ret, s);
					//ret.Append(CString(s));

				}
				break;

			case AF_INET6:
				sprintf_s(s,"\tAddress Family Name: AF_INET6\n");
				//strcat_s(ret, s);
				//ret.Append(CString(s));

#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
				if (a->addr){
					sprintf_s(s,"\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
#endif				//strcat_s(ret,s);
					ret.Append(CString(s));

				}
				break;

			default:
				sprintf_s(s,"\tAddress Family Name: Unknown\n");
				//strcat_s(ret, s);
				//ret.Append(CString(s));

				break;
			}
		}
		printf("\n");
		//strcat_s(ret, "\n");
		//ret.Append(CString("\n"));

		d = d->next;
	}
	return ret;
}

/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf_s(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

#ifndef __MINGW32__ /* Cygnus doesn't have IPv6 */
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}
#endif /* __MINGW32__ */

void DeviceOp::freeDevs()
{
	pcap_freealldevs(alldevs);
}


