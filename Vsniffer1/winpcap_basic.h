#ifndef _XKEYCHECK_H
#define _XKEYCHECK_H
#endif

#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif


#ifndef WIN32
#define WIN32
#include "winsock2.h"
#include "winsock.h"
#else

#endif 

//#include <pcap.h>
//#include <winsock2.h>

#define WINVER 0x0501
#define HAVE_REMOTE
#include <ws2tcpip.h>
#include "winpcap/pcap.h"
#include "map"
#include "string"
#include "iostream"
#include <wspiapi.h>//getnameinfo 


#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"packet.lib")