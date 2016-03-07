#ifndef __FILTER_H__
#define __FILTER_H__

#include "winpcap_basic.h"
//#include "list"


/*
protocol and struct
*/
#define PROTO_DEFAULT	0
#define PROTO_ANY		0
#define PROTO_TCP		1
#define PROTO_UDP		2
#define PROTO_ARP		4
#define PROTO_FTP		8
#define PROTO_IP		16
#define PROTO_IP6		32
struct proto_name
{
	//don't change the first field
	char *proto = "proto";

	//you can change this
	int var;
};

#define PR_NUM			7
/* prefix proto 1*/
#define PR_DEFAULT		0
#define PR_ANY			0
#define PR_TCP			1
#define PR_UDP			2
#define PR_ARP			4
#define PR_FTP			8

/* prefix proto 2*/
#define PR_IP			16
#define PR_IP6			32
#define PR_ETHER		64


#define TYPE_DEFAULT	1
#define TYPE_HOST		1
#define TYPE_NET		2
#define TYPE_PORT		4

struct type_name
{
	//change this with predefinations
	int type;

	//change this with predefinations
	char *var;
};


#define DIR_DEFAULT		0
#define DIR_SRC			1
#define DIR_DST			2
#define DIR_ANY			0


#define CALC_LESS		1
#define CALC_GREATER	2	
struct Filter_compare
{
	int op;
	int target;
};



class Filter
{
public :
	Filter(){};
	Filter(char *str);
	Filter(int prefix, int direction, struct type_name *name);

	/* Attention : 
		if you use proto_name 
			check it transferred meaning 
	*/
	Filter(int prefix, int direction, struct proto_name *name);
	Filter(struct Filter_compare *ret);

private :
	char* strFilter = NULL;

public:
	char *getFilterStr();
};

#endif