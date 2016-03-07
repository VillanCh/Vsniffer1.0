#ifndef __DEVICEOP_H__
#define __DEVICEOP_H__
#include "stdafx.h"
#include "winpcap_basic.h"
using namespace std;
class DeviceOp
{
public:
	DeviceOp(){};
	~DeviceOp(){};


public :
	map<int, char*> mapdevs;
//	int devs_count = mapdevs.count;
	pcap_if_t *alldevs;
	int dev_num = 0;
	CString showDevices();
//	pcap_if_t* getDevByID(int id);
//	void showDeviceById(int i);
	void freeDevs();
};
#endif
