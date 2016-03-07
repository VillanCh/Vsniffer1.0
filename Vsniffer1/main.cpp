#include "stdlib.h"
#include "stdio.h"
#include "DeviceOp.h"
#include "Dumper.h"
#include "Filter.h"



void main()
{
	DeviceOp ret = DeviceOp();
	ret.showDevices();

	system("pause");

	for (int i = 1; i <= ret.mapdevs.size(); i++)
	{
		printf(" id : %d \n name : %s\n\n" , i , ret.mapdevs[i]);
	}

	system("pause");

	Dumper *dumper = new Dumper(ret.mapdevs[1]);


//	struct type_name name;
//	name.type = TYPE_PORT;
//	name.var = "8080";
//	Filter *filter = new Filter(PR_ANY, DIR_ANY, &name);
	dumper->init();
//	dumper->setFilter(filter);

	dumper->startCapture(false,NULL);
	
	system("pause");
}