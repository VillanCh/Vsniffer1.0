
#include "Filter.h"

/* raw filter */
Filter::Filter(char *str)
{
	strFilter = str;
}

/* simple compare-based filter */
Filter::Filter(struct Filter_compare *ret)
{
	switch (ret->op)
	{
	case 1:
	{
		sprintf_s(strFilter, 8, "less %d", ret->target);
		return;
		//strFilter = "less "
	}

	case 2:
	{
		sprintf_s(strFilter,11, "greater %d", ret->target);
		return;
	}
	default:
	{
		/*
		TBD:
		throw a exception : wrong Filter_compare op (plz use the CALC_LESS or CALC_GREATER)
		*/
		return;
	}
	}
}

/* simple filter_ex */
Filter::Filter(int prefix, int direction, struct proto_name *name)
{
	char* pre;
	char* prproto[PR_NUM] = { "tcp", "udp", "arp", "ftp", "ip", "ip6", "ether" };
	//char* prprototemp[7];
	int temp[PR_NUM] = { 1, 2, 4, 8, 16, 32, 64 };
	int count = 7;
	char *pr = NULL;
	if (prefix != 0){

		for (int i = 0; i < PR_NUM; i++)
		{
			if (!(prefix & temp[i]))
			{
				prproto[i] = NULL;
				count--;
			}
		}

		for (int i = 0, k = 0; i < PR_NUM; i++)
		{
			if (prproto[i] == NULL)
			{
				k++;
				sprintf_s(pr,4, "%s ", prproto[i]);
			}

			if (k == count)
			{
				break;
			}
			else
			{
				sprintf_s(pr,6, "%sor ", pr);
			}
		}
	}
	else
	{
		pr = "";
	}

	char *dir;
	switch (direction)
	{
	case 0:
		dir = "";
		break;
	case 1:
		dir = "src ";
		break;
	case 2:
		dir = "dst ";
		break;
	case 3:
		dir = "";
		break;
	}


	char *body = NULL;
	switch (name->var)
	{
	case 1:
	{
		sprintf_s(body, 7,"%s tcp", name->proto);
		break;
	}
	case 2:
	{
		sprintf_s(body, 7,"%s udp", name->proto);
		break;
	}
	case 3:
	{
		sprintf_s(body,7, "%s arp", name->proto);
		break;
	}
	case 4:
	{
		sprintf_s(body,7, "%s ftp", name->proto);
		break;
	}
	case 5:
	{
		sprintf_s(body,6, "%s ip", name->proto);
		break;
	}
	case 6:
	{
		sprintf_s(body,7, "%s ip6", name->proto);
		break;
	}
	default:
		/*
		TBD
		throw a exception
		*/
		break;
	}


	sprintf_s(strFilter,9, "%s %s %s", pr, dir, body);
}
Filter::Filter(int prefix, int direction, struct type_name *name)
{
	char* pre;
	char* prproto[PR_NUM] = { "tcp", "udp", "arp", "ftp", "ip", "ip6", "ether" };
	//char* prprototemp[7];
	int temp[PR_NUM] = { 1, 2, 4, 8, 16, 32, 64 };
	int count = 7;
	char *pr = NULL;
	if (prefix != 0){

		for (int i = 0; i < PR_NUM; i++)
		{
			if (!(prefix & temp[i]))
			{
				prproto[i] = NULL;
				count--;
			}
		}

		for (int i = 0, k = 0; i < PR_NUM; i++)
		{
			if (prproto[i] == NULL)
			{
				k++;
				sprintf_s(pr,4, "%s ", prproto[i]);
			}

			if (k == count)
			{
				break;
			}
			else
			{
				sprintf_s(pr, 7,"%s or ", pr);
			}
		}
	}
	else
	{
		pr = "";
	}

	char *dir;
	switch (direction)
	{
	case 0:
		dir = "";
		break;
	case 1:
		dir = "src ";
		break;
	case 2:
		dir = "dst ";
		break;
	case 3:
		dir = "";
		break;
	}


	char *body = "";
	switch (name->type)
	{
	case 1:
	{
		sprintf_s(body, 7,"host %s", name->type, name->var);
		break;
	}
	case 2:
	{
		sprintf_s(body,7, "net %s", name->type, name->var);
		break;
	}
	case 4:
	{
//		sprintf_s(body, "port %s", name->var);
		body = "port 8080";
		break;
	}

	default:
		/*
		TBD
		throw a exception
		*/
		break;
	}

	
//	sprintf_s(strFilter, "%s %s %s", pr, dir, body);
	strFilter = "port 8080";
}

char* Filter::getFilterStr()
{
	return strFilter;
}
