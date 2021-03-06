#pragma once
#define WIN32

#include "pch.h"
#include<Windows.h>
#include<Iphlpapi.h>
#include<cstdio>


#define HAVE_REMOTE
#pragma comment(lib,"Iphlpapi")
#pragma comment(lib,"WS2_32")
using namespace std;

int main(int argc, char* argv[])
{
	PIP_ADAPTER_INFO pAdapterInfo = NULL;
	ULONG ulLen = 0;
	::GetAdaptersInfo(pAdapterInfo, &ulLen);
	pAdapterInfo = (PIP_ADAPTER_INFO)::malloc(ulLen);
	::GetAdaptersInfo(pAdapterInfo, &ulLen);
	int count = 0;
	while (pAdapterInfo) {
		printf("NIC %d: \n", ++count);
		printf("\tIP: %s; Mask: %s; Gateway: %s\n", pAdapterInfo->IpAddressList.IpAddress.String, pAdapterInfo->IpAddressList.IpMask.String,
			pAdapterInfo->GatewayList.IpAddress.String);
		printf("\tName: %s; Desc: %s\n", pAdapterInfo->AdapterName, pAdapterInfo->Description);
		printf("\tMAC: ");
		for (size_t i = 0; i < pAdapterInfo->AddressLength; i++) {
			printf("%02X", pAdapterInfo->Address[i]);
		}
		printf("\n");
		pAdapterInfo = pAdapterInfo->Next;
	}
	system("pause");
	if (pAdapterInfo) {
		free(pAdapterInfo);
	}




	return 0;
}


