#pragma once
#include <windows.h>  
#include <stdlib.h>  
#include <stdio.h>  
//#include "logger.h"
// 定义函数返回值  
typedef ULONG NTSTATUS;
// 宽字节字符串结构定义  
typedef struct _UNICODE_STRING {
	USHORT  Length;
	USHORT  MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
// 对象属性定义  
typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	UNICODE_STRING *ObjectName;
	ULONG Attributes;
	PSECURITY_DESCRIPTOR SecurityDescriptor;
	PSECURITY_QUALITY_OF_SERVICE SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
// 基本信息定义  
typedef struct _DIRECTORY_BASIC_INFORMATION {
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;
// 返回值或状态类型定义  
#define OBJ_CASE_INSENSITIVE    0x00000040L  
#define DIRECTORY_QUERY            (0x0001)  
#define STATUS_SUCCESS            ((NTSTATUS)0x00000000L) // ntsubauth  
#define STATUS_MORE_ENTRIES        ((NTSTATUS)0x00000105L)  
#define STATUS_BUFFER_TOO_SMALL    ((NTSTATUS)0xC0000023L)  
// 初始化对象属性宏定义  
#define InitializeObjectAttributes( p, n, a, r, s ) {(p)->Length = sizeof(OBJECT_ATTRIBUTES);(p)->RootDirectory = r;(p)->Attributes = a;(p)->ObjectName = n; (p)->SecurityDescriptor = s; (p)->SecurityQualityOfService = NULL;}
// 字符串初始化  
typedef VOID(CALLBACK* RTLINITUNICODESTRING)(PUNICODE_STRING, PCWSTR);
RTLINITUNICODESTRING RtlInitUnicodeString;
// 打开对象  
typedef NTSTATUS(WINAPI *ZWOPENDIRECTORYOBJECT)(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes
	);
ZWOPENDIRECTORYOBJECT ZwOpenDirectoryObject;
// 查询对象  
typedef
NTSTATUS
(WINAPI *ZWQUERYDIRECTORYOBJECT)(
IN HANDLE DirectoryHandle,
OUT PVOID Buffer,
IN ULONG BufferLength,
IN BOOLEAN ReturnSingleEntry,
IN BOOLEAN RestartScan,
IN OUT PULONG Context,
OUT PULONG ReturnLength OPTIONAL
);
ZWQUERYDIRECTORYOBJECT ZwQueryDirectoryObject;
// 关闭已经打开的对象  
typedef
NTSTATUS
(WINAPI *ZWCLOSE)(
IN HANDLE Handle
);
ZWCLOSE ZwClose;
int DriverSymbolicSearch()
{
	PDIRECTORY_BASIC_INFORMATION   pBuffer = NULL;
	PDIRECTORY_BASIC_INFORMATION   pBuffer2;
	PDIRECTORY_BASIC_INFORMATION   pBuffer3;
	HMODULE hNtdll = NULL;

	hNtdll = LoadLibrary(L"ntdll.dll");
	if (NULL == hNtdll)
	{
		printf("[~] Load ntdll.dll failed(%ld).\n", GetLastError());
		goto EXIT;
	}
	printf("[~] Load ntdll.dll sucess now get proc.\n");
	RtlInitUnicodeString = (RTLINITUNICODESTRING)GetProcAddress(hNtdll, "RtlInitUnicodeString");
	ZwOpenDirectoryObject = (ZWOPENDIRECTORYOBJECT)GetProcAddress(hNtdll, "ZwOpenDirectoryObject");
	ZwQueryDirectoryObject = (ZWQUERYDIRECTORYOBJECT)GetProcAddress(hNtdll, "ZwQueryDirectoryObject");
	ZwClose = (ZWCLOSE)GetProcAddress(hNtdll, "ZwClose");
	UNICODE_STRING     strDirName;
	OBJECT_ATTRIBUTES  oba;
	NTSTATUS           ntStatus;
	HANDLE             hDirectory;
	HANDLE             testHandle;
	LPCWSTR            lpDeviceName = NULL;
	char               deviceName[100] = "\\\\.\\";
	char               strcatbuffer[100];


	remove("Enum_Driver_log.txt");//删除指定文件
	RtlInitUnicodeString(&strDirName, L"\\Global??");
	InitializeObjectAttributes(&oba, &strDirName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	printf("[~] Open directory object now.\n");
	ntStatus = ZwOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &oba);
	if (ntStatus != STATUS_SUCCESS)
	{
		printf("[-] Open directory object failed(%ld).\n", GetLastError());
		goto EXIT;
	}
	printf("[~] Open directory object success.\n");
	logger_driverscan("Validate Driver maybe not all, please use IDA to search DeviceName second time!");
	ULONG    ulLength = 0x800;    // 2048  
	ULONG    ulContext = 0;
	ULONG    ulRet = 0;
	// 查询目录对象  
	do
	{
		if (pBuffer != NULL)
		{
			free(pBuffer);
		}
		ulLength = ulLength * 2;
		pBuffer = (PDIRECTORY_BASIC_INFORMATION)malloc(ulLength);
		if (NULL == pBuffer)
		{
			printf("[-] Malloc failed(%ld).\n", GetLastError());
			goto EXIT;
		}
		ntStatus = ZwQueryDirectoryObject(hDirectory, pBuffer, ulLength, FALSE, TRUE, &ulContext, &ulRet);
		printf("[!] ZwQueryDirectoryObject out return is %ld.\n", ulRet);
	} while (ntStatus == STATUS_MORE_ENTRIES || ntStatus == STATUS_BUFFER_TOO_SMALL);
	if (STATUS_SUCCESS == ntStatus)
	{
		printf("[!] ZwQueryDirectoryObject success.\n");
		pBuffer2 = pBuffer;
		while ((pBuffer2->ObjectName.Length != 0) && (pBuffer2->ObjectTypeName.Length != 0))
		{
			printf("[!] ObjectName: [%S]---ObjectTypeName: [%S]\n", pBuffer2->ObjectName.Buffer, pBuffer2->ObjectTypeName.Buffer);
			logger_driverscan("ObjectName: [%S]---ObjectTypeName: [%S]", pBuffer2->ObjectName.Buffer, pBuffer2->ObjectTypeName.Buffer);
			pBuffer2++;
		}
		logger_driverscan("\n");
		//测试可用的driver,但不限于,这个还需要配合ida测试
		pBuffer3 = pBuffer;
		while ((pBuffer3->ObjectName.Length != 0) && (pBuffer3->ObjectTypeName.Length != 0))
		{
			memset(deviceName, 0x00, 100);
			memset(strcatbuffer, 0x00, 100);
			WCHAR wsz[100] = { 0 };
			sprintf(deviceName, "\\\\.\\");
			sprintf(strcatbuffer, "%S", pBuffer3->ObjectName.Buffer);
			strncat(deviceName, strcatbuffer,50);
			MultiByteToWideChar(CP_ACP, 0, deviceName, strlen(deviceName) + 1, wsz, sizeof(wsz));
			lpDeviceName = wsz;
			testHandle = CreateFile(lpDeviceName,
				GENERIC_READ | GENERIC_WRITE,					// Open for reading/writing| GENERIC_WRITE
				0,//FILE_SHARE_WRITE,								// Allow Share
				NULL,											// Default security
				OPEN_EXISTING,									// Opens a file or device, only if it exists.
				0,//FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
				NULL);
			if (testHandle == INVALID_HANDLE_VALUE)
			{
				if (GetLastError() == 5)
				{
					printf("[-] %S Access Driver Deny,Please try Administrator...(If you are Administrator, Fuzz failure,try another Driver..\n)",pBuffer3->ObjectName.Buffer);
					logger_driverscan("Validate Driver: %S [But no privilege,check if Administrator, or try another Driver]", pBuffer3->ObjectName.Buffer);
				}
			}
			else if (testHandle != INVALID_HANDLE_VALUE)
			{
				printf("[+] Validate Driver: %S", pBuffer3->ObjectName.Buffer);
				logger_driverscan("Validate Driver: %S", pBuffer3->ObjectName.Buffer);
			}
			CloseHandle(testHandle);
			pBuffer3++;
		}
	}
	else
	{
		printf("[-] ZwQueryDirectoryObject failed(%ld).\n", GetLastError());
	}
EXIT:
	if (pBuffer != NULL)
	{
		free(pBuffer);
	}
	if (hDirectory != NULL)
	{
		ZwClose(hDirectory);
	}
	printf("[!] Scan Completed,check log...");
	return 0;
}