// System includes ------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <time.h>
#include <WINDOWS.h>
#include <winioctl.h>
#include <winerror.h>

// Program include ------------------------------------------------------------
#include "getopt.h"
#include "rng.h"
#include "ioctl_manipulation.h"
#include "ihm.h"
#include "utilities.h"
#include "logger.h"
#include "scan.h"
//#include "brute.h" //爆破ioctl codes模块,暂时没想好方法,肯定不会0x00000000-0xffffffff爆破,太慢了,用ioctl type可以,但是unknown部分不好处理

// Parameters -----------------------------------------------------------------
#define MAX_BUFSIZE 0xffff		// Max length for input buffer
#define brute_BUFSIZE 0x1000
#define SLEEP_TIME  10			// Sleep time between each fuzzing attempt
#define INVALID_BUF_ADDR_ATTEMPTS	5 

// Junk data used for fuzzing -------------------------------------------------
CHAR asciiString10[0x10];
CHAR asciiString100[0x100];
CHAR asciiString1000[0x1000];

WCHAR unicodeString10[0x10];
WCHAR unicodeString100[0x100];
WCHAR unicodeString1000[0x1000];

DWORD tableDwords[0x100];

DWORD FuzzRandomSize[] = { 0x00000000, 0x0000003f, 0x1, 0x2, 0x20, 0x3f, 0x40, 0x7f, 0x80, 0xff, 0x3ffff, -1, 0x7fffffff };

DWORD FuzzConstants[] = { 0x00000000, 0x00000001, 0x00000004, 0xFFFFFFFF,
0x00001000, 0xFFFF0000, 0xFFFFFFFE, 0xFFFFFFF0,
0xFFFFFFFC, 0x70000000, 0x7FFEFFFF, 0x7FFFFFFF,
0x80000000,
(DWORD)asciiString10,
(DWORD)asciiString100,
(DWORD)asciiString1000,
(DWORD)unicodeString10,
(DWORD)unicodeString100,
(DWORD)unicodeString1000,
(DWORD)tableDwords };

DWORD invalidAddresses[] = { 0xFFFF0000, 0x00001000 };

BOOL cont;

LPCVOID g_lpInputBuffer;
LPCVOID g_lpFuzzInputBuffer;

// Initialize junk data -------------------------------------------------------
void initializeJunkData() {
	int i;
	memset(asciiString10, 0x41, 0x10);
	memset(asciiString100, 0x41, 0x100);
	memset(asciiString1000, 0x41, 0x1000);

	wmemset(unicodeString10, 0x0041, 0x10);
	wmemset(unicodeString100, 0x0041, 0x100);
	wmemset(unicodeString1000, 0x0041, 0x1000);

	for (i = 0; i<(sizeof(tableDwords) / 4); i++)
		tableDwords[i] = 0xFFFF0000;
	return;
}


// Handler for the CTRL-C signal, used to stop an action without quitting -----
BOOL CtrlHandler(DWORD fdwCtrlType) {
	switch (fdwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
		cont = FALSE;
		return TRUE;
	default:
		return FALSE;
	}
}

// Main function --------------------------------------------------------------
int main(int argc, char *argv[]) {

	int c;
	extern char *optarg;
	char *deviceSymbolicName = NULL;
	char *LogFileName = NULL;//log

	char *singleIoctl = NULL;
	char *rangeIoctl = NULL;
	int singleflg = 0;
	int nullpointerflg = 0;
	int errflg = 0;
	int quietflg = 0;
	int displayerrflg = 0;
	int filteralwaysok = 0;
	int searchflg = 0;
	int loggerflg = 0;
	int bruteioctlflg = 0;

	HANDLE deviceHandle;
	char   deviceName[100] = "\\\\.\\";
	LPCWSTR lpDeviceName;
	DWORD  beginIoctl, endIoctl, currentIoctl;
	DWORD  status, errorCode;
	DWORD  nbBytes = 0;

	pIOCTLlist listIoctls = NULL;
	pIOCTLlist posListIoctls = NULL;
	pIOCTLlist loggerListIoctls = NULL;

	int choice = -1;
	unsigned int i, j;
	int fuzzData;

	BYTE  brutebufInput[0x10000];
	BYTE  brutebufOutput[0x10000];
	BYTE  bufInput[0x10000];
	BYTE  bufOutput[0x10000];
	size_t randomLength;

	//初始化全局变量,扇区对齐,FILE_FLAG_NO_BUFFERING模式
	g_lpInputBuffer = VirtualAllocEx(GetCurrentProcess(), NULL, 512, MEM_COMMIT, PAGE_READWRITE);
	if (g_lpInputBuffer == 0x0)
	{
		printf(" Alloc Virtual address error...\n");
		exit(-1);
	}
	g_lpFuzzInputBuffer = VirtualAllocEx(GetCurrentProcess(), NULL, 0x10000, MEM_COMMIT, PAGE_READWRITE);
	if (g_lpFuzzInputBuffer == 0x0)
	{
		printf(" Alloc Virtual address error...\n");
		exit(-1);
	}

	logger(g_lpInputBuffer, "Driver FuzZer Start!");
	while ((c = getopt(argc, argv, "d:i:r:nsulbqh?ef")) != -1) {
		switch (c) {
		//case 'b':
		//	bruteioctlflg++;
		//	break;
		case 'l'://logger模式,决定是否开启探测和fuzz阶段的日志记录过程,因为文件操作影响fuzz速度,该选项不影响主logger记录过程
			loggerflg++;
			break;
		case 's'://驱动枚举模式
			searchflg++;
			break;
		case 'd'://驱动名称
			deviceSymbolicName = optarg;
			break;
		case 'i'://单独测试ioctl
			if (rangeIoctl)
				errflg++;
			else
				singleIoctl = optarg;
			break;
		case 'r'://范围测试ioctl
			if (singleIoctl)
				errflg++;
			else
				rangeIoctl = optarg;
			break;
		case 'u'://单独测试时请加这个参数
			if (rangeIoctl)
				errflg++;
			singleflg = 1;
			break;
		case 'q'://非debug模式
			quietflg++;
			break;
		case 'e'://打印fuzz时的错误信息
			displayerrflg++;
			break;
		case 'f'://filter模式会测试0x00特殊填充
			filteralwaysok++;
			break;
		case 'n'://测试input inputsize是null的情况
			nullpointerflg++;
			break;
		case 'h'://帮助信息
		case '?':
			errflg++;
		}
	}

	//if ((!searchflg && deviceSymbolicName == NULL) || (rangeIoctl == NULL && singleIoctl == NULL))
	//如果是搜索模式,且没有"?"参数
	if (searchflg && !errflg)
		errflg = 0;
	//else if (bruteioctlflg && !errflg && deviceSymbolicName != NULL)
	//	errflg = 0;
	//否则需要给定驱动设备名称以及ioctl探测范围
	else if (deviceSymbolicName == NULL || (rangeIoctl == NULL && singleIoctl == NULL))
		errflg++;

	if (!errflg) {
		//根据-s标记提前进入驱动枚举模式
		if (searchflg)
		{
			banner();
			logger(g_lpInputBuffer, "\r\nSearch Validate Driver...file Enum_Driver_log.txt...");
			DriverSymbolicSearch();
			exit(-1);
		}
		// IOCTL range mode
		if (rangeIoctl) {
			if (strchr(rangeIoctl, '-') == NULL)
				errflg++;
			else {
				beginIoctl = (DWORD)parseHex(strtok(rangeIoctl, "-"));
				endIoctl = (DWORD)parseHex(strtok(NULL, "-"));
				if (endIoctl < beginIoctl)
					errflg++;
			}
		}
		// Function code + Transfer type (14 lowest bits) bruteforce mode
		else if (singleIoctl && !singleflg) {
			beginIoctl = (DWORD)parseHex(singleIoctl) & 0xffffc000;
			endIoctl = ((DWORD)parseHex(singleIoctl) & 0xffffc000) | 0x00003fff;
		}
		// Single IOCTL mode
		else {
			beginIoctl = (DWORD)parseHex(singleIoctl);
			endIoctl = beginIoctl;
		}
	}

	// Print usage if necessary
	if (errflg)
		usage(argv[0]);


	banner();
	
	// Open handle to the device
	strncat(deviceName, deviceSymbolicName, 90);

	WCHAR wsz[100] = { 0 };
	MultiByteToWideChar(CP_ACP, 0, deviceName, strlen(deviceName) + 1, wsz, sizeof(wsz));
	lpDeviceName = wsz;
	//lpDeviceName = L"\\\\.\\HackSysExtremeVulnerableDriver";
	printf("[~] Open handle to the device %s ...\n", deviceName);
	logger(g_lpInputBuffer,"\r\nOpen device %s", deviceName);
	deviceHandle = CreateFile(lpDeviceName,
		GENERIC_READ | GENERIC_WRITE,					// Open for reading/writing| GENERIC_WRITE
		0,//FILE_SHARE_WRITE,								// Allow Share
		NULL,											// Default security
		OPEN_EXISTING,									// Opens a file or device, only if it exists.
		0,//FILE_FLAG_OVERLAPPED | FILE_ATTRIBUTE_NORMAL,	// Normal file
		NULL);
	if (deviceHandle == INVALID_HANDLE_VALUE) {
		printf("[-] FAILED, error code: %d\n%s\n", GetLastError(),
			errorCode2String(GetLastError()));
		//如果是拒绝打开驱动,可能是由于权限问题,以及驱动本身的主动防御,如果Administrator也拒绝访问的话,可以放弃治疗了
		if (GetLastError() == 5)
		{
			printf("[!] Access Driver Deny,Please try Administrator...(If you are Administrator, Fuzz failure,try another Driver..\n)");
		}
		exit(1);
	}
	printf("OK\n\n");

	//根据-b模式进入爆破ioctl codes模式
	//if (bruteioctlflg)
	//{
	//	banner();
	//	printf("[+] Brute force %s IOCTL codes...file Enum_IOCTL_codes.txt...", deviceName);
	//	logger(g_lpFuzzInputBuffer, "\r\nBrute force %s IOCTL codes...file Enum_IOCTL_codes.txt...",deviceName);
	//	BruteForceIOCTLcodes(deviceHandle, g_lpInputBuffer);
	//	exit(-1);
	//}

	memset(bufInput, 0x00, 0x10000);
	memset(bufOutput, 0x00, 0x10000);
	memset(brutebufInput, 0x41, 0x10000);
	memset(brutebufOutput, 0x41, 0x10000);


	// Print summary	
	printf("  Summary                             	\n");
	printf("  -------								\n");
	printf("  IOCTL scanning mode 	: ");
	if (rangeIoctl)
		printf("Range mode 0x%08x - 0x%08x\n", beginIoctl, endIoctl);
	else if (singleIoctl && singleflg)
		printf("Single mode 0x%08x\n", beginIoctl);
	else
		printf("Function + transfer type bf 0x%08x - 0x%08x\n",
		beginIoctl, endIoctl);
	printf("  Filter mode           : ");
	if (filteralwaysok)
		printf("Filter codes that return true for all buffer sizes\n");
	else
		printf("Filter disabled\n");

	printf("  Symbolic Device Name  : %s\n", deviceName);
	if (singleIoctl)
		printf("  Device Type    	: 0x%08x\n",
		(beginIoctl & 0xffff0000) >> 16);
	printf("  Device handle         : 0x%08x\n", deviceHandle);
	printf("\n");


	//**************** IOCTL code探测部分**********************8
	if (singleIoctl && singleflg)
		printf("[~] Test given IOCTL and determine input size...\n");
	else
		printf("[~] Bruteforce function code + transfer type and determine "
		"input sizes...\n");

	if (filteralwaysok){
		logger(g_lpInputBuffer, "\r\nMode: 0x00 Fill Buffer Testing");
	}
	if (nullpointerflg){
		logger(g_lpInputBuffer, "\r\nMode: Null Pointer");
	}
	else{
		logger(g_lpInputBuffer, "\r\nMode: Normal,Input BufferSize: %d", brute_BUFSIZE);
	}
	
	if (loggerflg)
	{
		printf("[!] Write Detect info in logger_detect...Check it!\n");
		logger(g_lpInputBuffer, "\r\nWrite Detect info in logger.detect...Check it!");
	}
	else{
		printf("[!] No detect logger Mode...If you want log_detect,please add parameter \"-l\"!!!\n");
		logger(g_lpInputBuffer, "\r\nNo detect logger Mode...If you want log_detect,please add parameter \"-l\"!!!");
	}

	i = 0;
	for (currentIoctl = beginIoctl; currentIoctl <= endIoctl; currentIoctl++) {

		logger(g_lpInputBuffer, "\r\nTest on IOCTL_CODE 0x%.08x", currentIoctl);


		if (!singleflg && !displayerrflg && currentIoctl % 0x400 == 0)
			printf(".");

		//-n模式,特殊input,都为null,主要探测null pointer dereference,可能会引发bsod

		if (nullpointerflg)
		{
			if (loggerflg)
			{
				logger_detect(g_lpInputBuffer, "Detect IOCTL CODE: 0x%08x\r\nInput Buff: NULL\r\nInput Buff Size: 0\r\nOutput Buff: NULL\r\nOutput Buff Size: 0", currentIoctl);
			}
			status = DeviceIoControl(deviceHandle,
				currentIoctl,
				NULL,
				0,
				NULL,
				0,
				&nbBytes,
				NULL);
			if (status == 0) {
				errorCode = GetLastError();

				// -- DEBUG
				//if(errorCode != 87)
				if (displayerrflg) {
					printf("0x%08x -> error code %03d - %s\n", currentIoctl,
						errorCode, errorCode2String(errorCode));
				}

				//printf("0x%08x -> code %d\n", currentIoctl, errorCode);
				// errorCode == ERROR_INVALID_FUNCTION || 
				if (errorCode == ERROR_ACCESS_DENIED ||
					errorCode == ERROR_NOT_SUPPORTED)
					continue;
			}
		}

		//常规模式,常规填充
		else{
			if (loggerflg)
			{
				logger_detect(g_lpInputBuffer, "Detect IOCTL CODE: 0x%08x\r\nInput Buff: 0x41 fill buffer\r\nInput Buff Size: %d\r\nOutput Buff: 0x41 fill buffer\r\nOutput Buff Size: %d", currentIoctl, brute_BUFSIZE, brute_BUFSIZE);
			}
			status = DeviceIoControl(deviceHandle,
				currentIoctl,
				&brutebufInput,
				brute_BUFSIZE,
				&brutebufOutput,
				brute_BUFSIZE,
				&nbBytes,
				NULL);
			if (status == 0) {
				errorCode = GetLastError();

				// -- DEBUG
				//if(errorCode != 87)
				if (displayerrflg) {
					printf("0x%08x -> error code %03d - %s\n", currentIoctl,
						errorCode, errorCode2String(errorCode));
				}

				//printf("0x%08x -> code %d\n", currentIoctl, errorCode);
				// errorCode == ERROR_INVALID_FUNCTION || 
				if (errorCode == ERROR_ACCESS_DENIED ||
					errorCode == ERROR_NOT_SUPPORTED)
					continue;
			}
		}

		// filter模式, 0x00填充探测
		if (filteralwaysok) {
			if (loggerflg)
			{
				logger_detect(g_lpInputBuffer, "Detect IOCTL CODE: 0x%08x\r\nInput Buff: 0x00 fill buffer\r\nInput Buff Size: %d\r\nOutput Buff: 0x00 fill buffer\r\nOutput Buff Size: %d", currentIoctl, MAX_BUFSIZE, MAX_BUFSIZE);
			}
			status = DeviceIoControl(deviceHandle,
				currentIoctl,
				&bufInput,
				MAX_BUFSIZE,
				&bufOutput,
				MAX_BUFSIZE,
				&nbBytes,
				NULL);
			if (status != 0) {
				cont = TRUE;
				status = 1;

				for (j = 0; j<MAX_BUFSIZE && status != 0 && cont; j++) {
					if (loggerflg)
					{
						logger_detect(g_lpInputBuffer, "Detect IOCTL CODE: 0x%08x\r\nInput Buff: 0x00 fill buffer\r\nInput Buff Size: %d\r\nOutput Buff: 0x00 fill buffer\r\nOutput Buff Size: %d", currentIoctl, j, j);
					}
					status = DeviceIoControl(deviceHandle,
						currentIoctl,
						&bufInput,
						j,
						&bufOutput,
						j,
						&nbBytes,
						NULL);

					/*
					if(status == 0)
					printf("0x%08x (size %d) -> error code %03d \n", currentIoctl, j, GetLastError());
					else
					printf("0x%08x (size %d) -> status != 0 \n", currentIoctl, j);
					*/

				}
				if (j == 4) {
					//printf("Skip 0x%08x\n", currentIoctl);
					continue;
				}
			}
		}

		//探测buffer size的最大最小值,常规填充
		cont = TRUE;
		//__asm int 3;
		for (j = 0; j<MAX_BUFSIZE && cont; j++) {
			if (loggerflg)
			{
				logger_detect(g_lpInputBuffer, "Detect IOCTL CODE: 0x%08x\r\nInput Buff: 0x41 fill buffer\r\nInput Buff Size: %d\r\nOutput Buff: 0x41 fill buffer\r\nOutput Buff Size: %d", currentIoctl, j, j);
			}
			status = DeviceIoControl(deviceHandle,
				currentIoctl,
				&brutebufInput,
				j,
				&brutebufOutput,
				j,
				&nbBytes,
				NULL);

			if (status != 0) {
				listIoctls = addIoctlList(listIoctls,
					currentIoctl,
					0,
					j,
					MAX_BUFSIZE);
				cont = FALSE;
				i++;
			}
			/*
			else {
			// DEBUG
			if(GetLastError() != 31)
			printf("Size = %04x -> code %d\n", j, GetLastError());
			}
			*/

		}
		if (!cont) {
			cont = TRUE;
			if (loggerflg)
			{
				logger_detect(g_lpInputBuffer, "Detect IOCTL CODE: 0x%08x\r\nInput Buff: 0x41 fill buffer\r\nInput Buff Size: %d\r\nOutput Buff: 0x41 fill buffer\r\nOutput Buff Size: %d", currentIoctl, MAX_BUFSIZE, MAX_BUFSIZE);
			}
			//__asm int 3;
			status = DeviceIoControl(deviceHandle,
				currentIoctl,
				&brutebufInput,
				MAX_BUFSIZE,
				&brutebufOutput,
				MAX_BUFSIZE,
				&nbBytes,
				NULL);
			if (status != 0) {
				listIoctls->maxBufferLength = MAX_BUFSIZE;
				cont = FALSE;
			}

			for (j = listIoctls->minBufferLength + 1;
				j<MAX_BUFSIZE && cont; j++) {
				if (loggerflg)
				{
					logger_detect(g_lpInputBuffer, "Detect IOCTL CODE: 0x%08x\r\nInput Buff: 0x41 fill buffer\r\nInput Buff Size: %d\r\nOutput Buff: 0x41 fill buffer\r\nOutput Buff Size: %d", currentIoctl, j, j);
				}
				status = DeviceIoControl(deviceHandle,
					currentIoctl,
					&brutebufInput,
					j,
					&brutebufOutput,
					j,
					&nbBytes,
					NULL);
				if (status == 0) {
					listIoctls->maxBufferLength = j - 1;
					cont = FALSE;
				}
			}
			if (cont) {
				listIoctls->maxBufferLength = MAX_BUFSIZE;
			}
		}
		/*
		else {
		// If we're here, it means no min input buffer size has been found
		// DEBUG -----
		printf("No min bufsize found for IOCTL 0x%08x\n", currentIoctl);
		//listIoctls = addIoctlList(listIoctls, currentIoctl,
		//GetLastError(), 0, MAX_BUFSIZE);
		//i++;
		}
		*/
	}
	printf("\n");
	if (i == 0) {
		if (singleflg)
			printf("[!] Given IOCTL code seems not to be recognized by the "
			"driver !\n");
		else
			printf("[!] No valid IOCTL code has been found !\n");
		exit(1);
	}
	else {
		if (singleflg)
			printf("[!] Given IOCTL code is recognized by the driver !\n\n");
		else
			printf("[+] %d valid IOCTL have been found\n\n", i);
	}

	printf("[!] Write IOCTL List in logger.database...Check it!\n");
	logger(g_lpInputBuffer, "\r\nWrite IOCTL List in logger.database...Check it!");
	
	//读取Ioctl code list中的元素到database文件，方便查询相关信息
	int log_IoctlListLength = getIoctlListLength(listIoctls);
	for (int i = 0; i < log_IoctlListLength; i++)
	{
		loggerListIoctls = getIoctlListElement(listIoctls, i);
		if (i == 0){
			logger_database(g_lpInputBuffer, "Index: %d\r\nIOCTL_CODE: 0x%08x\r\n0x%08x IOCTL MaxLength: %d\r\n0x%08x IOCTL MinLength: %d", i, loggerListIoctls->IOCTL, loggerListIoctls->IOCTL, loggerListIoctls->maxBufferLength, loggerListIoctls->IOCTL,loggerListIoctls->minBufferLength);
		}
		else{
			logger_database(g_lpInputBuffer, "\r\n\r\n\r\nIndex: %d\r\nIOCTL_CODE: 0x%08x\r\n0x%08x IOCTL MaxLength: %d\r\n0x%08x IOCTL MinLength: %d", i, loggerListIoctls->IOCTL, loggerListIoctls->IOCTL, loggerListIoctls->maxBufferLength, loggerListIoctls->IOCTL, loggerListIoctls->minBufferLength);
		}
	}

	if (loggerflg)
	{
		printf("[!] Write Fuzz info in logger_fuzz...Check it!\n");
		logger(g_lpInputBuffer, "\r\nWrite Fuzz info in logger.fuzz...Check it!");
	}
	else{
		printf("[!] No Fuzz logger Mode...If you want log_fuzz,please add parameter \"-l\"!!!\n");
		logger(g_lpInputBuffer, "\r\nNo Fuzz logger Mode...If you want log_fuzz,please add parameter \"-l\"!!!");
	}

	//针对input buffer变异,加入特殊字符与随机字符串,请在ioctl_bf.c开始位置的Array修改特殊字符串的值
	logger(g_lpInputBuffer, "\r\nBegin Fuzzing...");

	while (1) {

		// Choice of the IOCTL to fuzz
		printf("  Valid IOCTLs found \n");
		printf("  ------------------ \n");
		printIoctlList(listIoctls, MAX_BUFSIZE);
		printf("\n");

		if (singleflg) {
			choice = 0;
		}
		else {
			printf("[?] Choose an IOCTL to fuzz...\n");
			printIoctlChoice(listIoctls);
			printf("Choice : ");
			scanf_s("%d", &choice, 3);

			if (choice < 0 || choice >= getIoctlListLength(listIoctls))
				continue;
		}


		posListIoctls = getIoctlListElement(listIoctls, choice);

		// Start fuzzing
		printf("\n");
		printf("  FuzZing IOCTL 0x%08x     \n", posListIoctls->IOCTL);
		printf("  ------------------------ \n");
		logger(g_lpInputBuffer, "\r\nFuzZing IOCTL CODE 0x%08x", posListIoctls->IOCTL);

		// --------------------------------------------------------------------
		// Stage 1: Check for invalid addresses of buffer 
		// (for method != METHOD_BUFFERED)
		if ((posListIoctls->IOCTL & 0x00000003) != 0) {
			printf("[0x%08x] Checking for invalid addresses of in/out buffers...",
				posListIoctls->IOCTL);
			//getch();
			printf("\n");
			cont = TRUE;
			for (i = 0; cont && i<INVALID_BUF_ADDR_ATTEMPTS; i++) {
				for (j = 0; cont && j<(sizeof(invalidAddresses) / 4); j++) {
					// Choose a random length for the buffer
					randomLength = getrand(posListIoctls->minBufferLength,
						posListIoctls->maxBufferLength);
					if (loggerflg)
					{
						logger_fuzz(g_lpInputBuffer, g_lpFuzzInputBuffer, NULL, "Fuzz Mode: invalidate address\r\nFuzz target IOCTL CODE: 0x%08x\r\nInvalidate Input Address: 0x%08x\r\nInput Buff Size: %d\r\nInvalidate Output Address: 0x%08x\r\n Output Buff Size: %d", posListIoctls->IOCTL, invalidAddresses[j], randomLength, invalidAddresses[j], randomLength);
					}
					status = DeviceIoControl(deviceHandle,
						posListIoctls->IOCTL,
						(LPVOID)invalidAddresses[j],
						randomLength,
						(LPVOID)invalidAddresses[j],
						randomLength,
						&nbBytes,
						NULL);
					Sleep(SLEEP_TIME);
				}
				printf(".");
			}
			printf("DONE\n\n");
		}


		// --------------------------------------------------------------------
		// Stage 2: Check for trivial kernel overflow
		printf("[0x%08x] Checking for trivial kernel overflows ...",
			posListIoctls->IOCTL);
		//getch();
		printf("\n");
		cont = TRUE;
		for (i = 0x100; i <= 0x10000; i += 0x100) {
			if (i % 0x1000 == 0)
				printf(".");
			if (loggerflg)
			{
				logger_fuzz(g_lpInputBuffer, g_lpFuzzInputBuffer, NULL, "Fuzz Mode: trivial kernel overflow\r\nFuzz target IOCTL CODE: 0x%08x\r\nInput Address: 0x41 fill buffer\r\nInput Buff Size: %d\r\nOutput Address: 0x41 fill buffer\r\n Output Buff Size: %d", posListIoctls->IOCTL, i, i);
			}
			status = DeviceIoControl(deviceHandle,
				posListIoctls->IOCTL,
				&brutebufInput,
				i,
				&brutebufOutput,
				i,
				&nbBytes,
				NULL);
			Sleep(SLEEP_TIME);
		}
		memset(bufInput, 0x00, 0x10000);
		printf("DONE\n\n");


		// --------------------------------------------------------------------
		// Stage 3: Fuzzing with predetermined DWORDs
		printf("[0x%08x] Fuzzing with predetermined DWORDs, max buffer size...\n",
			posListIoctls->IOCTL);
		printf("(Ctrl+C to pass to the next step)");
		//getch();
		printf("\n");
		cont = TRUE;
		if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) {

			// Fill the buffer with data from FuzzConstants (1 DWORD after 1)
			for (i = 0; cont && i<posListIoctls->maxBufferLength; i = i + 4) {

				printf("Fuzzing DWORD %d/%d\n",
					i / 4 + 1, posListIoctls->maxBufferLength / 4);

				// Fill the whole buffer with random data...
				for (j = 0; cont && j<posListIoctls->maxBufferLength; j++) {
					bufInput[j] = (BYTE)getrand(0x00, 0xff);
				}

				// ...and put a DWORD from FuzzConstants at the i_th position
				for (j = 0; cont && j<(sizeof(FuzzConstants) / 4); j++) {
					fuzzData = FuzzConstants[j];

					/*
					printf("Fuzzing DWORD %d/%d with 0x%08x (%d/%d)\n",
					i/4+1, posListIoctls->maxBufferLength/4,
					fuzzData, j+1, sizeof(FuzzConstants)/4);
					*/

					// Choose a random element into FuzzConstants
					bufInput[i] = fuzzData & 0x000000ff;
					bufInput[i + 1] = (fuzzData & 0x0000ff00) >> 8;
					bufInput[i + 2] = (fuzzData & 0x00ff0000) >> 16;
					bufInput[i + 3] = (fuzzData & 0xff000000) >> 24;

					if (!quietflg) {
						Hexdump(bufInput, posListIoctls->maxBufferLength);
						printf("Fuzzing DWORD %d/%d with 0x%08x (%d/%d)\n",
							i / 4 + 1, posListIoctls->maxBufferLength / 4,
							fuzzData, j + 1, sizeof(FuzzConstants) / 4);
						printf("Input buffer: %d (0x%x) bytes \n",
							posListIoctls->maxBufferLength,
							posListIoctls->maxBufferLength);
					}
					if (loggerflg)
					{
						logger_fuzz(g_lpInputBuffer, g_lpFuzzInputBuffer, bufInput, "Fuzz Mode: Predetermined DWORDs\r\nFuzz target IOCTL CODE: 0x%08x\r\nVariation Data: 0x%x 0x%x 0x%x 0x%x\r\nOffset in buffer: 0x%x\r\nInput Buff Size: %d\r\nOutput Address: 0x41 fill buffer\r\n Output Buff Size: %d\r\n\r\nInput Buffer:\r\n", posListIoctls->IOCTL, bufInput[i], bufInput[i + 1], bufInput[i + 2], bufInput[i + 3], i, posListIoctls->maxBufferLength, posListIoctls->maxBufferLength);
					}
					status = DeviceIoControl(deviceHandle,
						posListIoctls->IOCTL,
						&bufInput,
						posListIoctls->maxBufferLength,
						&brutebufOutput,
						posListIoctls->maxBufferLength,
						&nbBytes,
						NULL);

					if (!quietflg) {
						if (status == 0)
							printf("Error %d: %s\n\n", GetLastError(),
							errorCode2String(GetLastError()));
						printf("-------------------------------------------------------------------\n\n");
					}

					Sleep(SLEEP_TIME);
				}
			}

			printf("Filling the whole buffer with predetermined DWORDs\n");
			while (cont) {
				// Choose a random length for the buffer
				randomLength = getrand(posListIoctls->minBufferLength,
					posListIoctls->maxBufferLength);

				// Fill the whole buffer with data from FuzzConstants
				memset(bufInput, 0x00, MAX_BUFSIZE);
				for (i = 0; i<randomLength; i = i + 4) {
					fuzzData = FuzzConstants[getrand(0, (sizeof(FuzzConstants) / 4) - 1)];

					// Choose a random element into FuzzConstants
					bufInput[i] = fuzzData & 0x000000ff;
					bufInput[i + 1] = (fuzzData & 0x0000ff00) >> 8;
					bufInput[i + 2] = (fuzzData & 0x00ff0000) >> 16;
					bufInput[i + 3] = (fuzzData & 0xff000000) >> 24;
				}

				if (!quietflg) {
					Hexdump(bufInput, randomLength);
					printf("Filling the whole buffer with predetermined DWORDs\n");
					printf("Input buffer: %d (0x%x) bytes \n", randomLength,
						randomLength);
				}
				if (loggerflg)
				{
					logger_fuzz(g_lpInputBuffer, g_lpFuzzInputBuffer, bufInput, "Fuzz Mode: Fill all predetermined DWORDs\r\nFuzz target IOCTL CODE: 0x%08x\r\nVariation Data: Fill All\r\nInput Buff Size: %d\r\nOutput Address: 0x41 fill buffer\r\n Output Buff Size: %d\r\n\r\nInput Buffer:\r\n", posListIoctls->IOCTL, randomLength, randomLength);
				}
				status = DeviceIoControl(deviceHandle,
					posListIoctls->IOCTL,
					&bufInput,
					randomLength,
					&bufOutput,
					randomLength,
					&nbBytes,
					NULL);

				if (!quietflg) {
					if (status == 0)
						printf("Error %d: %s\n\n", GetLastError(), errorCode2String(GetLastError()));
					printf("-------------------------------------------------------------------\n\n");
				}

				Sleep(SLEEP_TIME);
			}

		}
		else {
			printf("[!] Error: could not set control handler.");
			exit(1);
		}
		printf("STOPPED\n\n");


		// --------------------------------------------------------------------
		// Stage 4: Fuzzing with fully random data
		printf("[0x%08x] Fuzzing with fully random data...\n",
			posListIoctls->IOCTL);
		printf("(Ctrl+C to pass to the next step)");
		//getch();
		printf("\n");
		cont = TRUE;
		if (SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) {
			while (cont) {
				// Choose a random length for the buffer
				randomLength = getrand(posListIoctls->minBufferLength,
					posListIoctls->maxBufferLength);

				// Fill the buffer with random data
				memset(bufInput, 0x00, MAX_BUFSIZE);
				for (i = 0; i<randomLength; i++) {
					bufInput[i] = (BYTE)getrand(0x00, 0xff);
				}


				if (!quietflg) {
					Hexdump(bufInput, randomLength);
					printf("Input buffer: %d (0x%x) bytes \n", randomLength,
						randomLength);
				}
				if (loggerflg)
				{
					logger_fuzz(g_lpInputBuffer, g_lpFuzzInputBuffer, bufInput, "Fuzz Mode: Fill all random data\r\nFuzz target IOCTL CODE: 0x%08x\r\nInput Data: Fill random data\r\nInput Buff Size: %d\r\nOutput Address: 0x41 fill buffer\r\n Output Buff Size: %d\r\n\r\nInput Buffer:\r\n", posListIoctls->IOCTL, randomLength, randomLength);
				}
				status = DeviceIoControl(deviceHandle,
					posListIoctls->IOCTL,
					&bufInput,
					randomLength,
					&bufOutput,
					randomLength,
					&nbBytes,
					NULL);

				if (!quietflg) {
					if (status == 0)
						printf("Error %d: %s\n\n", GetLastError(),
						errorCode2String(GetLastError()));
					printf("-------------------------------------------------------------------\n\n");
				}

				Sleep(SLEEP_TIME);
			}
		}
		else {
			printf("[!] Error: could not set control handler.");
			exit(1);
		}
		printf("STOPPED\n\n");


		// --------------------------------------------------------------------


		printf("[0x%08x] FuzZing finished, no BSOD :'(\n\n",
			posListIoctls->IOCTL);
		logger(g_lpInputBuffer, "\r\nFuzzing Finished, no BSOD");

		printf("[?] Continue ? (y/n)");
		if (getch() == 'n')
			exitProgram(listIoctls);
		printf("\n");
	}

	return 0;
}