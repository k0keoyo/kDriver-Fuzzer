#include<stdio.h>
#include<stdlib.h>
#include "ioctl_manipulation.h"

/*

IHM functions

*/


// Banner ---------------------------------------------------------------------
void banner() {

	printf("    _                   _  _       ___                      \n");
	printf("   (_)              _  | || |     / __)                     \n");
	printf("    _  ___   ____ _| |_| || |__ _| |__                      \n");
	printf("   | |/ _ \\ / ___|_   _) ||  _ (_   __)                    \n");
	printf("   | | |_| ( (___  | |_| || |_) )| |                        \n");
	printf("   |_|\\___/ \\____)  \\__)\\_)____/ |_|	FrameWork  v1.0 \n");
	printf("   Author: @koutoo                                          \n");
	printf("   Github: https://github.com/koutto/ioctlbf                \n");
	printf("   Customized by k0shl @KeyZ3r0                             \n");
	printf("   Github: https://github.com/k0keoyo                       \n");
	printf("   Contact me: k0pwn_0110@sina.cn                           \n");
	return;
}


// Usage/Help message ---------------------------------------------------------
void usage(char *progName) {
	banner();
	printf("  Usage                                                             \n");
	printf("  -----                                                             \n");
	printf("  %s -d <deviceName> (-i <code>|-r <code>-<code>) [-u] [-q] [-f] [-e]\n\n",
		progName);
	printf("  Options                                                           \n");
	printf("  -------                                                           \n");
	printf("  -l	Enable logger                                               \n");
	printf("  -s	Search Driver Service Name                                  \n");
	printf("  -d	Symbolic device name (without \\\\.\\)                      \n");
	printf("  -i	IOCTL code used as reference for scanning (see also -u)     \n");
	printf("  -n 	Detect IOCTL codes with null pointer                        \n");
	printf("  -r 	IOCTL codes range (format: 00004000-00008000) to fuzz       \n");
	printf("  -u	Fuzz only the IOCTL specified with -i                       \n");
	printf("  -f 	Fill 0x00 in Input buffer                                   \n");
	printf("  -q	Quiet mode (do not display hexdumps when fuzzing)           \n");
	printf("  -e	Display error codes during IOCTL codes scanning             \n");
	printf("  -h	Display this help                                           \n\n");
	printf("  Examples                                                          \n");
	printf("  --------                                                          \n");
	printf("Brute IOCTL codes with Device Name:\n");
	printf("  > %s -d devicename -b                                    \n\n", progName);
	printf("Scanning Driver Service Name:\n");
	printf("  > %s -s                                                  \n\n", progName);
	printf("Scanning range IOCTL codes by null pointer with logger:\n");
	printf("  > %s -d deviceName -i 00004000 -n -l                     \n\n", progName);
	printf("Scanning by Function code + Transfer type bruteforce from given valid IOCTL with logger:\n");
	printf("  > %s -d deviceName -i 00004000 -l                        \n\n", progName);
	printf("Scanning a given IOCTL codes range (filter enabled fill 0x00) and detect in normal(0x41 fill buffer) with logger:\n");
	printf("  > %s -d deviceName -r 00004000-00004fff -f -l            \n\n", progName);
	printf("Fuzzing only a given IOCTL (quiet mode) without logger:\n");
	printf("  > %s -d deviceName -i 00004000 -u -q                      \n", progName);
	printf("\n");
	exit(1);
}


// Exit the program -----------------------------------------------------------
void exitProgram(pIOCTLlist listIoctls) {
	printf("\n[~] Exiting ...\n");
	freeIoctlList(listIoctls);
	exit(1);
}


// Gives the error message corresponding to a given Win32 error code ----------
char *errorCode2String(DWORD errorCode) {

	LPVOID lpMsgBuf;

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		errorCode,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL);

	return lpMsgBuf;
}


// Print hexdump of a given data ----------------------------------------------
//                                                 code taken from IOCTLfuzzer
void Hexdump(PUCHAR Data, ULONG Size)  {

	unsigned int dp = 0, p = 0;
	const char trans[] =
		"................................ !\"#$%&'()*+,-./0123456789"
		":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
		"nopqrstuvwxyz{|}~...................................."
		"....................................................."
		"........................................";

	char szBuff[0x100], szChr[10];
	RtlZeroMemory(szBuff, sizeof(szBuff));

	for (dp = 1; dp <= Size; dp++) {
		sprintf(szChr, "%02x ", Data[dp - 1]);
		strcat(szBuff, szChr);

		if ((dp % 8) == 0) {
			strcat(szBuff, " ");
		}

		if ((dp % 16) == 0) {
			strcat(szBuff, "| ");
			p = dp;

			for (dp -= 16; dp < p; dp++) {
				sprintf(szChr, "%c", trans[Data[dp]]);
				strcat(szBuff, szChr);
			}
			printf("%s\r\n", szBuff);
			RtlZeroMemory(szBuff, sizeof(szBuff));
		}
	}

	if ((Size % 16) != 0) {
		p = dp = 16 - (Size % 16);

		for (dp = p; dp > 0; dp--) {
			strcat(szBuff, "   ");

			if (((dp % 8) == 0) && (p != 8)) {
				strcat(szBuff, " ");
			}
		}

		strcat(szBuff, " | ");
		for (dp = (Size - (16 - p)); dp < Size; dp++) {
			sprintf(szChr, "%c", trans[Data[dp]]);
			strcat(szBuff, szChr);
		}
		printf("%s\r\n", szBuff);
	}

	printf("\r\n");
}


// Convert a string into hexadecimal ------------------------------------------
DWORD parseHex(char *str) {
	DWORD value = 0;

	for (;; ++str) {
		switch (*str) {
		case '0': case '1': case '2': case '3': case '4':
		case '5': case '6': case '7': case '8': case '9':
			value = value << 4 | *str & 0xf;
			break;
		case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
		case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
			value = value << 4 | 9 + *str & 0xf;
			break;
		default:
			return value;
		}
	}
}

