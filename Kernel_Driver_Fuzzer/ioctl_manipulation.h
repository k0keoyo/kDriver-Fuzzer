
#include <WINDOWS.h>

typedef struct IOCTLlist_ {
	DWORD IOCTL;
	DWORD errorCode;
	size_t minBufferLength;
	size_t maxBufferLength;
	struct IOCTLlist_ *previous;
} IOCTLlist, *pIOCTLlist;

pIOCTLlist addIoctlList(pIOCTLlist listIoctls, DWORD ioctl, DWORD errorCode,
	size_t minBufferLength, size_t maxBufferLength);
int getIoctlListLength(pIOCTLlist listIoctls);
pIOCTLlist getIoctlListElement(pIOCTLlist listIoctls, int index);
void freeIoctlList(pIOCTLlist listIoctls);
void printIoctl(DWORD ioctl, DWORD errorCode);
void printIoctlList(pIOCTLlist listIoctls, size_t maxBufsize);
void printIoctlChoice(pIOCTLlist listIoctls);
char *transferTypeFromCode(DWORD code);