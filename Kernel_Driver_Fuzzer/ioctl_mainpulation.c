#include <stdio.h>
#include <stdlib.h>
#include <WINDOWS.h>
#include "ioctl_manipulation.h"

/*

IOCTLs list manipulation functions


IOCTL code specifications:
-------------------------

According to winioctl.h:

IOCTL's are defined by the following bit layout.
[Common |Device Type|Required Access|Custom|Function Code|Transfer Type]
31     30       16 15          14  13   12           2  1            0

Common          - 1 bit.  This is set for user-defined
device types.
Device Type     - This is the type of device the IOCTL
belongs to.  This can be user defined
(Common bit set).  This must match the
device type of the device object.
Required Access - FILE_READ_DATA, FILE_WRITE_DATA, etc.
This is the required access for the
device.
Custom          - 1 bit.  This is set for user-defined
IOCTL's.  This is used in the same
manner as "WM_USER".
Function Code   - This is the function code that the
system or the user defined (custom
bit set)
Transfer Type   - METHOD_IN_DIRECT, METHOD_OUT_DIRECT,
METHOD_NEITHER, METHOD_BUFFERED, This
the data transfer method to be used.


Buffer specifications:
---------------------

Input Size   =  Parameters.DeviceIoControl.InputBufferLength
Output Size  =  Parameters.DeviceIoControl.OutputBufferLength

- METHOD_BUFFERED:
Input Buffer = Irp->AssociatedIrp.SystemBuffer
Ouput Buffer = Irp->AssociatedIrp.SystemBuffer

input & output buffers use the same location, so the buffer allocated
by the I/O manager is the size of the larger value (output vs. input).

- METHOD_X_DIRECT:
Input Buffer = Irp->AssociatedIrp.SystemBuffer
Ouput Buffer = Irp->MdlAddress

the INPUT buffer is passed in using "BUFFERED" implementation. The
output buffer is passed in using a MDL (DMA). The difference between
"IN" and "OUT" is that with "IN", you can use the output buffer to
pass in data! The "OUT" is only used to return data.

- METHOD_NEITHER:
Input Buffer = Parameters.DeviceIoControl.Type3InputBuffer
Ouput Buffer = Irp->UserBuffer

input & output buffers sizes may be different. The I/O manager does not
provide any system buffers or MDLs. The IRP supplies the user-mode
virtual addresses of the input and output buffer

*/


// Add an IOCTL to the list ---------------------------------------------------
pIOCTLlist addIoctlList(pIOCTLlist listIoctls, DWORD ioctl, DWORD errorCode,
	size_t minBufferLength, size_t maxBufferLength) {

	pIOCTLlist newListIoctls;

	newListIoctls = (pIOCTLlist)malloc(sizeof(IOCTLlist));
	if (newListIoctls == NULL) {
		printf("[!] malloc() error\n");
		exit(1);
	}
	newListIoctls->IOCTL = ioctl;
	newListIoctls->errorCode = errorCode;
	newListIoctls->previous = listIoctls;
	newListIoctls->minBufferLength = minBufferLength;
	newListIoctls->maxBufferLength = maxBufferLength;

	return newListIoctls;
}


// Get the IOCTLs list length -------------------------------------------------
int getIoctlListLength(pIOCTLlist listIoctls) {
	int len;
	for (len = 0; listIoctls != NULL; listIoctls = listIoctls->previous, len++);
	return len;
}


// Get a given element of the IOCTLs list -------------------------------------
pIOCTLlist getIoctlListElement(pIOCTLlist listIoctls, int index) {
	int i;
	if (index == 0)
		return listIoctls;

	for (i = 1; listIoctls != NULL && i <= index; i++,
		listIoctls = listIoctls->previous);
		return listIoctls;
}


// Free the IOCTLs list -------------------------------------------------------
void freeIoctlList(pIOCTLlist listIoctls) {
	pIOCTLlist prev;

	while (listIoctls != NULL) {
		prev = listIoctls->previous;
		free(listIoctls);
		listIoctls = prev;
	}

	return;
}


// Print an IOCTL code --------------------------------------------------------
void printIoctl(DWORD ioctl, DWORD errorCode) {

	printf("\t0x%08x ", ioctl);

	if (errorCode)
		printf("- Error %d", errorCode);

	printf("\n");
	return;
}


// Print the whole list -------------------------------------------------------
void printIoctlList(pIOCTLlist listIoctls, size_t maxBufsize) {
	pIOCTLlist currentIoctl;

	for (currentIoctl = listIoctls; currentIoctl != NULL;
		currentIoctl = currentIoctl->previous) {

		printf("  0x%08x  \tfunction code: 0x%04x\n", currentIoctl->IOCTL,
			(currentIoctl->IOCTL & 0x00003ffc) >> 2);
		printf("\t\ttransfer type: %s\n",
			transferTypeFromCode(currentIoctl->IOCTL & 0x00000003));
		printf("\t\tinput bufsize: ");

		if (currentIoctl->minBufferLength == 0 &&
			currentIoctl->maxBufferLength == maxBufsize) {
			printf("seems not fixed... min = 0 | max = %d (0x%x) used\n",
				maxBufsize, maxBufsize);
		}
		else if (currentIoctl->minBufferLength == currentIoctl->maxBufferLength) {
			printf("fixed size = %d (0x%x)", currentIoctl->minBufferLength,
				currentIoctl->minBufferLength);
			if (currentIoctl->minBufferLength == 0)
				printf(" [Not Fuzzable]");

			printf("\n");
		}
		else
			printf("min = %d (0x%x) | max = %d (0x%x)\n",
			currentIoctl->minBufferLength, currentIoctl->minBufferLength,
			currentIoctl->maxBufferLength, currentIoctl->maxBufferLength);

		if (currentIoctl->errorCode)
			printf("\t\t\terror code: %d (0x%x)\n", currentIoctl->errorCode,
			currentIoctl->errorCode);

		printf("\n");
	}
	return;
}


// Print IOCTLs codes choice menu ---------------------------------------------
void printIoctlChoice(pIOCTLlist listIoctls) {
	pIOCTLlist currentIoctl;
	int i;

	for (currentIoctl = listIoctls, i = 0;
		currentIoctl != NULL;
		currentIoctl = currentIoctl->previous, i++) {

		printf("\t[%d] 0x%08x \n", i, currentIoctl->IOCTL);
	}
	return;
}


// Gives the name of the transfer type from its code --------------------------
//                   cf. http://msdn.microsoft.com/en-us/library/ms810023.aspx
char *transferTypeFromCode(DWORD code) {
	switch (code) {
	case 0:	return "METHOD_BUFFERED";
	case 1: return "METHOD_IN_DIRECT";
	case 2: return "METHOD_OUT_DIRECT";
	case 3: return "METHOD_NEITHER";
	default: return "";
	}
}