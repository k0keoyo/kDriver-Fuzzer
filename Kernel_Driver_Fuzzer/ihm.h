

void banner();
void usage(char *progName);
void exitProgram(pIOCTLlist listIoctls);
char *errorCode2String(DWORD errorCode);
void Hexdump(PUCHAR Data, ULONG Size);
DWORD parseHex(char *str);