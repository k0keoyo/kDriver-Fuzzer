#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <windows.h>

// Global variable to store the log filename.
char logfilename[128];
char log_detectfilename[128];
char log_databasefilename[128];
char log_fuzzfilename[128];
char log_driverscanfilename[128];
// Whether this filename has been set.
int flag = 0;
int flag_detect = 0;
int flag_fuzz = 0;
int flag_database = 0;

//记录驱动枚举的情况
VOID logger_driverscan(const char* fmt, ...)
{
	FILE *stream = NULL;

	va_list args;
	va_start(args, fmt);

	sprintf(logfilename, "Enum_Driver_log.txt");


	// Open our log file.
	if ((stream = fopen(logfilename, "a+")) == NULL) {
		printf("Error! Cannot open log file, exiting...");
		exit(1);
	}

	// Write to file.
	if (vfprintf(stream, fmt, args) < 0) {
		printf("Error! Cannot write to log file, exiting...");
		exit(1);
	}
	fprintf(stream, "\n");

	// Flush content to log file and close handle.
	fflush(stream);
	fclose(stream);

	// Print to standard out as well.
	// Check for error conditions.
	if (vfprintf(stdout, fmt, args) < 0) {
		printf("Error! Cannot write to standard output, exiting...");
		exit(1);
	}
	fprintf(stdout, "\n");

	va_end(args);
}


//detecting mode,记录探测的日志
VOID logger_detect(LPCVOID lpInputBuffer, const char* fmt, ...)
{
	LPCWSTR lpPathName;
	FILE *stream = NULL;
	WCHAR wsz[100] = { 0 };
	HANDLE hFile = NULL;
	DWORD junk = 0;

	va_list args;
	va_start(args, fmt);
	//Init InputBuffer
	memset(lpInputBuffer, 0x00, 512);
	if (!flag_detect) {
		// Set the log file name.
		sprintf(log_detectfilename, "log_detect.%d.txt", time(NULL) + GetCurrentProcessId() + GetCurrentThreadId());
		flag_detect = 1;
	}

	MultiByteToWideChar(CP_ACP, 0, log_detectfilename, strlen(log_detectfilename) + 1, wsz, sizeof(wsz));
	// Open our log file.
	lpPathName = wsz;

	hFile = CreateFile(lpPathName, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_ATTRIBUTE_NORMAL, NULL);

	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	// Write to file.
	vsprintf(lpInputBuffer, fmt, args);


	WriteFile(hFile, lpInputBuffer, 512, &junk, NULL);

	FlushFileBuffers(hFile);
	// Print to standard out as well.
	// Check for error conditions.
	CloseHandle(hFile);

	va_end(args);
}

//记录当前fuzz数据,ioctl以及fuzz的inputbuffer和size,lpbuffer记录data信息
VOID logger_fuzz(LPCVOID lpInputBuffer,LPCVOID data_lpInputBuffer,LPCVOID InputDataBuffer, const char* fmt, ...)
{
	LPCWSTR lpPathName;
	FILE *stream = NULL;
	WCHAR wsz[100] = { 0 };
	HANDLE hFile = NULL;
	DWORD junk = 0;
	LPCVOID m_InputDataBuffer = NULL;

	va_list args;
	va_start(args, fmt);
	//Init InputBuffer
	memset(lpInputBuffer, 0x00, 512);
	memset(data_lpInputBuffer, 0x00, 0x10000);

	if (!flag_fuzz) {
		// Set the log file name.
		sprintf(log_fuzzfilename, "log_fuzz.%d.txt", time(NULL) + GetCurrentProcessId() + GetCurrentThreadId());
		flag_fuzz = 1;
	}

	m_InputDataBuffer = InputDataBuffer;
	MultiByteToWideChar(CP_ACP, 0, log_fuzzfilename, strlen(log_fuzzfilename) + 1, wsz, sizeof(wsz));
	// Open our log file.
	lpPathName = wsz;

	hFile = CreateFile(lpPathName, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_ATTRIBUTE_NORMAL, NULL);

	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	
	// Write to file.
	vsprintf(lpInputBuffer, fmt, args);


	WriteFile(hFile, lpInputBuffer, 512, &junk, NULL);

	if (m_InputDataBuffer != NULL)//如果要记录fuzz数据部分
	{
		memcpy_s(data_lpInputBuffer,0x10000, m_InputDataBuffer, 0x10000);//将data部分存入data_lpInputBuffer
		SetFilePointer(hFile, 0, NULL, FILE_END);//文件指针挪到文件末尾
		WriteFile(hFile, data_lpInputBuffer, 0x10000, &junk, NULL);//将data部分写入文件
	}
	FlushFileBuffers(hFile);
	// Print to standard out as well.
	// Check for error conditions.
	CloseHandle(hFile);

	va_end(args);
}

//记录ioctl list数据库的内容
VOID logger_database(LPCVOID lpInputBuffer, const char* fmt, ...)
{
	LPCWSTR lpPathName;
	FILE *stream = NULL;
	WCHAR wsz[100] = { 0 };
	HANDLE hFile = NULL;
	DWORD junk = 0;

	va_list args;
	va_start(args, fmt);
	//Init InputBuffer
	memset(lpInputBuffer, 0x00, 512);
	if (!flag_database) {
		// Set the log file name.
		sprintf(log_databasefilename, "log_database.%d.txt", time(NULL) + GetCurrentProcessId() + GetCurrentThreadId());
		flag_database = 1;
	}

	MultiByteToWideChar(CP_ACP, 0, log_databasefilename, strlen(log_databasefilename) + 1, wsz, sizeof(wsz));
	// Open our log file.
	lpPathName = wsz;

	hFile = CreateFile(lpPathName, GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_ATTRIBUTE_NORMAL, NULL);

	SetFilePointer(hFile, 0, NULL, FILE_END);
	// Write to file.
	vsprintf(lpInputBuffer, fmt, args);


	WriteFile(hFile, lpInputBuffer, 512, &junk, NULL);

	FlushFileBuffers(hFile);
	// Print to standard out as well.
	// Check for error conditions.
	CloseHandle(hFile);

	va_end(args);
}

//main log 主日志,记录fuzz过程
VOID logger(LPCVOID lpInputBuffer,const char* fmt, ...)
{
	LPCWSTR lpPathName;
	FILE *stream = NULL;
	WCHAR wsz[100] = { 0 };
	HANDLE hFile = NULL;
	DWORD junk = 0;
	
	va_list args;
	va_start(args, fmt);
	//Init InputBuffer
	memset(lpInputBuffer, 0x00, 512);
	if (!flag) {
		// Set the log file name.
    	sprintf(logfilename, "log.%d.txt", time(NULL) + GetCurrentProcessId() + GetCurrentThreadId());
		flag = 1;
	}

	MultiByteToWideChar(CP_ACP, 0, logfilename, strlen(logfilename) + 1, wsz, sizeof(wsz));
	// Open our log file.
	lpPathName = wsz;

	hFile = CreateFile(lpPathName, GENERIC_WRITE | GENERIC_READ, NULL, NULL, OPEN_ALWAYS, FILE_FLAG_NO_BUFFERING | FILE_ATTRIBUTE_NORMAL, NULL);

	SetFilePointer(hFile, 0, NULL, FILE_END);
	// Write to file.
	vsprintf(lpInputBuffer,fmt,args);

	WriteFile(hFile, lpInputBuffer, 512, &junk, NULL);

	FlushFileBuffers(hFile);
	// Print to standard out as well.
	// Check for error conditions.
	CloseHandle(hFile);

	va_end(args);
}