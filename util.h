#pragma once

#include "winapi.h" // SYSTEM_PROCESS_INFO

typedef struct _DRIVE_PREFIX_ENTRY {
	WCHAR Prefix[256];
	WCHAR Letter;
} DRIVE_PREFIX_ENTRY;
void InitDriverPrefixArray();

typedef struct _REG_LOOKUP_ENTRY {
	WCHAR longPrefix[256];
	WCHAR shortPrefix[32];
	SIZE_T length;
} REG_LOOKUP_ENTRY;
void InitRegLookupTable();

BOOL ObtainPrivilege(LPCTSTR pName);
void ConvertPath_File(LPWSTR path);
void ConvertPath_Driver(LPWSTR path);
void ConvertPath_Reg(LPWSTR path);
LPWSTR AnsiToUnicode(LPCSTR str);
void FormatLastError(LPTSTR buffer, DWORD size);

extern SYSTEM_INFO g_SysInfo;
extern BOOL g_Is32BitProgramOn64BitSystem;
extern BOOL g_IsSystem64Bit;
void LoadSystemInfo();

SYSTEM_PROCESS_INFO *ReadSystemProcessInfo();

BOOL GetSIDString(PSID pSid, LPTSTR outBuf, ULONG *pReturnLen);

BOOL ExtractResource(LPCTSTR pResId, LPCTSTR pResType, LPCTSTR filePath);
BOOL ExtractDriver(LPCTSTR pResId, LPCTSTR pResType, LPCTSTR fileName, LPTSTR outFilePath);
BOOL LoadDriver(LPCWSTR driverName, LPCWSTR fullPath);
BOOL OpenDriver(LPCWSTR driverName, HANDLE *pHandle);
