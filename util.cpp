#include "global.h"
#include "winapi.h"
#include "util.h"

BOOL ObtainPrivilege(LPCTSTR pName)
{
	HANDLE curProcess = GetCurrentProcess();
	HANDLE tokenHandle;
	LUID luid;
	TOKEN_PRIVILEGES newState;

	if (!OpenProcessToken(curProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle))
		return 0;
	if (!LookupPrivilegeValue(NULL, pName, &luid))
		return 0;

	newState.PrivilegeCount = 1;
	newState.Privileges->Luid.LowPart = luid.LowPart;
	newState.Privileges->Attributes = SE_PRIVILEGE_ENABLED;
	if (!AdjustTokenPrivileges(tokenHandle, FALSE, &newState, sizeof newState, NULL, NULL))
		return FALSE;

	CloseHandle(tokenHandle);
	return TRUE;
}

NTSTATUS MyOpenDirObj(HANDLE *phDir, OBJECT_ATTRIBUTES *pObjAttr, WCHAR *pSrc, BOOL bRealDir)
{
	UNICODE_STRING pDest;

	g_RtlInitUnicodeString(&pDest, pSrc);
	InitializeObjectAttributes(pObjAttr, &pDest, OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS status;
	ACCESS_MASK desiredAccess = 0x20001;
	if (bRealDir) {
		status = g_NtOpenDirectoryObject(phDir, desiredAccess, pObjAttr);
	} else {
		status = g_NtOpenSymbolicLinkObject(phDir, desiredAccess, pObjAttr);
	}

	return status;
}

static DRIVE_PREFIX_ENTRY g_DriverPrefixArr[26];

void InitDriverPrefixArray()
{
	int letterIndex;
	int writeIndex;
	TCHAR rootPath[12];
	TCHAR buffer[64];
	TCHAR pathBuffer[MAX_PATH];
	UINT drvType;
	OBJECT_ATTRIBUTES objAttr;
	HANDLE hObj;
	ULONG returnLen;
	UNICODE_STRING usPath;

	usPath.MaximumLength = MAX_PATH;
	usPath.Buffer = pathBuffer;
	writeIndex = 0;

	for (letterIndex = 0; letterIndex < 26; letterIndex++) {
		wsprintf(rootPath, _T("%c:\\"), 'A' + letterIndex);
		drvType = GetDriveType(rootPath);
		if (drvType == DRIVE_FIXED || drvType == DRIVE_REMOVABLE) {
			wsprintf(buffer, _T("\\DosDevices\\%c:"), 'A' + letterIndex);
			if (MyOpenDirObj(&hObj, &objAttr, buffer, FALSE) == STATUS_SUCCESS) {
				g_NtQuerySymbolicLinkObject(hObj, &usPath, &returnLen);
				CloseHandle(hObj);
				if (MyOpenDirObj(&hObj, &objAttr, pathBuffer, FALSE) == STATUS_SUCCESS) {
					g_NtQuerySymbolicLinkObject(hObj, &usPath, &returnLen);
					CloseHandle(hObj);
				}
				wcscpy(g_DriverPrefixArr[writeIndex].Prefix, pathBuffer);
				g_DriverPrefixArr[writeIndex].Letter = 'A' + letterIndex;
				writeIndex++;
			}
		}
	}
	g_DriverPrefixArr[writeIndex].Prefix[0] = 0;
}

void ConvertPath_File(LPWSTR path)
{
	int index;
	size_t len;

	for (index = 0; g_DriverPrefixArr[index].Prefix[0] != '\0'; index++) {
		len = wcslen(g_DriverPrefixArr[index].Prefix);
		if (_wcsnicmp(g_DriverPrefixArr[index].Prefix, path, len) == 0 && path[len] == '\\') {
			path[0] = g_DriverPrefixArr[index].Letter;
			path[1] = L':';
			memmove(&path[2],
				&path[len],
				(wcslen(path) - wcslen(g_DriverPrefixArr[index].Prefix) + 1) * 2);
			return;
		}
	}
}

void ConvertPath_Driver(LPWSTR path)
{
	LPWSTR pSrcCopy = new WCHAR[wcslen(path) + 1];
	wcscpy(pSrcCopy, path);

	WCHAR sysDir[MAX_PATH];
	GetSystemDirectoryW(sysDir, MAX_PATH);

	size_t lenNeeded = wcslen(sysDir) + wcslen(L"\\system32\\drivers\\") + 1;
	LPWSTR pSecondSlash = wcschr(&sysDir[3], L'\\');
	*pSecondSlash = '\0';
	
	if (wcsncmp(pSrcCopy, L"\\SystemRoot\\", wcslen(L"\\SystemRoot\\")) == 0) {
		wsprintfW(path, L"%s%s", sysDir, wcschr(pSrcCopy + 1, L'\\'));
	} else if (wcsncmp(pSrcCopy, L"\\??\\", wcslen(L"\\??\\")) == 0) {
		wcscpy(path, pSrcCopy + 4);
	} else if (pSrcCopy[0] == L'\\') {
		wsprintfW(path, L"%c:%s", sysDir[0], pSrcCopy);
	} else {
		wsprintfW(path, L"%s\\System32\\Drivers\\%s", sysDir, pSrcCopy);
	}

	delete[] pSrcCopy;
}

LPWSTR AnsiToUnicode(LPCSTR str)
{
	int n;
	WCHAR *buf;

	n = MultiByteToWideChar(CP_THREAD_ACP, 0, str, -1, NULL, 0);
	if (n == 0) {
		buf = new WCHAR[1];
		buf[0] = '\0';
		return buf;
	}
	
	buf = new WCHAR[n * 2];
	n = MultiByteToWideChar(CP_THREAD_ACP, 0, str, -1, buf, n);
	return buf;
}

SYSTEM_INFO g_SysInfo;
BOOL g_Is32BitProgramOn64BitSystem = FALSE;
BOOL g_IsSystem64Bit;

void LoadSystemInfo()
{
	GetNativeSystemInfo(&g_SysInfo);
	g_IsSystem64Bit = (
		g_SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		g_SysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64);

	typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process =
		(LPFN_ISWOW64PROCESS) GetProcAddress(GetModuleHandle(TEXT("kernel32")),"IsWow64Process");

	if (fnIsWow64Process)
		fnIsWow64Process(GetCurrentProcess(), &g_Is32BitProgramOn64BitSystem);
}

SYSTEM_PROCESS_INFO *ReadSystemProcessInfo()
{
	NTSTATUS status;
	BYTE *buffer;
	ULONG size;
	
	size = 1000;
	for (;;) {
		buffer = new BYTE[size];
		status = g_NtQuerySystemInformation(SystemProcessInformation, buffer, size, NULL);
		if (status == STATUS_SUCCESS)
			break;
		delete[] buffer;
		size += 10000;
	}

	return (SYSTEM_PROCESS_INFO *) buffer;
}

void FormatLastError(LPTSTR buffer, DWORD size)
{
	LPTSTR msgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		LANG_USER_DEFAULT,
		(LPWSTR) &msgBuf,
		0,
		NULL);
	StringCbPrintf(buffer, size, _T("%s"), msgBuf);
	LocalFree(msgBuf);
}

BOOL GetSIDString(PSID pSid, LPTSTR outBuf, ULONG *pReturnLen)
{
	if (IsValidSid(pSid)) {
		PSID_IDENTIFIER_AUTHORITY pAuth = GetSidIdentifierAuthority(pSid);
		BYTE count = *GetSidSubAuthorityCount(pSid);
		if (*pReturnLen >= (ULONG)(28 + 12 * count)) {
			int offset = _sntprintf(outBuf, *pReturnLen, _T("S-%lu-"), 1);
			int totalLen = offset;
			if (pAuth->Value[0] || pAuth->Value[1]) {
				totalLen += _sntprintf(
					outBuf + offset,
					*pReturnLen - offset,
					_T("0x%02hx%02hx%02hx%02hx%02hx%02hx"),
					pAuth->Value[0],
					pAuth->Value[1],
					pAuth->Value[2],
					pAuth->Value[3],
					pAuth->Value[4],
					pAuth->Value[5]);
			} else {
				totalLen += _sntprintf(
					outBuf + offset,
					*pReturnLen - offset,
					_T("%lu"),
					(pAuth->Value[2] << 24) + (pAuth->Value[3] << 16) + (pAuth->Value[4] << 8) + (unsigned int)pAuth->Value[5]);
			}
			for (unsigned i = 0; i < count; i++) {
				PDWORD pdw = GetSidSubAuthority(pSid, i);
				totalLen += _sntprintf(
					outBuf + totalLen,
					*pReturnLen - totalLen,
					_T("-%lu"),
					*pdw);
			}
			return TRUE;
		} else {
			*pReturnLen = 28 + 12 * count;
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return FALSE;
		}
	} else {
		return FALSE;
	}
}

static TCHAR *g_CurrentUserSIDString = NULL;

static void LoadCurrentUserSIDString()
{
	HANDLE hToken;
	union {
		TOKEN_USER tu;
		BYTE buffer[2048];
	};
	DWORD retLen;

	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken);
	GetTokenInformation(hToken, TokenUser, &tu, sizeof buffer, &retLen);

	retLen = 0;
	GetSIDString(tu.User.Sid, NULL, &retLen);
	g_CurrentUserSIDString = new TCHAR[retLen];
	GetSIDString(tu.User.Sid, g_CurrentUserSIDString, &retLen);
	CloseHandle(hToken);
}

static REG_LOOKUP_ENTRY g_RegLookupTable1[2] =
{
	{ L"\\REGISTRY\\USER\\", L"HKCU" },
	{ L"HKU\\", L"HKCU" },
};

static REG_LOOKUP_ENTRY g_RegLookupTable2[4] =
{
	{ L"\\REGISTRY\\USER", L"HKU" },
	{ L"\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\HARDWARE PROFILES\\CURRENT", L"HKCC" },
	{ L"\\REGISTRY\\MACHINE\\SOFTWARE\\CLASSES", L"HKCR" },
	{ L"\\REGISTRY\\MACHINE", L"HKLM" },
};

void InitRegLookupTable()
{
	LoadCurrentUserSIDString();

	for (int i = 0; i < _countof(g_RegLookupTable1); i++) {
		g_RegLookupTable1[i].length = wcslen(g_RegLookupTable1[i].longPrefix);
	}
	for (int i = 0; i < _countof(g_RegLookupTable2); i++) {
		g_RegLookupTable2[i].length = wcslen(g_RegLookupTable2[i].longPrefix);
	}
}

void ConvertPath_Reg(LPWSTR path)
{
	size_t userIdStrLen;
	LPCWSTR pClasses = L"_Classes";
	size_t classesLen;

	userIdStrLen = wcslen(g_CurrentUserSIDString);
	classesLen = wcslen(pClasses);
	for (int i = 0; i < 2; i++) {
		BOOL bClasses;
		LPCWSTR p;

		if (_wcsnicmp(path, g_RegLookupTable1[i].longPrefix, g_RegLookupTable1[i].length) != 0)
			continue;
		if (_wcsnicmp(path + g_RegLookupTable1[i].length, g_CurrentUserSIDString, userIdStrLen) != 0)
			continue;

		bClasses = FALSE;
		if (_wcsnicmp(path + g_RegLookupTable1[i].length + userIdStrLen, pClasses, classesLen) == 0)
			bClasses = TRUE;

		wcscpy(path, g_RegLookupTable1[i].shortPrefix);

		p = path + g_RegLookupTable1[i].length;
		while (*p && *p != '\\')
			p++;

		if (bClasses)
			wcscpy(path, _T("\\Software\\Classes"));
		wcscat(path, p);
		return;
	}

	for (int i = 0; i < 4; i++) {
		if (_wcsnicmp(path, g_RegLookupTable2[i].longPrefix, g_RegLookupTable2[i].length) != 0)
			continue;

		wcscpy(path, g_RegLookupTable2[i].shortPrefix);
		wcscat(path, path + g_RegLookupTable2[i].length);
	}
}

BOOL ExtractResource(LPCTSTR pResId, LPCTSTR pResType, LPCTSTR filePath)
{
	BOOL result = FALSE;
	HRSRC hResInfo = FindResource(NULL, pResId, pResType);
	if (hResInfo) {
		HGLOBAL hResData = LoadResource(NULL, hResInfo);
		DWORD size = SizeofResource(NULL, hResInfo);
		PVOID data = LockResource(hResData);
		FILE *pFile;
		if (_tfopen_s(&pFile, filePath, _T("wb")) == 0) {
			fwrite(data, 1, size, pFile);
			fclose(pFile);
			result = TRUE;
		}
		UnlockResource(hResData); // will do nothing
	}
	return result;
}

BOOL ExtractDriver(LPCTSTR pResId, LPCTSTR pResType, LPCTSTR fileName, LPTSTR outFilePath)
{
	TCHAR buf[264];
	return
		(GetSystemDirectory(buf, MAX_PATH),
			wsprintf(outFilePath, _T("%s\\Drivers\\%s"), buf, fileName),
			ExtractResource(pResId, pResType, outFilePath)) ||
		(wsprintf(buf, _T("%%TEMP%%\\%s"), fileName),
			ExpandEnvironmentStrings(buf, outFilePath, MAX_PATH),
			ExtractResource(pResId, pResType, outFilePath)) ||
		(GetCurrentDirectory(MAX_PATH, buf),
			wsprintf(outFilePath, L"%s\\%s", buf, fileName),
			ExtractResource(pResId, pResType, outFilePath));
	return 0;
}

BOOL LoadDriver(LPCWSTR driverName, LPCWSTR fullPath)
{
	// ? 264 --> multiply of 8
	BOOL result = FALSE;

	WCHAR keyStr[264];
	wsprintfW(keyStr, L"System\\CurrentControlSet\\Services\\%s", driverName);
	
	HKEY hKey;
	if (RegCreateKeyW(HKEY_LOCAL_MACHINE, keyStr, &hKey) == ERROR_SUCCESS) {
		DWORD data;
		data = 1;
		RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE *)&data, 4);
		data = 1;
		RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE *)&data, 4);
		data = 3;
		RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE *)&data, 4);

		WCHAR pathBuf[264];
		wsprintfW(pathBuf, L"\\??\\%s", fullPath);
		RegSetValueExW(hKey, L"ImagePath", 0, REG_SZ, (BYTE *)pathBuf, wcslen(pathBuf) * sizeof(WCHAR));

		RegCloseKey(hKey);

		WCHAR objPath[264];
		wsprintfW(objPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\%s", driverName);

		UNICODE_STRING us;
		g_RtlInitUnicodeString(&us, objPath);
		NTSTATUS status = g_NtLoadDriver(&us);

		WCHAR keyStr2[264];
		wsprintfW(keyStr2, L"%s\\Enum", keyStr);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyStr2);
		wsprintfW(keyStr2, L"%s\\Security", keyStr);
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyStr2);
		
		RegDeleteKeyW(HKEY_LOCAL_MACHINE, keyStr);

		// can be STATUS_OBJECT_NAME_COLLISION
		// (load our driver after the original driver loaded)
		if (status == STATUS_SUCCESS || status == STATUS_IMAGE_ALREADY_LOADED) {
			result = TRUE;
		} else {
			SetLastError(g_RtlNtStatusToDosError(status));
		}
	}
	return result;
}

BOOL OpenDriver(LPCWSTR driverName, HANDLE *pHandle)
{
	BOOL result;
	HANDLE handle;
	WCHAR objPath[264];
	wsprintfW(objPath, L"\\\\.\\%s", driverName);
	handle = CreateFile(objPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (handle == INVALID_HANDLE_VALUE) {
		wsprintfW(objPath, L"\\\\.\\Global\\%s", driverName);
		handle = CreateFile(objPath, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	}
	*pHandle = handle;
	result = (handle != INVALID_HANDLE_VALUE);
	return result;
}
