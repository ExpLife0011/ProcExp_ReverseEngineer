#include "global.h"
#include "winapi.h"
#include "util.h"
#include "driver.h"
#include "handles.h"

static WCHAR g_TypeNameArr[256][64] = {0};

HANDLE MyOpenProcess(ULONG_PTR pid, DWORD desiredAccess)
{
	HANDLE hProcess = OpenProcess(desiredAccess, FALSE, (DWORD) pid);
	if (!hProcess && GetLastError() == ERROR_ACCESS_DENIED) {
		hProcess = g_Driver.OpenProcess(pid);
	}
	return hProcess;
}

HANDLE MyDuplicateHandle(ULONG_PTR pid, ULONG_PTR srcHandle, DWORD desiredAccess)
{
	HANDLE targetHandle;
	HANDLE hSourceProcess;
	
	targetHandle = NULL;
	hSourceProcess = MyOpenProcess(pid, PROCESS_DUP_HANDLE);
	if (hSourceProcess) {
		BOOL bUserDup = TRUE;
		if (pid <= 8) {
			if (g_Driver.IsReady() && g_Driver.DuplicateHandle(pid, (HANDLE) srcHandle, &targetHandle)) {
				bUserDup = FALSE;
			}
		}

		if (bUserDup) {
			DuplicateHandle(hSourceProcess, (HANDLE) srcHandle, GetCurrentProcess(), &targetHandle, desiredAccess, FALSE, 0);
		}
		
		CloseHandle(hSourceProcess);
	}

	return targetHandle;
}

static SYSTEM_PROCESS_INFO *g_SPI = NULL;

static void GetProcessName(ULONG_PTR pid, LPWSTR buffer)
{
	BYTE *p;
	SYSTEM_PROCESS_INFO *pInfo;

	if (pid == 0xFFFFFFF6) {
		wcscpy(buffer, L"Hardware Interrupts and DPCs");
		return;
	}

	p = (BYTE *) g_SPI;
	do {
		pInfo = (SYSTEM_PROCESS_INFO *) p;
		if (pInfo->ProcessId == pid) {
			if (pInfo->ImageName.Length == 0) {
				wcscpy(buffer, L"System Idle Process");
				return;
			} else {
				wcscpy(buffer, pInfo->ImageName.Buffer);
				return;
			}
		}
		p += pInfo->NextEntryOffset;
	} while (pInfo->NextEntryOffset);

	wcscpy(buffer, L"<Non-existent Process>");
	return;
}

HANDLE g_QueryObjectBeginEvent = NULL;
HANDLE g_QueryObjectFinishEvent = NULL;
HANDLE g_QueryObjectThread = NULL;
HANDLE g_hObject;
OBJECT_NAME_INFORMATION *g_pObjectInfo;
NTSTATUS g_QueryObjectResult;

unsigned int __stdcall QueryObjectThreadFunc(void *)
{
	while (WaitForSingleObject(g_QueryObjectBeginEvent, INFINITE) == WAIT_OBJECT_0) {
		g_QueryObjectResult = g_NtQueryObject(
			g_hObject, ObjectNameInformation, g_pObjectInfo, g_pObjectInfo->Name.Length, NULL);
		SetEvent(g_QueryObjectFinishEvent);
	}
	return 0;
}

void FormatObjectString(
	LPWSTR nameBuffer,
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *pEntry,
	WCHAR *pathBuffer, SIZE_T pathBufferSize, SIZE_T *pReturnLen)
{
	HANDLE hObject = NULL;
	NTSTATUS status;

	pathBuffer[0] = '\0';
	if (pReturnLen)
		*pReturnLen = 0;

	if (nameBuffer[0] == '\0' || wcscmp(nameBuffer, L"<Unknown type>") == 0) {
		hObject = MyDuplicateHandle(pEntry->UniqueProcessId, pEntry->HandleValue, 0);
		if (hObject) {
			DWORD returnLen;
			BYTE *buffer;

			g_NtQueryObject(hObject, ObjectTypeInformation, NULL, 0, &returnLen);
			buffer = new BYTE[returnLen];
			status = g_NtQueryObject(hObject, ObjectTypeInformation, buffer, returnLen, NULL);
			if (status == STATUS_SUCCESS) {
				wcscpy(nameBuffer, ((PUBLIC_OBJECT_TYPE_INFORMATION *) buffer)->TypeName.Buffer);
			} else {
				wsprintfW(nameBuffer, L"<Unknown type: %X>", status);
			}

			delete[] buffer;
			CloseHandle(hObject);
			hObject = NULL;
		} else {
			if (g_Driver.IsReady()) {
				g_Driver.QueryObjectType(pEntry->UniqueProcessId, (PVOID) pEntry->HandleValue, pEntry->Object,
					nameBuffer, 64);

				// this should produce a FULL access handle for below use
				// and that's (the only) why we check a access handle already exist below				
			} else {
				wcscpy(nameBuffer, L"<Unknown Type>");
			}
		}
	}
	
	if (_wcsicmp(nameBuffer, L"process") == 0 || _wcsicmp(nameBuffer, L"thread") == 0) {
		if (!hObject) {
			DWORD desiredAccess;
			if (_wcsicmp(nameBuffer, L"process") == 0)
				desiredAccess = PROCESS_QUERY_INFORMATION;
			else
				desiredAccess = THREAD_QUERY_INFORMATION;
			hObject = MyDuplicateHandle(pEntry->UniqueProcessId, pEntry->HandleValue, desiredAccess);
		}
		if (hObject) {
			if (_wcsicmp(nameBuffer, L"process") == 0) {
				PROCESS_BASIC_INFORMATION pbi;
				status = g_NtQueryInformationProcess(hObject, ProcessBasicInformation, &pbi, sizeof pbi, NULL);
				if (status == STATUS_SUCCESS) {
					WCHAR buffer[256];
					GetProcessName(pbi.UniqueProcessId, buffer);
					*pReturnLen = wsprintfW(pathBuffer, L"%s(%d)", buffer, pbi.UniqueProcessId);
				}
			} else {
				THREAD_BASIC_INFORMATION tbi;
				status = g_NtQueryInformationThread(hObject, ThreadBasicInformation, &tbi, sizeof tbi, NULL);
				if (status == STATUS_SUCCESS) {
					WCHAR buffer[256];
					GetProcessName(tbi.ClientId.UniqueProcess, buffer);
					*pReturnLen = wsprintfW(pathBuffer, L"%s(%d): %d", buffer, (DWORD) tbi.ClientId.UniqueProcess, (DWORD) tbi.ClientId.UniqueThread);
				}
			}
		} else if (g_Driver.IsReady()) {
			WCHAR buffer[256];
			FormatLastError(buffer, sizeof buffer);
			*pReturnLen = wsprintfW(pathBuffer, L"<%s>", buffer);
		}
	} else if (_wcsicmp(nameBuffer, L"token") == 0) {
		HANDLE hToken;
		hToken = MyDuplicateHandle(pEntry->UniqueProcessId, pEntry->HandleValue, 8);
		if (hToken) {
			TOKEN_STATISTICS tokenStat;
			TOKEN_USER tokenUser;
			TCHAR name[264];
			DWORD cchName = 104;
			TCHAR domainName[264];
			DWORD cchDomainName = 260;
			union {
				SID_NAME_USE use;
				BYTE localBuf[2048];
			};
			DWORD retLen; // unused but can't eliminate

			GetTokenInformation(hToken, TokenStatistics, &tokenStat, sizeof tokenStat, &retLen);
			GetTokenInformation(hToken, TokenUser, &tokenUser, sizeof localBuf, &retLen);
			if (LookupAccountSid(NULL, tokenUser.User.Sid, name, &cchName, domainName, &cchDomainName, &use)) {
				*pReturnLen = wsprintfW(
					pathBuffer, L"%s\\%s:%x",
					domainName,
					name, tokenStat.AuthenticationId.LowPart); // (strange) only low part
			}
			CloseHandle(hToken);
		}

	} else if (_wcsicmp(nameBuffer, L"EtwRegistration") == 0) {
		hObject = MyDuplicateHandle(pEntry->UniqueProcessId, pEntry->HandleValue, 0);
		if (hObject)
			CloseHandle(hObject);
	} else if (g_Driver.IsReady()) {
		BOOL bFileObj = (_wcsicmp(nameBuffer, L"file") == 0);
		g_Driver.QueryObjectName(pEntry->UniqueProcessId, (PVOID) pEntry->HandleValue, bFileObj, pEntry->Object,
			pathBuffer, pathBufferSize, pReturnLen);
	} else {
		if (!hObject)
			hObject = MyDuplicateHandle(pEntry->UniqueProcessId, pEntry->HandleValue, 0);
		
		if (hObject) {
			// 据说是为了防止（同步I/O）死锁才创建的新线程
			if (!g_QueryObjectBeginEvent) {
				g_QueryObjectBeginEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
				g_QueryObjectFinishEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			}
			if (!g_QueryObjectThread) {
				g_QueryObjectThread = (HANDLE) _beginthreadex(NULL, 0, QueryObjectThreadFunc, NULL, 0, NULL);
			}
			g_hObject = hObject;

			const int size = 1024;
			g_pObjectInfo = (OBJECT_NAME_INFORMATION *) new BYTE[size];
			memset(g_pObjectInfo, '\0', size);
			g_pObjectInfo->Name.Length = size - sizeof UNICODE_STRING; // 用于传递

			SetEvent(g_QueryObjectBeginEvent);
			if (WaitForSingleObject(g_QueryObjectFinishEvent, 1000) != WAIT_TIMEOUT) {
				if (g_QueryObjectResult == STATUS_SUCCESS) {
					*pReturnLen = wsprintfW(pathBuffer, L"%s", g_pObjectInfo->Name.Buffer);
				}
			} else {
				// 进程看来是卡住了，因此强制结束
				TerminateThread(g_QueryObjectThread, 1); // 会怎样影响WaitForSingleObject?
				CloseHandle(g_QueryObjectThread);
				g_QueryObjectThread = NULL;
			}

			delete[] (BYTE *)g_pObjectInfo; // ? need coerce ?
		}
	}

	if (hObject)
		CloseHandle(hObject);
}

void QueryHandles(DWORD pid, HandleList &hl)
{
	ULONG size;
	NTSTATUS status;
	BYTE *buffer;
	SYSTEM_HANDLE_INFORMATION_EX *pHandles;

	size = 0x10000;
	for (;;) {
		buffer = new BYTE[size];
		status = g_NtQuerySystemInformation(SystemHandleInformationEx, buffer, size, NULL);
		if (status == STATUS_SUCCESS)
			break;
		delete[] buffer;
		size <<= 1;
	}

	pHandles = (SYSTEM_HANDLE_INFORMATION_EX *) buffer;

	g_SPI = ReadSystemProcessInfo();

	WCHAR pathBuffer[1024];
	SIZE_T retLen;

	for (unsigned i = 0; i < pHandles->NumberOfHandles; i++) {
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX *pHandle = &pHandles->Handles[i];
		if (pHandle->UniqueProcessId != pid)
			continue;

		FormatObjectString(g_TypeNameArr[pHandle->ObjectTypeIndex], pHandle, pathBuffer, 1024, &retLen);

		if (pathBuffer[0] == '\0')
			continue;

		LPCWSTR typeName = g_TypeNameArr[pHandle->ObjectTypeIndex];

		if (_wcsicmp(typeName, L"key") == 0) {
			ConvertPath_Reg(pathBuffer);
		} else if (_wcsicmp(typeName, L"file") == 0 || _wcsicmp(typeName, L"section") == 0) {
			ConvertPath_File(pathBuffer);
		}

		HandleInfo *pInfo = new HandleInfo;
		pInfo->pid = pid;
		pInfo->handle = (HANDLE) pHandle->HandleValue;
		pInfo->typeName = typeName;
		wcscpy(pInfo->path, pathBuffer);
		HandleList_Add(hl, pInfo);
	}

	delete[] buffer;

	delete[] g_SPI;
	g_SPI = NULL;
}

void HandleList_Add(HandleList &hl, HandleInfo *pInfo)
{
	hl.push_back(pInfo);
}

void HandleList_Free(HandleList &hl)
{
	struct my_free {
		void operator()(HandleInfo *p) { delete p; }
	};
	std::for_each(hl.begin(), hl.end(), my_free());
	hl.clear();
}
