#include "global.h"
#include "util.h"
#include "driver_common.h"
#include "driver.h"

DriverAgent g_Driver;

void DriverAgent::Init(LPCWSTR driverName)
{
	OpenDriver(driverName, &m_hDev);
}

void DriverAgent::UnInit()
{
	if (m_hDev != INVALID_HANDLE_VALUE)
		::CloseHandle(m_hDev);
}

HANDLE DriverAgent::OpenProcess(ULONG_PTR pid)
{
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	DWORD bytesRet;
	::DeviceIoControl(m_hDev, IOCTL_OPEN_PROCESS, &pid, sizeof(pid), &hProcess, sizeof(hProcess), &bytesRet, NULL);
	return hProcess;
}

BOOL DriverAgent::DuplicateHandle(ULONG_PTR pid, PVOID srcHandle, PVOID *pTargetHandle)
{
	HANDLE targetHandle = INVALID_HANDLE_VALUE;
	DUP_HANDLE_PARAM inBuf;
	inBuf.pid = pid;
	inBuf.srcHandle = srcHandle;

	DWORD bytesRet;
	BOOL b = ::DeviceIoControl(m_hDev, IOCTL_DUPLICATE_HANDLE, &inBuf, sizeof(inBuf), &targetHandle, sizeof(targetHandle), &bytesRet, NULL);
	if (b)
		*pTargetHandle = targetHandle;

	return b;
}

BOOL DriverAgent::QueryObjectType(ULONG_PTR pid, PVOID handle, PVOID objectToMatch, LPWSTR typeBuf, SIZE_T cchTypeBuf)
{
	QUERY_OBJ_PARAM inBuf;
	inBuf.pid = pid;
	inBuf.handle = handle;
	inBuf.object = objectToMatch;
	
	QUERY_OBJ_OUT *pOutBuf;
	const DWORD size = sizeof(pOutBuf->len) + cchTypeBuf * sizeof(WCHAR);
	pOutBuf = (QUERY_OBJ_OUT *) malloc(size);
	
	DWORD bytesRet;
	BOOL b = ::DeviceIoControl(m_hDev, IOCTL_QUERY_OBJECT_TYPE, &inBuf, sizeof(inBuf), pOutBuf, size, &bytesRet, NULL);
	if (b) {
		wcscpy(typeBuf, pOutBuf->str);
	}

	free(pOutBuf);

	return b;
}

BOOL DriverAgent::QueryObjectName(ULONG_PTR pid, PVOID handle, BOOL bFileObj, PVOID objectToMatch, LPWSTR nameBuf, SIZE_T cchNameBuf, SIZE_T *pReturnLen)
{
	QUERY_OBJ_PARAM inBuf;
	inBuf.pid = pid;
	inBuf.handle = handle;
	inBuf.bFileObj = bFileObj;
	inBuf.object = objectToMatch;

	QUERY_OBJ_OUT *pOutBuf;
	const DWORD size = sizeof(pOutBuf->len) + cchNameBuf * sizeof(WCHAR);
	pOutBuf = (QUERY_OBJ_OUT *) malloc(size);

	DWORD bytesRet;
	BOOL b = ::DeviceIoControl(m_hDev, IOCTL_QUERY_OBJECT_NAME, &inBuf, sizeof(inBuf), pOutBuf, size, &bytesRet, NULL);
	if (b) {
		wcscpy(nameBuf, pOutBuf->str);
		if (pReturnLen)
			*pReturnLen = pOutBuf->len;
	}

	free(pOutBuf);

	return b;
}
