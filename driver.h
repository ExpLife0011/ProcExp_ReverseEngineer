#pragma once

class DriverAgent
{
public:
	HANDLE m_hDev;

	DriverAgent() : m_hDev(INVALID_HANDLE_VALUE)
	{
	}

	void Init(LPCWSTR driverName);
	void UnInit();
	bool IsReady() { return m_hDev != INVALID_HANDLE_VALUE; }

	HANDLE OpenProcess(ULONG_PTR pid);
	BOOL DuplicateHandle(ULONG_PTR pid, PVOID srcHandle, PVOID *pTargetHandle);
	BOOL QueryObjectType(ULONG_PTR pid, PVOID handle, PVOID objectToMatch, LPWSTR typeBuf, SIZE_T cchTypeBuf);
	BOOL QueryObjectName(ULONG_PTR pid, PVOID handle, BOOL bFileObj, PVOID objectToMatch, LPWSTR nameBuf, SIZE_T cchNameBuf, SIZE_T *pReturnLen);
};

extern DriverAgent g_Driver;
