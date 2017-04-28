#pragma once
struct HandleInfo
{
	DWORD pid;
	HANDLE handle;
	LPCWSTR typeName;
	WCHAR path[1024];
};

typedef std::vector<HandleInfo *> HandleList;
void HandleList_Add(HandleList &hl, HandleInfo *pInfo);
void HandleList_Free(HandleList &hl);

void QueryHandles(DWORD pid, HandleList &hl);
