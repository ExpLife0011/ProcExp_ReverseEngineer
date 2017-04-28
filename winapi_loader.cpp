#include "global.h"
#include "winapi.h"

#pragma warning(disable: 4200) // nonstandard extension used : zero-sized array in struct/union

struct API_ENTRY {
	LPCSTR name;
	PVOID *pVar;
	BOOL bOptional;
};

#define ENTRY(s) { #s, (PVOID*) &g_##s, FALSE }
#define ENTRY_T(s) { #s "W", (PVOID*) &g_##s, FALSE }
#define ENTRY_END { NULL, NULL }

struct LIB_DESC {
	LPCTSTR fileName;
	API_ENTRY api[0];
};

#define LOG(...) wsprintf(__VA_ARGS__)

////////////////////////////////////////

static LIB_DESC ntdll = {
	_T("ntdll.dll"),
	{
		ENTRY(RtlInitUnicodeString),
		ENTRY(RtlNtStatusToDosError),
		ENTRY(NtLoadDriver),
		ENTRY(NtQueryInformationProcess),
		ENTRY(NtQueryInformationThread),
		ENTRY(NtQueryObject),
		ENTRY(NtQuerySystemInformation),
		ENTRY(NtQueryInformationProcess),
		ENTRY(NtOpenDirectoryObject),
		ENTRY(NtOpenSymbolicLinkObject),
		ENTRY(NtQuerySymbolicLinkObject),
		ENTRY_END
	}
};

static LIB_DESC psapi = {
	_T("psapi.dll"),
	{
		ENTRY_T(GetMappedFileName),
		ENTRY_END
	}
};

static LIB_DESC dbghelp = {
	_T("dbghelp.dll"),
	{
		ENTRY(ImageNtHeader),
		ENTRY_END
	}
};

static LIB_DESC *libraries[] = {
	&ntdll,
	&psapi,
	&dbghelp
};

static HMODULE libraries_mod[_countof(libraries)];

BOOL LoadAPI()
{
	BOOL result = TRUE;

	for (int i = 0; i < _countof(libraries); i++) {
		LIB_DESC *pLib = libraries[i];
		HMODULE hMod = LoadLibrary(pLib->fileName);
		libraries_mod[i] = hMod;
		if (!hMod) {
			LOG(_T("LoadLibrary(%s) failed\n"), pLib->fileName);
			result = FALSE;
			continue;
		}
		
		API_ENTRY *pEntry = &pLib->api[0];
		while (pEntry->name) {
			FARPROC proc = GetProcAddress(hMod, pEntry->name);
			if (!proc) {
				LOG(_T("GetProcAddress(%s, %hs) failed\n"), pLib->fileName, pEntry->name);
				result = FALSE;
			}
			*pEntry->pVar = (PVOID) proc;
			pEntry++;
		}
	}

	return result;
}

void UnloadAPI()
{
	for (int i = 0; i < _countof(libraries_mod); i++) {
		FreeLibrary(libraries_mod[i]);
	}
}
