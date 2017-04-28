#include "global.h"
#include "resource.h"
#include "winapi.h"
#include "winapi_loader.h"
#include "util.h"
#include "driver_common.h"
#include "driver.h"
#include "modules.h"
#include "handles.h"

BOOL ParsePID(char *str, DWORD *pPID)
{
	return (sscanf(str, "%d", pPID) == 1);
}

enum Action
{
	Action_ListModules,
	Action_ListHandles
};

#ifdef _WIN64
#define HexFmt "0x%I64X"
#else
#define HexFmt "0x%X"
#endif

int main(int argc, char *argv[])
{
	//printf("%d <-> %d\n", sizeof(ULONG_PTR), sizeof(HANDLE));
	//return 0;

	LoadSystemInfo();

	if (g_Is32BitProgramOn64BitSystem) {
		printf("ERROR: This program is 32-bit. It can't get all information on your 64-bit system due to the address space.\n");
		printf("ERROR: Please rebuild with x64 platform.\n");
		return 0;
	}

	LoadAPI();

	ObtainPrivilege(SE_DEBUG_NAME); // to open system process
	ObtainPrivilege(SE_LOAD_DRIVER_NAME);

	{
		BOOL result;
		TCHAR path[MAX_PATH];
		result = ExtractDriver(MAKEINTRESOURCE(IDR_DRIVER), _T("BINRES"), DRIVER_NAME _T(".SYS"), path);
		if (result) {
			result = LoadDriver(DRIVER_NAME, path);
			DeleteFile(path);
		}
		printf("LoadDrv: %S\n", path);
		printf("LoadDrv: %d\n", result);
	}

	g_Driver.Init(DRIVER_NAME);
	//printf("%d\n", g_Driver.IsReady());

	InitDriverPrefixArray();
	InitRegLookupTable();

	BOOL paramsValid = TRUE;
	Action action;
	DWORD pid;
	if (argc < 3) {
		paramsValid = FALSE;
	} else if (strcmp(argv[1], "modules") == 0) {
		action = Action_ListModules;
		paramsValid = ParsePID(argv[2], &pid);
	} else if (strcmp(argv[1], "handles") == 0) {
		action = Action_ListHandles;
		paramsValid = ParsePID(argv[2], &pid);
	} else {
		paramsValid = FALSE;
	}

	if (!paramsValid) {
		printf("usage: %s action pid\n", argv[0]);
	} else if (action == Action_ListModules) {
		ModuleList ml;
		BOOL b;
		sscanf(argv[2], "%d", &pid);
		if (pid == 4) {
			b = QuerySystemModules(ml);
		} else {
			b = QueryUserModules(pid, ml);
		}
		if (b) {
			struct by_name
			{
				bool operator()(ModuleInfo *pA, ModuleInfo *pB)
				{
					LPCWSTR fileNameA = PathFindFileNameW(pA->path);
					LPCWSTR fileNameB = PathFindFileNameW(pB->path);
					return _wcsicmp(fileNameA, fileNameB) < 0;
				}
			};
			std::sort(ml.begin(), ml.end(), by_name());

			for (unsigned i = 0; i < ml.size(); i++) {
				ModuleInfo *p = ml[i];
				LPCWSTR mapping = (p->type == Module_Image) ? L"Image" : L"Data";
				LPCWSTR imageBit = NULL;
				if (p->type != Module_Image)
					imageBit = L"n/a";
				else if (p->imageBits == Image_32Bit)
					imageBit = L"32-bit";
				else if (p->imageBits == Image_64Bit)
					imageBit = L"64-bit";
				LPCWSTR fileName = PathFindFileNameW(p->path);
				printf(HexFmt "," HexFmt "," "%S,%S,%S,%S\n",
					(ULONG_PTR) p->loadAddr,
					(ULONG_PTR) p->mappedSize,
					mapping,
					imageBit,
					fileName,
					p->path);
			}
		}
		FreeModuleList(ml);
	} else if (action == Action_ListHandles) {
		HandleList hl;
		QueryHandles(pid, hl);
		struct by_type
		{
			bool operator()(HandleInfo *pA, HandleInfo *pB)
			{
				int a = _wcsicmp(pA->typeName, pB->typeName);
				return (a < 0) || (a == 0) && (pA->handle < pB->handle);
			}
		};
		std::sort(hl.begin(), hl.end(), by_type());

		for (unsigned i = 0; i < hl.size(); i++) {
			HandleInfo *p = hl[i];
			printf("%d,%d,%S,%S\n",
				p->pid,
				(DWORD) p->handle,
				p->typeName,
				p->path);
		}
		HandleList_Free(hl);
	}

	g_Driver.UnInit();

	UnloadAPI();
	return 0;
}
