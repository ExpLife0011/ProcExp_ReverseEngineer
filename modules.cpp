#include "global.h"
#include "winapi.h"
#include "util.h"
#include "modules.h"

static LPCTSTR s_ModuleTypeStr[] = { _T("Image"), _T("Data") };

static void AddToModuleList(ModuleList &ml, ModuleInfo *pInfo)
{
	ml.push_back(pInfo);
}

void FreeModuleList(ModuleList &ml)
{
	struct my_free {
		void operator()(ModuleInfo *p) { delete p; }
	};
	std::for_each(ml.begin(), ml.end(), my_free());
	ml.clear();
}

static SIZE_T GetModuleSize(HANDLE hProcess, MEMORY_BASIC_INFORMATION &mbi)
{
	SIZE_T regionSize;
	MEMORY_BASIC_INFORMATION mbiAhead;

	regionSize = mbi.RegionSize;

	mbiAhead.BaseAddress = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
	while (VirtualQueryEx(hProcess, mbiAhead.BaseAddress, &mbiAhead, sizeof mbiAhead) > 0 &&
		mbiAhead.AllocationBase == mbi.AllocationBase)
	{
		mbiAhead.BaseAddress = (PBYTE)mbiAhead.BaseAddress + mbiAhead.RegionSize;
		regionSize = (PBYTE)mbiAhead.BaseAddress - (PBYTE)mbi.AllocationBase; // update region length
	}

	return regionSize;
}

static BOOL CheckModuleImage(HANDLE hProcess, MEMORY_BASIC_INFORMATION &mbi, ImageBits *pBits)
{
	BYTE buffer[4096];
	SIZE_T numBytesRead;

	if (!ReadProcessMemory(hProcess, mbi.AllocationBase, buffer, 4096, &numBytesRead))
		return FALSE;
	
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)buffer;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *) g_ImageNtHeader(buffer);
	if (!pNtHeaders)
		return FALSE;

	if ((pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE) == 0 ||
		pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ||
		pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_IA64)
	{
		IMAGE_NT_HEADERS64 *pNtHeaders64 = (IMAGE_NT_HEADERS64 *)pNtHeaders;
		if (pNtHeaders64->OptionalHeader.ImageBase == (ULONGLONG) mbi.AllocationBase) {
			*pBits = Image_64Bit;
			return TRUE;
		}
	}
	else
	{
		IMAGE_NT_HEADERS32 *pNtHeaders32 = (IMAGE_NT_HEADERS32 *)pNtHeaders;
		if (pNtHeaders32->OptionalHeader.ImageBase == (DWORD) mbi.AllocationBase) {
			*pBits = Image_32Bit;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL QueryUserModules(DWORD pid, ModuleList &result)
{
	HANDLE hProcess;
	SIZE_T regionSize;
	MEMORY_BASIC_INFORMATION mbi;
	TCHAR path[MAX_PATH];
	ModuleInfo *pInfo;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	if (hProcess == NULL) {
		printf("OpenProcess error 0x%08X\n", GetLastError());
		return FALSE;
	}

	// 判断目标进程是64位的进程，如果本进程同时是32位进程，那么 失败

	for (mbi.BaseAddress = (PVOID) 0;
		VirtualQueryEx(hProcess, mbi.BaseAddress, &mbi, sizeof mbi) == sizeof mbi;
		mbi.BaseAddress = (PBYTE)mbi.BaseAddress + regionSize)
	{
		regionSize = GetModuleSize(hProcess, mbi);

		if (!(mbi.Type == MEM_MAPPED || mbi.Type == SEC_IMAGE))
			continue;
		if (!g_GetMappedFileName(hProcess, mbi.BaseAddress, path, MAX_PATH))
			continue;
		
		pInfo = new ModuleInfo;
		ConvertPath_File(path);
		wcscpy(pInfo->path, path);
		pInfo->loadAddr = mbi.AllocationBase;
		pInfo->mappedSize = regionSize;
		pInfo->type = CheckModuleImage(hProcess, mbi, &pInfo->imageBits) ? Module_Image : Module_Data;
		AddToModuleList(result, pInfo);
	}

	CloseHandle(hProcess);

	return TRUE;
}

// 在64位系统下，32位程序不能遍历系统的所有模块（指针只能获取到low DWORD
// 所以仍然不允许32位程序遍历系统模块

BOOL QuerySystemModules(ModuleList &result)
{
	ULONG size;
	NTSTATUS status;
	BYTE *buffer;
	RTL_PROCESS_MODULES *pModules;
	ModuleInfo *pInfo;

	status = g_NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &size); // STATUS_INFO_LENGTH_MISMATCH
	buffer = new BYTE[size];
	status = g_NtQuerySystemInformation(SystemModuleInformation, buffer, size, NULL);

	pModules = (RTL_PROCESS_MODULES *) buffer;
	for (unsigned i = 0; i < pModules->NumberOfModules; i++) {
		RTL_PROCESS_MODULE_INFORMATION *pModule = &pModules->Modules[i];
		LPWSTR pUnicodePath;

		if (pModule->ImageBase <= g_SysInfo.lpMaximumApplicationAddress)
			continue;

		pInfo = new ModuleInfo;
		pUnicodePath = AnsiToUnicode(pModule->FullPathName);
		wcscpy(pInfo->path, pUnicodePath);
		ConvertPath_Driver(pInfo->path);
		delete[] pUnicodePath;
		pInfo->loadAddr = pModule->ImageBase;
		pInfo->mappedSize = pModule->ImageSize;
		pInfo->type = Module_Image;
		pInfo->imageBits = g_IsSystem64Bit ? Image_64Bit : Image_32Bit;
		AddToModuleList(result, pInfo);
	}

	delete[] buffer;

	return TRUE;
}
