#pragma once

enum ModuleType
{
	Module_Image,
	Module_Data
};

enum ImageBits
{
	Image_Unknown,
	Image_32Bit,
	Image_64Bit
};

struct ModuleInfo
{
	WCHAR path[MAX_PATH];
	PVOID loadAddr;
	SIZE_T mappedSize;
	ModuleType type;
	ImageBits imageBits;
};

typedef std::vector<ModuleInfo *> ModuleList;

void FreeModuleList(ModuleList &ml);
BOOL QueryUserModules(DWORD pid, ModuleList &result);
BOOL QuerySystemModules(ModuleList &result);
