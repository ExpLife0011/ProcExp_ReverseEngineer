#pragma once
#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0501

#include <stdio.h>
#include <tchar.h>
#include <process.h> // _beginthreadex, _endthreadex
#include <Windows.h>
#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

#define STRSAFE_NO_DEPRECATE
#include <strsafe.h>

#include <vector>
#include <algorithm>
