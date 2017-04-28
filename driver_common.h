#pragma once

#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
	((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define METHOD_BUFFERED                 0
#define METHOD_IN_DIRECT                1
#define METHOD_OUT_DIRECT               2
#define METHOD_NEITHER                  3

#define FILE_ANY_ACCESS                 0
#define FILE_SPECIAL_ACCESS    (FILE_ANY_ACCESS)
#define FILE_READ_ACCESS          ( 0x0001 )    // file & pipe
#define FILE_WRITE_ACCESS         ( 0x0002 )    // file & pipe


#define FILE_DEVICE_PROCEXP 0x8335

const ULONG IOCTL_OPEN_PROCESS =
	CTL_CODE(FILE_DEVICE_PROCEXP, 15, METHOD_BUFFERED, FILE_ANY_ACCESS);
const ULONG IOCTL_DUPLICATE_HANDLE =
	CTL_CODE(FILE_DEVICE_PROCEXP, 5, METHOD_BUFFERED, FILE_ANY_ACCESS);
const ULONG IOCTL_QUERY_OBJECT_TYPE =
	CTL_CODE(FILE_DEVICE_PROCEXP, 19, METHOD_BUFFERED, FILE_ANY_ACCESS);
const ULONG IOCTL_QUERY_OBJECT_NAME =
	CTL_CODE(FILE_DEVICE_PROCEXP, 18, METHOD_BUFFERED, FILE_ANY_ACCESS);

// 32bit:
//   sizeof(ULONG_PTR) = 4
//   sizeof(PVOID) = 4
//   TotalSize = 4 * 4 = 0x10
typedef struct _DUP_HANDLE_PARAM
{
	ULONG_PTR pid;
	PVOID _unk1;
	PVOID _unk2;
	PVOID srcHandle;
} DUP_HANDLE_PARAM;

// same as UP
typedef struct _QUERY_OBJ_PARAM
{
	ULONG_PTR pid;
	PVOID object;
	ULONG_PTR bFileObj;
	PVOID handle;
} QUERY_OBJ_PARAM;

typedef struct _QUERY_OBJ_OUT
{
	DWORD len;
	WCHAR str[1];
} QUERY_OBJ_OUT;

#define DRIVER_NAME L"PROCEXP152"
