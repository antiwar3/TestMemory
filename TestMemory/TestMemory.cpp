// TestMemory.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include "windows.h"

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT * Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef ULONG(WINAPI fnNtUnmapViewOfSection)(IN HANDLE ProcessHandle, IN PVOID BaseAddress);
typedef NTSTATUS(WINAPI fnNtCreateSection)(
	OUT PHANDLE  SectionHandle,
	IN ACCESS_MASK  DesiredAccess,
	IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER  MaximumSize OPTIONAL,
	IN ULONG  SectionPageProtection,
	IN ULONG  AllocationAttributes,
	IN HANDLE  FileHandle OPTIONAL
	);

typedef NTSTATUS(NTAPI
	fnNtMapViewOfSection)
(
	_In_        HANDLE          SectionHandle,
	_In_        HANDLE          ProcessHandle,
	_Inout_     PVOID           *BaseAddress,
	_In_        ULONG_PTR       ZeroBits,
	_In_        SIZE_T          CommitSize,
	_Inout_opt_ PLARGE_INTEGER  SectionOffset,
	_Inout_     PSIZE_T         ViewSize,
	_In_        SECTION_INHERIT InheritDisposition,
	_In_        ULONG           AllocationType,
	_In_        ULONG           Win32Protect
);
typedef void (WINAPI fnTestFun)();

fnTestFun *pfnTestFun = NULL;
fnNtUnmapViewOfSection *pfnNtUnmapViewOfSection = NULL;
fnNtCreateSection *pfnNtCreateSection = NULL;
fnNtMapViewOfSection *pfnNtMapViewOfSection = NULL;
int GetDllMemorySize(HMODULE hModule);

DWORD WINAPI TestThread(LPVOID lp)
{
	if (pfnTestFun)
	{
		while (1)
		{
			pfnTestFun();
			Sleep(5000);
		}
	}
	return 0;
}

int main()
{

	HMODULE hModule = LoadLibraryA("TestMemoryDll");
	HMODULE hNtModule = LoadLibraryA("ntdll.DLL");
	if (hModule&&hNtModule)
	{
		printf("%x\n", hModule);

		pfnTestFun = (fnTestFun*)GetProcAddress(hModule, "?TestFun@@YGXXZ");
		pfnNtUnmapViewOfSection = (fnNtUnmapViewOfSection*)GetProcAddress(hNtModule, "NtUnmapViewOfSection");
		pfnNtCreateSection = (fnNtCreateSection *)GetProcAddress(hNtModule, "ZwCreateSection");
		pfnNtMapViewOfSection = (fnNtMapViewOfSection*)GetProcAddress(hNtModule, "NtMapViewOfSection");
		DWORD dwImage = GetDllMemorySize(hModule);
		PVOID copybuf = VirtualAlloc(NULL, dwImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		SIZE_T numberOfBytesRead = 0;
		ReadProcessMemory(GetCurrentProcess(), hModule, copybuf, dwImage, &numberOfBytesRead);

		ULONG uRet = pfnNtUnmapViewOfSection(GetCurrentProcess(), hModule);

		HANDLE hSection = NULL;
		LARGE_INTEGER sectionMaxSize = {};
		sectionMaxSize.QuadPart = dwImage;
		NTSTATUS st =  pfnNtCreateSection(&hSection,
			SECTION_ALL_ACCESS,
			NULL,
			&sectionMaxSize,
			PAGE_EXECUTE_READWRITE,
			SEC_COMMIT,
			NULL);

		PVOID viewBase = hModule;
		LARGE_INTEGER sectionOffset = {};

		SIZE_T viewSize = 0;
		pfnNtMapViewOfSection(hSection,
			GetCurrentProcess(),
			&viewBase,
			0,
			dwImage,
			&sectionOffset,
			&viewSize,
			ViewUnmap,
			0,
			PAGE_EXECUTE_READWRITE);
		SIZE_T numberOfBytesWritten = 0;
		WriteProcessMemory(GetCurrentProcess(), viewBase, copybuf, viewSize, &numberOfBytesWritten);

		pfnNtUnmapViewOfSection(GetCurrentProcess(), hModule);

		pfnNtMapViewOfSection(hSection,
			GetCurrentProcess(),
			&viewBase,
			0,
			dwImage,
			&sectionOffset,
			&viewSize,
			ViewUnmap,
			0,
			PAGE_EXECUTE_READ);

		VirtualFree(copybuf, 0, MEM_RELEASE);

	}
	HANDLE hThread = CreateThread(0, 0, TestThread, 0, 0, 0);


	getchar();
    return 0;
}

