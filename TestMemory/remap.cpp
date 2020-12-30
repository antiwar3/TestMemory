#include "remap.h"
#include "stdio.h"
fnNtUnmapViewOfSection *pfnNtUnmapViewOfSection = NULL;
fnNtCreateSection *pfnNtCreateSection = NULL;
fnNtMapViewOfSection *pfnNtMapViewOfSection = NULL;
fnNtQueryInformationProcess *pfnNtQueryInformationProcess = NULL;
fnRtlAcquirePrivilege *pfnRtlAcquirePrivilege = NULL;
fnNtSetInformationProcess *pfnNtSetInformationProcess = NULL;
fnRtlReleasePrivilege *pfnRtlReleasePrivilege = NULL;
fnNtLockVirtualMemory*pfnNtLockVirtualMemory = NULL;
fnNtProtectVirtualMemory*pfnNtProtectVirtualMemory = NULL;

int GetDllMemorySize(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(hModule);
	if (pDosHeader)
	{
		PIMAGE_NT_HEADERS64 pNTHeader = (PIMAGE_NT_HEADERS64)((DWORD64)hModule + pDosHeader->e_lfanew);
		if (pNTHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			int result = 0;
			int alignment = pNTHeader->OptionalHeader.SectionAlignment;
			if (pNTHeader->OptionalHeader.SizeOfHeaders % alignment == 0)
			{

				result += pNTHeader->OptionalHeader.SizeOfHeaders;
			}
			else
			{
				int val = pNTHeader->OptionalHeader.SizeOfHeaders / alignment;
				val++;
				result += (val * alignment);
			}
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD64)pNTHeader + sizeof(IMAGE_NT_HEADERS64));

			for (int i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
			{

				if (pSectionHeader[i].Misc.VirtualSize)
				{
					if (pSectionHeader[i].Misc.VirtualSize % alignment == 0)
						result += pSectionHeader[i].Misc.VirtualSize;
					else
					{
						int val = pSectionHeader[i].Misc.VirtualSize / alignment;
						val++;
						result += (val * alignment);
					}
				}
			}
			return result;
		}
	}
}

//-------------------------------------------------------
//	Extend WorkingSet size to lock memory
//-------------------------------------------------------
VOID ExtendWorkingSet(HANDLE hProcess)
{
	QUOTA_LIMITS ql;
	DWORD PrivilegeValue = SE_AUDIT_PRIVILEGE;
	PVOID PrivilegeState = NULL;

	pfnNtQueryInformationProcess(hProcess, ProcessQuotaLimits, &ql, sizeof(ql), NULL);

	ql.MinimumWorkingSetSize += PAGE_SIZE;
	if (ql.MaximumWorkingSetSize < ql.MinimumWorkingSetSize)
		ql.MaximumWorkingSetSize = ql.MinimumWorkingSetSize;

	pfnRtlAcquirePrivilege(&PrivilegeValue, 1, 0, &PrivilegeState);
	pfnNtSetInformationProcess(hProcess, ProcessQuotaLimits, &ql, sizeof(ql));
	pfnRtlReleasePrivilege(PrivilegeState);
}


BOOL InitNtApi(HMODULE hNtModule)
{
	BOOL bRet = FALSE;
	pfnNtUnmapViewOfSection = (fnNtUnmapViewOfSection*)GetProcAddress(hNtModule, "NtUnmapViewOfSection");
	pfnNtCreateSection = (fnNtCreateSection *)GetProcAddress(hNtModule, "ZwCreateSection");
	pfnNtMapViewOfSection = (fnNtMapViewOfSection*)GetProcAddress(hNtModule, "NtMapViewOfSection");
	pfnNtQueryInformationProcess = (fnNtQueryInformationProcess*)GetProcAddress(hNtModule, "NtQueryInformationProcess");
	pfnRtlAcquirePrivilege = (fnRtlAcquirePrivilege*)GetProcAddress(hNtModule, "RtlAcquirePrivilege");
	pfnNtSetInformationProcess = (fnNtSetInformationProcess*)GetProcAddress(hNtModule, "NtSetInformationProcess");
	pfnRtlReleasePrivilege = (fnRtlReleasePrivilege*)GetProcAddress(hNtModule, "RtlReleasePrivilege");
	pfnNtLockVirtualMemory = (fnNtLockVirtualMemory*)GetProcAddress(hNtModule, "NtLockVirtualMemory");
	pfnNtProtectVirtualMemory = (fnNtProtectVirtualMemory*)GetProcAddress(hNtModule, "NtProtectVirtualMemory");
	if (pfnNtUnmapViewOfSection)
		if (pfnNtCreateSection)
			if (pfnNtMapViewOfSection)
				if (pfnNtQueryInformationProcess)
					if (pfnRtlAcquirePrivilege)
						if (pfnNtSetInformationProcess)
							if (pfnRtlReleasePrivilege)
								if(pfnNtLockVirtualMemory)
									if(pfnNtProtectVirtualMemory)
								bRet = TRUE;


	return bRet;
}

BOOL ReMapModule(HMODULE hModule)
{
	BOOL bRet = FALSE;
	
	DWORD64					LockSize = 1;
	DWORD64 ExecuteSize = 0;
	DWORD64 ReadOnlySize = 0;


	DWORD dwImage = GetDllMemorySize(hModule);

	PVOID copybuf = VirtualAlloc(NULL, dwImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	SIZE_T numberOfBytesRead = 0;
	ReadProcessMemory(GetCurrentProcess(), hModule, copybuf, dwImage, &numberOfBytesRead);
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(copybuf);
	PIMAGE_NT_HEADERS64		pNtHeader = PIMAGE_NT_HEADERS64((DWORD64)copybuf + (DWORD)(pDosHeader->e_lfanew));


	PIMAGE_SECTION_HEADER	pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
	HANDLE hSection = NULL;
	LARGE_INTEGER sectionMaxSize = {};
	sectionMaxSize.QuadPart = dwImage;
	NTSTATUS st = pfnNtCreateSection(&hSection,
		SECTION_ALL_ACCESS,
		NULL,
		&sectionMaxSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL);

	LARGE_INTEGER sectionOffset = {};
	PVOID viewBase = 0;
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

	ULONG uRet = pfnNtUnmapViewOfSection(GetCurrentProcess(), hModule);

	if (pNtHeader->OptionalHeader.SectionAlignment == AllocationGranularity)
	{
		
		MessageBoxA(0, 0, 0, 0);
		viewBase = hModule;
		DWORD ViewSize = AllocationGranularity;
		pfnNtMapViewOfSection(hSection, GetCurrentProcess(), &viewBase, NULL, NULL, NULL, (PSIZE_T)&ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_READONLY);
		while (pfnNtLockVirtualMemory(GetCurrentProcess(), &viewBase, (ULONG)&LockSize, (PULONG)1) == STATUS_WORKING_SET_QUOTA)
			ExtendWorkingSet(GetCurrentProcess());
		for (DWORD i = 0, Protect; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			// Calculate size and get page protection
			viewBase = hModule + pSectionHeader[i].VirtualAddress;
			ViewSize = PADDING(pSectionHeader[i].Misc.VirtualSize, AllocationGranularity);
			sectionMaxSize.QuadPart = pSectionHeader[i].VirtualAddress;
			if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)		Protect = PAGE_EXECUTE_READ;
			else if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)	Protect = PAGE_READWRITE;
			else																Protect = PAGE_READONLY;
			pfnNtMapViewOfSection(hSection, GetCurrentProcess(), &viewBase, NULL, NULL, NULL, (PSIZE_T)&ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_EXECUTE_READ);
		
			pfnNtMapViewOfSection(hSection, GetCurrentProcess(), &viewBase, NULL, NULL, &sectionMaxSize, (PSIZE_T)&ViewSize, ViewUnmap, SEC_NO_CHANGE, Protect);

	
			while (pfnNtLockVirtualMemory(GetCurrentProcess(), &viewBase, (ULONG)&LockSize, (PULONG)1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(GetCurrentProcess());
			bRet = TRUE;
		}
	}
	else
	{
		
		for (DWORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
				ExecuteSize += PADDING(pSectionHeader[i].Misc.VirtualSize, PAGE_SIZE);
			else
			{
				ReadOnlySize = PADDING(pSectionHeader[i].Misc.VirtualSize, PAGE_SIZE);
				ExecuteSize += PAGE_SIZE;
				break;
			}
		}
		pfnNtUnmapViewOfSection(GetCurrentProcess(), hModule);
		viewBase = hModule;

		if (ExecuteSize + ReadOnlySize >= AllocationGranularity && ExecuteSize + ReadOnlySize >= PADDING(ExecuteSize, AllocationGranularity))
		{

			// 7. Remap with SEC_NO_CHANGE flag and PAGE_EXECUTE_READ (.text + .rdata section)
			DWORD ViewSize = PADDING(ExecuteSize, AllocationGranularity);
			pfnNtMapViewOfSection(hSection, GetCurrentProcess(), &viewBase, NULL, NULL, NULL, (PSIZE_T)&ViewSize, ViewUnmap, SEC_NO_CHANGE, PAGE_EXECUTE_READ);
			while (pfnNtLockVirtualMemory(GetCurrentProcess(), &viewBase, (ULONG)&LockSize, (PULONG)1) == STATUS_WORKING_SET_QUOTA)
				ExtendWorkingSet(GetCurrentProcess());

			// 7. Remap with PAGE_READWRITE (writable section)
			sectionMaxSize.QuadPart = ViewSize;
			PVOID ViewBase = hModule + ViewSize;
			ViewSize = dwImage - ViewSize;
			pfnNtMapViewOfSection(hSection, GetCurrentProcess(), &ViewBase, NULL, NULL, &sectionMaxSize, (PSIZE_T)&ViewSize, ViewUnmap, NULL, PAGE_READWRITE);
		}
		//This module is  but too small size to remap with PAGE_EXECUTE_READ
		else
			pfnNtMapViewOfSection(hSection, GetCurrentProcess(), (PVOID*)&hModule, NULL, NULL, NULL, (PSIZE_T)&sectionMaxSize, ViewUnmap, NULL, PAGE_EXECUTE_WRITECOPY);

		// Restore page protection
		DWORD OldProtect = 0;
		DWORD64 Size = PAGE_SIZE;
		PVOID Address = (PVOID)hModule;
		pfnNtProtectVirtualMemory(GetCurrentProcess(), &Address, (ULONG*)&Size, PAGE_READONLY, &OldProtect);
		for (DWORD i = 0, Protect; i < pNtHeader->FileHeader.NumberOfSections; i++)
		{
			if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)		Protect = PAGE_EXECUTE_READ;
			else if (pSectionHeader[i].Characteristics & IMAGE_SCN_MEM_WRITE)	Protect = PAGE_WRITECOPY;
			else																Protect = PAGE_READONLY;
			OldProtect = 0;
			Size = pSectionHeader[i].Misc.VirtualSize;
			Address = (PVOID)(hModule + pSectionHeader[i].VirtualAddress);
			pfnNtProtectVirtualMemory(GetCurrentProcess(), &Address, (ULONG*)&Size, Protect, &OldProtect);
		}

		// 8. Lock memory (.text section)
		viewBase = (PVOID)((DWORD64)viewBase + PAGE_SIZE);
		while (pfnNtLockVirtualMemory(GetCurrentProcess(), &viewBase, (ULONG)&LockSize, (PULONG)1) == STATUS_WORKING_SET_QUOTA)
			ExtendWorkingSet(GetCurrentProcess());
		bRet = TRUE;

	}
	VirtualFree(copybuf, 0, MEM_RELEASE);
	return bRet;
}