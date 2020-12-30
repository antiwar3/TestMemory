// TestMemory.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include "remap.h"

typedef void (WINAPI fnTestFun)();
fnTestFun *pfnTestFun = NULL;

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
		if (InitNtApi(hNtModule))
		{

		}
		

		pfnTestFun = (fnTestFun*)GetProcAddress(hModule, "?TestFun@@YAXXZ");
		printf("%I64X %I64X\n", hModule, pfnTestFun);
		
		if (ReMapModule(hModule))
		{
			HANDLE hThread = CreateThread(0, 0, TestThread, 0, 0, 0);
		}
	}
	
	

	getchar();
    return 0;
}

