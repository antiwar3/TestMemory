#include "stdafx.h"


int GetDllMemorySize(HMODULE hModule)
{
	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER(hModule);
	if (pDosHeader)
	{
		PIMAGE_NT_HEADERS pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pDosHeader + pDosHeader->e_lfanew);
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
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((int)pNTHeader + sizeof(IMAGE_NT_HEADERS));
			
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