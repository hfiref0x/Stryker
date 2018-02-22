/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       TEST.C
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

void TestConvert()
{
    WCHAR szBuffer[100];

    PWCHAR		text;
    ULONG_PTR	phy = 0;
    ULONG_PTR value = 0;
    BYTE *temp;

    HANDLE hProcess;
    ULONG_PTR Address = 0;

    BOOLEAN bWasEnabled = FALSE;

    unsigned long long	table;

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
    if (hProcess) {
        supQueryObjectFromHandle(hProcess, &Address, NULL);

        _strcpy(szBuffer, TEXT("\r\nEPROCESS 0x"));
        u64tohex(Address, _strend(szBuffer));
        supPrintText(szBuffer);
        CloseHandle(hProcess);
    }

    if (cpuz_readcrX(3, &value) == 0)
        return;

    _strcpy(szBuffer, TEXT("\r\nCR3 0x"));
    u64tohex(value, _strend(szBuffer));
    supPrintText(szBuffer);

    table = value & 0x000ffffffffff000ull;

    RtlAdjustPrivilege(SE_LOCK_MEMORY_PRIVILEGE, TRUE, FALSE, &bWasEnabled);

    temp = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (temp) {
        if (VirtualLock(temp, 65536)) {
            cpuz_readPhysicalMemory(value, temp, 2048);
            supWriteBufferToFile(L"out.bin", temp, 65536);
            VirtualUnlock(temp, 65536);
        }
        VirtualFree(temp, 65536, MEM_RELEASE);
    }


    _strcpy(szBuffer, TEXT("test message"));

    text = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (VirtualToPhysical((ULONG_PTR)&szBuffer, &phy) != 0)
    {
        cpuz_readPhysicalMemory(phy, text, 64);
        supPrintText(text);
    }
    MessageBox(GetDesktopWindow(), TEXT("Press OK to close"), TEXT(""), MB_OK);
}
