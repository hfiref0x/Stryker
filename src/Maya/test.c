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

    _strcpy(szBuffer, TEXT("test message"));

    text = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (text) {

        if (VirtualToPhysical((ULONG_PTR)&szBuffer, &phy) != 0)
        {
            cpuz_readPhysicalMemory(phy, text, 64);
            supPrintText(text);
        }
    }
    MessageBox(GetDesktopWindow(), TEXT("Press OK to close"), TEXT(""), MB_OK);
}
