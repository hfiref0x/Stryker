/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       SUP.C
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Misc support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* supPrintText
*
* Purpose:
*
* Output text to the console.
*
*/
VOID supPrintText(
    _In_ LPWSTR lpText
)
{
    SIZE_T consoleIO;
    DWORD bytesIO;

    consoleIO = _strlen(lpText);
    WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), lpText, (DWORD)consoleIO, &bytesIO, NULL);
}

/*
* supShowError
*
* Purpose:
*
* Output last error to the console.
*
*/
VOID supShowError(
    _In_ DWORD LastError,
    _In_ LPWSTR Msg
)
{
    LPWSTR lpMsgBuf = NULL;
    DWORD bytesIO;
    WCHAR *OutBuf;
    SIZE_T OutBufLen;

    if (FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, LastError,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPWSTR)&lpMsgBuf, 0, NULL))
    {
        OutBufLen = (20 + _strlen(lpMsgBuf) + _strlen(Msg));
        OutBuf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, OutBufLen * sizeof(WCHAR));
        if (OutBuf) {
            _strcpy(OutBuf, TEXT("\n\r[!] "));
            _strcat(OutBuf, Msg);
            _strcat(OutBuf, TEXT(": "));
            _strcat(OutBuf, lpMsgBuf);
            _strcat(OutBuf, TEXT("\r\n"));
            WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), OutBuf, (DWORD)OutBufLen, &bytesIO, NULL);
        }
        LocalFree(lpMsgBuf);
    }
}

/*
* supWriteBufferToFile
*
* Purpose:
*
* Create new file and write buffer to it.
*
*/
BOOL supWriteBufferToFile(
    _In_ LPWSTR lpFileName,
    _In_ PVOID Buffer,
    _In_ DWORD BufferSize
)
{
    HANDLE hFile;
    DWORD bytesIO = 0;

    if ((Buffer == NULL) || (BufferSize == 0))
        return FALSE;

    hFile = CreateFile(lpFileName,
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);

    if (hFile != INVALID_HANDLE_VALUE) {
        WriteFile(hFile, Buffer, BufferSize, &bytesIO, NULL);
        CloseHandle(hFile);
    }
    else {
        return FALSE;
    }

    return (bytesIO == BufferSize);
}

/*
* supHeapAlloc
*
* Purpose:
*
* Wrapper for RtlAllocateHeap with WinObjEx heap.
*
*/
PVOID FORCEINLINE supHeapAlloc(
    _In_ SIZE_T Size)
{
    return RtlAllocateHeap(NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Size);
}

/*
* supHeapFree
*
* Purpose:
*
* Wrapper for RtlFreeHeap with WinObjEx heap.
*
*/
BOOL FORCEINLINE supHeapFree(
    _In_ PVOID Memory)
{
    return RtlFreeHeap(NtCurrentPeb()->ProcessHeap, 0, Memory);
}

/*
* supGetSystemInfo
*
* Purpose:
*
* Return buffer with system information by given InfoClass.
*
* Returned buffer must be freed with supHeapFree after usage.
* Function will return error after 20 attempts.
*
*/
PVOID supGetSystemInfo(
    _In_ SYSTEM_INFORMATION_CLASS InfoClass
)
{
    INT         c = 0;
    PVOID       Buffer = NULL;
    ULONG       Size = PAGE_SIZE;
    NTSTATUS    status;
    ULONG       memIO;

    do {

        Buffer = supHeapAlloc((SIZE_T)Size);
        if (Buffer != NULL) {
            status = NtQuerySystemInformation(InfoClass, Buffer, Size, &memIO);
        }
        else {
            return NULL;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            supHeapFree(Buffer);
            Buffer = NULL;
            Size *= 2;
            c++;
            if (c > 20) {
                status = STATUS_SECRET_TOO_LONG;
                break;
            }
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    if (NT_SUCCESS(status)) {
        return Buffer;
    }

    if (Buffer) {
        supHeapFree(Buffer);
    }
    return NULL;
}

/*
* supGetNtOsBase
*
* Purpose:
*
* Return ntoskrnl base address.
*
*/
ULONG_PTR supGetNtOsBase(
    VOID
)
{
    PRTL_PROCESS_MODULES   miSpace;
    ULONG_PTR              NtOsBase = 0;

    miSpace = supGetSystemInfo(SystemModuleInformation);
    if (miSpace != NULL) {
        NtOsBase = (ULONG_PTR)miSpace->Modules[0].ImageBase;
        supHeapFree(miSpace);
    }
    return NtOsBase;
}

/*
* supGetModuleBaseByName
*
* Purpose:
*
* Return module base address.
*
*/
ULONG_PTR supGetModuleBaseByName(
    _In_ LPSTR ModuleName
)
{
    ULONG_PTR ReturnAddress = 0;
    ULONG i, k;
    PRTL_PROCESS_MODULES miSpace;

    miSpace = supGetSystemInfo(SystemModuleInformation);
    if (miSpace != NULL) {
        for (i = 0; i < miSpace->NumberOfModules; i++) {
            k = miSpace->Modules[i].OffsetToFileName;
            if (_strcmpi_a(
                (CONST CHAR*)&miSpace->Modules[i].FullPathName[k],
                ModuleName) == 0)
            {
                ReturnAddress = (ULONG_PTR)miSpace->Modules[i].ImageBase;
                break;
            }
        }
        supHeapFree(miSpace);
    }
    return ReturnAddress;
}

/*
* supQueryObjectFromHandle
*
* Purpose:
*
* Return object kernel address from handle in current process handle table.
*
*/
BOOL supQueryObjectFromHandle(
    _In_ HANDLE hOject,
    _Out_ ULONG_PTR *Address,
    _Inout_opt_ USHORT *TypeIndex
)
{
    BOOL   bFound = FALSE;
    ULONG  i;
    DWORD  CurrentProcessId = GetCurrentProcessId();

    PSYSTEM_HANDLE_INFORMATION_EX pHandles;

    if (Address == NULL) {
        return bFound;
    }

    *Address = 0;

    pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
    if (pHandles) {
        for (i = 0; i < pHandles->NumberOfHandles; i++) {
            if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId) {
                if (pHandles->Handles[i].HandleValue == (USHORT)(ULONG_PTR)hOject) {
                    *Address = (ULONG_PTR)pHandles->Handles[i].Object;
                    if (TypeIndex) {
                        *TypeIndex = pHandles->Handles[i].ObjectTypeIndex;
                    }
                    bFound = TRUE;
                    break;
                }
            }
        }
        supHeapFree(pHandles);
    }
    return bFound;
}

/*
* supCopyMemory
*
* Purpose:
*
* Copies bytes between buffers.
*
* dest - Destination buffer
* cbdest - Destination buffer size in bytes
* src - Source buffer
* cbsrc - Source buffer size in bytes
*
*/
void supCopyMemory(
    _Inout_ void *dest,
    _In_ size_t cbdest,
    _In_ const void *src,
    _In_ size_t cbsrc
)
{
    char *d = (char*)dest;
    char *s = (char*)src;

    if ((dest == 0) || (src == 0) || (cbdest == 0))
        return;
    if (cbdest < cbsrc)
        cbsrc = cbdest;

    while (cbsrc > 0) {
        *d++ = *s++;
        cbsrc--;
    }
}
