/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       READWRT.H
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Prototypes and definitions for CPU-Z IOCTL requests.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define CPUZDRV L"cpuz141"

#define LODWORD(x) ((DWORD)((DWORDLONG)(x)))
#define HIDWORD(x) ((DWORD)(((DWORDLONG)(x) >> 32) & 0xffffffff))

#define CPUZ_DEVICE_TYPE                (DWORD)40000

#define CPUZ_READ_PHYSMEMORY_FUNCTION   (DWORD)2312
#define CPUZ_READ_CRX_FUNCTION          (DWORD)2314
#define CPUZ_WRITE_PHYSMEMORY_FUNCTION  (DWORD)2316

#define IOCTL_CPUZ_READ_CRX_REGISTER        CTL_CODE(CPUZ_DEVICE_TYPE, CPUZ_READ_CRX_FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9C402428
#define IOCTL_CPUZ_READ_PHYSICAL_MEMORY     CTL_CODE(CPUZ_DEVICE_TYPE, CPUZ_READ_PHYSMEMORY_FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9C402420
#define IOCTL_CPUZ_WRITE_PHYSICAL_MEMORY    CTL_CODE(CPUZ_DEVICE_TYPE, CPUZ_WRITE_PHYSMEMORY_FUNCTION, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9C402430

#define CTL_CODE_TO_VALUES(ControlCode, DeviceType, Access, Function, Method ) (\
    DeviceType = ((DWORD)ControlCode & 0xffff0000) >> 16,\
    Access = ((DWORD)ControlCode & 0x0000c000) >> 14, \
    Function = ((DWORD)ControlCode & 0x00003ffc) >> 2,\
    Method = ((DWORD)ControlCode & 0x00000003)\
)

typedef struct _READ_ADDRESS {

    struct {
        ULONG HighPart;
        ULONG LowPart;
    } InputAddress;

    ULONG OutputBufferLength;

    struct {
        ULONG HighPart;
        ULONG LowPart;
    } OutputBuffer;

} READ_ADDRESS, *PREAD_ADDRESS;

typedef struct _WRITE_ADDRESS_ULONG {

    struct {
        ULONG HighPart;
        ULONG LowPart;
    } Address;

    ULONG Value;

} WRITE_ADDRESS_ULONG, *PWRITE_ADDRESS_ULONG;

typedef struct _OUT_DATA {
    ULONG OperationCode;
    ULONG BufferLowPart;
} OUT_DATA, *POUT_DATA;

BOOL cpuz_readcrX(
    _In_ ULONG Index,
    _Out_ PDWORD_PTR Value);

BOOL cpuz_readPhysicalMemory(
    _In_ DWORD_PTR PhysicalAddress,
    _In_ PVOID Buffer,
    _In_ DWORD BufferLength);

BOOL cpuz_readVirtualMemory(
    _In_ DWORD_PTR VirtualAddress,
    _In_ PVOID Buffer,
    _In_ DWORD BufferLength);

BOOL cpuz_writePhysicalMemory(
    _In_ DWORD_PTR PhysicalAddress,
    _In_ PDWORD Buffer,
    _In_ DWORD BufferLength);

BOOL cpuz_WriteVirtualMemory(
    _In_ DWORD_PTR VirtualAddress,
    _In_ PVOID Buffer,
    _In_ DWORD BufferLength);
