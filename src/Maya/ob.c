/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       OB.C
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Object Manager support routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

typedef enum _OBJ_HEADER_INFO_FLAG {
    HeaderCreatorInfoFlag = 0x1,
    HeaderNameInfoFlag = 0x2,
    HeaderHandleInfoFlag = 0x4,
    HeaderQuotaInfoFlag = 0x8,
    HeaderProcessInfoFlag = 0x10
} OBJ_HEADER_INFO_FLAG;

/*
* ObpGetObjectHeaderOffset
*
* Purpose:
*
* Query requested structure offset for the given mask.
*
*
* Object In Memory Disposition
*
* POOL_HEADER
* OBJECT_HEADER_PROCESS_INFO
* OBJECT_HEADER_QUOTA_INFO
* OBJECT_HEADER_HANDLE_INFO
* OBJECT_HEADER_NAME_INFO
* OBJECT_HEADER_CREATOR_INFO
* OBJECT_HEADER
*
*/
BYTE ObpGetObjectHeaderOffset(
    _In_ BYTE InfoMask,
    _In_ OBJ_HEADER_INFO_FLAG Flag
)
{
    BYTE OffsetMask, HeaderOffset = 0;

    if ((InfoMask & Flag) == 0)
        return 0;

    OffsetMask = InfoMask & (Flag | (Flag - 1));

    if ((OffsetMask & HeaderCreatorInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_CREATOR_INFO);

    if ((OffsetMask & HeaderNameInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_NAME_INFO);

    if ((OffsetMask & HeaderHandleInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_HANDLE_INFO);

    if ((OffsetMask & HeaderQuotaInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_QUOTA_INFO);

    if ((OffsetMask & HeaderProcessInfoFlag) != 0)
        HeaderOffset += (BYTE)sizeof(OBJECT_HEADER_PROCESS_INFO);

    return HeaderOffset;
}

/*
* ObpHeaderToNameInfoAddress
*
* Purpose:
*
* Calculate address of name structure from object header flags and object address.
*
*/
BOOL ObpHeaderToNameInfoAddress(
    _In_ UCHAR ObjectInfoMask,
    _In_ ULONG_PTR ObjectAddress,
    _Inout_ PULONG_PTR HeaderAddress,
    _In_ OBJ_HEADER_INFO_FLAG InfoFlag
)
{
    BYTE      HeaderOffset;
    ULONG_PTR Address;

    if (HeaderAddress == NULL)
        return FALSE;

    HeaderOffset = ObpGetObjectHeaderOffset(ObjectInfoMask, InfoFlag);
    if (HeaderOffset == 0)
        return FALSE;

    Address = ObjectAddress - HeaderOffset;

    *HeaderAddress = Address;
    return TRUE;
}

/*
* ObpQueryNameString
*
* Purpose:
*
* Reads object name from kernel memory, returned buffer must be freed with supHeapFree.
*
*/
LPWSTR ObpQueryNameString(
    _In_ ULONG_PTR NameInfoAddress,
    _Out_opt_ PSIZE_T ReturnLength
)
{
    ULONG  fLen;
    LPWSTR lpObjectName = NULL;

    OBJECT_HEADER_NAME_INFO NameInfo;

    if (ReturnLength)
        *ReturnLength = 0;
  
    RtlSecureZeroMemory(&NameInfo, sizeof(OBJECT_HEADER_NAME_INFO));
    if (cpuz_readVirtualMemory(NameInfoAddress, &NameInfo, sizeof(OBJECT_HEADER_NAME_INFO))) {
        fLen = NameInfo.Name.Length + sizeof(UNICODE_NULL);
        lpObjectName = supHeapAlloc(fLen);
        if (lpObjectName != NULL) {
            NameInfoAddress = (ULONG_PTR)NameInfo.Name.Buffer;
            if (cpuz_readVirtualMemory(NameInfoAddress, lpObjectName, NameInfo.Name.Length)) {
                if (ReturnLength)
                    *ReturnLength = fLen;
            }
            else {
                supHeapFree(lpObjectName);
                lpObjectName = NULL;
            }
        }
    }
    return lpObjectName;
}

/*
* ObGetDirectoryObjectAddress
*
* Purpose:
*
* Return directory object kernel address.
*
*/
BOOL ObGetDirectoryObjectAddress(
    _In_opt_ LPWSTR lpDirectory,
    _Inout_ PULONG_PTR lpRootAddress,
    _Inout_opt_ PUSHORT lpTypeIndex
)
{
    BOOL                bFound = FALSE;
    HANDLE              hDirectory = NULL;
    NTSTATUS            status;
    LPWSTR              lpTarget;
    OBJECT_ATTRIBUTES   objattr;
    UNICODE_STRING      objname;

    if (lpRootAddress == NULL)
        return bFound;

    if (lpDirectory == NULL) {
        lpTarget = L"\\";
    }
    else {
        lpTarget = lpDirectory;
    }
    RtlSecureZeroMemory(&objname, sizeof(objname));
    RtlInitUnicodeString(&objname, lpTarget);
    InitializeObjectAttributes(&objattr, &objname, OBJ_CASE_INSENSITIVE, NULL, NULL);
    status = NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &objattr);
    if (!NT_SUCCESS(status))
        return bFound;

    bFound = supQueryObjectFromHandle(hDirectory, lpRootAddress, lpTypeIndex);
    NtClose(hDirectory);
    return bFound;
}

/*
* ObpWalkDirectory
*
* Purpose:
*
* Walks given directory and looks for specified object inside.
* Return value is the kernel address of object to find.
* Simplified version from WinObjEx64
*
*/
PVOID ObpWalkDirectory(
    _In_ LPWSTR lpObjectToFind,
    _In_ ULONG_PTR DirectoryAddress
)
{
    BOOL      bFound;
    INT       c;
    SIZE_T    retSize;
    LPWSTR    lpObjectName;
    ULONG_PTR ObjectHeaderAddress, item0, item1, InfoHeaderAddress;

    OBJECT_HEADER          ObjectHeader;
    OBJECT_DIRECTORY       DirObject;
    OBJECT_DIRECTORY_ENTRY Entry;

    __try {

        if (lpObjectToFind == NULL)
            return NULL;

        RtlSecureZeroMemory(&DirObject, sizeof(OBJECT_DIRECTORY));
        if (!cpuz_readVirtualMemory(DirectoryAddress, &DirObject, sizeof(OBJECT_DIRECTORY))) {

#ifdef _DEBUG
            OutputDebugString(L"cpuz_readVirtualMemory(DirectoryAddress) failed");
#endif
            return NULL;
        }

        lpObjectName = NULL;
        retSize = 0;
        bFound = FALSE;

        for (c = 0; c < NUMBEROFBUCKETS; c++) {

            item0 = (ULONG_PTR)DirObject.HashBuckets[c];
            if (item0 != 0) {

                item1 = item0;
                do {

                    //read object directory entry
                    RtlSecureZeroMemory(&Entry, sizeof(OBJECT_DIRECTORY_ENTRY));
                    if (!cpuz_readVirtualMemory(item1, &Entry, sizeof(OBJECT_DIRECTORY_ENTRY))) {

#ifdef _DEBUG
                        OutputDebugString(L"cpuz_readVirtualMemory(OBJECT_DIRECTORY_ENTRY) failed");
#endif
                        break;
                    }

                    //read object header
                    RtlSecureZeroMemory(&ObjectHeader, sizeof(OBJECT_HEADER));
                    ObjectHeaderAddress = (ULONG_PTR)OBJECT_TO_OBJECT_HEADER(Entry.Object);
                    if (!cpuz_readVirtualMemory(ObjectHeaderAddress, &ObjectHeader, sizeof(OBJECT_HEADER))) {

#ifdef _DEBUG
                        OutputDebugString(L"cpuz_readVirtualMemory(ObjectHeaderAddress) failed");
#endif
                        goto NextItem;
                    }

                    //check if object has name
                    InfoHeaderAddress = 0;
                    retSize = 0;
                    if (!ObpHeaderToNameInfoAddress(ObjectHeader.InfoMask, ObjectHeaderAddress, 
                        &InfoHeaderAddress, HeaderNameInfoFlag))
                    {
                        goto NextItem;
                    }

                    //object has name, query it
                    lpObjectName = ObpQueryNameString(InfoHeaderAddress, &retSize);
                    if ((lpObjectName == NULL) || (retSize == 0))
                        goto NextItem;

                    //compare full object names
                    bFound = (_strcmpi(lpObjectName, lpObjectToFind) == 0);
                    supHeapFree(lpObjectName);
                    if (bFound == FALSE) {
                        goto NextItem;
                    }
                    //identical, return object address
                    return Entry.Object;

                NextItem:
                    if (bFound)
                        break;

                    item1 = (ULONG_PTR)Entry.ChainLink;
                } while (item1 != 0);
            }
            if (bFound)
                break;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return NULL;
}

/*
* ObQueryObject
*
* Purpose:
*
* Look for object inside specified directory.
*
*/
PVOID ObQueryObject(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpObjectName
)
{
    BOOL       needFree = FALSE;
    ULONG_PTR  DirectoryAddress;
    SIZE_T     i, l, rdirLen, ldirSz;
    LPWSTR     SingleDirName, LookupDirName;

    __try {

        LookupDirName = lpDirectory;

        l = 0;
        rdirLen = _strlen(lpDirectory);
        for (i = 0; i < rdirLen; i++) {
            if (lpDirectory[i] == '\\')
                l = i + 1;
        }
        SingleDirName = &lpDirectory[l];
        if (_strcmpi(SingleDirName, lpObjectName) == 0) {

            ldirSz = rdirLen * sizeof(WCHAR) + sizeof(UNICODE_NULL);
            LookupDirName = supHeapAlloc(ldirSz);
            if (LookupDirName == NULL)
                return NULL;

            needFree = TRUE;

            if (l == 1) l++;

            supCopyMemory(LookupDirName, ldirSz, lpDirectory, (l - 1) * sizeof(WCHAR));
        }

        DirectoryAddress = 0;
        if (ObGetDirectoryObjectAddress(LookupDirName, &DirectoryAddress, NULL)) {

            if (needFree)
                supHeapFree(LookupDirName);

            return ObpWalkDirectory(lpObjectName, DirectoryAddress);
        }
    }

    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
    return NULL;
}
