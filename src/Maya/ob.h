/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       OB.H
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

#pragma once

//number of buckets in the object directory
#define NUMBEROFBUCKETS 0x25

BOOL ObGetDirectoryObjectAddress(
    _In_opt_ LPWSTR lpDirectory,
    _Inout_ PULONG_PTR lpRootAddress,
    _Inout_opt_ PUSHORT lpTypeIndex);

PVOID ObQueryObject(
    _In_ LPWSTR lpDirectory,
    _In_ LPWSTR lpObjectName);
