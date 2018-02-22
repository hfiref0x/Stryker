/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       CI.H
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  CI prototypes and definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#define NTOSKRNL_EXE    "ntoskrnl.exe"
#define CI_DLL          "ci.dll"

BOOL ControlDSE(
    _In_ BOOL Enable);
