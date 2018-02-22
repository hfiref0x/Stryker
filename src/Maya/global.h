/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       GLOBAL.H
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Global definitions.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#pragma once

#if !defined UNICODE
#error ANSI build is not supported
#endif

#if (_MSC_VER >= 1900)
#ifdef _DEBUG
#pragma comment(lib, "vcruntimed.lib")
#pragma comment(lib, "ucrtd.lib")
#else
#pragma comment(lib, "libvcruntime.lib")
#endif
#endif

#pragma warning(disable: 4005) // macro redefinition
#pragma warning(disable: 4054) // %s : from function pointer %s to data pointer %s
#pragma warning(disable: 4055) // conversion from data pointer to code
#pragma warning(disable: 4152) // function/data pointer conversion in expression
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union

#include <Windows.h>
#include <ntstatus.h>
#include "minirtl\minirtl.h"
#include "minirtl\cmdline.h"
#include "hde\hde64.h"
#include "ntos.h"
#include "sup.h"
#include "instdrv.h"
#include "readwrt.h"
#include "pagewalk.h"
#include "ob.h"
#include "ldr.h"
#include "ps.h"
#include "ci.h"
#include "drvmap.h"
#include "test.h"

extern HANDLE g_hDevice;
extern ULONG  g_NtBuildNumber;
