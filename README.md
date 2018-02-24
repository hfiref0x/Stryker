
# Stryker
## Multi-purpose proof-of-concept tool based on CPU-Z CVE-2017-15303

#### System Requirements

+ x64 Windows 7/8/8.1/10;
+ Stryker designed only for x64 Windows;
+ Administrative privilege is required.

# Features

+ Driver Signature Enforcement Overrider (similar to DSEFIx);
+ Protected Processes Hijacking via Process object modification;
+ Driver loader for bypassing Driver Signature Enforcement (similar to TDL).

#### Usage

###### STRYKER -dse on | off
###### STRYKER -prot ProcessID (ProcessID in decimal form)
###### STRYKER -load filename
* -dse   - turn off/on Driver Signature Enforcement (similar to DSEFix functionality);
* -prot  - modify process object of given ProcessID;
* -load  - load input file as code buffer to kernel mode and run it (similar to TDL functionality).

Example:
+ stryker -dse off
+ stryker -prot 1188
+ stryker -load c:\driverless\mysuperhack.sys

Note:
Stryker expects both cpuz141.sys and procexp152.sys are located in the same directory as program itself.

#### Limitations of -dse command

+ PatchGuard awareness.

#### Limitations of -prot command

+ Likely PatchGuard awareness or subject of future PatchGuard awareness.

#### Limitations of -load command

+ Loaded drivers MUST BE specially designed to run as "driverless".
+ No SEH support for target drivers.
+ No driver unloading.
+ Only ntoskrnl import resolved, everything else is up to you.
+ SysInternals Process Explorer driver as shellcode storage/executor is required.
+ Several Windows primitives are banned by PatchGuard from usage from the pool buffer not inside loaded modules list, e.g. notify routines.

You use it at your own risk. Some lazy AV may flag this tool as hacktool/malware.

# How it work

It uses CPU-Z (https://www.cpuid.com/softwares/cpu-z.html) internal driver (version 1.41 as per CVE-2017-15303) to read/write into physical memory and read CPU control registers.

Depending on command Stryker will either work as DSEFix/TDL or modify kernel mode process objects (EPROCESS). 

When in -load mode Stryker will use 3rd party signed driver from SysInternals Process Explorer software (driver version 1.52) to place a small loader shellcode inside it IRP_MJ_DEVICE_CONTROL/IRP_MJ_CREATE/IRP_MJ_CLOSE handler. This is done by overwriting physical memory where Process Explorer dispatch handler located and triggering it by calling driver IRP_MJ_CREATE (CreateFile call). Triggered shellcode will map input driver as code buffer to kernel mode and run it, current IRQL will be PASSIVE_LEVEL.

Also with slight modification shellcode can be used to simple execute your small piece of code in the kernel mode (not implemented in this tool).

# Build 

Stryker comes with full source code.
In order to build from source you need Microsoft Visual Studio 2015 U1 and later versions. For driver builds you need Microsoft Windows Driver Kit 8.1 and/or above.

# Support and Warranties

There is no support except critical bugfixes for Stryker itself. There is absolutely ZERO warranties of it work. 
Using this program might render your computer into BSOD. Compiled binary and source code provided AS-IS in help it will be useful BUT WITHOUT WARRANTY OF ANY KIND.

ANY USE OF THE SOFTWARE IS ENTIRELY AT YOUR OWN RISK.

#  Short answers on possible Frequency Asked Questions
+ Q: Can anything else except Process Explorer driver be used to execute shellcode?
+ A: Yes, but you have to carefully examine candidate to make sure it can store and execute shellcode.

+ Q: What about newest versions of CPU-Z? Can they be used to read/write physical memory, CPU control registers?
+ A: CPU-Z driver was redesigned to address CVE-2017-15303 and some functionality is no longer available. However old versions of CPU-Z may have the same functionality.

+ Q: Are the any other similar drivers with same functionality as CPU-Z?
+ A: Yes, a lot of them, e.g. WinIO.sys, AsIO64.sys, Asmmap64.sys. They all generally provide read/write access to the physical memory in different ways (\Device\PhysicalMemory).

+ Q: Does this work on every Windows version? Including not released yet?
+ A: It was tested on Windows 7 / 8.1 / 10 up to RS3. Working in future versions is unlikely.

+ Q: Will be support of Windows 10 NEXT or Windows XX NEXT added?
+ A: Unlikely.

# References

* CVE-2017-15303, https://www.cvedetails.com/cve/CVE-2017-15303/
* Decrement Windows kernel for fun and profit, https://sww-it.ru/2018-01-29/1532

# Authors

(c) 2018 Stryker Project

