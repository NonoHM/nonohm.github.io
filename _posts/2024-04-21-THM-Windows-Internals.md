---
layout: post
title: THM Windows Internals
tags: [THM, Malware Analysis, Operating System, Windows]
author: NonoHM
date: 2024-04-20 17:32:42
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

In this room, we will be observing the Windows operating system common internal components. Because Windows machines are making up a majority of corporate infrastructure, it is crucial to understand how it works to aid in evasion and exploitation.

### Learning Objectives

- Understand and intreact with Windows processes and their underlying technologies.
- Learn about core file formats and how they are used.
- Interact with Windows internals and understand how the Windows kernel operates.

## Task 2 - Processes

A process is a representation of the execution of a program and an application can contain one or more processes. It has many components that get broken down in order to be stored and interacted with.  

A process contains:

|       Process Component       |                                             Purpose                                             |
|:-----------------------------:|:-----------------------------------------------------------------------------------------------:|
| Private Virtual Address Space |                     Virtual memory addresses that the process is allocated.                     |
|       Executable Program      |                    Defines code and data stored in the virtual address space.                   |
|          Open Handles         |                  Defines handles to system resources accessible to the process.                 |
|        Security Context       | The access token defines the user, security groups, privileges, and other security information. |
|          Process ID           |                           Unique numerical identifier of the process.                           |
|            Threads            |                          Section of a process scheduled for execution.                          |

Because they are created during the execution of an applicaction, processes are core of Windows functions like Windows Defender (MsMpEng).

Attackers can target processes to evade detection and hide malware and legitimate processes with [Process Injection](https://attack.mitre.org/techniques/T1055/), [Process Hollowing](https://attack.mitre.org/techniques/T1055/012/), [Process Masquerading](https://attack.mitre.org/techniques/T1055/013/) and so on...

Here is what components resides in a Private Virtual Address Space:

|     Component     |                    Purpose                    |
|:-----------------:|:---------------------------------------------:|
|        Code       |      Code to be executed by the process.      |
|  Global Variables |               Stored variables.               |
|    Process Heap   |     Defines the heap where data is stored.    |
| Process Resources |   Defines further resources of the process.   |
| Environment Block | Data structure to define process information. |
|   Threads Memory  | Section of a process scheduled for execution. |

There are tools which allow us to visualize processes like Task Manager or Process Explorer/Procmon from [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/).

Most of time, end-users deal with Name, PID, Status and User parameters.

### Questions

**What is the process ID of "notepad.exe"?**

*Answer: `5984`*

**What is the parent process ID of the previous process?**

*Answer: `3412`*

**What is the integrity level of the process?**

*Answer: `High`*

## Task 3 - Threads

A thread is an executable unit utilized within a process and scheduled based on system-specific factors, including CPU and memory attributes, priority levels, and logical considerations.  
Essentially, a thread can be defined as controlling the execution of a process.  

Threads are commonly abused to aid in code execution by controling thread execution.

Threads share the same details and resources as their parent process, such as code, global variables, etc. Threads also have their unique values and data, outlined in the table below.

|       Component      |                                      Purpose                                     |
|:--------------------:|:--------------------------------------------------------------------------------:|
|        Stack         | All data relevant and specific to the thread (exceptions, procedure calls, etc.) |
| Thread Local Storage |           Pointers for allocating storage to a unique data environment           |
|    Stack Argument    |                       Unique value assigned to each thread                       |
|   Context Structure  |              Holds machine register values maintained by the kernel              |

### Questions

**What is the thread ID of the first thread created by notepad.exe?**

*Answer: `5908`*

**What is the stack argument of the previous thread?**

*Answer: `6584`*

## Task 4 - Virtual Memory

Virtual Memory is crucial component of how processes work and interact with each other. It allows components to interact as if it was physical memory without the risk of collision between applications.

Virtual Memory provides a priate virtual address space to each process. A memory manager is used to translate virtual addresses to physical addresses.

Memory manager divides the virtual memory space into fixed-size block called pages. Because the RAM is not infinite, Memory manager transfers pages that are not used by the application to the disk and retrives them when needed.

On 32-bit system, the maximum VA space is 4 GB and is 256 TB on 64-bit systems.
The lower half is allocated to applications and the upper half of memory is allocated for OS memory utilization.

### Questions

**What is the total theoretical maximum virtual address space of a 32-bit x86 system?**

*Answer: `4 gb`*

**What default setting flag can be used to reallocate user process address space?**

*Answer: `increaseUserVA`*

**What is the base address of "notepad.exe"?**

*Answer: `0x7ff652ec0000`*

## Task 5 - Dynamic Link Libraries

DLLs are libraries that contain code and data that can be used by more than one program at a time. They help:

- Promote modularization of code
- Code reuse
- More efficient memory usage
- Reduce disk usage

DLL are assigned as dependencies when loaded in a program. Since programs can be dependent on DLLs, they can be targeted rather than the program itself to control some aspects of the functionality using [DLL Hijacking](https://attack.mitre.org/techniques/T1574/001/), [DLL Side-loading](https://attack.mitre.org/techniques/T1574/002/) and [DLL injection](https://attack.mitre.org/techniques/T1055/001/).

DLLs are created slightly different than normal programs:

``` cpp
#include "stdafx.h"
#define EXPORTING_DLL
#include "sampleDLL.h"
BOOL APIENTRY DllMain( HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved
)
{
    return TRUE;
}

void HelloWorld()
{
    MessageBox( NULL, TEXT("Hello World"), TEXT("In a DLL"), MB_OK);
}
```

The header file `sampleDLL.h` defines what functions are imported and exported:

``` cpp
#ifndef INDLL_H
    #define INDLL_H
    #ifdef EXPORTING_DLL
        extern __declspec(dllexport) void HelloWorld();
    #else
        extern __declspec(dllimport) void HelloWorld();
    #endif
#endif
```

When loaded using *load-time dynamic linking*, explicit calls to the DLL functions are made from the application. This type of linking can be achieved only by providing a header (.h) and import library (.lib) file.

``` cpp
#include "stdafx.h"
#include "sampleDLL.h"
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HelloWorld();
    return 0;
}
```

When loaded using *run-time dynamic linking*, a separate function (`LoadLibrary` or `LoadLibraryEx`) is used to load the DLL at run time. Once loaded, `GetProcAddress` is needed to identify the exported DLL function to call.

``` cpp
typedef VOID (*DLLPROC) (LPTSTR);
...
HINSTANCE hinstDLL;
DLLPROC HelloWorld;
BOOL fFreeDLL;

hinstDLL = LoadLibrary("sampleDLL.dll");
if (hinstDLL != NULL)
{
    HelloWorld = (DLLPROC) GetProcAddress(hinstDLL, "HelloWorld");
    if (HelloWorld != NULL)
        (HelloWorld);
    fFreeDLL = FreeLibrary(hinstDLL);
}
```

### Questions

**What is the base address of "ntdll.dll" loaded from "notepad.exe"?**

*Answer: `0x7ffd0be200000`*

**What is the size of "ntdll.dll" loaded from "notepad.exe"?**

*Answer: `0x1ec000`*

**How many DLLs were loaded by "notepad.exe"?**

*Answer: `51`*

## Task 6 - Portable Executable Format

The PE format defines the structure of the information about the executable and stored data.

The PE format is a comprehensive structure of executable and object files. The PE (Portable Executable) and COFF (Common Object File Format) files makes up the PE format.

PE Data is most commonly seen in a hex dump of an executable file. The PE data is broken up into seven components:

- **DOS header**: The `MZ` DOS header defines the file format as `.exe`
- **DOS Stub**: A program run by default that prints a compatibility message like `This program cannot be run in DOS mode`
- **PE File Header**: Provides PE header information of the binary by defining file format, signature, image file header...
- **Image Optional Header**: Provides configuration settings and metadata for a Windows executable's runtime environment, including memory allocation, entry point, subsystem type, section alignment, import/export data directories, version information, security checks, and loader configuration.
- **Data Dictionnaries**: Points to the image data directory structure and are a part of *Image optional Header*
- **Section Table**: Define the available sections and information in the image such as code, imports and data

Here is a table containing the purpose of the different sections:

|      Section     |                        Purpose                       |
|:----------------:|:----------------------------------------------------:|
|       .text      |       Contains executable code and entry point       |
|      .data       | Contains initialized data (strings, variables, etc.) |
| .rdata or .idata |       Contains imports (Windows API) and DLLs.       |
|      .reloc      |            Contains relocation information           |
|       .rsrc      |     Contains application resources (images, etc.)    |
|      .debug      |              Contains debug information              |

### Questions

**What PE component prints the message "This program cannot be run in DOS mode"?**

*Answer: `DOS Stub`*

**What is the entry point reported by DiE?**

*Answer: `000000014001acd0`*

**What is the value of "NumberOfSections"?**

*Answer: `0006`*

**What is the virtual address of ".data"?**

*Answer: `00024000`*

**What string is located at the offset "0001f99c"?**

*Answer: `Microsoft.Notepad`*

## Task 7 - Interacting with Windows Internals

Interacting with Windows internals is simpler using the Windows API because it provides native functionality to interact with the OS. The API contains the Win32 API and the Win 64 API.

Most Windows internals components interacting with physical hardware and memory.

The windows kernel controls all programs and processes and bridges software and hardware interactions. Because an application cannot normally interact with the kernel or modify physical hardware, the use of processor modes and access levels are required.

A Windows processor has a *user* and *kernel* mode and it switched between these depending the requested mode.

The switch between these is facilitated by system and API calls and is referred to as the *Switching Point*.

|                       User mode                      |                  Kernel Mode                 |
|:----------------------------------------------------:|:--------------------------------------------:|
|               No direct hardware access              |            Direct hardware access            |
| Creates a process in a private virtual address space | Ran in a single shared virtual address space |
|          Access to "owned memory locations"          |       Access to entire physical memory       |

This is a flow chart on how a program interact most of the time with hardware.

{% include figure.liquid path="/assets/img/images/thm_windows_internals/S12Sp3zZC.png" title="Program syscall Flow Chart" class="img-fluid rounded z-depth-1 bg-white" %}

Here is a Proof-Of-Concept on how to interact with memory by creating a message box into a local process.

The steps are:

1. Allocate local process memory for the message box
2. Write/copy the message box to allocated memory
3. Execute the message box from local process memory

At step one, we can use `OpenProcess` to obtain the handle of the specified process.

``` cpp
HANDLE hProcess = OpenProcess(
	PROCESS_ALL_ACCESS, // Defines access rights
	FALSE, // Target handle will not be inhereted
	DWORD(atoi(argv[1])) // Local process supplied by command-line arguments 
);
```

At step two, we can use `VirtualAllocEx` to allocate a region of memory with the payload buffer.

``` cpp
remoteBuffer = VirtualAllocEx(
	hProcess, // Opened target process
	NULL, 
	sizeof payload, // Region size of memory allocation
	(MEM_RESERVE | MEM_COMMIT), // Reserves and commits pages
	PAGE_EXECUTE_READWRITE // Enables execution and read/write access to the commited pages
);
```

At step three, we can use `WriteProcessMemory` to write the payload to the allocated region of memory.

``` cpp
WriteProcessMemory(
	hProcess, // Opened target process
	remoteBuffer, // Allocated memory region
	payload, // Data to write
	sizeof payload, // byte size of data
	NULL
);
```

At step four, we can use `CreateRemoteThread` to execute our payload from memory.

``` cpp
remoteThread = CreateRemoteThread(
	hProcess, // Opened target process
	NULL, 
	0, // Default size of the stack
	(LPTHREAD_START_ROUTINE)remoteBuffer, // Pointer to the starting address of the thread
	NULL, 
	0, // Ran immediately after creation
	NULL
); 
```

### Question

**Enter the flag obtained from the executable *inject-poc.exe*.**

*Answer: `THM{1Nj3c7_4lL_7H3_7h1NG2}`*

## Task 8 - Conclusion

Throughout this exploration of Windows internals, we've delved into the foundational components that underpin the Windows operating system. From processes and threads to virtual memory management, dynamic link libraries (DLLs), and the Portable Executable (PE) format, each element contributes to the intricate workings of Windows. These internals, deeply ingrained and integral to system functionality, present both opportunities and risks. Attackers leverage these internals for malicious purposes, exploiting vulnerabilities that can compromise system integrity.  
The universality of these concepts extends beyond Windows to Unix environments, highlighting the enduring relevance of system internals in cybersecurity. Whether defending against or exploiting these fundamentals, understanding Windows internals is essential for both offensive and defensive security efforts, ensuring a comprehensive grasp of capabilities and vulnerabilities within complex operating system architectures. 