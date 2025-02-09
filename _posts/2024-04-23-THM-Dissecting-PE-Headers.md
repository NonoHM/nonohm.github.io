---
layout: post
title: THM Dissecting PE Headers
tags: [THM, Malware Analysis, RE, Static Analysis, Windows]
author: NonoHM
date: 2024-04-23 19:48:06
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

In Windows, `.exe` files stands for executable files. It contains code that can be executed by the machine. An executable file is also called a portable Executable (PE) file. A PE file is a Common object File Format (COFF) data structure. The COFF consists in Windows of PE files and DLL and in Linux, it is shared objects and ELF files.

### Learning Objectives  

In this room, we'll review the following:

- Understanding the different headers in a PE file
- Learning how to read PE headers
- Identify packed executables
- Use the information from PE headers to analyze malware

## Task 2 - Overview of PE Headers

A PE executable is like other type of data, a combination of bits and when looking into it using an Hex editor, we can see a bunch of random hex chars. These are instructions for Windows to execute the file.

In this room, we will use *wxHexEditor* and *pe-tree* to visualize better a PE header structure.

The most impotrant headers are:

- IMAGE_DOS_HEADER
- IMAGE_NT_HEADERS
    - FILE_HEADER
    - OPTIONAL_HEADER
    - IMAGE_SECTION_HEADER
    - IMAGE_IMPORT_DESCRIPTOR

These headers are the data type STRUCT in C, which is a user-defined data type that combines different types of data elements into a single variable. Thus, to understand each header, we need to go through documentation.

### Question

**What data type are the PE headers**

*Answer: `STRUCT`*

## Task 3 - IMAGE_DOS_HEADER and DOS_STUB

We are using *pe-tree* with the given sample *redline*.

### IMAGE_DOS_HEADER

The IMAGE_DOS_HEADER consists of the first 64 bytes of the PE file. In *pe tree*, the values are shown in little endian format; the least significant bytes are shown first (the ones in right).

LE: `0x1020304050`
BE: `Ox5040302010`

The first thing we can understand is `MZ`, which stands for Mark Zbikowski (one of the architect of this format), and it is the character identifying the PE format. This signature is also called `e_magic` and has a value of `0x5a4d`.

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/Hy3M6urbR.png" title="IMAGE_DOS_HEADER Structure" class="img-fluid rounded z-depth-1" %}

The last value called `e_lfanew`, has a value of `0x000000d8` and denotes the address where IMAGE_NT_HEADERS start.

### DOS_STUB

The DOS_STUB is just after the IMAGE_DOS_HEADER and is mainly used to contain the piece of code if the PE file is incompatible with the system.

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/SJH_COSZA.png" title="DOS_STUB Structure" class="img-fluid rounded z-depth-1" %}

### Questions

**How many bytes are present in the IMAGE_DOS_HEADER?**

*Answer: `64`*

**What does MZ stand for?**

*Answer: `Mark Zbikowski`*

**In what variable of the IMAGE_DOS_HEADER is the address of IMAGE_NT_HEADERS saved?**

*Answer: `e_lfanew`*

**In the attached VM, open the PE file Desktop/Samples/zmsuz3pinwl in pe-tree. What is the address of IMAGE_NT_HEADERS for this PE file?**

*Answer: `0x000000f8`*

## Task 4 - IMAGE_NT_HEADERS

Here, we will focus on the different parts of [IMAGE_NT_HEADERS](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32), containing vital information related to the PE file.

### NT_HEADERS

NT_HEADERS consist of:

- Signature: Contains `PE` keyword in ASCII  
- FILE_HEADER
- OPTIONAL_HEADER

The Signature consists of marking the start of NT_HEADERS.

### FILE_HEADER

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/rJy0g9rbC.png" title="FILE_HEADER Structure" class="img-fluid rounded z-depth-1" %}

The FILE_HEADER gives some vital information like:

- **Machine**: Type of architecture the PE file is written. `i386` is for 32-bit architecture.
- **NumberOfSections**: A PE file contains section where code, variables and other ressources are stored. It mentions how many the PE file has.
- **TimeDateStamp**: Time and date of binary compilation
- **PointerToSymbolTable and NumberOfSymbols**: Generally not related to PE files and are there due to COFF file headers.
- **SizeOfOptionalHeader**: Size of the optional header
- **Charactristics**: Tells us that the PE file is an executable image, has stripped relocation information, line numbers, and local symbol information.  

For characteristics, these means that the executable is not position-independent and must be loaded at a specific base address, the PE file does not contain detailed debugging data and debugging symbols are removed, making it harder to debug or analyze the executable.

These are located here in the hex view with the value `0x0f01`.

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/Sys3NtB-R.png" title="FILE_HEADER Characteristics Hex location" class="img-fluid rounded z-depth-1" %}

### Questions

**In the attached VM, there is a file Desktop\Samples\zmsuz3pinwl. Open this file in pe-tree. Is this PE file compiled for a 32-bit machine or a 64-bit machine?**

According to *pe-tree*, `Machine  0x014c I386`.

*Answer: `32-bit machine`*

**What is the TimeDateStamp of this file?**

*Answer: `0x62289d45 Wed Mar  9 12:27:49 2022 UTC`*

## Task 5 - OPTIONAL_HEADER

The OPTIONAL_HEADER is also a part of the NT_HEADERS and contains some of the most important information.

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/HJSnl9SZC.png" title="OPTIONAL_HEADER Structure" class="img-fluid rounded z-depth-1" %}

The most important fields are:

- **Magic**: Tells whether the PE file is a 32-bit (`0x010B`) or a 64-bit appliaction (`0x020B`).
- **AddressOfEntryPoint**: Address where Windows will begin execution. This is an offset relative (RVA - Relative Virtual Address) of the base address contained into ImageBase.
- **BaseOfCode** and **BaseOfData**: Relative addresses of code and data sections.
- **ImageBase**: Preferred loading address of the PE in the memory. Generally, the value is `0x00400000` but can sometimes be changed and relative addresses are relocated following the new ImageBase.
- **Subsystem**: Represent a value for Windows Native, GUI, CLI or other ones.
- **DataDirectory**: Contains import and export information of the PE file. These locate the RVA of the needed sections.

### Questions

**Which variable from the OPTIONAL_HEADER indicates whether the file is a 32-bit or a 64-bit application?**

*Answer: `Magic`*

**What Magic value indicates that the file is a 64-bit application?**

*Answer: `0x020B`*

**What is the subsystem of the file Desktop\Samples\zmsuz3pinwl?**

*Answer: `0x0003 WINDOWS_CUI`*

## Task 6 - IMAGE_SECTION_HEADER

Sections in a PE file contains data like code, icons, images, GUI elements... and information about these are stored into the IMAGE_SECTION_HEADER.

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/SJf5lqHZR.png" title="IMAGE_SECTION_HEADER Structure" class="img-fluid rounded z-depth-1" %}

In this header, we can find different sections named `.text`, `.rdata`, `.data`, `.ndata` and `.rsrc`.

- **.text**: Contains the executable code. The Characteristics for this section include *CODE*, *EXECUTE* and *READ*, meaning that this section contains executable code, which can be read but can't be written to.
- **.data**: Contains initialized data of the application. The Characteristics are *READ/WRITE*.
- **.rdata/.idata**: Contains import information to import functions or data from other files.
- **.ndata**: Contains uninitialized data.
- **.reloc**: Contains relocation information of the PE.
- **.rsrc**: Contains icons, images or other ressources required for UI.

Into each sections, we can retrieve information like:

- **VirtualAddress**: Section's RVA.
- **VirtualSize**: Section's size once loaded into memory.
- **SizeOfRawData**: Section's size as stored on the disk before loaded in memory.
- **Characteristics**: Permissions of the section.

### Questions

**How many sections does the file Desktop\Samples\zmsuz3pinwl have?**

*Answer: `7`*

**What are the characteristics of the .rsrc section of the file Desktop\Samples\zmsuz3pinwl**

*Answer: `0xe0000040 INITIALIZED_DATA | EXECUTE | READ | WRITE`*

## Task 7 - IMAGE_IMPORT_DESCRIPTOR

The IMAGE_IMPORT_DESCRIPTOR structure contains information about the different Windows APIs needed to be loaded when the application in executed.

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/Hkpkl5SWA.png" title="IMAGE_IMPORT_DESCRIPTOR pe-tree" class="img-fluid rounded z-depth-1" %}

As we can see, this PE imports functions from *ADVAPI32.dll*, *SHELL32.dll*, *ole32.dll*, *COMCTL32.dll*, and *USER32.dll*.
`OriginalFirstThunk` and `FirstThunk` values are used by the OS to build the Import Address Table (IAT) of the PE file.

- **OriginalFirstThunk** is an array of pointers to IMAGE_THUNK_DATA structures containing references to imported function names or ordinals, used by the OS loader during dynamic linking of a PE file.
- **FirstThunk** is an array of pointers within the Import Descriptor table of a PE file, initially populated with the same values as `OriginalFirstThunk` and later updated with resolved function addresses during dynamic linking.
- The **Import Address Table (IAT)** is a data structure used by the operating system to store the resolved addresses of imported functions from external DLLs, facilitating dynamic linking in a PE file.

By studying imports of the PE file, we can learn a lot about what activities it might perform.

### Questions

**The PE file Desktop\Samples\redline imports the function CreateWindowExW. From which dll file does it import this function?**

*Answer: `USER32.dll`*

## Task 8 - Packing and Identifying packed executables

Because PE file's information can be easily read, packers obfuscate the data in a PE file in a way that it can't be read without unpacking it. The unpacking process is ran when the PE file is executed. This is done in order to prevent program's static reverse engineering.

### From Section Headers

In previous task, we have seen that sections are commonly named `.text`, `.data` and `.rsrc`. When looking at the file *zmsuz3pinwl*, we can see there is some unconventional names.

{% include figure.liquid path="/assets/img/images/thm_dissecting_pe_headers/ByOwr9BWA.png" title="zmsuz3pinwl Sections" class="img-fluid rounded z-depth-1" %}

Using `pecheck`:

``` sh
...
 entropy: 7.999788 (Min=0.0, Max=8.0)
 entropy: 7.961048 (Min=0.0, Max=8.0)
 entropy: 7.554513 (Min=0.0, Max=8.0)
.rsrc entropy: 6.938747 (Min=0.0, Max=8.0)
 entropy: 0.000000 (Min=0.0, Max=8.0)
.data entropy: 7.866646 (Min=0.0, Max=8.0)
.adata entropy: 0.000000 (Min=0.0, Max=8.0)
...
[IMAGE_SECTION_HEADER]
0x1F0      0x0   Name:                          
0x1F8      0x8   Misc:                          0x3F4000  
0x1F8      0x8   Misc_PhysicalAddress:          0x3F4000  
0x1F8      0x8   Misc_VirtualSize:              0x3F4000  
0x1FC      0xC   VirtualAddress:                0x1000    
0x200      0x10  SizeOfRawData:                 0xD3400
```

When checking the Entropy of *.data* and three of the four unnamed section, it is high, approaching 8. This means there is a high level in randomness in data and confirms our toughts about this is indicating a packed executable.  
Also, these sections has the *EXECUTE* permissions, which means there is many data parts and the depacking code in one of the sections.

Another valuable piece information is that in packed executable, `SizeOfRawData` is always smaller than `Misc_VirtualSize` because unpacking process makes the section significantly larger.

### From Import functions

When looking into import functions, packed executables only imports the libraries needed to unpack the program like `LoadLibraryA`...

To sum up, a packed executable will always have one of these indications:

- Unconventional section names
- EXECUTE permissions for multiple sections
- High Entropy, approaching 8, for some sections.
- A significant difference between SizeOfRawData and Misc_VirtualSize of some PE sections
- Very few import functions

### Questions

**Which of the files in the attached VM in the directory Desktop\Samples seems to be a packed executable?**

*Answer: `zmsuz3pinwl`*

## Task 9 - Conclusion

This room provided a detailed overview of Portable Executable (PE) file headers, focusing on their role in analyzing Windows executable files. Key topics covered included:

- Understanding the structure of PE files and their headers like IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, and others.
- Learning to interpret critical information stored in these headers, such as machine architecture, compilation timestamp, entry point address, section details, and import libraries.
- Exploring methods for identifying packed executables through unconventional section names, high entropy values, and minimal import functions.

Using tools like pe-tree and wxHexEditor, analysts can efficiently dissect PE files, spot potential malware indicators, and gain insights into executable behavior. This knowledge is crucial for professionals involved in malware analysis and Windows security.
