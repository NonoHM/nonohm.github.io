---
layout: post
title: THM Basic Static Analysis
tags: [THM, Malware Analysis, RE, Static Analysis]
author: NonoHM
date: 2024-05-01 20:32:29
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

### Learning Objectives

The first step in analyzing malware is generally to look at its properties without running it by doing static analysis.
Here, we will cover the following topics:

* Lab setup for malware analysis
* Searching for strings in a malware
* Fingerprinting malware through hashes
* Signature-based detection mechanisms
* Extracting useful information from the PE header

## Task 2 - Lab Setup

Because by analyzing malware is risky and often destructive, we must set a proper environment before it damages our envrionment. Therefore, we need to create a lab setup to analyze them.

To make it alive, we are using here Virtual Machines because of its ability to save the state of the machine and revert as well as its flexibility. VMs are created using [Oracle VirtualBox](https://www.virtualbox.org/) or [VMWare Workstation](https://www.vmware.com/products/workstation-pro.html).

Two distributions are mainly used to make Reverse Engineering, [FLARE VM](https://github.com/mandiant/flare-vm?tab=readme-ov-file) and [REMnux](https://docs.remnux.org/install-distro/get-virtual-appliance).
FLARE VM is a Windows Based VM, but it is given as a toolkit script and REMnux is a Linux based malware analysis distro.

## Task 3 - String search

A string search can provide useful information of a malware by identifying important pieces of strings.

String search, regardless of the file type, identifies sequences of ASCII/unicode character followed by a null character. Werever it finds such a sequence, it reports that as a string but many sequences of bytes can fulfill the criteria mentionned above. Many values are not useful and a string search can provide many False Positives like memory addresses, asm instructions... and they should be ignored.

Because an analyst has to differentiate strings of interest from garbage ones, the following artefacts can be used as Indicators of Compromise (IOCs):

- Windows Functions and APIs for providing possible functionality of the malware
- IP Addresses, URL or domain like for a C2 server
- Miscellaneous strings

### Basic String Search

String searches can be made using the `strings` utility that comes pre-installed in linux or `strings.exe` in the SysInternals Suite for Windows.
Several tools like Cyberchef or PEStudio allows us the ability to make string searches and more.

### Obfuscated strings

Beceause string searches can disrupt malware propagation and infection, malware authors deploy obfuscation techniques to obfuscate key parts of their code. These often make a string search ineffective.

[FLOSS](https://www.mandiant.com/resources/blog/automatically-extracting-obfuscated-strings) for FireEye Labs Obfuscated String Solver can be sometimes useful to deobfuscate and extract strings that would not normally

### Question

**On the Desktop in the attached VM, there is a directory named 'mal' with malware samples 1 to 6. Use floss to identify obfuscated strings found in the samples named 2, 5, and 6. Which of these samples contains the string 'DbgView.exe'?**

By using FLOSS on these samples with the command:  

``` cmd
floss --no-static-strings <file>
```

*Answer: `6`*

## Task 4 - Fingerprinting malware

When analyzing malware, it is often required to identify unique malware and differentiate them from each other. Because file names can be easily canged, hashes are a good option because they create a unique fixed-length indentifier.

These functions are the most common used methods to create a file hash. However, the first two are now considered insecure because they can produce the same hash for multiple inputs.

- Md5sum
- Sha1sum
- Sha256sum

### Finding Similar files using hashes

We have seen that hashes are unique and even a slight change can modify a hash's content. Though, some types of hashes can help identify similarities among different files.

**Imphash**

[Imphash](https://www.mandiant.com/resources/blog/tracking-malware-import-hashing) stands for *import hash* and it is a hash of the function calls/libraries that a malware sample imports and the order in which these libraries are present in the sample. This helps identify samples from the same threat groups of performing similar activities.

Imphash of a program can be viewed in PEstudio and similar samples can be identified in [Malware Bazaar](https://bazaar.abuse.ch/browse.php).

**Fuzzy Hashes/SSDEEP**

A fuzzy hash is a Context Triggered Piecewise Hash (CTPH). This hash is calculates by dividing a file into pieces and calculating the hashes of the different pieces. This method creates multiple inputs with similar sequences of bytes.

`ssdeep` or CyberChef are utilities that can calculate a file's fuzzy hash.

``` cmd
ssdeep <file> # Calculate a file's fuzzy hash
ssdeep -l -r -d <directory> # Match files recursively with similar fuzzy hashes 
```

### Questions

**In the samples located at `Desktop\mal\` directory in the attached VM, which of the samples has the same imphash as file 3?**

By running `ssdeep -d  ../mal/*`:

*Answer: `1`*

**Using the ssdeep utility, what is the percentage match of the above-mentioned files?**

*Answer: `93`*

## Task 5 - Signature-based detection

We have learnt how hashes could identify identical files and identify file similarities using imphash and ssdeep. Sometimes, we just need to identify if a file contains the information of interesst though.

### Signatures

Signatures are a way to idetify a particular type of content because signatures can be considered as a pattern that might be found inside a file.
The pattern is often a sequence of bytes in a file, with or without any context.

**Yara rules**

Yara rules are a type of signature-based rule. It can identify information based on binary and textual patterns such as hex or strings.
However, even if [community rules](https://github.com/Yara-Rules/rules) or homebrew rules hits doesn't mean the file is malicious. It is important to know the properties of the rule.

**Proprietary Signatures - Antivirus Scans**

Proprietary signatures have the advantage of having less chances of False Positives (a signature hits a non-malicious file) but this might lead to few False Negatives (a malicious file does not hit any signature).

That is why it is important to get a verdict from multiple products like with [Virustotal](https://www.virustotal.com/gui/home/upload). When analyzing a sensitive file, it is important to search hash on Virustotal or importing it on non-reporting scanning service (which Virustotal does not do).

**Capa**

[Capa](https://github.com/mandiant/capa) is an FOSS tool to help identify the capabilities found in a PE file. It reads the file and tries to identifies the behavior based on signatures such as imports, strings, mutexes...

Capa identifies and maps capabilities according to the [MITRE ATT&CK](https://attack.mitre.org/) framework and [Malware Behavior Catalog](https://github.com/MBCProject/mbc-markdown).

The syntax is the following:

``` cmd
capa <file>
capa -h
```

### Questions

Using the file in `Desktop\mal\4`:

**How many matches for anti-VM execution techniques were identified in the sample?**

*Answer: `86`*

**Does the sample have to capability to suspend or resume a thread? Answer with Y for yes and N for no.**

*Answer: `Y`*

**What MBC behavior is observed against the MBC Objective 'Anti-Static Analysis'?**

*Answer: `Disassembler Evasion::Argument Obfuscation [B0012.001]`*

**At what address is the function that has the capability 'Check HTTP Status Code'?**

*Answer: `0x486921`*

## Task 6 - Leveraging the PE header

Because the covered techniques, even though they provide information regardless of the file type of the malware, don't always provide us deterministic information; PE Heasers provide a more deterministic characteristics of the sample, which tells us more about it.

### PE Header

PE files consist of a sequence of bits stored on the disk in a specific format. The initial bits of the PE file define the characteristics of it and explains us how to read the contained data. This initial part is called the PE Header.

PEStudio can help us dissect PE Header.

**Linked Libraries, imports and functions**

A PE File does not contain all of its code to perform tasks and reuses code from different liraries. The information about what library (.dll) is imported, is contained in the PE Header and can give us a rough idea of the functionnality of the malware sample.

**Identifying Packed Executables**

Static analysis can provide a lot of informatio about the executable, so in order to face this problem, obfuscation is often used to block analysis. One way of doing this is by packing the original sample inside a shell-type code that obfuscates the proerties of the actual malware sample.  
Packed executables are identifiable by analyzing ressource sections and entropies.

### Questions

**Open the sample Desktop\mal\4 in PEstudio. Which library is blacklisted?**

{% include figure.liquid path="/assets/img/images/thm_basic_static_analysis/r1lS4FbzR.png" title="PEStudio Libraries Import" class="img-fluid rounded z-depth-1" %}

*Answer: `rpcrt4.dll`*

**What does this DLL do?**

*Answer: `Remote Procedure Call Runtime`*

## Task 7 - Conclusion

In this room, we have learned about:

- Lab setup for malware analysis
- Searching for strings and obfuscated strings
- Fingerprinting malware using hashes and identifying similar samples using imphash and ssdeep
- Using signature-based detection like Yara and Capa
- Identifying artifacts from the PE header
