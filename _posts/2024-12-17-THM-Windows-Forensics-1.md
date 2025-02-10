---
layout: post
title: 'THM Windows Forensics 1'
tags: [THM, Digital Forensics, Incident Response, Windows, Windows Forensics]
author: NonoHM
date: 2024-12-17 19:37:17
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction to Windows

Computer forensics is an essential field of cyber security that involves gathering evidence of activities performed on a computer. It is a part of the wider field, *Digital Forensics*, which deals with all types of digital devices, including recovering, examining and analyzing data found in digital devices. Applications of *Digital Forensics* are detailed in the [Introductory room](https://tryhackme.com/r/room/introductoryroomdfirmodule).

Because Windows is the most used Operating System right now and holds roughly 80% of the desktop market share, it is important to know how to perform forensic analysis on Windows. Here, we will learn how can we gather forensic data from the Windows registry and make conclusions about the activity performed on a Windows based system.

### Forensic Artifacts

Forensic artifacts are essential pieces of information that provide evidence of human activity. While it can be fingerprints or a broken button of a coat in real life, in computer corensics, artifacts can be small footprints of activity left on a system. These artifacts often reside in location *normal* users won't typically venture to.

### Is my computer spying on me ?

Windows systems keeps track of a lot of activity performed by users. Even if it does not look like, these records are primarily made to improve the user's experience.  

To illustrate, most out-of-he-box windows are similar for all users. However, with time, each user personalizes their computer according to their preferences. These include desktop layout, browser history, the different applications, other accounts...

Windows saves the preferences to make computers more personalized. However, forensic investigators use these preferences as artifacts to identify the activity performed on a system. Hence, while computers might be spying on us, it is not for the explicit reason of spying but more to make the usage more pleasant.  
Through this room, we will see the different locations where these artifacts are stored throughout the file system.

## Task 2 - Windows registry and Forensics

### Windows Registry

The *Windows Registry* is a collection of databases that contains the **system's configuration data**. This data can be about **the hardware**, **the software**, **the user's information**, **the recently used files**, **the used programs** or **devices connected to the system**. As we can see, this data is beneficial from a forensic standpoint. It is possible to nattively consult the registry using *regedit*.  
Unlike Windows, which uses a registry for system settings, Linux stores its main configuration files in the `/etc` directory.

The *Windows Registry* is composed of **Keys** and **Values**. In *regedit*, folders represents the **registry keys** and data are stored in these keys into **registry values**. A [Registry Hive](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) is a group of keys, subkeys and values stored in a single file on the disk.

### Registry Structure

The registry on any Windows system contains the following five root keys :  

1. **HKEY_CURRENT_USER**
2. **HKEY_USERS**
3. **HKEY_LOCAL_MACHINE**
4. **HKEY_CLASSES_ROOT**
5. **HKEY_CURRENT_CONFIG**

These keys can be viewed with the registry editor `Win + R -> regedit.exe`.

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/r1747DJBkx.png" title="Regedit Main View" class="img-fluid rounded z-depth-1" %}

Root keys, keys and subkeys are shown in the **left pane** and the values of the selected key are show in the **right pane**.

Microsoft [defines](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users) each of these root keys as follow :  

| **Folder/Predefined Key** | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **HKEY_CURRENT_USER**     | Contains the root of the configuration information for the user who is currently logged on. The user's folders, screen colors, and Control Panel settings are stored here. This information is associated with the user's profile. This key is sometimes abbreviated as **HKCU**.                                                                                                                                                                                                             |
| **HKEY_USERS**            | Contains all the actively loaded user profiles on the computer. **HKEY_CURRENT_USER** is a subkey of **HKEY_USERS**. **HKEY_USERS** is sometimes abbreviated as **HKU**.                                                                                                                                                                                                                                                                                                                      |
| **HKEY_LOCAL_MACHINE**    | Contains configuration information particular to the computer (for any user). This key is sometimes abbreviated as **HKLM**.                                                                                                                                                                                                                                                                                                                                                                  |
| **HKEY_CLASSES_ROOT**     | Is a subkey of **HKEY_LOCAL_MACHINE\Software**. The information stored here ensures that the correct program opens when you open a file using Windows Explorer. This key is sometimes abbreviated as **HKCR**. Starting with Windows 2000, this information is stored under both the **HKEY_LOCAL_MACHINE** and **HKEY_CURRENT_USER** keys. **HKEY_CLASSES_ROOT** merges these two sources, providing a unified view for programs, especially those designed for earlier versions of Windows. |
| **HKEY_CURRENT_CONFIG**   | Contains information about the hardware profile that is used by the local computer at system startup.                                                                                                                                                                                                                                                                                                                                                                                         |

### Question

**What is the short form for HKEY_LOCAL_MACHINE?**

*Answer: `HKLM`*

## Task 3 - Accessing registry hives offline

If we are able to access to the live system, we will be able to access the regitry using regedit and be greeted with all of the standard root keys we previously learned about.

However, with only an access to a disk image, we must know where the registry hives are located. The majority of these hives are located in the `C:\Windows\System32\Config`.

| **Hive**         | **Mounted On**                     | **Location**                                           | **Notes**                                                                                                                                |
|------------------|------------------------------------|--------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| **DEFAULT**      | HKEY_USERS\DEFAULT                 | C:\Windows\System32\Config\DEFAULT                     | Contains default user profile settings used when no specific user is logged in. Serves as a baseline for initializing new user accounts. |
| **SAM**          | HKEY_LOCAL_MACHINE\SAM             | C:\Windows\System32\Config\SAM                         | Contains Security Account Manager (SAM) database.                                                                                        |
| **SECURITY**     | HKEY_LOCAL_MACHINE\Security        | C:\Windows\System32\Config\SECURITY                    | Contains security information.                                                                                                           |
| **SOFTWARE**     | HKEY_LOCAL_MACHINE\Software        | C:\Windows\System32\Config\SOFTWARE                    | Contains software configuration information.                                                                                             |
| **SYSTEM**       | HKEY_LOCAL_MACHINE\System          | C:\Windows\System32\Config\SYSTEM                      | Contains system-specific information.                                                                                                    |
| **NTUSER.DAT**   | HKEY_CURRENT_USER                  | C:\Users\\NTUSER.DAT                                   | Contains user-specific configuration. Hidden file.                                                                                       |
| **USRCLASS.DAT** | HKEY_CURRENT_USER\Software\Classes | C:\Users\\AppData\Local\Microsoft\Windows\USRCLASS.DAT | Contains user-specific software class information. Hidden file.                                                                          |
| **AmCache Hive** | N/A                                | C:\Windows\AppCompat\Programs\Amcache.hve              | Stores information about programs recently run on the system.                                                                            |

### Transation Logs and Backups

Some other vital sources of forensic data are the **Registry Transaction Logs** and **Backups**. These transaction logs can be considered as the **journal or changelog of the registry hive**. Windows often uses transaction logs when writing data to registry hives. This means transaction logs can often have the **latest changes** in the registry that have not yet been written to the registry hives themselves.  
The transaction log for each hive is stored as a **`*.LOG`** file. Sometimes, there can be multiple transaction logs, named **`*.LOG1`**, **`*.LOG2`**, etc.

**Registry Backups** are essentially the **opposite** of *transaction logs*. These are backups of the registry hives located in `C:\Windows\System32\Config\`, which are copied to `C:\Windows\System32\Config\RegBack` every 10 days. This might be an excellent place to look if we suspect that some registry keys have been deleted or modified recently.

### Questions

**What is the path for the five main registry hives, DEFAULT, SAM, SECURITY, SOFTWARE, and SYSTEM?**

*Answer : `C:\Windows\System32\Config`*

**What is the path for the AmCache hive?**

*Answer : `C:\Windows\AppCompat\Programs\Amcache.hve`*

## Task 4 - Data Acquisition

When performing forensics, it is possible to either encounter a live system or a system image. For the sake of accuracy and best practice, it is recommended to image the system or copy the required data and forensic on it. This process is called **Data Acquisition**.

Though we can view the registry through *regedit* on a live system, the forensically correct method is to acquire a copy of this data and perform analysis on it.  
However, because registry hives from `%WINDIR%\System32\Config` are restricted files (when copying with *explorer* to another place on a live system, we are greeted with the message *This action can't be completed because the file is open in System*), we might use third-party tool.

> **Hypothesis**
> Because the file is owned by *System*, we should elevate us to a similar privilege... (TBD with test on windows machine)

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/r1Cfb5lr1e.png" title="Trying to copy registry hive on a live system" class="img-fluid rounded z-depth-1" %}

### KAPE

[KAPE](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) is a live data acquisition and analysis tool which can be used to acquire registry data. It is primarily a CLI tool but also comes with a GUI.  
To extract registry data, we need to select registry components we want like :  

- **RegistryHives**
- **RegistryHivesOther**
- **RegistryHivesSystem**
- **RegistryHivesUser**
- **Amcache**

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/HJB77qlH1l.png" title="KAPE Main UI" class="img-fluid rounded z-depth-1" %}

### Autopsy

[Autopsy](https://www.autopsy.com/) gives us the opton to acquire and analyze data from both live systems and disk images. After adding our data source, we must navigate to the location of the file we want to extract, here the registry hives location and then select the *Extract File(s)* option.

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/B1emEclSkg.png" title="Autopsy Extract Data" class="img-fluid rounded z-depth-1" %}

### FTK Imager

FTK Imager is similar to Autopsy and allow us to extract files from a disk image or a live system.

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/rJK54qxBkg.png" title="FTK Imager Main UI" class="img-fluid rounded z-depth-1" %}

Another way we can extract Registry files with this tool  is through *Obtain Protected Files* option. This feature is available for live systems and allow us to extract all registry hives to a chosen location. However it will not copy `Amcache.hve`, which is often necessary to investigate evidence of last executed programs.

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/HJhqSqlB1l.png" title="FTK Imager Obtain Protected Files" class="img-fluid rounded z-depth-1" %}

## Task 5 - Exploring Windows Registry

Once registry hives are extracted, we need a tool to view these as *regedit* only works on live systems and cannot load exported hives.

| Tool                      | Key Features                                                                                      | Limitations                                                                                      | Supported OSes               |
|---------------------------|--------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------|------------------------------|
| **AccessData's Registry Viewer** | - User interface similar to Windows Registry Editor.                                          | - Loads only one hive at a time. <br> - Does not account for transaction logs.                  | Windows                      |
| **Zimmerman's Registry Explorer** | - Can load multiple hives simultaneously. <br> - Merges data from transaction logs for cleaner hives. <br> - Includes a 'Bookmarks' option for forensically important keys. | - None significant; preferred tool for Digital Forensics.                                       | Windows                      |
| **RegRipper**             | - Extracts forensically important keys and values from registry hives. <br> - CLI and GUI options available. | - Does not account for transaction logs. <br> - Requires pre-processing with Registry Explorer for accuracy. | Windows, Linux (via CLI)     |
| **RegistrySpy**           | - Open-source and written in Python. <br> - Platform-independent and customizable. <br> - Lightweight and easy to integrate into workflows. | - May lack advanced features like transaction log processing. <br> - Potentially limited documentation and support. | Windows, Linux, macOS        |

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/rkrSA9xSke.png" title="Zimmerman's Registry Explorer" class="img-fluid rounded z-depth-1" %}

## Task 6 - System Information an System Accounts

After learning how to read registry data, we need to know **where to look interesting ones** to perform our **forensic analysis**.

### Current Control Set

Hives containing the machine's configuration data used for **controlling system startup** are called *Control Sets*. These are located in the hive *SYSTEM* located into `C:\Windows\System32\config`. It is important to know them as they **contain many forensic artifacts**.  
Commonly, there are two Control Sets :

- **SYSTEM\ControlSet001** : Control Set used at the machine's boot
- **SYSTEM\ControlSet002** : Last known good configuration

When the machine is live, Windows creates a volatile Control Set called *CurrentControlSet* at `HKLM\SYSTEM\CurrentControlSet`. For getting the most accurate information, this is the hive to refer to.  
Furthermore, to know which ControlSet is being used as the CurrentControlSet, we must look at the registry value `SYSTEM\Select\Current`. Similarly, the *last known good* configuratio

n can be found at `SYSTEM\Select\LastKnownGood`.

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/SkU0d-y8Je.png" title="Registry Explorer SYSTEM\Select" class="img-fluid rounded z-depth-1" %}

### Important Registry Locations

Owing to the fact we know a bit more about *ControlSets*, we must know what data we might extract from registry values contained in them and in other Registry Hives. Below is a recap of those places.

| Information                | Registry Location(s)                                                            | Purpose                                                                                             |
|----------------------------|---------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| **OS Version**             | `SOFTWARE\Microsoft\Windows NT\CurrentVersion`                                  | Determine the operating system version from which the data was pulled.                              |
| **Current Control Set**    | `SYSTEM\ControlSet001`                                                          | Identify the active configuration and last known good configuration for accurate artifact analysis. |
|                            | `SYSTEM\ControlSet002`                                                          |                                                                                                     |
|                            | `SYSTEM\Select\Current`                                                         |                                                                                                     |
|                            | `SYSTEM\Select\LastKnownGood`                                                   |                                                                                                     |
| **Computer Name**          | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`                    | Confirm the identity of the machine being analyzed.                                                 |
| **Time Zone Information**  | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`                          | Establish the local time zone to ensure the correct chronology of events.                           |
| **Network Interfaces**     | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`                 | Obtain TCP/IP configurations, including IP addresses, DHCP, DNS, and Subnet Mask.                   |
| **Past Networks**          | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged` | Identify previously connected networks and their last connection times.                             |
|                            | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed`   |                                                                                                     |
| **Autostart Programs**     | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run`                      | Determine programs or services configured to start automatically during boot or user logon.         |
|                            | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce`                  |                                                                                                     |
|                            | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`                                 |                                                                                                     |
|                            | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`                             |                                                                                                     |
|                            | `SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run`               |                                                                                                     |
|                            | `SYSTEM\CurrentControlSet\Services`                                             |                                                                                                     |
| **SAM Hive and User Info** | `SAM\Domains\Account\Users`                                                     | Retrieve user account details, login history, password policies, and group memberships.             |

### Questions

**What is the Current Build Number of the machine whose data is being investigated?**

*CurrentBuild* in `SOFTWARE\Microsoft\Windows NT\CurrentVersion`.

*Answer : `19044`*

**Which ControlSet contains the last known good configuration?**

*LastKnownGood* in `SYSTEM\Select\Current`.

*Answer : `1`*

**What is the Computer Name of the computer?**

*ComputerName* in `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`.

*Answer : `THM-4n6`*

**What is the value of the *TimeZoneKeyName*?**

*TimeZoneKeyName* in `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`.

*Answer : `Pakistan Standard Time`*

**What is the DHCP IP address**

*DhcpIPAddress* in `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`.

*Answer : `192.168.100.58`*

**What is the RID of the Guest User account?**

*UserId* in `SAM\Domains\Account\Users`.

*Answer : `501`*

## Task 7 - Usage or knowledge of Files/Folders

In order for Windows to remember about recent files or locations opened, these need to be stored somewhere, which is in the Registry. The common places to find information about this topic are in the following hives :

- **NTUSER.DAT**: `%USERPROFILE%\NTUSER.DAT` – Stores user-specific settings like preferences, recent files, and autostart entries.  
- **USRCLASS.DAT**: `%USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat` – Stores user-specific shell and GUI configurations.  

Here is a summary table for many types or file/folder tracking data in the registry :

| Information                               | Registry Location(s)                                                                        | Purpose                                                                                                                                                |
|-------------------------------------------|---------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Recent Files**                          | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`                  | Tracks recently accessed files. Also provides MRU data for specific file extensions (e.g., `.pdf`).                                                    |
|                                           | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.pdf`             | Enables identification of files based on extensions, with timestamps for last access.                                                                  |
| **Office Recent Files**                   | `NTUSER.DAT\Software\Microsoft\Office\VERSION`                                              | Tracks recent Office document activity by application (e.g., Word, Excel).                                                                             |
|                                           | `NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU`                  | Contains detailed paths of recently accessed Office files tied to user accounts.                                                                       |
| **ShellBags**                             | `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags`                         | Tracks folder view settings and layouts for each user, along with the history of accessed directories.                                                 |
|                                           | `USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`                       | ShellBags can help identify the Most Recently Used (MRU) folders and files, even for deleted or moved folders, aiding in reconstructing user activity. |
|                                           | `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU`                                        |                                                                                                                                                        |
|                                           | `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags`                                          |                                                                                                                                                        |
| **Open/Save and LastVisited Dialog MRUs** | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePIDlMRU`    | Tracks recently accessed files via open/save dialog boxes, aiding in identifying file interaction.                                                     |
|                                           | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU` | Tracks recent folder or file locations visited via dialogs.                                                                                            |
| **Windows Explorer Address/Search Bars**  | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`                  | Records paths typed in the Windows Explorer address bar, helping trace user navigation.                                                                |
|                                           | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`              | Tracks searches performed in Windows Explorer.                                                                                                         |
|                                           | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`                                             |                                                                                                                                                        |
|                                           | `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`                                         |                                                                                                                                                        |
|                                           | `SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer\Run`                           |                                                                                                                                                        |
|                                           | `SYSTEM\CurrentControlSet\Services`                                                         |                                                                                                                                                        |

### Questions

**When was EZtools opened?**

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/SkofnfkIyl.png" title="Registry Explorer Recent Files" class="img-fluid rounded z-depth-1" %}

*OpenedOn* in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`.

*Answer : `2021-12-01 13:00:34`*

**At what time was My Computer last interacted with?**

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/SJh23GkIkx.png" title="ShellBags Explorer" class="img-fluid rounded z-depth-1" %}

*LastInteracted* in `USRCLASS.DAT` using *ShellBags Explorer* by  Eric Zimmerman.

*Answer : `2021-12-01 13:06:47`*

**What is the Absolute Path of the file opened using notepad.exe?**

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/H1jepfJLJe.png" title="Registry Explorer Last Visited Dialog MRUs" class="img-fluid rounded z-depth-1" %}

*AbsolutePath* in `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`.

*Answer : `C:\Program Files\Amazon\Ec2ConfigService\Settings`*

**When was this file opened?**

*OpenedOn* at the same location as before.

*Answer : `2021-11-30 10:56:19`*

## Task 8 - Evidence of Execution

For statistical purposes, Windows keeps track of applications launched by the user using Windows Explorer. These informations are contained into the Registry within many Hives. Down below is a summary of the different execution data that are possible to retrieve :

| Evidence Type  | Registry Location                                                                       | Purpose                                                                                                                                                                                        |
|----------------|-----------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **UserAssist** | `NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count` | Tracks programs launched via Windows Explorer, including launch time and execution count. Does not include programs run from the command line.                                                 |
| **ShimCache**  | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`                       | Tracks all launched applications for compatibility purposes, storing file names, sizes, and last modified times. It is also called *Application Compatibility Cache* (AppCompatCache).         |
|                |                                                                                         | Because Registry Explorer does not parse ShimCache Data in a human-readable format, we need to first use *AppCompatCacheParser*, which exports it in *csv* and then, view it using *EZviewer*. |
| **AmCache**    | `C:\Windows\appcompat\Programs\Amcache.hve\Root\File\{Volume GUID}\`                    | Artifact related to ShimCache. Provides detailed data on executed programs, including execution path, times (install, execute, delete), and SHA1 hashes.                                       |
| **BAM/DAM**    | `SYSTEM\CurrentControlSet\Services\bam\UserSettings\{SID}`                              | Monitors background and desktop application activity, including last run programs, their paths, and last execution times to optimize power consumption.                                        |
|                | `SYSTEM\CurrentControlSet\Services\dam\UserSettings\{SID}`                              |                                                                                                                                                                                                |

### Questions

**How many times was the File Explorer launched?**

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/SJ0ygNyUJx.png" title="Registry Explorer " class="img-fluid rounded z-depth-1" %}

- **Value** : *RunCounter*
- **Location** :`NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{GUID}\Count`
- **Program Name** : *{User Pinned}\Taskbar\File Explorer.Ink*

*Answer : `26`*

**What is another name for ShimCache?**

*Answer : `AppCompatCache`*

**Which of the artifacts also saves SHA1 hashes of the executed programs?**

*Answer : `AmCache`*

**Which of the artifacts saves the full path of the executed programs?**

*Answer : `BAM/DAM`*

## Task 9 - External Devices/USB device forensics

When performing forensics on a machine, there is often the need to identify if any USB or removable devices were attached to the machine and some of their characteristics. Subsequently, there are different ways to find information on connected devices and system drives on a system using the registry, which are resumed in the table below :

| **Information**            | **Registry Location**                                                                                                      | **Purpose**                                                                                                                                                |
|----------------------------|----------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Device Identification**  | `SYSTEM\CurrentControlSet\Enum\USBSTOR`                                                                                    | Tracks USB devices connected to the system, including vendor ID, product ID, and version.                                                                  |
|                            | `SYSTEM\CurrentControlSet\Enum\USB`                                                                                        | Stores identification details of USB devices plugged into the system.                                                                                      |
| **First/Last Times**       | `SYSTEM\CurrentControlSet\Enum\USBSTOR\Ven_Prod_Version\USBSerial#\Properties\{83da6326-97a6-4088-9453-a19231573b29}\####` | Tracks the first and last times the device was connected and the last time it was removed. The *####* sign needs to be replaced by the following digits.   |
|                            | **Value Codes**: `0064` (First Connection time), `0066` (Last Connection time), `0067` (Last Removal time)                 | Provides timestamp data for when the USB device was connected or removed. This data is already parsed by *Registry Explorer* if *USBSTOR* key is selected. |
| **USB Device Volume Name** | `SOFTWARE\Microsoft\Windows Portable Devices\Devices`                                                                      | Stores the device name of the connected USB drive, used to correlate with unique devices.                                                                  |

### Questions

**What is the serial number of the device from the manufacturer 'Kingston'?**

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/Sya1V4JL1l.png" title="Registry Explorer USB Device identification" class="img-fluid rounded z-depth-1" %}

- **Value** : *SerialNumber*
- **Location** : `SYSTEM\CurrentControlSet\Enum\USBSTOR`

*Answer : `1C6f654E59A3B0C179D366AE&0`*

**What is the name of this device?**

Using the same image as the *Question 1*.

- **Value** : *DeviceName*
- **Location** : `SYSTEM\CurrentControlSet\Enum\USBSTOR`

*Answer : `Kingston Data Traveler 2.0 USB Device`*

**What is the friendly name of the device from the manufacturer 'Kingston'?**

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/B1dzB418kx.png" title="Registry Explorer USB device Volume Name" class="img-fluid rounded z-depth-1" %}

- **Value** : *Friendly Name*
- **Location** : `SOFTWARE\Microsoft\Windows Portable Devices\Devices`

*Answer : `USB`*

## Task 10 - Hands-on Challenge

In this task, we are required to make a **forensic analysis on a triage** (Quick, initial collection of key forensic artifacts from a system) to put in practice what we have learnt. Below is the presented challenge setup.

``` raw
The Setup

If preferred, use the following credentials to log into the machine:

Username: THM-4n6

Password: 123

Once we log in, we will see two folders on the Desktop named triage and EZtools. The triage folder contains a triage collection collected through KAPE, which has the same directory structure as the parent. This is where our artifacts will be located. The EZtools folder contains Eric Zimmerman's tools, which we will be using to perform our analysis. You will also find RegistryExplorer, EZViewer, and AppCompatCacheParser.exe in the same folder.

The Challenge

Now that we know where the required toolset is, we can start our investigation. We will have to use our knowledge to identify where the different files for the relevant registry hives are located and load them into the tools of our choice. Let's answer the questions below using our knowledge of registry forensics.

Scenario

One of the Desktops in the research lab at Organization X is suspected to have been accessed by someone unauthorized. Although they generally have only one user account per Desktop, there were multiple user accounts observed on this system. It is also suspected that the system was connected to some network drive, and a USB device was connected to the system. The triage data from the system was collected and placed on the attached VM. Can you help Organization X with finding answers to the below questions?

Note: When loading registry hives in RegistryExplorer, it will caution us that the hives are dirty. This is nothing to be afraid of. We just need to remember the little lesson about transaction logs and point RegistryExplorer to the .LOG1 and .LOG2 files with the same filename as the registry hive. It will automatically integrate the transaction logs and create a 'clean' hive. Once we tell RegistryExplorer where to save the clean hive, we can use that for our analysis and we won't need to load the dirty hives anymore. RegistryExplorer will guide you through this process. 
```

### Questions

**How many user created accounts are present on the system?**

- **Hive Location** : `C:\Windows\System32\config\SAM`
- **Registry Location** : `SAM\Domains\Account\Users`

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/H1mbjEJLJe.png" title="Registry Explorer User Accounts" class="img-fluid rounded z-depth-1" %}

*Answer : `3`*

> **Note**
> Here *Registry Explorer* automatically parses every users' values. Normally, all these values are stored in a binary form like below.
>
> {% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/Bkg02NyIyx.png" title="A user in the Registry" class="img-fluid rounded z-depth-1" %}

**What is the username of the account that has never been logged in?**

- **Hive Location** : `C:\Windows\System32\config\SAM`
- **Registry Location** : `SAM\Domains\Account\Users`
- **Registry Value** : *Last Login Time*

*Answer : `thm-user2`*

**What's the password hint for the user THM-4n6?**

- **Hive Location** : `C:\Windows\System32\config\SAM`
- **Registry Location** : `SAM\Domains\Account\Users`
- **Registry Value** : *Password Hint*

*Answer : `count`*

**When was the file 'Changelog.txt' accessed?**

The *Find* feature of *Registry Explorer* can also be used to find certain *Key Values*. Moreover, when I loaded in the *NTUSER.DAT* hive, I was requested to load transaction logs *NTUSER.DAT.log1* and *NTUSER.DAT.log2* to create a clean hive.

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/ry1TkBk8Je.png" title="Registry Explorer Find tool" class="img-fluid rounded z-depth-1" %}

- **Hive Location** : `%USERPROFILE%\NTUSER.DAT`
- **Registry Location** : `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`
- **Registry Value** : *Opened On*

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/Hkc5JSk8kx.png" title="Registry Explorer Recent Docs" class="img-fluid rounded z-depth-1" %}

*Answer : `2021-11-24 18:18:48`*

**What is the complete path from where the python 3.8.2 installer was run?**

> **Note**  
>GUIDs are unique identifiers used to track the type of access to files and applications. For example:  
>
> - `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` tracks a list of applications, files, and other objects accessed.  
> - `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` lists the shortcut links used to start programs.
> Here we need to know the data that corresponds to the python 3.8.2 installer, hence we will check into the first mentioned GUID.

- **Hive Location** : `%USERPROFILE%\NTUSER.DAT`
- **Registry Location** : `NTUSER.DAT\Software\Microsoft\Windows\Currentversion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count`
- **Registry Value** : *Last Executed*

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/r17E-By81x.png" title="Registry Explorer Recently Opened Files" class="img-fluid rounded z-depth-1" %}

*Answer : `Z:\setups\python-3.8.2.exe`

**When was the USB device with the friendly name 'USB' last connected?**

Firstly, we need to retrieve the usb device's GUID.

- **Hive Location** : `C:\Windows\System32\SOFTWARE`
- **Registry Location** : `SOFTWARE\Microsoft\Windows Portable Devices`
- **Registry Value** : *GUID*

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/r1ZQTHkIkx.png" title="Registry Explorer Portable Devices" class="img-fluid rounded z-depth-1" %}

Then, we have to correlate the GUID *{e251...7110}* of the device's frieldy name *USB* to the one located in *USBSTOR*, in order to get the last connected timestamp.

- **Hive Location** : `C:\Windows\System32\SYSTEM`
- **Registry Location** : `SYSTEM\ControlSet001\Enum\USBSTOR
- **Registry Value** : *Last Connected*

{% include figure.liquid path="/assets/img/images/2024-12-17-thm-windows-forensics-1/HkAXAr1U1e.png" title="Registry Explorer USB Storage" class="img-fluid rounded z-depth-1" %}

*Answer : `2021-11-24 18:40:06`*

## Task 11 - Conclusion

In conclusion, Windows registry forensics is essential for extracting and analyzing system and user activity data. Accessing offline registry hives allows forensic investigators to examine system information, including OS version, hardware configuration, user accounts, and device interactions. Tools like Registry Explorer and Eric Zimmerman's utilities simplify the exploration of registry hives and provide insights into system and user activity. Key areas include evidence of file and application usage (via `UserAssist` and `ShimCache`), external device connection history (via USBSTOR), and user activity regarding files and folders. These artifacts offer a comprehensive understanding of system behavior, application execution, and device interactions, providing crucial evidence for forensic investigations.

A Windows Forensics Cheat Sheet made by *[umairalizafar](https://tryhackme.com/p/umairalizafar)*, the author of this room, is available [here](https://assets.tryhackme.com/cheatsheets/Windows%20Forensics%20Cheatsheet.pdf).
