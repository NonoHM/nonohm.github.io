---
layout: post
title: THM CTF Investigating Windows
tags: [CTF, THM, Windows]
date: 2023-10-08 15:02:47
toc:
    sidebar: left
    toc-depth: 3
---

## Introduction

In today's CTF, we'll investigate a windows machine that has been hacked to find clues of what the hacker might have done.

## Task 1 - Investigating Windows

We have to connect to the infected machine through RDP.

Username: Administrator
Password: letmein123!

``` sh
xfreerdp /v:10.10.36.176 /u:Administrator /p:letmein123!
```

After being connected to it, we check the version of windows that is running.

``` cmd
winver
```

![Winver](/assets/img/images/thm_ctf_investigating_windows_writeup/HyCRqXgWp.png)

**Whats the version and year of the windows machine?**

*Answer: `Windows Server 2016`*

We also have to check who was the last person connected to the machine.

``` powershell
PS C:\Users\Administrator> Get-LocalUser | Select Name, Lastlogon

Name           LastLogon
----           ---------
Administrator  10/8/2023 1:09:49 PM
DefaultAccount
Guest
Jenny
John           3/2/2019 5:48:32 PM

```

**Which user logged in last?**

*Answer: `Administrator`*

**When did John log onto the system last?**

*Answer: `03/02/2019 5:48:32 PM`*

To get which programs run on startup, we can use the following command on Powershell.

``` powershell
PS C:\Users\Administrator> Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User

Command                                                Description User
-------                                                ----------- ----
C:\TMP\p.exe -s \\10.34.2.3 'net user' > C:\TMP\o2.txt UpdateSvc   Public
```

We can see at every startup, a suspicious program connect to an unknown IP address.

**What IP does the system connect to when it first starts?**

*Answer: `10.34.2.3`*

We need to know who are the system administators other than *Administrator* if the hacker can access to the machine with those privileges.

``` powershell
PS C:\Users\Administrator> Get-LocalGroupMember Administrators

ObjectClass Name                          PrincipalSource
----------- ----                          ---------------
User        EC2AMAZ-I8UHO76\Administrator Local
User        EC2AMAZ-I8UHO76\Guest         Local
User        EC2AMAZ-I8UHO76\Jenny         Local
```

**What two accounts had administrative privileges (other than the Administrator user)?**

*Answer: `Guest, Jenny`*

To get the current scheduled tasks, we can use the command `Get-ScheduledTask`

``` powershell
PS C:\Users\Administrator> Get-ScheduledTask

TaskPath                                       TaskName                          State
--------                                       --------                          -----
\                                              Amazon Ec2 Launch - Instance I... Disabled
\                                              check logged in                   Ready
\                                              Clean file system                 Ready
\                                              falshupdate22                     Ready
```
There's 4 suspicious tasks. To get their actions, we run the command `(ScheduledTask "Clean file system").Actions`

``` powershell

PS C:\Users\Administrator> (Get-ScheduledTask 'Clean file system').Actions


Id               :
Arguments        : -l 1348
Execute          : C:\TMP\nc.ps1
WorkingDirectory :
PSComputerName   :



PS C:\Users\Administrator> (Get-ScheduledTask 'Check logged in').Actions


Id               :
Arguments        :
Execute          : "C:\Program Files (x86)\Internet Explorer\iexplore.exe"
WorkingDirectory :
PSComputerName   :



PS C:\Users\Administrator> (Get-ScheduledTask 'falshupdate22').Actions


Id               :
Arguments        : -WindowStyle Hidden -nop -c ""
Execute          : powershell.exe
WorkingDirectory :
PSComputerName   :



PS C:\Users\Administrator> (Get-ScheduledTask 'GameOver').Actions


Id               :
Arguments        : sekurlsa::LogonPasswords > C:\TMP\o.txt
Execute          : C:\TMP\mim.exe
WorkingDirectory :
PSComputerName   :

```

**Whats the name of the scheduled task that is malicious.**

*Answer: `clean file system`*

**What file was the task trying to run daily?**

*Answer: `nc.ps1`*

**What port did this file listen locally for?**

*Answer: `1348`*

With the last ran command `Get-LocalUser | Select Name, Lastlogon`, we know the user account *Jenny* never logged in.

**When did Jenny last logon?**

*Answer: `Never`*

To know more informations about Jenny (because the account looks suspect), we can run `net user Jenny` or `Get-LocalUser Jenny | Select *`

``` powershell
PS C:\Users\Administrator> Get-LocalUser Jenny | Select *


AccountExpires         :
Description            :
Enabled                : True
FullName               : Jenny
PasswordChangeableDate : 3/2/2019 4:52:25 PM
PasswordExpires        :
UserMayChangePassword  : True
PasswordRequired       : True
PasswordLastSet        : 3/2/2019 4:52:25 PM
LastLogon              :
Name                   : Jenny
SID                    : S-1-5-21-3685962493-259677494-3116396707-1008
PrincipalSource        : Local
ObjectClass            : User
```

**At what date did the compromise take place?**

*Answer: `03/02/2019`*

To know when Windows first assigned special privileges to a new logon, we can use `Get-EventLog` with powershell and some filter or the Event Viewer.
With some research, we know the EventID assigned to 4672 and because the hint says `00/00/0000 0:00:49 PM`, it helps to narrow our results.

``` powershell
$startTime = Get-Date "3/2/2019 4:00:00 PM"
$endTime = Get-Date "3/2/2019 5:00:00 PM"
Get-EventLog -LogName "Security" | Where-Object { $_.EventID -eq 4672 -and $_.TimeGenerated -ge $startTime -and $_.TimeGenerated -lt $endTime } | Select-Object -Property @{Label="LogonName";Expression={$_.ReplacementStrings[0]}}, @{Label="CreationTime";Expression={$_.TimeGenerated}}, @{Label="Description";Expression={$_.Message}}
```

Or to get the non-concatenated Descriptions
``` powershell
$startTime = Get-Date "3/2/2019 4:00:00 PM"
$endTime = Get-Date "3/2/2019 5:00:00 PM"
Get-EventLog -LogName "Security" | Where-Object { $_.EventID -eq 4672 -and $_.TimeGenerated -ge $startTime -and $_.TimeGenerated -lt $endTime } | ForEach-Object {
    $logonName = $_.ReplacementStrings[0]
    $creationTime = $_.TimeGenerated
    $description = $_.Message -split "`r`n"  # Split the message into an array of lines
    
    # Output each line as a separate object
    $description | ForEach-Object {
        [PSCustomObject]@{
            LogonName = $logonName
            CreationTime = $creationTime
            Description = $_
        }
    }
} | Select-Object -Property LogonName, CreationTime, Description

S-1-5-18                                     3/2/2019 4:04:49 PM Special privileges assigned to new logon.
S-1-5-18                                     3/2/2019 4:04:49 PM
S-1-5-18                                     3/2/2019 4:04:49 PM Subject:
S-1-5-18                                     3/2/2019 4:04:49 PM        Security ID:            S-1-5-18
S-1-5-18                                     3/2/2019 4:04:49 PM        Account Name:           SYSTEM
S-1-5-18                                     3/2/2019 4:04:49 PM        Account Domain:         NT AUTHORITY
S-1-5-18                                     3/2/2019 4:04:49 PM        Logon ID:               0x3e7
S-1-5-18                                     3/2/2019 4:04:49 PM
S-1-5-18                                     3/2/2019 4:04:49 PM Privileges:            SeAssignPrimaryTokenPrivilege
S-1-5-18                                     3/2/2019 4:04:49 PM                        SeTcbPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeSecurityPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeTakeOwnershipPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeLoadDriverPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeBackupPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeRestorePrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeDebugPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeAuditPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeSystemEnvironmentPrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeImpersonatePrivilege

S-1-5-18                                     3/2/2019 4:04:49 PM                        SeDelegateSessionUserImpersonatePrivilege
```

**During the compromise, at what time did Windows first assign special privileges to a new logon?**

*Answer: `03/02/2019 4:04:49 PM`*

We now look at the scheduled task *GameOver*.
It shows that it uses mimikatz to retrieve passwords.

``` powershell
PS C:\Users\Administrator> Get-ScheduledTaskInfo 'GameOver'


LastRunTime        : 10/8/2023 2:27:27 PM
LastTaskResult     : 0
NextRunTime        : 10/8/2023 2:32:32 PM
NumberOfMissedRuns : 0
TaskName           : GameOver
TaskPath           :
PSComputerName     :

PS C:\Users\Administrator> (Get-ScheduledTask 'GameOver').Actions


Id               :
Arguments        : sekurlsa::LogonPasswords > C:\TMP\o.txt
Execute          : C:\TMP\mim.exe
WorkingDirectory :
PSComputerName   :

```

We could have take the hash and check on the internet but we can guess.

**What tool was used to get Windows passwords?**

*Answer: `mimikatz`*

For the attackers, they have multiple options to resolve a FQDN to their C2 IP address. The simplest form of it is just by putting an entry in the *hosts* file. 
We can check it by retrieving its content.
Here we see a suspicious entry, the FQDN google.com or its alias www.google.com is already here.

``` powershell
PS C:\Users\Administrator> cat C:\Windows\System32\drivers\etc\hosts
# Copyright (c) 1993-2009 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

# localhost name resolution is handled within DNS itself.
#       127.0.0.1       localhost
#       ::1             localhost
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
10.2.2.2        update.microsoft.com
127.0.0.1  www.virustotal.com
127.0.0.1  www.www.com
127.0.0.1  dci.sophosupd.com
76.32.97.132 google.com
76.32.97.132 www.google.com
```

**What was the attackers external control and command servers IP?**

*Answer: `76.32.97.132`*

Apparently, this server was a probably a webserver because we can see the directory `C:\inetpub\wwwroot` created. That means the attackers could have accessed to the machine using an uploaded malware.
This is what the directory contains.

``` powershell
PS C:\inetpub\wwwroot> ls


    Directory: C:\inetpub\wwwroot


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/2/2019   4:37 PM          74853 b.jsp
-a----         3/2/2019   4:37 PM          12572 shell.gif
-a----         3/2/2019   4:37 PM            657 tests.jsp
```

The server was certainly a java web server.

**What was the extension name of the shell uploaded via the servers website?**

*Answer: `.jsp`*

To know what outbound port exception the attacker has made, we can use the *Event Viewer* at `Applications and Services Logs\Microsoft\Windows\Windows Firewall with Advanced Security\Firewall` or we can use a powershell command.
When we look and filter at the date *3/2/2019*, the date of attack, we have to see through all the events to determine which one can be useful.

![Event Viewer](/assets/img/images/thm_ctf_investigating_windows_writeup/Bk4__DgW6.png)

``` powershell
$eventLogName = "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"
$eventID = 2004
$targetDate = Get-Date "3/2/2019"

Get-WinEvent -LogName $eventLogName -FilterXPath "*[System[(EventID=$eventID) and TimeCreated[@SystemTime>='$($targetDate.AddHours(0).ToString("yyyy-MM-ddTHH:mm:ss") + "Z")' and @SystemTime<'$($targetDate.AddHours(24).ToString("yyyy-MM-ddTHH:mm:ss") + "Z")']]]" | 
    Format-Table -Property TimeCreated, Id, ProviderName, Message -AutoSize
```

> Not very useful, better use the graphical version.

**What was the last port the attacker opened?**

*Answer: `1337`*

When we looked at the *hosts* file, we saw that the site google.com was usurpated. That's called DNS Poisoning and used to trick the user that the connection being made to the C2 is not malicious.

**Check for DNS poisoning, what site was targeted?**

*Answer: `google.com`*
