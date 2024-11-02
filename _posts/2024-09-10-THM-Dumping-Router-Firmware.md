---
layout: post
title: THM Dumping Router Firmware
tags: [THM, CTF, Forensics]
author: NonoHM
date: 2024-09-10 18:31:46
toc:
    sidebar: left
    toc-depth: 3
---

> **Note:**  
> Unlike many of my other writeups, this one doesn’t include a summary, and the phrases are identical to those in [Dumping Router Firmware](https://tryhackme.com/r/room/rfirmware). I completed this room to gain a basic overview of firmware analysis.

## Task 1 - Preparation

### Installing the Required Software

Each year millions of home routers are sold to consumers; a large majority of them don't even know what's running on them. Today we're going to take a look. Before proceeding, we will need a few tools:

- Access to a Linux distribution (Or WSL) with strings and binwalk on it.
- Linksys WRT1900ACS v2 Firmware found here: <https://github.com/Sq00ky/Dumping-Router-Firmware-Image/>
- Lastly, ensure binwalk has JFFS2 support with the following command:

``` raw
sudo pip install cstruct; 

git clone https://github.com/sviehb/jefferson;

cd jefferson && sudo python setup.py install
```

After you've got the tools, you're ready to set up your workspace!

### Rebuilding the Firmware

First, we're going to clone the repository that holds the firmware:

git clone <https://github.com/Sq00ky/Dumping-Router-Firmware-Image/> /opt/Dumping-Router-Firmware && cd /opt/Dumping-Router-Firmware/

Next, we're going to unzip the multipart zip file:

`7z x ./FW_WRT1900ACSV2_2.0.3.201002_prod.zip`

running ls you should see the firmware image:

``` raw
FW_WRT1900ACSV2_2.0.3.201002_prod.img
```

Lastly, running a `sha256sum`  on the firmware image you should be left with the value

``` raw
dbbc9e8673149e79b7fd39482ea95db78bdb585c3fa3613e4f84ca0abcea68a4
```

## Task 2 - Investigating Firmware

In this section we will be taking a look at the firmware, checking for strings and, dump the file system from the image. The next section will cover mounting and exploring the file system.

*While running strings on the file, there is a lot of notable clear text. This is due to certain aspects of the firmware image not being encrypted. This likely means that with Binwalk, we can dump the firmware from the image.*

**What does the first clear text line say when running `strings` on the file?**

By running `strings FW_WRT1900ACSV2_2.0.3.201002_prod.img | head`, we get the following result:

``` sh
┌──(nono㉿lenovo-PC)-[/opt/Dumping-Router-Firmware]
└─$ strings FW_WRT1900ACSV2_2.0.3.201002_prod.img | head
Linksys WRT1900ACS Router
@ #!
!1C "
 -- System halted
Attempting division by 0!
Uncompressing Linux...
decompressor returned an error
 done, booting the kernel.
invalid distance too far back
invalid distance code
```

*Answer: `Linksys WRT1900ACS Router`*

**Also, using `strings`, what operating system is the device running?**

*Answer: `Linux`*

Scrolling through with strings, you may notice some other interesting lines like

`/bin/busybox`

and various other lua files. It really makes you wonder what's going on inside there

Next, we will be dumping the filesystem from the image file. To do so, we will be using a tool called binwalk.

Binwalk is a tool that checks for well-known file signatures within a given file. This can be useful for many things; it even has its uses in Steganography. A file could be hidden within the photo, and Binwalk would reveal that and help us extract it. We will be using it to extract the filesystem of the router in this instance.

**What option within Binwalk will allow us to extract files from the firmware image?**

By checking the help page with `binwalk -h`, we get that:

``` sh
┌──(nono㉿lenovo)-[/opt/Dumping-Router-Firmware]
└─$ binwalk -h
/usr/lib/python3/dist-packages/binwalk/core/magic.py:431: SyntaxWarning: invalid escape sequence '\.'
  self.period = re.compile("\.")

Binwalk v2.3.3
Craig Heffner, ReFirmLabs
https://github.com/ReFirmLabs/binwalk

Usage: binwalk [OPTIONS] [FILE1] [FILE2] [FILE3] ...
...

Extraction Options:
    -e, --extract                Automatically extract known file types
    -D, --dd=<type[:ext[:cmd]]>  Extract <type> signatures (regular expression), give the files an extension of <ext>, and execute <cmd>
    -M, --matryoshka             Recursively scan extracted files
    -d, --depth=<int>            Limit matryoshka recursion depth (default: 8 levels deep)
    -C, --directory=<str>        Extract files/folders to a custom directory (default: current working directory)
    -j, --size=<int>             Limit the size of each extracted file
    -n, --count=<int>            Limit the number of extracted files
    -0, --run-as=<str>           Execute external extraction utilities with the specified user's privileges
    -1, --preserve-symlinks      Do not sanitize extracted symlinks that point outside the extraction directory (dangerous)
    -r, --rm                     Delete carved files after extraction
    -z, --carve                  Carve data from files, but don't execute extraction utilities
    -V, --subdirs                Extract into sub-directories named by the offset
```

*Answer: `-e`*

**Now that we know how to extract the contents of the firmware image, what was the first item extracted?**

After doing `sudo binwalk -e FW_WRT1900ACSV2_2.0.3.201002_prod.img --run-as=root`, we get all the extracted and detailed contents:

``` sh
┌──(nono㉿lenovo)-[/opt/Dumping-Router-Firmware]
└─$ sudo binwalk -e FW_WRT1900ACSV2_2.0.3.201002_prod.img --run-as=root

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             uImage header, header size: 64 bytes, header CRC: 0xFF40CAEC, created: 2020-04-22 11:07:26, image size: 4229755 bytes, Data Address: 0x8000, Entry Point: 0x8000, data CRC: 0xABEBC439, OS: Linux, CPU: ARM, image type: OS Kernel Image, compression type: none, image name: "Linksys WRT1900ACS Router"
64            0x40            Linux kernel ARM boot executable zImage (little-endian)
26736         0x6870          gzip compressed data, maximum compression, from Unix, last modified: 1970-01-01 00:00:00 (null date)
4214256       0x404DF0        Flattened device tree, size: 15563 bytes, version: 17
...
6291456       0x600000        JFFS2 filesystem, little endian
```

*Answer: `uImage header`*

**What was the creation date?**

*Answer: `2020-04-22 11:07:26`*

The Cyclical Redundancy Check is used similarly to file hashing to ensure that the file contents were not corrupted and/or modified in transit.

**What is the CRC of the image?**

The CRC of the image is provided in the binwalk's extraction resume

*Answer: `0xABEBC439`*

**What is the image size?**

*Answer: `4229755 bytes`*

**What architecture does the device run?**

*Answer: `ARM`*

**Researching the results to question 10, is that true?**

Knowing the device architecture is very important for reverse engineering.

*Answer: `yes`*

You will notice two files got extracted, one being the jffs2 file system and another that Binwalk believes in gzipping compressed data.

You can attempt to extract the data, but you won't get anywhere. Binwalk misinterpreted the data. However, we can still do some analysis of it.

**Running strings on 6870, we notice a large chunk of clear text. We can actually rerun binwalk on this file to receive even more files to investigate. Interestingly enough, a copy of the Linux kernel is included. What version is it for?**

When we run `sudo binwalk -e 6870 --run-as=root`, we get an new extraction of the file

``` sh
┌──(nono㉿lenovo)-[/opt/Dumping-Router-Firmware/_FW_WRT1900ACSV2_2.0.3.201002_prod.img.extracted]
└─$ sudo binwalk -e 6870 --run-as=root
[sudo] password for nono:

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
1904228       0x1D0E64        SHA256 hash constants, little endian
4112676       0x3EC124        SHA256 hash constants, little endian
5877920       0x59B0A0        Linux kernel version 3.10.3
6120324       0x5D6384        AES S-Box
6120580       0x5D6484        AES Inverse S-Box
6176102       0x5E3D66        Unix path: /var/run/rpcbind.sock
6261498       0x5F8AFA        MPEG transport stream data
6261758       0x5F8BFE        MPEG transport stream data
6902132       0x695174        Unix path: /dev/vc/0
6993884       0x6AB7DC        xz compressed data
7027944       0x6B3CE8        Unix path: /lib/firmware/updates/3.10.39
```

Thus, we get the linux kernel version, which is 3.10.3.

*Answer: `3.10.39`*

Suppose you extract the contents of 6870 with Binwalk and run strings on 799E38.cpio, you may see a lot of hex towards the bottom of the file. Some of it can be translated into human-readable text. Some of it is interesting and makes you wonder about its purpose. Some additional investigation may reveal its purpose. I will leave you to explore that on your own, though :)

Continuing with the analysis, we have a jffs2 file system that we can examine the contents of. First, we must mount it, bringing us to the next section.

## Task 3 - Mounting and Analysis of the Router's Filesystem

In this section, we will begin to review how to mount the file system. Note, if you are doing this with any other file system, not in the Little Endian format, you must convert it from Big Endian to Little Endian using a tool called jffs2dump. But here is a reasonably concise guide to mounting the filesystem:

Step 1. If /dev/mtdblock0 exists, remove the file/directory and re-create the block device

``` sh
rm -rf /dev/mtdblock0
mknod /dev/mtdblock0 b 31 0
```

Step 2. Create a location for the jffs2 filesysystem to live

``` sh
mkdir /mnt/jffs2_file/
```

Step 3. Load required kernel modules

``` sh
modprobe jffs2
modprobe mtdram
modprobe mtdblock
```

Step 4. Write image to /dev/mtdblock0

``` sh
dd if=/opt/Dumping-Router-Firmware-Image/_FW_WRT1900ACSV2_2.0.3.201002_prod.img.extracted/600000.jffs2 of=/dev/mtdblock0
```

Step 5. Mount file system to folder location

``` sh
mount -t jffs2 /dev/mtdblock0 /mnt/jffs2_file/
```

Step 6. Lastly, move into the mounted filesystem.

``` sh
cd /mnt/jffs2_file/
```

To explain a little bit of what the command does, we're creating a block device (mtdblock ([Memory Technology Device](https://en.wikipedia.org/wiki/Memory_Technology_Device))) that will allow us to dump the flash memory. We're first removing it if it exists, and then re-creating it.

Next, we're creating a location for our [jffs2](https://en.wikipedia.org/wiki/JFFS2) file to be mounted to.

After that, we're loading some kernel modules that will allow us to interact with the jffs2 file system and dump the flash memory.

Next, we write the file system to the block device, and after that we mount the mtdblock device which now contains the flash memory of the file system.  

Lastly, executing  `cd /mnt/jffs2_file/` we are now sitting inside the router's dumped firmware and can begin the investigation.

### Questions

Running an ls -la reveals a lot of interesting information. First, we notice that many files are symbolically linked (similar to a shortcut).  

``` sh
root@ip-10-10-205-228:/mnt/jffs2_file# ls -lha
total 6.5K
drwxr-xr-x 17 root root    0 Jan  1  1970 .
drwxr-xr-x  3 root root 4.0K Oct 10 13:45 ..
drwxr-xr-x  2 root root    0 Apr 22  2020 bin
drwxr-xr-x  2 root root    0 Apr 22  2020 cgroup
drwxr-xr-x  2 root root    0 Apr 22  2020 dev
drwxr-xr-x 17 root root    0 Apr 22  2020 etc
drwxr-xr-x  2 root root    0 Apr 22  2020 home
drwxr-xr-x  3 root root    0 Apr 22  2020 JNAP
drwxr-xr-x  2 root root    0 Apr 22  2020 lib
lrwxrwxrwx  1 root root   11 Apr 22  2020 linuxrc -> bin/busybox
lrwxrwxrwx  1 root root    8 Apr 22  2020 mnt -> /tmp/mnt
-r--r--r--  1 root root   20 Apr 22  2020 .mtoolsrc
lrwxrwxrwx  1 root root    8 Apr 22  2020 opt -> /tmp/opt
drwxr-xr-x  2 root root    0 Apr 22  2020 proc
drwxr-xr-x  2 root root    0 Apr 22  2020 root
drwxr-xr-x  2 root root    0 Apr 22  2020 sbin
drwxr-xr-x  2 root root    0 Apr 22  2020 sys
drwxr-xr-x  2 root root    0 Apr 22  2020 tmp
drwxr-xr-x  2 root root    0 Apr 22  2020 usr
lrwxrwxrwx  1 root root    8 Apr 22  2020 var -> /tmp/var
drwxr-xr-x  2 root root    0 Apr 22  2020 www
```

**Where does linuxrc link to?**

*Answer: `/bin/busybox`*

**What parent folder do mnt, opt, and var link to?**

*Answer: `/tmp/`*

**What folder would store the router's HTTP server?**

*Answer: `/www/`*

Scanning through a lot of these folders, you may begin to notice that they are empty. This is extremely strange, but that is because the router is not up and running. Remember, we are merely looking at a template of the filesystem that will be flashed onto the router, not the firmware from a router that has been dumped. Other information about the router may be contained in the previous section within the 6870 block.

The first of the folders that aren't empty is /bin/; where do a majority of the files link to?

``` sh
ip-10-10-205-228# ls -la bin/ | head
total 1357
drwxr-xr-x  2 root root      0 Apr 22  2020 .
drwxr-xr-x 17 root root      0 Jan  1  1970 ..
lrwxrwxrwx  1 root root      7 Apr 22  2020 addgroup -> busybox
lrwxrwxrwx  1 root root      7 Apr 22  2020 adduser -> busybox
lrwxrwxrwx  1 root root      7 Apr 22  2020 ash -> busybox
-rwxr-xr-x  1 root root   7112 Apr 22  2020 attr
-rwxr-xr-x  1 root root 593280 Apr 22  2020 busybox
lrwxrwxrwx  1 root root      7 Apr 22  2020 cat -> busybox
lrwxrwxrwx  1 root root      7 Apr 22  2020 catv -> busybox
```

Why is that? Well, [busybox is more or less a tool suite of common executable commands within the Unix environment.](https://ubuntuforums.org/archive/index.php/t-846852.html)

*Answer: `busybox`*

Interestingly, what database would be running within the bin folder if the router was online?

``` sh
ip-10-10-205-228# ls -la bin/ | grep sql   
-rwxr-xr-x  1 root root  33764 Apr 22  2020 sqlite3
```

*Answer: `sqlite3`*
The following notable folder of interest is /etc/. This folder contains many configuration files for the router, such as Access Point power levels regulated by certain countries. One you might recognize is the FCC (Federal Communications Commission).

**We can even see the build date of the device. What is the build date?**

``` sh
ip-10-10-205-228# cat etc/builddate
2020-04-22 11:44# 
```

*Answer: `2020-04-22 11:44`*

**There are even files related to the SSH server on the device. What SSH server does the machine run?**

``` sh
ls -lh
-r--r--r--  1 root root  458 Apr 22  2020 dropbear_dss_host_key
-r--r--r--  1 root root  427 Apr 22  2020 dropbear_rsa_host_key
```

*Answer: `dropbear`*

**We can even see the file for the media server, which company developed it?**

``` sh
root@ip-10-10-205-228:/mnt/jffs2_file# head etc/mediaserver.ini 
#! Cisco MediaServer ini file ( twonky revision ) / charset UTF-8
#! change settings by editing this file
#! version 5.1.05
```

*Answer: `cisco`*

This company use to own Linksys at one point in time, which is likely why it is still being used.

Which file within /etc/ contains a list of standard Network services and their associated port numbers?

``` sh
root@ip-10-10-205-228:/mnt/jffs2_file# head etc/services -n 20
# Network services, Internet style
#
# Note that it is presently the policy of IANA to assign a single well-known
# port number for both TCP and UDP; hence, officially ports have two entries
# even if the protocol doesn't support UDP operations.
...

tcpmux  1/tcp    # TCP port service multiplexer
echo  7/tcp
echo  7/udp
discard  9/tcp  sink null
discard  9/udp  sink null
systat  11/tcp  users
daytime  13/tcp
daytime  13/udp
```

*Answer: `services`*

**Which file contains the default system settings?**

``` sh
root@ip-10-10-239-139:/mnt/jffs2_file/etc# head system_defaults
################################################################################
# This file contains system defaults which will be used
# if, and only if, the value has not yet been set
# Both sysevent and syscfg namespace can be set
...
```

*Answer: `system_defaults`*

**What is the specific firmware version within the `/etc/` folder?**

``` sh
root@ip-10-10-239-139:/mnt/jffs2_file/etc# cat version
2.0.3.201002
```

*Answer: `2.0.3.201002`*

Backing out into the JNAP folder, the JNAP API (formerly known as HNAP, the Home Network Administration Protocol) has been a potential attack vector and vulnerability in the past, which this article highlights [here](https://routersecurity.org/hnap.php). Interestingly enough, reminisce of it is still here today on Linksys devices. Going to `http://<Default_Gateway>/JNAP/` on a Linksys router reveals an interesting 404. Much different than the standard 404.

**Accessing /JNAP/**

{% include figure.liquid path="/assets/img/images/thm_dumping_router_firmware/ry9Q0vrJJg.png" title="Accessing JNAP" class="img-fluid rounded z-depth-1" %}

**Accessing any other invalid URI**

{% include figure.liquid path="/assets/img/images/thm_dumping_router_firmware/Hy1rRwSJ1l.png" title="Accessing any other invalid URI" class="img-fluid rounded z-depth-1" %}

This makes you wonder if something is still really there. If you investigate within /JNAP/modules folder back on the dumped filesystem, you will see some contents related to the device and what services it offers, some of them are firewalls, http proxies, QoS, VPN servers, uPnP, SMB, MAC filtering, FTP, etc.

> Side note: If you have a Linksys router and are interested in playing around further, I found this [Github Repository](https://github.com/jakekara/jnap) for tools to interact with JNAP, I chose not to include this within the room since not everyone has access to a Linksys router. I won't go much further than exploring the File System.  

**What three networks have a folder within /JNAP/modules?**

``` sh
root@ip-10-10-239-139:/mnt/jffs2_file/JNAP/modules# ls -d */
guest_lan/  lan/  wan/
```

*Answer: `guest_lan, lan, wan`*

After the JNAP folder, `lib` is the only other folder with any contents whatsoever, and what's in there is standard in terms of libraries. The rest of the file system is relatively bare, leading us to this room's end.

I hope I made you all more curious about what's happening in your device; most importantly, I hope you enjoyed it. I encourage all of you to go out on your own and get your own router's Firmware, do some firmware dumping, and look at what's happening inside your device.

A room about Cable Modems may come in the future. However, Cable Modems firmware images are relatively difficult to access since they are only distributed to CMOs (Cable Modem Operators, like Charter, Xfinity, Cox, etc.)
