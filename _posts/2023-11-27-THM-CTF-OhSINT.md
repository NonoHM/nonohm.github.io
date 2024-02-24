---
layout: post
title: THM CTF OhSINT
tags: [THM, CTF, OSINT]
date: 2023-11-27 23:04:19
toc:
    sidebar: left
    toc-depth: 3
---

## Introduction

In this room, we are asked to do some online and offline seach about a provided image of the famous valley background of Windows XP.

## Task 1 - OhSINT

**What is this user's avatar of?**

Firstly, we need to check the image's metadata using exiftool.

``` kali
exiftool WindowsXP.jpg
ExifTool Version Number         : 12.67
File Name                       : WindowsXP.jpg
Directory                       : .
File Size                       : 234 kB
File Modification Date/Time     : 2023:11:27 23:09:36+01:00
File Access Date/Time           : 2023:11:27 23:09:36+01:00
File Inode Change Date/Time     : 2023:11:27 23:09:36+01:00
File Permissions                : -rwxr-xr-x
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
XMP Toolkit                     : Image::ExifTool 11.27
GPS Latitude                    : 54 deg 17' 41.27" N
GPS Longitude                   : 2 deg 15' 1.33" W
Copyright                       : OWoodflint
Image Width                     : 1920
Image Height                    : 1080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 1920x1080
Megapixels                      : 2.1
GPS Latitude Ref                : North
GPS Longitude Ref               : West
GPS Position                    : 54 deg 17' 41.27" N, 2 deg 15' 1.33" W
```

We can see in the copyright section that the image author's name is *OWoodflint*.
After doing a google search, we can find his [X](https://twitter.com/OWoodflint)'s (twitter) profile.
Then, we can see his profile picture is a cat

*Answer: `cat`*

**What city is this person in?**

With the website [wigle.net](https://wigle.net/), which is a map of many wifi networks availale across the world, we can try to locate him using his WiFi's BSSID he provided on his X account.

![BSSID Location](/assets/img/images/thm_ctf_ohsint/H1ZNI5MBT.png)

*Answer: `London`*

**What is the SSID of the WAP he connected to?**

To see the Wifi's SSID, we need first to create an account. After that, we have to zoom until we see the correct network.

![SSID Location](/assets/img/images/thm_ctf_ohsint/Hy_awqGHa.png)

*Answer: `UnileverWiFi`*

**What is his personal email address?**

After a google search, we can find his email address on one of his [GitHub Repositories](https://github.com/OWoodfl1nt/people_finder).

*Answer: `Owoodflint@gmail.com`*

**What site did you find his email address on?**

Like said previously, on GitHub.

*Answer: `GitHub`

**Where has he gone on holiday?**

On his [personal blog](https://oliverwoodflint.wordpress.com/author/owoodflint/), he says he went to New York.

*Answer: `New York`*

**What is the person's password?**

After digging in his blog's source code, we can see a weird string appearing.

![Blog Source Code](/assets/img/images/thm_ctf_ohsint/Bk5O25MBT.png)

*Answer: `pennYDr0pper.!`*
