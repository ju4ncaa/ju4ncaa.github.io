---
description: >-
  Writeup de la máquina de dificultad fácil Sightless de la página https://hackthebox.eu
title: Hack The Box - Sightless | (Difficulty Easy) - Linux
date: 2025-01-15 00:00:00 +0800
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, easy, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/3369b1c5-339a-4c19-abb3-aa5b8226b4ea
---

## Useful Skills

* Web enumeration

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.32 --ulimit 5000 -g
10.10.11.32 -> [21,22,80]
```

```bash
nmap -p22,21,80 -sCV 10.10.11.32 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 15:10 CET
Nmap scan report for 10.10.11.32
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=1/16%Time=67891346%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20
SF:Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20
SF:try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x
SF:20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.07 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.32 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 15:13 CET
Nmap scan report for 10.10.11.32
Host is up (0.038s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
17146/udp closed unknown
17494/udp closed unknown
27682/udp closed unknown
36384/udp closed unknown
44334/udp closed unknown
49207/udp closed unknown
```

### FTP Enumeration

En el puerto 21/TCP observo un servidor ProFTPD asociado a un nombre de dominio llamado sightless.htb. Por otra parte no se puede visualizar en el escaneo la versión y no se detecta anonymous login

> Hay que añadir el dominio sightless.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP 10.10.11.32
{: .prompt-tip }

### HTTP Enumeration

Whatweb reporta que se produce una redirección desde http://10.10.11.32 a http://sightless.htb/, un email el cual es sales@sightless.htb y un servidor Nginx 1.18.0

```bash
whatweb http://10.10.11.32
http://10.10.11.32 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.32], RedirectLocation[http://sightless.htb/], Title[302 Found], nginx[1.18.0]
http://sightless.htb/ [200 OK] Country[RESERVED][ZZ], Email[sales@sightless.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.32], Title[Sightless.htb], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Accediendo a la página en http://sightless.htb/ se puede observar una web de una empresa que se dedidca a la gestión de bases de datos y servidores.

![imagen](https://github.com/user-attachments/assets/0bbc6ad5-d426-4d78-8882-91bf492d9e93)

