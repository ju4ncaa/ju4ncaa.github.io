---
description: >-
  Writeup de la máquina de dificultad media Administrator de la página https://hackthebox.eu
title: Hack The Box - Administrator | (Difficulty Medium) - Windows
date: 2025-01-29
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, active directory, medium, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/9d60c834-3318-4bfd-910e-a6c5febfcba0
---

## Useful Skills

* 

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.42 --ulimit 5000 -g
10.10.11.42 -> [21,53,88,135,139,389,445,464,593,9389,3268,3269,47001,49664,49665,49666,49667,49668,60306,60293,60286,60281]
```

```bash
nmap -p21,53,88,135,139,389,445,464,593,9389,3268,3269,47001,49664,49665,49666,49667,49668,60306,60293,60286,60281 -sCV 10.10.11.42 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 15:37 CET
Nmap scan report for 10.10.11.42
Host is up (0.038s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-29 21:37:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
60281/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
60286/tcp open  msrpc         Microsoft Windows RPC
60293/tcp open  msrpc         Microsoft Windows RPC
60306/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 6h59m58s
| smb2-time: 
|   date: 2025-01-29T21:38:33
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 64.83 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.42 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-29 15:39 CET
Nmap scan report for 10.10.11.42
Host is up (0.035s latency).
Not shown: 1496 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
53/udp    open   domain
88/udp    open   kerberos-sec
123/udp   open   ntp
21710/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.82 seconds
```

> Esta máquina sigue activa en HackTheBox. Una vez que se retire, este artículo se publicará para acceso público, de acuerdo con la política de HackTheBox sobre la publicación de contenido de su plataforma.
{: .prompt-danger }

<!--

> Hay que añadir el dominio administrator.htb en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 10.10.11.42
{: .prompt-tip }



-->
