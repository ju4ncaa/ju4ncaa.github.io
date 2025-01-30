---
description: >-
  Writeup de la máquina de dificultad media Trickster de la página https://hackthebox.eu
title: Hack The Box - Trickster | (Difficulty Medium) - Linux
date: 2025-01-29
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, medium, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/898dbeb2-0635-42de-809f-da03b35510d0
---

## Useful Skills

* Web enumeration
* 

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.34 --ulimit 5000 -g
10.10.11.34 -> [22,80]
```

```bash
nmap -p22,80 -sCV 10.10.11.34 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 20:26 CET
Nmap scan report for 10.10.11.34
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.95 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.34 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-30 20:27 CET
Nmap scan report for 10.10.11.34
Host is up (0.035s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
139/udp   closed netbios-ssn
902/udp   closed ideafarm-door
16896/udp closed unknown
26196/udp closed unknown
28220/udp closed unknown
28485/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.80 seconds
```

> Esta máquina sigue activa en HackTheBox. Una vez que se retire, este artículo se publicará para acceso público, de acuerdo con la política de HackTheBox sobre la publicación de contenido de su plataforma.
{: .prompt-danger }
<!--
> Hay que añadir el dominio trickster.htb en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 10.10.11.34
{: .prompt-tip }

### HTTP Enumeration

Whatweb reporta que se está realizano una redirección de http://10.10.11.34 a http://trickster.htb/, un servidor Apache 2.4.52 al igual que Nmap y un codigo de estado 403 Forbidden

```bash
whatweb http://10.10.11.34
http://10.10.11.34 [301 Moved Permanently] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.34], RedirectLocation[http://trickster.htb/], Title[301 Moved Permanently]
http://trickster.htb/ [403 Forbidden] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.34], Title[403 Forbidden]
```
-->
