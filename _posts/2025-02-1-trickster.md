---
description: >-
  Writeup de la máquina de dificultad media Trickster de la página https://hackthebox.eu
title: Hack The Box - Trickster | (Difficulty Medium) - Linux
date: 2025-02-1
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, medium, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/68c7e29e-5394-442f-b624-df3200f6c713

---

## Useful Skills

* Web enumeration

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.34 --ulimit 5000 -g
10.10.11.34 -> [22,80]
```

```bash
nmap -p22,80 -sCV 10.10.11.34 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 20:15 CET
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
Nmap done: 1 IP address (1 host up) scanned in 8.04 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.34 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 20:16 CET
Nmap scan report for 10.10.11.34
Host is up (0.037s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
772/udp   closed cycleserv2
8010/udp  closed unknown
22862/udp closed unknown
23322/udp closed unknown
26026/udp closed unknown
41967/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.85 seconds
```

> Hay que añadir el dominio trickster.htb en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 10.10.11.34
{: .prompt-tip }

### HTTP Enumeration

Whatweb reporta un servidor Apache 2.4.52, y un código de estado 403-Forbidden

```bash
whatweb http://trickster.htb
http://trickster.htb [403 Forbidden] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.34], Title[403 Forbidden]
```

Accediendo a la página en http://trickster.htb/ puedo observar una página web dedicada al comercio minorista online

![imagen](https://github.com/user-attachments/assets/06cbe552-d1bc-4362-80f3-23b3f6cf4fa4)

Al intentar acceder a shop obtengo un mensaje el cual indica que no se puede conectar a http://shop.trickster.htb

![imagen](https://github.com/user-attachments/assets/8db23a76-a609-41b6-b69f-1069b4d2bf77)

> Hay que añadir el subdominio shop.trickster.htb en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 10.10.11.34
{: .prompt-tip }

Utilizo gobuster para realizar una enumeración exhaustiva de directorios

```bash
gobuster dir -u http://trickster.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -b 403,404 -q
```

```bash
gobuster dir -u http://shop.trickster.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -b 403,404 -q
/.git/config          (Status: 200) [Size: 112]
/.git                 (Status: 301) [Size: 323] [--> http://shop.trickster.htb/.git/]
/.git/HEAD            (Status: 200) [Size: 28]
/.git/logs/           (Status: 200) [Size: 1137]
/.git/index           (Status: 200) [Size: 252177]
```

Utilizo la herramienta git-dumper para dumpear todo el repositorio git del sitio web

```bash
python3 git_dumper.py http://shop.trickster.htb/.git/ .
```
