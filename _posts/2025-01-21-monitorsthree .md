---
description: >-
  Writeup de la máquina de dificultad media MonitorsThree de la página https://hackthebox.eu
title: Hack The Box - MonitorsThree  | (Difficulty Medium) - Linux
date: 2025-01-21
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, medium, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/c5f79db4-c798-43f1-a916-4634a30f219d
---

## Useful Skills

* Web enumeration
* Subdomain enumeration
* SQLInjection in login panel to exfiltrate data
* Abusing Authenticated RCE (Cacti 1.2.26 - CVE-2024-25641)

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.30 --ulimit 5000 -g
10.10.11.30 -> [22,80]
```

```bash
nmap -p22,80 -sCV 10.10.11.30 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 19:39 CET
Nmap scan report for 10.10.11.30 (10.10.11.30)
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.15 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.30 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-22 19:40 CET
Nmap scan report for 10.10.11.30
Host is up (0.036s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
1007/udp  closed unknown
16086/udp closed unknown
23865/udp closed unknown
32430/udp closed unknown
32611/udp closed unknown
61961/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.82 seconds
```

> Hay que añadir el dominio monitorsthree.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP 10.10.11.30
{: .prompt-tip }

### HTTP Enumeration

Whatweb reporta un email el cual es sales@monitorsthree.htb, un título el cual da indicios que es una empresa de soluciones de red y un servidor Nginx 1.18.0

```bash
whatweb http://monitorsthree.htb
http://monitorsthree.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[sales@monitorsthree.htb], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.30], JQuery, Script, Title[MonitorsThree - Networking Solutions], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Accediendo a la página en http://monitorsthree.htb/ puedo observar una web de una empresa que se dedidca a la gestión y securización de red. La página contiene una opción de login

![imagen](https://github.com/user-attachments/assets/639ad92e-5129-4782-a0a7-68dc0f1d72f1)

Accedo a Login e intento diferentes credenciales pero sin exito nignuno, accedo tambien a reset password e interceptando peticiones con burpsuite no obtengo nada de interés

![imagen](https://github.com/user-attachments/assets/407e9960-c5ff-4672-905c-d0198d63edc7)

![imagen](https://github.com/user-attachments/assets/0464a8b9-2cb9-4804-b231-a708a6b16244)

Utilizo gobuster para realizar enumeración de directorios

```bash
gobuster dir -u http://monitorsthree.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -
/images               (Status: 301) [Size: 178] [--> http://monitorsthree.htb/images/]
/admin                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/admin/]
/css                  (Status: 301) [Size: 178] [--> http://monitorsthree.htb/css/]
/js                   (Status: 301) [Size: 178] [--> http://monitorsthree.htb/js/]
/fonts                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/fonts/]
```

La unica ruta que encuentro de interés es /admin pero al acceder obtengo un codigo de estado 403 Forbidden

![imagen](https://github.com/user-attachments/assets/ecba2719-65e8-4679-99dc-4a9c5533a450)

Utilizo wfuzz para realizar enumeración de subdominios

```bash
wfuzz -c --hw=982 --hc=404 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://monitorsthree.htb/ -H "Host: FUZZ.monitorsthree.htb"
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                       
=====================================================================
000000246:   302        0 L      0 W        0 Ch        "cacti"
```

> Hay que añadir el dominio cacti.monitorsthree.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP 10.10.11.30
{: .prompt-tip }

Accedo a http://cacti.monitorsthree.htb, la primera visión que obtengo es un panel de login para el software cacti, en la parte inferior del login observo la versión del software, la cual es Versión 1.2.26

> Sabiendo que es Cacti y que la versión es 1.2.26 puedo buscar información sobre posibles vulnerabilidades existentes
{: .prompt-info }

## Vulnerability analysis

### ¿Qué es Cacti?

Antes de comenzar con el análisis de vulnerabilidades debo de comprender que es cacti y para que se usa

![imagen](https://github.com/user-attachments/assets/1af79f96-c730-4235-8b97-9d861ed138b2)
