---
description: >-
  Writeup de la máquina de dificultad fácil Curiosity de la página https://thehackerslabs.com
title: THL - Curiosity | (Difficulty Easy) - Windows
date: 2025-02-06
categories: [Writeup, The Hackers Labs]
tags: [vulnhub, hacking, active directory, LLMRN poisoning, easy, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/f355d63c-7590-4d07-9f45-b217e54cdeae
---

## Useful Skills

* DNS Enumeration
* SMB Enumeration
* LLMNR Poisoning

## Enumeration

### TCP Scan

 ```bash
rustscan -a 192.168.56.8 --ulimit 5000 -g
192.168.56.8 -> [53,88,135,139,389,445,464,593,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49676,49696,49707,49709,49712]
```

```bash
nmap -p53,88,135,139,389,445,464,593,3268,3269,5985,9389,47001,49664,49665,49666,49667,49669,49670,49676,49696,49707,49709,49712 -sCV 192.168.56.8              
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 12:36 EST
Nmap scan report for 192.168.56.8
Host is up (0.0011s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-06 16:36:09Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hackme.thl, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-06T16:37:11+00:00; -1h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC.hackme.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.hackme.thl
| Not valid before: 2024-10-16T13:11:58
|_Not valid after:  2025-10-16T13:11:58
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hackme.thl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.hackme.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.hackme.thl
| Not valid before: 2024-10-16T13:11:58
|_Not valid after:  2025-10-16T13:11:58
|_ssl-date: 2025-02-06T16:37:11+00:00; -1h00m00s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hackme.thl, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-06T16:37:11+00:00; -1h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC.hackme.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC.hackme.thl
| Not valid before: 2024-10-16T13:11:58
|_Not valid after:  2025-10-16T13:11:58
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
49707/tcp open  msrpc         Microsoft Windows RPC
49709/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:14:4E:14 (Oracle VirtualBox virtual NIC)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-06T16:37:03
|_  start_date: 2025-02-06T15:38:27
|_clock-skew: mean: -1h00m00s, deviation: 0s, median: -1h00m00s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:14:4e:14 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.34 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 192.168.56.8 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 12:38 EST
Nmap scan report for 192.168.56.8
Host is up (0.00086s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
53/udp    open   domain
88/udp    open   kerberos-sec
123/udp   open   ntp
137/udp   open   netbios-ns
389/udp   open   ldap
20366/udp closed unknown
MAC Address: 08:00:27:14:4E:14 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.94 seconds
```

> Hay que añadir los dominios hackme.thl y DC.hackme.thl en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 192.168.56.8
{: .prompt-tip }

### DNS Enumeration

Intento obtener información adicional sobre el dominio a través de consultas DNS con dig, donde intento obtener los registros NS, MX, CNAME entre otros, posteriormente, trato de realizar una transferencia de zona, pero esta resulta fallida.

```bash
dig hackme.thl@192.168.56.8 axfr

; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> hackme.thl@192.168.56.8 axfr
;; global options: +cmd
; Transfer failed.
```
