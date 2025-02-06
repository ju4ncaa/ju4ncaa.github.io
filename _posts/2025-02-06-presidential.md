---
description: >-
  Writeup de la máquina de dificultad media Presidential de la página https://vulnhub.com
title: VulnHub - Presidential | (Difficulty Medium) - Linux
date: 2025-02-06
categories: [Writeup, VulnHub]
tags: [vulnhub, hacking, linux, medium, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/bb94b984-cc01-4945-a8ba-7b5bd73cae7c
---

## Useful Skills

* Web Enumeration

## Enumeration

### TCP Scan

 ```bash
rustscan -a 192.168.2.142 --ulimit 5000 -g
192.168.2.142 -> [80,2082]
```

```bash
nmap -p80,2082 -sCV 192.168.2.142 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 21:59 CET
Nmap scan report for votenow.local (192.168.2.142)
Host is up (0.00034s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.5.38)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Ontario Election Services &raquo; Vote Now!
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.5.38
2082/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 06:40:f4:e5:8c:ad:1a:e6:86:de:a5:75:d0:a2:ac:80 (RSA)
|   256 e9:e6:3a:83:8e:94:f2:98:dd:3e:70:fb:b9:a3:e3:99 (ECDSA)
|_  256 66:a8:a1:9f:db:d5:ec:4c:0a:9c:4d:53:15:6c:43:6c (ED25519)
MAC Address: 00:0C:29:CE:40:3D (VMware)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.84 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 192.168.2.142 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-06 22:01 CET
Nmap scan report for 192.168.2.142
Host is up (0.00025s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
19663/udp closed unknown
22852/udp closed unknown
23108/udp closed unknown
30093/udp closed unknown
45928/udp closed unknown
51690/udp closed unknown
MAC Address: 00:0C:29:CE:40:3D (VMware)

Nmap done: 1 IP address (1 host up) scanned in 0.88 second
```
