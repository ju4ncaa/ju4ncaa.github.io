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

* Enumeración DNS (dig)
* Domain Zone Transfer AXRF (failed)
* RPC Enumeration (rpcclient)
* SMB Enumeration (netexec)
* LDAP Enumeration (netexec + ldapsearch)

> En este escenario, comenzaremos con las siguientes credenciales (usuario: Olivia, contraseña: ichliebedich)
{: .prompt-info }

## TCP Scan

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

## UDP Scan

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

> Hay que añadir el dominio administrator.htb en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 10.10.11.42
{: .prompt-tip }

## DNS Enumeration

Intento obtener información adicional sobre el dominio a través de consultas DNS con dig, donde intento obtener los registros NS, MX, CNAME entre otros, posteriormente, trato de realizar una transferencia de zona, pero esta resulta fallida.

```bash
dig administrator.htb@10.10.11.42 axfr

; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> administrator.htb@10.10.11.42 axfr
;; global options: +cmd
; Transfer failed.
```

## SMB Enumeration

Utilizo NetExec para realizar un escaneo de SMB y obtener información clave como el sistema operativo, nombre del servidor, dominio, si la firma smb está habilita y si la versión antigua SMBv1 está activada o desactivada.

```bash
netexec smb 10.10.11.42
SMB  10.10.11.42 445  DC  [*] Windows Server 2022 Build 20348 x64 (name:DC)(domain:administrator.htb)  (signing:True)  (SMBv1:False)
```

Utilizo NetExec para enumerar los recursos compartidos del sistema a través del protocolo SMB, ejecutando el comando con el usuario Olivia y la contraseña ichliebedich y así poder identificar qué recursos pueden ser accedidos. No obtengo nada interesante.

```bash
netexec smb 10.10.11.42 -u 'olivia' -p 'ichliebedich' --shares
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\olivia:ichliebedich 
SMB         10.10.11.42     445    DC               [*] Enumerated shares
SMB         10.10.11.42     445    DC               Share           Permissions     Remark
SMB         10.10.11.42     445    DC               -----           -----------     ------
SMB         10.10.11.42     445    DC               ADMIN$                          Remote Admin
SMB         10.10.11.42     445    DC               C$                              Default share
SMB         10.10.11.42     445    DC               IPC$            READ            Remote IPC
SMB         10.10.11.42     445    DC               NETLOGON        READ            Logon server share 
SMB         10.10.11.42     445    DC               SYSVOL          READ            Logon server share 
```

## RPC Enumeration

Haciendo uso de las credenciales válidas, intento enumerar los usuarios usando la herramienta rpcclient. Obtengo con éxito los nombres de usuarios del sistema.

```bash
rpcclient -U administrator.htb/olivia%ichliebedich 10.10.11.42 -c enumdomusers | grep -oP '\[.*?\]' | tr -d '[]' | grep -v 0x
Administrator
Guest
krbtgt
olivia
michael
benjamin
emily
ethan
alexander
emma
```

> Sabiendo los usuarios del sistema, una de las posibles vías de ataque a considerar sería el AS-REP Roasting
{: .prompt-tip }

## LDAP Enumeration

Utilizo NetExec para verificar si las credenciales (olivia:ichliebedich) son válidas para conectarme al servicio LDAP.

```bash
netexec ldap 10.10.11.42 -u 'olivia' -p 'ichliebedich'
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
LDAP        10.10.11.42     389    DC               [+] administrator.htb\olivia:ichliebedich 
```

Haciendo uso de las credenciales válidas (olivia:ichliebedich), intento enumerar los usuarios del sistema utilizando la herramienta ldapsearch, este método es una alternativa a la enumeración de usuarios mediante rpcclient.

```bash
ldapsearch "objectclass=user" -x -H ldap://10.10.11.42 -b "dc=administrator,dc=htb" -D "olivia@administrator.htb" -w "ichliebedich" | grep sAMAccountName | cut -d : -f 2
 Administrator
 Guest
 DC$
 krbtgt
 olivia
 michael
 benjamin
 emily
 ethan
 alexander
 emma
```

## Gain access

Haciendo uso de las credenciales válidas (olivia:ichliebedich), intento verificar con NetExec si puedo acceder al sistema mediante el servicio WinRM. Obtengo un (Pwned!) lo que indica que las credenciales proporcionadas son válidas

```bash
netexec winrm 10.10.11.42 -u 'olivia' -p 'ichliebedich'
WINRM       10.10.11.42     5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:administrator.htb)
WINRM       10.10.11.42     5985   DC               [+] administrator.htb\olivia:ichliebedich (Pwn3d!)
```

Accedo al sistema con evil-winrm como el usuario olivia

```bash
evil-winrm -i 10.10.11.42 -u olivia -p ichliebedich
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\olivia\Documents>
```

## Privilege escalation
