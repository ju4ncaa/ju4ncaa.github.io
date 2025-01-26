---
description: >-
  Writeup de la máquina de dificultad media MonitorsThree de la página https://hackthebox.eu
title: Hack The Box - MonitorsThree | (Difficulty Medium) - Linux
date: 2025-01-26
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, medium, cacti, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/17fc44c9-d486-4d62-aee3-3b14956a7ded
---

## Useful Skills

* Web enumeration
* Subdomain enumeration
* SQL Injection password recovery panel
* Cacti 1.2.26 Authentication Remote Command Execution

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.30 --ulimit 5000 -g
10.10.11.30 -> [22,80]
```

```bash
nmap -p22,80 -sCV 10.10.11.30 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 12:16 CET
Nmap scan report for 10.10.11.30
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 86:f8:7d:6f:42:91:bb:89:72:91:af:72:f3:01:ff:5b (ECDSA)
|_  256 50:f9:ed:8e:73:64:9e:aa:f6:08:95:14:f0:a6:0d:57 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://monitorsthree.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.13 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.30 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-26 12:16 CET
Nmap scan report for 10.10.11.30
Host is up (0.035s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
774/udp   closed acmaint_dbd
5050/udp  closed mmcc
9370/udp  closed unknown
17006/udp closed unknown
21568/udp closed unknown
27919/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.89 seconds
```

> Hay que añadir el dominio monitorsthree.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP 10.10.11.30
{: .prompt-tip }

### HTTP Enumeration

Whatweb reporta que se produce una redirección desde http://10.10.11.30 a http://monitorsthree.htb/, un email el cual es sales@monitorsthree.htb y un servidor Nginx 1.18.0

```bash
whatweb http://monitorsthree.htb/
http://monitorsthree.htb/ [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[sales@monitorsthree.htb], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.30], JQuery, Script, Title[MonitorsThree - Networking Solutions], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Accediendo a la página en http://monitorsthree.htb/ puedo observar una web de una empresa que se dedidca a soluciones de red y mejora de infraestructura de red para empresas

![imagen](https://github.com/user-attachments/assets/f381b208-226e-490b-816f-152ddc80be91)

Observo un panel de Login, accedo e intento introducir diferentes credenciales diferentes comunes sin éxito ninguno. También intento detectar si es vulnerable a inyección SQL pero no consigo obtener nada interesante.

![imagen](https://github.com/user-attachments/assets/4895d605-6f40-43e5-87c2-7619ddb8da46)

Observo que se dispone de una panel de Password recovery, donde se permite introducir un usuario existen en el sistema y al mismo se le envía un correo de recuperación

![imagen](https://github.com/user-attachments/assets/abceccd9-625e-441d-b1df-4fdc2e777368)

Introduzco el usuario admin y obtengo una respuesta correcta donde se indica que se ha enviado el correo de recuperación de contraseña.

![imagen](https://github.com/user-attachments/assets/c669a155-40d1-49b1-80ce-77036113e912)

Sin embargo si introduzco el usuario ju4ncaa obtengo un mensaje de error donde se indica que no se ha podido procesar la solicitud. Esto me hace saber que el usuario admin existe y que hay una via potencial de enumeración de usuarios.

![imagen](https://github.com/user-attachments/assets/d0b678a0-5ed9-4a83-9d87-c4d669cb8256)

Utilizo gobuster para realizar enumeración de directorios exhaustiva

```bash
gobuster dir -u http://monitorsthree.htb/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 100 -q
/login.php            (Status: 200) [Size: 4252]
/index.php            (Status: 200) [Size: 13560]
/images               (Status: 301) [Size: 178] [--> http://monitorsthree.htb/images/]
/admin                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/admin/]
/css                  (Status: 301) [Size: 178] [--> http://monitorsthree.htb/css/]
/js                   (Status: 301) [Size: 178] [--> http://monitorsthree.htb/js/]
/forgot_password.php  (Status: 200) [Size: 3030]
/fonts                (Status: 301) [Size: 178] [--> http://monitorsthree.htb/fonts/]
```

Encuentro el directorio /admin, al intentar acceder obtengo un codigo de estado 403 Forbidden

![imagen](https://github.com/user-attachments/assets/f2cb742d-2433-48bc-b036-ce13925c569a)

Intento enumerar recursos y directorios dentro de /admin, observo que se redirige continuamente a login.php, menos /assets, /footer.php y /navbar.php

```bash
gobuster dir -u http://monitorsthree.htb/admin -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php -t 100 -q
/users.php            (Status: 302) [Size: 0] [--> /login.php]
/assets               (Status: 301) [Size: 178] [--> http://monitorsthree.htb/admin/assets/]
/footer.php           (Status: 200) [Size: 303]
/customers.php        (Status: 302) [Size: 0] [--> /login.php]
/db.php               (Status: 200) [Size: 0]
/logout.php           (Status: 302) [Size: 0] [--> /login.php]
/changelog.php        (Status: 302) [Size: 0] [--> /login.php]
/navbar.php           (Status: 200) [Size: 6248]
/dashboard.php        (Status: 302) [Size: 0] [--> /login.php]
/tasks.php            (Status: 302) [Size: 0] [--> /login.php]
```

Al acceder a http://monitorsthree.htb/admin/navbar.php consigo echar un vistazo parcial a la interfaz de administración

![imagen](https://github.com/user-attachments/assets/16e3a4b7-a415-4835-bf09-2af6a82f4bf1)

Utilizo wfuzz para realizar enumeración de subdominios

```bash
wfuzz -c --hw=982 --hc=404 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://monitorsthree.htb/ -H "Host: FUZZ.monitorsthree.htb"
=====================================================================
ID           Response   Lines    Word       Chars       Payload                                              
=====================================================================
000000246:   302        0 L      0 W        0 Ch        "cacti" 
```

> Hay que añadir el dominio cacti.monitorsthree.htb en el archivo de configuración /etc/hosts para que se puede resolver el nombre de dominio a la dirección IP 10.10.11.30
{: .prompt-tip }

Al acceder a http://cacti.monitorsthree.htb observo un panel de login de cacti, también puedo observar debajo del formulario la versión de cacti, la cual es 1.2.26.

![imagen](https://github.com/user-attachments/assets/eb6e0959-916f-46fc-83b1-d2e36b575fd7)

> Sabiendo que es Cacti y que la versión es 1.2.26 puedo buscar información sobre posibles vulnerabilidades existentes
{: .prompt-info }

## Vulnerability analysis

### CVE-2024-25641 (Cacti 1.2.26 Authenticated RCE)

Una pequeña búsqueda en internet me permite dar con la vulnerabilidad CVE-2024-25641, se trata de una ejecución remota de comandos (RCE) disponiendo de un usuario autenticado.

* [NVD Explanation CVE-2024-25641](https://nvd.nist.gov/vuln/detail/CVE-2024-25641)

## Exploitation

### SQLi password recovery panel

Necesito disponder de un usuario autenticado para llevar a cabo la explotación de la ejecución remota de comandos, probe a realizar inyección SQL en el panel de login, pero no probe a testar si el panel de recuperación de contraseña es vulnerable a SQLi. Introduzco una comilla y obtengo una error de sintaxis SQL, lo cual me indica que es vulnerable

![imagen](https://github.com/user-attachments/assets/9640c304-164f-4f53-bb33-6450cceafa6f)

Utilizo order by para detectar cuantas columnas existen, existen nueve columnas.

![imagen](https://github.com/user-attachments/assets/91f07568-f8f8-45cf-a9a1-b8798319881f)

Intercepto la petición con BurpSuite y la envío al Repeater, al realizar union select observo que no se refleja ninguno de los datos en ninguna de las columnas

![imagen](https://github.com/user-attachments/assets/a0158dc9-dd61-443f-b169-66e1cfe35f17)

![imagen](https://github.com/user-attachments/assets/2f3f95e4-c612-45ca-ab26-b42a3dc63e1c)

Podría utilizar herramientas como SQLmap o Ghauri para automatizar la inyección SQL, pero existe una forma más rapida de realizar la inyección a través de la función EXTRACTVALUE(), esta función permite generar errores cuando se proporciona una consulta XPath malformada o con datos inesperados, revelando información de la base de datos.

![imagen](https://github.com/user-attachments/assets/e03ad5db-67de-4252-9124-553ce728c065)

![imagen](https://github.com/user-attachments/assets/7b289c5d-0f41-4d35-b35f-2796120c9714)

### Abusing Cacti 1.2.26 Authenticated RCE Vulnerability (CVE-2024-25641)

En GitHub encuentro un repositorio sobre la vulnerabilidad CVE-2024-25641 el cual me sirven de guía para realizar la explotación de forma manual y entender como funciona todo.

* [CVE-2024-25641](https://github.com/Safarchand/CVE-2024-25641)

![imagen](https://github.com/user-attachments/assets/d3447fc4-82cb-4615-ad3d-e0160445f5af)
