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
* 

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

