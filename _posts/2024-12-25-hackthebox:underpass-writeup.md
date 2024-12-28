---
title: HackTheBox, UnderPass Pentesting, WriteUp
date: 2024-12-25
description: Writeup de la máquina UnderPass de la página HackTheBox
categories: [Writeup's]
tags: [Hacking, Pentesting]
image_path: https://github.com/user-attachments/assets/2543b3fa-fc24-4772-a554-4aeb7184da61
image: https://github.com/user-attachments/assets/2543b3fa-fc24-4772-a554-4aeb7184da61
---
## **Introducción**

![imagen](https://github.com/user-attachments/assets/8293287e-087c-4f61-a5ba-29c6462cd608)

En la imagen podemos ver representado el entorno al que nos vamos a enfrentar, por un parte tenemos la máquina atacante es Kali Linux que sirve como base para realizar análisis, escaneos y explotación de vulnerabilidades. Por otro lado, la máquina víctima es UnderPass, con dirección IP 10.10.11.48

## **Información de la máquina**

<div align="center"><img src="https://github.com/user-attachments/assets/f19c3768-4d63-4934-8074-702cb6ccfd19" alt="machine info" width=700px></div>

## **Habilidades empleadas**

* Enumeración Web
* Enumeración SNMP (snmpbulkwalk)
* Acceso no autorizado debido al uso de credenciales por defecto
* Crackeo de hashes (hashcat) 
* Abuso de privilegios sudoers (mosh-server) - [Privilege escalation]

## **Enumeración**

### **Descubrimiento de hosts**

Usamos ping para verificar la conectividad del host 10.10.11.48, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del TTL (Time To Live) también podemos identificar que se trata de un equipo Linux.

![image](https://github.com/user-attachments/assets/25a4e933-b829-4adc-b73c-76bffa0087d2)

### **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta whichSystem.py, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. Windows tiene un ttl=128 y Linux tiene un ttl=64 por defecto.

![image](https://github.com/user-attachments/assets/63005d96-592a-43ee-a2fe-7650a0e61814)


### **Nmap (Network Mapper)**

#### **Escaneo de Puertos TCP**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos TCP sobre la dirección IP objetivo **10.10.11.48**, usando los siguientes parámetros:

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-p-`         | Escanea todos los puertos (del 1 al 65535).                             |
| `--open`      | Muestra solo los puertos que están abiertos.                            |
| `-sS`         | Realiza un escaneo de tipo SYN (escaneo sigiloso) para detectar puertos abiertos sin establecer una conexión completa. |
| `--min-rate`  | Establece la velocidad mínima de envío de paquetes (útil para aumentar la velocidad del escaneo). |
| `-vvv`        | Muestra la salida en modo detallado y verbose (nivel máximo de información). |
| `-n`          | Desactiva la resolución de DNS, lo que acelera el escaneo al no intentar resolver nombres de dominio. |
| `-Pn`         | Desactiva la detección de hosts, lo que indica que Nmap no realice un "ping" previo para determinar si el host está activo. |
| `-oG`         | Guarda los resultados en formato "grepable" para facilitar la posterior búsqueda de resultados. |

![image](https://github.com/user-attachments/assets/eaedcf2e-541d-416f-827c-dd8e2739533d)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **10.10.11.48**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![image](https://github.com/user-attachments/assets/bc8f19e6-2049-48f1-86bd-d4224d6f638b)

#### **Detalles del escaneo**

En el escaneo de puertos TCP realizado a la dirección IP objetivo **10.10.11.48**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 22         | SSH           | OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0) |
| 80         | HTTP          | Apache httpd 2.4.52 ((Ubuntu)) |


#### **Escaneo de Puertos UDP**

Utilizamos la herramienta **Nmap** para realizar un escaneo de puertos UDP sobre la dirección IP objetivo **10.10.11.48**, usando los siguientes parámetros:

#### **Escaneo de Puertos UDP**

Utilizamos la herramienta **Nmap** para realizar un escaneo de puertos UDP sobre la dirección IP objetivo **10.10.11.48**, usando los siguientes parámetros:

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sU`         | Especifica un escaneo de puertos UDP (en lugar del escaneo TCP por defecto). |
| `--open`      | Muestra únicamente los puertos que están abiertos en la máquina objetivo. |
| `--top-ports` | Escanea los puertos más comunes, en función de una lista predefinida por Nmap. |
| `--min-rate`  | Establece la velocidad mínima de envío de paquetes (útil para aumentar la velocidad del escaneo). |
| `-n`          | Desactiva la resolución de DNS, lo que acelera el escaneo al no intentar resolver nombres de dominio. |
| `-Pn`         | Desactiva la detección de hosts, lo que indica que Nmap no realice un "ping" previo para determinar si el host está activo. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

Una vez obtenido los puertos UDP abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **10.10.11.48**, haciendo uso de los siguientes parámetros.

![image](https://github.com/user-attachments/assets/be82e940-9501-419d-9df7-11b39f46d9c0)

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sU`         | Especifica un escaneo de puertos UDP (en lugar del escaneo TCP por defecto). |
| `--script`    | Permite ejecutar scripts de Nmap Scripting Engine (NSE) durante un escaneo. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![image](https://github.com/user-attachments/assets/77ffab7c-56fa-4865-83cc-17d2298b5248)

#### **Detalles del escaneo**

En el escaneo de puertos UDP realizado a la dirección IP objetivo **10.10.11.48**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones. Además usando la comunidad public, podemos realizar consultas SNMP sin necesidad de una contraseña adicional.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 161         | SNMP         | SNMPv1 server; net-snmp SNMPv3 server (public) |

### **Enumeración de servicios (SSH - Puerto 22)**

La versión de **OpenSSH 8.2p1** no es vulnerable a la enumeración de usuarios, y no se encontraron usuarios accesibles para realizar ataques de fuerza bruta.

### **Enumeración de servicios (HTTP - Puerto 80)**

#### **WhatWeb**

Utilizamos la herramienta **WhatWeb**, esta nos permite obtener información detallada sobre el servidor web, incluyendo el software utilizado, tecnologías relacionadas y posibles vulnerabilidades.

![image](https://github.com/user-attachments/assets/048b30c3-8c87-4284-8428-ff88748516a2)

#### **Reconocimiento web inicial**

Accedemos al servicio web HTTP a través de `http://10.10.11.48`, podemos identificar que se trata de una página Apache Ubuntu por defecto.

![image](https://github.com/user-attachments/assets/14cfcd13-1c5e-4255-b0e9-17a2648400fb)

#### **Gobuster**

Utilizamos la herramienta Gobuster, una poderosa herramienta de enumeración de directorios y subdominios en aplicaciones web, la cual nos permite realizar ataques de diccionario para descubrir rutas ocultas, subdominios y recursos en servidores web, lo que ayuda a identificar puntos de entrada potenciales. Tras realizar diferentes enumeraciones no logramos obtener ningún directorio de interés.

![image](https://github.com/user-attachments/assets/2a9609f9-ce4e-4c10-aacb-0e69eebe5057)

### **Enumeración de servicios (SNMP - Puerto 161)**

#### **snmpbulkwalk**

Utilizamos la herramienta snmpbulkwalk con la clave pública para realizar una consulta SNMP de tipo Bulk a dispositivos de red, lo que nos va a permitir obtener de manera rápida información detallada sobre la configuración, interfaces y versiones de software, facilitando la identificación de posibles vulnerabilidades en dispositivos mal configurados.

![image](https://github.com/user-attachments/assets/3eaaf019-777e-4331-9234-c1397549a59f)

##### **Información de interés obtenida**

* Dominio: `underpass.htb`
* Servidor web: `daloradius`
* Posible usuario: `steve@underpass.htb`

## **Explotación**

Daloradius es una herramienta de código abierto. Está licenciada bajo la licencia GPLv2 (GNU General Public License versión 2), lo que significa que cualquiera puede acceder, modificar y distribuir el software de acuerdo con los términos de la licencia. Por lo que inspeccionando el proyecto en github [Daloradius GitHub](https://github.com/lirantal/daloradius/tree/master) veo que podemos acceder a través de `http://URL/daloradius/app/operators/login.php`

![image](https://github.com/user-attachments/assets/3bdf12b9-b531-43fa-8245-2546790dddcf)


Una pequeña búsqueda en internet me permite obtener las credenciales por defecto de acceso a daloradius, utilizando las credenciales **administrator:radius** consigo ganar acceso al panel de administración.

![image](https://github.com/user-attachments/assets/f9a68165-4bf3-4f3a-b870-78145e4c0a40)

![image](https://github.com/user-attachments/assets/ec1ef7fc-9f74-4ba3-b3cb-17945a869735)

En el panel de administración se puede observar la existencia de un usuario, por lo que accedo a lista de los usuarios con el fin de obtener información de forma mas detallada.

![image](https://github.com/user-attachments/assets/6d64f9aa-3b35-4fc1-b4a3-c28fd9694f3f)

En la lista de usuarios se puede ver un usuario llamado **svcMosh** y una contraseña **412DD4759978ACFCC81DEAB01B382403**, hasheada al parecer en MD5.

![image](https://github.com/user-attachments/assets/1ebb7e88-9560-42be-ab55-7e8a553a5384)

### **Password Cracking (hashcat)**

Utilizamos la herramienta **hashcat** para intentar descifrar el hash **412DD4759978ACFCC81DEAB01B382403**, a través de un ataque por diccionario.

![image](https://github.com/user-attachments/assets/e94483b5-18c4-4b40-bfb6-cd4c8bad3a24)

## **Ganando acceso**

Utilizamos **ssh** para autenticarnos con las credenciales obtenidas a través del Password Cracking realizado con hashcat `svcmosh:underwaterfriends`, consiguiendo ganar acceso de forma exitosa.

![image](https://github.com/user-attachments/assets/b0bc8a1c-1489-4a5c-b34c-742ad05dba4f)

## **Escalada de privilegios**

### **Abuso de privilegios sudoers**

Inspeccionando los permisos sudoers observo que se nos permite ejecutar **/usr/bin/mosh-server** como root y sin contraseña.

![image](https://github.com/user-attachments/assets/20e7b6aa-5466-4072-8b88-c74d99866f35)

Buscando información obtengo que mosh-server se utiliza para acceder de manera segura y eficiente a sistemas remotos, pero a diferencia de SSH, está diseñado para ser más robusto en redes con latencia alta o conexiones que puedan ser interrumpidas. Por lo que realizamos los pasos para iniciar sesión de forma remota y escalar privilegios al usuario root.

![image](https://github.com/user-attachments/assets/275f6bf8-9d89-4794-b3c7-7e575030e9c2)

![image](https://github.com/user-attachments/assets/efd4b9c5-3ee1-4d85-8640-85ae82390d04)
