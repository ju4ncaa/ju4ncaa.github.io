---
title: VulnHub, DarkHole Enterprise Pentesting, WriteUp
date: 2024-12-21
categories: [Writeup's]
tags: [Hacking, Pentesting]
img_path: https://github.com/user-attachments/assets/e360d62b-370f-4135-9d39-06d9250fe52f
image: https://github.com/user-attachments/assets/7de8a25c-9cfb-4764-a7ac-ded02d10831e
---

## **Introducción**

![imagen](https://github.com/user-attachments/assets/4fbfab85-4434-48e7-97b3-cea058cb1e28)

Este laboratorio simula un "**entorno empresarial pequeño**" con una infraestructura básica dividida en dos redes, una red externa y una red interna

1. **Kali (192.168.2.x):** Máquina atacante ubicada en la red externa, el objetivo es comprometer los sistemas internos de la empresa.
2. **Darkhole 1 (192.168.2.x / 10.0.2.x):** Servidor en la red perimetral que actúa como puente entre la red externa e interna, permite el movimiento lateral hacia la red interna.
3. **Darkhole 2 (10.0.2.x):** Servidor crítico ubicado exclusivamente en la red interna, objetivo final.

## **Informe Pentesting**

Se adjunta un informe donde se resume el proceso de pentesting, donde se capturan los hallazgos, la metodología utilizada y las recomendaciones para mejorar la seguridad de la infraestructura.

## **Habilidades empleadas**

### **DarkHole 1**

* Enumeración Web
* Abuso del panel de cambio de contraseña - Cambio de contraseña para el usuario administrador
* Abuso de carga de archivos - Subida de un archivo PHAR malicioso
* Abuso de un binario SUID personalizado - [User pivoting]
* Abuso de privilegios sudoers - Manipulación de scripts en Python [Privilege escalation]

### **DarkHole 2**

* Fuga de Información
* Enumeración de proyecto en GitHub
* SQLI (Inyección SQL)
* Chisel (Remote Port Forwarding) + Abuso del Servidor Web Interno
* Bash history - Fuga de Información [User pivoting]
* Abuso de privilegios sudoers [Privilege escalation]

## **Enumeración** (192.168.2.129)

### **Descubrimiento de hosts**

Utilizamos **arp-scan** para descubrir los dispositivos activos en nuestra red, fijamos como objetivo el host **192.168.2.129**

![imagen](https://github.com/user-attachments/assets/1787b025-78b6-42e1-96a8-91c30f658a85)

Usamos **ping** para verificar la conectividad del host **192.168.2.129**, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del **TTL (Time To Live)** también podemos identificar que se trata de un equipo Linux.

![imagen](https://github.com/user-attachments/assets/38ed40c1-8f61-41f0-abdf-6b6a1f791f03)

### **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta **whichSystem.py**, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. **Windows tiene un ttl=128** y **Linux tiene un ttl=64** por defecto.

![imagen](https://github.com/user-attachments/assets/c45068ba-2b06-4972-9946-293092cfd888)

### **Nmap (Network Mapper)**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos sobre la dirección IP objetivo **192.168.2.129**, usando los siguientes parámetros:

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

![imagen](https://github.com/user-attachments/assets/f32341c2-1096-4b57-8dba-24eb13237688)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **192.168.2.129**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![imagen](https://github.com/user-attachments/assets/d6f4a8ed-17ad-4505-883f-66d663e0ebab)

#### **Detalles del escaneo**

En el escaneo realizado a la dirección IP objetivo **192.168.2.129**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones.

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 22         | SSH           | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux) |
| 80         | HTTP          | Apache HTTPD 2.4.41 (Ubuntu) |

### **Enumeración de servicios (SSH - Puerto 22)**

La versión de **OpenSSH 8.2p1** no es vulnerable a la enumeración de usuarios, y no se encontraron usuarios accesibles para realizar ataques de fuerza bruta.

### **Enumeración de servicios (HTTP - Puerto 80)**

#### **WhatWeb**

Utilizamos la herramienta **WhatWeb**, esta nos permite obtener información detallada sobre el servidor web, incluyendo el software utilizado, tecnologías relacionadas y posibles vulnerabilidades.

![imagen](https://github.com/user-attachments/assets/68e1d273-d6fb-4405-a5f7-662751f5dbbb)

#### Reconocimiento web inicial

Accedemos al servicio web HTTP a través de `http://192.168.2.129`, podemos identificar que existe una opción **Login**.

![imagen](https://github.com/user-attachments/assets/e5c660dd-ec5c-4a40-b29d-ded6fb1318b9)

Accedemos a **Login** y probamos combinaciones típicas de credenciales por defecto como: **admin-admin, admin-password, root-admin, user-user**, pero no obtenemos acceso exitoso.

![imagen](https://github.com/user-attachments/assets/dbc79a5c-c263-4056-89a4-b7a9a30dffc6)

Disponemos de un opción de Registro, por lo que accedemos a la misma y registramos un nuevo usuario **ju4ncaa-ju4ncaa1234**.

![imagen](https://github.com/user-attachments/assets/f0453d03-f7e0-4375-90df-4a227318a50f)

## **Análisis de vulnerabilidades** (192.168.2.129)

Accedemos a la web como el usuario **ju4ncaa-ju4ncaa1234** y la vista inicial es un panel donde se muestran nuestros datos de usuarios y un campo en el cual se nos permite cambiar la contraseña. Por otro lado tambien podemos observar que en la URL se utiliza un **parámetro GET** llamado **id** el cual tiene como valor **3**

![imagen](https://github.com/user-attachments/assets/55194279-90a2-43d9-96fd-a5eb9cc5a06d)

Probamos a cambiar el valor del **parámetro GET id** de **3** a **1**, obtenemos como respuesta **Your Not Allowed To Access another user information** por lo que se encuentra bien sanitizado y no se permite listar información de otros usuarios.

![imagen](https://github.com/user-attachments/assets/007aa67e-07d4-472c-b525-20c2d6548d9c)

## Explotación (192.168.2.129)

### IDOR (Insecure Direct Object Reference)

Interceptamos la petición de cambio de contraseña con **BurpSuite**, podemos observar que se tramitan dos parámetros por **POST** **password** e **id** 

![imagen](https://github.com/user-attachments/assets/4e7349a3-7a91-4719-99e5-5a3a33f788c4)

![imagen](https://github.com/user-attachments/assets/5a28d14a-9e91-49d0-b032-cbf0c2661955)

Nos encontramos ante la vulnerabilidad **Insecure Direct Object Reference (IDOR)**, donde se nos permite modificar directamente recursos o datos de otros usuarios simplemente manipulando identificadores que no están adecuadamente protegidos. Esto quiere decir que si suponemos que el usuario admin posee el **id=1** le cambiamos la contraseña y posteriormente accedemos a su panel.

![imagen](https://github.com/user-attachments/assets/c2d4e712-13dc-4c78-a35e-e6ac5dd041c7)

Podemos ver que no hemos obtenido aparentemente ningun error para cambiar la contraseña del usuario que posee el **id=1**.

![imagen](https://github.com/user-attachments/assets/30f39136-1c75-4ce7-90d5-7380c99d00c0)

Accedemos como el usuario **admin** y la contraseña que hemos establecido **admin1234**

![imagen](https://github.com/user-attachments/assets/f637d5aa-1272-4748-99e9-ca7a94bd072c)

### File Upload

Accedemos con exito como el usuario **admin**, disponemos de un campo de subida de archivos.

![imagen](https://github.com/user-attachments/assets/2abb9fca-b4a8-4369-8bfc-4105ca2e35c7)

Vamos directamente al grano e intentamos subir un archivo PHP malicioso, el cual nos permite ejecuta un comando del sistema operativo pasado como parámetro **?cmd=** en la URL y muestra el resultado en el navegador.

![imagen](https://github.com/user-attachments/assets/1460f152-ecaa-4753-a4e6-25b959dea560)

Obtenemos como respuesta que unicamente se permiten subir archivo con extensión: **jpg,png,gif**

![imagen](https://github.com/user-attachments/assets/64c7bd5a-73e6-4cc3-ae62-fea8bfc642a1)

Puede que en el codigo se contemple que la extensión **.php** no es valida para subir, pero existen otras extensiones php que tambien son válidas e interpretan el código y puede que no estén contempladas como: **.php2, .php3, .php4, .php5, .php6, .php7, .phps, .pht, .phtm, .phtml, .phar**, por ello interceptamos con **BurpSuite** la petición de subido del archivo **cmd.php** y utilizamos el Intruder para comprobar si se permite subir alguna de estas extensiones.

![imagen](https://github.com/user-attachments/assets/1bd447ec-fdcb-420a-bc68-247ed34b09d6)

![imagen](https://github.com/user-attachments/assets/c6dd9a8a-bf16-4374-b27a-84851e75aaae)

![imagen](https://github.com/user-attachments/assets/d671c1c1-4e05-4d8a-97af-4ae32a2e90ab)

Una vez terminado el ataque **Intruder**, visualizamos por ejemplo la subida del archivo **cmd.phar**, podemos ver que nos ha permitido subir el fichero malicioso en `http://192.168.2.129/upload`

![imagen](https://github.com/user-attachments/assets/770b3935-4ede-46de-b7a4-8aab8844a062)

Accedemos a `http://192.168.2.129/upload` donde podemos ver que nos ha permitido subir todas las extensiones, esto no quiere decir que todas nos interpreten el codigo PHP por ello debemos de ir una a una comprobando.

![imagen](https://github.com/user-attachments/assets/1cb0f88f-cade-44e2-a260-48fc29faa089)

La extensione **.phar** interpreta codigo PHP, por lo que si empleamos el **parámetro GET** **?cmd=** y por ejemplo usamos el comando **id** este se ejecuta y nos muestra el resultado en el navegador.

![imagen](https://github.com/user-attachments/assets/5e9557a3-02ff-4af7-bad1-8df695b751bd)

## Ganando acceso (192.168.2.129)
