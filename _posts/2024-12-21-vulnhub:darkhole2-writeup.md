---
title: VulnHub, DarkHole2 Pentesting, WriteUp
date: 2024-12-21
description: WriteUp de la máquina DarkHole 2 de la página VulnHub
categories: [Writeup's]
tags: [Hacking, Pentesting]
img_path: https://github.com/user-attachments/assets/1a121111-d9f3-4e18-bc4f-28e2ca1ba8fe
image: https://i.ibb.co/5RvhKwb/darkhole2.png
---

## **Habilidades empleadas**

* Fuga de información
* Enumeración de Proyectos en Github
* Inyección SQL (SQL Injection)
* Bash history - Fugas de información [User Pivoting]
* SSH (Local Port Forwarding) + Abuso de Servidor Web Interno
* Abuso de privilegios sudoers -  [Privilege escalation]

## **Enumeración**

### **Descubrimiento de hosts**

Utilizamos **arp-scan** para descubrir los dispositivos activos en nuestra red, fijamos como objetivo el host **192.168.2.131**

![imagen](https://github.com/user-attachments/assets/d4e7328f-f07b-4415-9432-1c1d0f011c03)

Usamos **ping** para verificar la conectividad del host **192.168.2.131**, enviando un paquete ICMP obtenemos respuesta, lo que nos indica que el dispositivo está disponible en la red. A través del **TTL (Time To Live)** también podemos identificar que se trata de un equipo Linux.

![imagen](https://github.com/user-attachments/assets/1ad59142-8eee-4762-931e-4e740b49f175)

### **Identificación del sistema operativo**

Una alternativa para identificar el sistema operativo al que nos estamos enfrentando es la herramienta **whichSystem.py**, esta herramienta es un pequeño script en python que nos permite saber si estamos ante un sistema operativo Windows o Linux en base al TTL. **Windows tiene un ttl=128** y **Linux tiene un ttl=64** por defecto.

![imagen](https://github.com/user-attachments/assets/49803cc1-cf64-47bc-88d8-f01a1b176c5d)

### **Nmap (Network Mapper)**

Utilizamos la herramienta **Nmap** para realizar un escaneo inicial de puertos sobre la dirección IP objetivo **192.168.2.131**, usando los siguientes parámetros:

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

![imagen](https://github.com/user-attachments/assets/d6ddbcdd-ac12-4e13-8098-2bd6ffcb58fe)

Una vez obtenido los puertos abiertos, utilizamos **Nmap** para realizar un escaneo de versiones y ejecución de scripts básicos de reconocimiento sobre la dirección IP objetivo **192.168.2.131**, haciendo uso de los siguientes parámetros.

| **Parámetro** | **Uso**                                                                 |
|---------------|-------------------------------------------------------------------------|
| `-sC`         | Ejecuta scripts básicos de reconocimiento para detectar configuraciones de seguridad y vulnerabilidades comunes. |
| `-sV`         | Realiza la detección de versiones de los servicios en los puertos abiertos, proporcionando información sobre las versiones exactas de cada servicio. |
| `-oN`         | Guarda los resultados en un archivo de salida en formato normal (legible por humanos), útil para analizar los resultados posteriormente. |

![imagen](https://github.com/user-attachments/assets/8c6c9226-a2cf-4d07-8d82-74259d0fa83b)

#### **Detalles del escaneo**

En el escaneo realizado a la dirección IP objetivo **192.168.2.131**, se han identificado los siguientes puertos abiertos, servicios en ejecución y sus respectivas versiones. Ademas se ha podido identificar un repositorio git en **192.168.2.131:80/.git/**

| **Puerto** |**Servicio**   | **Versión**    |
|------------|---------------|----------------|
| 22         | SSH           | OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)|
| 80         | HTTP          | Apache httpd 2.4.41 (Ubuntu) |

### **Enumeración de servicios (SSH - Puerto 22)**

La versión de **OpenSSH 8.2p1** no es vulnerable a la enumeración de usuarios, y no se encontraron usuarios accesibles para realizar ataques de fuerza bruta.

### **Enumeración de servicios (HTTP - Puerto 80)**

#### **WhatWeb**

Utilizamos la herramienta **WhatWeb**, esta nos permite obtener información detallada sobre el servidor web, incluyendo el software utilizado, tecnologías relacionadas y posibles vulnerabilidades.

![imagen](https://github.com/user-attachments/assets/1df60098-b943-4d0b-b173-066c6fdeb889)

#### **Reconocimiento web inicial**

Accedemos al servicio web HTTP a través de `http://192.168.2.131`, podemos identificar que existe una opción **Login**.

![imagen](https://github.com/user-attachments/assets/bc6a1ab9-3527-433a-a5f9-c167d8fc8545)

Accedemos a **Login** y probamos diferentes combinaciones de credenciales para intentar acceder, sin exito ninguno.

![imagen](https://github.com/user-attachments/assets/dc2961fb-942a-41c8-9f48-6f058e1a2cab)

Intentamos difentes inyecciones SQL típicas, sin exito ninguno.

![imagen](https://github.com/user-attachments/assets/8d0dffc2-d35a-4093-9062-bfd77f1a47cc)

![imagen](https://github.com/user-attachments/assets/e92e141f-ca6d-4984-8701-cac507979198)

![imagen](https://github.com/user-attachments/assets/3afe84cb-eb44-4d00-a479-bf3b612ef00b)

#### **Enumeración de proyecto git**

Accedemos al **proyecto git** detectado con **Nmap** el cual se encuentra alojado en http://192.168.2.131/.git

![imagen](https://github.com/user-attachments/assets/900c35c5-c33f-47d4-a28e-db2034022cd2)

Descargamos con **wget** de forma recursiva todo el contenido del proyecto.

![imagen](https://github.com/user-attachments/assets/cc3b4f6f-f208-48ab-a8cc-5f29f19d14f3)

Utilizamos **tree** para mostrar el contenido descargado de manera mas visual, es decir, en forma de árbol. No observamos nada relevante en el contenido.

![imagen](https://github.com/user-attachments/assets/ed3c426d-1cc3-46a1-b1da-07a6c6cdd106)

Utilizamos el comando **git log** para enumerar todos los commit del proyecto en orden cronológico inverso. Podemos observar un commit importante donde se indica que se han añadido a **login.php** las credenciales por defecto.

![imagen](https://github.com/user-attachments/assets/5c3fc9ad-3e1a-4d7b-bebb-2f2cc14c39a2)

Utilizamos el comando **git show** para visualizar el commit **a4d900a8d85e8938d3601f3cef113ee293028e10** de forma detallada. Obtenemos las credenciales por defecto: `lush@admin.com - 321`

![imagen](https://github.com/user-attachments/assets/5907accf-4d69-4da7-a566-d12acb4c6b7e)

## **Análisis de vulnerabilidades**

Accedemos a la web como el usuario `lush@admin.com - 321` y la vista inicial es un panel donde se muestran nuestros datos de usuario y un boton submit. Por otro lado en la URL tenemos un **parámetro GET** **?id=** con valor **1**

![imagen](https://github.com/user-attachments/assets/4682b540-b430-4d8e-80b6-f9a81b6f4e40)


![imagen](https://github.com/user-attachments/assets/fb405603-c41f-4012-aa4a-58c9f8fd84a8)

Cambiamos el parámetro GET **?id=** de valor **1** a **2**. Podemos observar que no se muestra ningun dato en los campos cuando anteriormente con el valor **?id=1** si se mostraban datos.

![imagen](https://github.com/user-attachments/assets/c0d2018e-3d33-4f00-9da3-ef4b919818d2)

Utilizamos **BurpSuite** para de manera cómoda realizar diferentes pruebas sobre el parámetro **?id=**, comenzamos introduciendo una sola comilla donde obtenemos un **Error 500 Internal Server Error**

![imagen](https://github.com/user-attachments/assets/a8d017f3-ecdb-44bf-8c4d-a05415fe8f8e)

![imagen](https://github.com/user-attachments/assets/951682b5-c642-4f1b-963b-bf93da740a9e)

## **Explotación**

### SQLi (SQL Injection)

Realizamos un ordenamiento de columnas con **order by**, por ejemplo si introducimos **order by 100** obtenemos el **Error 500 Internal Server Error**, pero si cuando introducimos **order by 6** no obtenemos el **error 500**, por lo que llegamos a la conclusión de que existen 6 columnas en la tabla actual que se está haciendo uso en la base de datos.

![imagen](https://github.com/user-attachments/assets/dbb04078-9d64-44bc-b3eb-5b3bb36fc63e)

![imagen](https://github.com/user-attachments/assets/54d33e9a-549f-45f3-8550-5d46a9fafad5)

![imagen](https://github.com/user-attachments/assets/60c5119f-8f40-4a70-8fdb-2728e47db6a4)

![imagen](https://github.com/user-attachments/assets/f1d00f8b-0af4-4328-9ac9-3087a014988b)

Sabemos que existen 6 columnas, por lo que vamos a combinar datos los cuales se deben de ver representados en alguno de los campos disponibles en la web.

![imagen](https://github.com/user-attachments/assets/d447ecce-413e-4e7a-9b21-11713e66480a)

![imagen](https://github.com/user-attachments/assets/eea4fa0d-e87c-455c-a3df-d2c57b0b59f6)

Una vez comprobado, comenzaremos enumerando todas las bases de datos existentes utilzando la siguiente query: **union+select+1,group_concat(schema_name),3,4,5,6+from+information_schema.schemata--+-**. La base de datos **darkhole_2** se ve bastante interesante

![imagen](https://github.com/user-attachments/assets/efffc7ff-1e39-402c-997f-272fa1e75cb8)

![imagen](https://github.com/user-attachments/assets/223418c2-01c6-41b8-8ec6-a63cff1235f4)

Enumeramos las tablas existentes en la base de datos **darkhole_2** utilizando la siguiente query: **union+select+1,2,group_concat(table_name),4,5,6+from+information_schema.tables+where+table_schema%3d'darkhole_2'--+-**. La tabla **ssh** promete bastante

![imagen](https://github.com/user-attachments/assets/08a8213e-249f-4a02-99ab-5dba74487b09)

![imagen](https://github.com/user-attachments/assets/b5ec9a5c-3baa-4849-b8dd-bbcef81d1833)

Enumeramos las columnas existentes de la tabla ssh haciendo uso de la siguiente query: **union+select+1,2,group_concat(column_name),4,5,6+from+information_schema.columns+where+table_schema%3d'darkhole_2'+and+table_name%3d'ssh'--+-**, podemos ver que tenemos **id,user,pass**

![imagen](https://github.com/user-attachments/assets/fa9143db-5b86-4982-a157-fc787b4a5cea)

![imagen](https://github.com/user-attachments/assets/246f0c69-c1dd-4430-a4db-48a81b9375e5)

Listamos los valores de las columnas **user** y **pass** de la tabla **ssh** la cual se encuentra en la base de datos **darkhole_2**, haciendo uso de la siguiente query: **union+select+1,2,concat(user,0x3a,pass),4,5,6+from+darkhole_2.ssh--+-**. Obtnemos una credenciales de acceso ssh **jehad:fool**

![imagen](https://github.com/user-attachments/assets/039d17ca-2ca1-411c-b59a-5dde535a2666)

![imagen](https://github.com/user-attachments/assets/243975d6-2388-4d35-8533-17ead9de533e)

## **Ganando acceso**

Utilizamos **ssh** para autenticarnos con las credenciales obtenidas a través de la inyección SQL `jehad:fool`, consiguiendo ganar acceso de forma exitosa.

![imagen](https://github.com/user-attachments/assets/8cf44f63-ab3a-46bc-931a-cfa094bdc9f9)

## **User Pivoting**

Hemos ganado acceso como el usuario **jehad** pero existen otros usuarios en el sistema a los cuales debemos de intentar pivotar de alguna manera.

![imagen](https://github.com/user-attachments/assets/471723b0-3bbc-41bf-b18b-bc2de8149e5b)

Visualizamos el **historico de bash** y observamos que existe un servicio interno en el **puerto 9999** alojado en **/opt/web**

![imagen](https://github.com/user-attachments/assets/6ff62955-1789-45e5-9040-fe3b9b53544b)

![imagen](https://github.com/user-attachments/assets/ad6e8cb3-569e-4255-b610-62842c2b70a9)

![imagen](https://github.com/user-attachments/assets/5706ecbe-1542-44f5-adbb-dfced59cbcb2)

Observamos el codigo del servicio web en **/opt/web/index.php** y podemos ver que se nos permite ejecutar comando a través del parámetro **?cmd=** ya que hace uso de la función **system()**

![imagen](https://github.com/user-attachments/assets/768b3e01-9414-4ed9-880c-79b904e7bf1b)

Ejecutamos el comando **id** y observamos que el comando ejecutado se realiza como el usuario **losy**

![imagen](https://github.com/user-attachments/assets/b34051a3-2f8a-42e5-8857-ceb8e50ef71e)

Realizamos un **Local Port Forwarding** con **SSH** para trabajar de manera mas cómoda.

![imagen](https://github.com/user-attachments/assets/215069be-23d5-4d6c-be72-e3cd7af039ef)

Una vez realizado el **Local Port Forwarding** accedemos al servico en **http://127.0.0.1:9999**

![imagen](https://github.com/user-attachments/assets/915ed158-899d-4a55-bc5e-ac954aa229ac)

Nos ponemos en escucha con netcat para obtener una **Reverse Shell** y ganar acceso como **losy**.

![imagen](https://github.com/user-attachments/assets/ef8b721b-cf82-4139-b2ac-07073c459f27)

A través del parámetro GET **?cmd=** nos entablamos una **Reverse Shell** hacia nuestra máquina de atacante, obteniendo acceso al sistema como **losy**.

![imagen](https://github.com/user-attachments/assets/0d801816-496d-478b-90ac-1d055da78dc6)

![imagen](https://github.com/user-attachments/assets/8873279b-796e-4565-9ef5-26835a685b1d)

## **Escalada de privilegios**

### **Abuso de privilegios sudoers**

Al igual que con el usuario **jehad** somos capaces de visualizar el **histórico de bash** donde al final del mismo podemos ver una información bastante curiosa que dice `password:gang`

![imagen](https://github.com/user-attachments/assets/3a798e8b-3ba6-431b-9fac-99eab28c8f23)

Utilzo la contraseña **gang** para listar los **permisos sudo** y se permite satisfactoriamente, donde podemos ver que podemos ejecutar como root **/usr/bin/python3**

![imagen](https://github.com/user-attachments/assets/3f0bd213-6ee2-42b9-acf6-e8222f0f19e9)

Es bastante sencillo como ejecutar **python3** como sudo e importar la librería **os** para otrorgarnos una **bash** como **root**.

![imagen](https://github.com/user-attachments/assets/07d99dce-a71f-4342-908a-b5da64a1a25d)
