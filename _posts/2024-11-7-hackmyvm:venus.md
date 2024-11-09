---
title: Resolución CTF HackMyVM:Venus, Level 0-50 Write-Up
description: En este apartado se resuleven los 50 niveles del CTF de HackMyVM Venus.
date: 2024-11-7
categories: [CTFs]
tags: [CTFs, Linux]
img_path: https://i.ibb.co/j5SFvBf/venus.png
image: https://i.ibb.co/j5SFvBf/venus.png
---

## **Introducción**

En este apartado se resuelven los 50 niveles del CTF de HackMyVM Venus, son una serie de retos que se simulan escenarios del mundo real, permitiendo ponerte a prueba y mejorar tus habilidades de hacking ético, resolución de vulnerabilidades y análisis de sistemas. En definitva es una paso mas allá de Bandit ya que los retos son más complejos y requieren una comprensión más profunda de técnicas de hacking y seguridad informática. Por eso si estás comenzando en el mundo de la ciberseguridad, te recomendaría empezar con Bandit para aprender lo básico y luego avanzar hacia Venus.

### ¿Empezamos?
* **Objetivo:** Utilizar el cliente SSH para conectarse a Venus.
* **Host:** venus.hackmyvm.eu
* **Puerto:** 5000
* **Nombre de usuario** hacker
* **Contraseña:** havefun!

Utilizamos ssh para conectarnos remotamente al CTF utilizando los siguientes parámetros:
* **-p:** Indicasr puerto al que conectarse en el host remoto.
* **-q:** Modo silencioso para suprimir la mayoría de los mensajes de advertencia y diagnóstico.

![image](https://github.com/user-attachments/assets/f21c34ec-c7c6-4ad1-b78d-edb3198ea87f)

### Level 0 -> Level 1
* **Misión:** La usuaria sophia ha guardado su contraseña en un fichero oculto en esta carpeta . Encuentralo y logueate como sophia.
* **Contraseña sophia:** Y1o645M3mR84ejc

Utilizamos el comando **ls** el cual permite listar el contenido del directorio en el que nos encontramos y lo combinamos con el parámetro **-a** lo cual permite mostrar todos los archivos incluidos los ocultos.

![image](https://github.com/user-attachments/assets/14becad5-9719-417f-a9d5-0caa904ea546)

Observamos que existe un fichero oculto llamado **".myhiddenpazz"** al cual si realizamos un **cat** obtenemos la contraseña del usuario sophia.

![image](https://github.com/user-attachments/assets/a3ae83a7-2fdb-4616-8823-bec0bcb6ee93)

### Level 1 -> Level 2
* **Misión:** La usuaria angela ha guardado su password en un fichero pero no recuerda donde... solo recuerda que el fichero se llamaba whereismypazz.txt
* **Contraseña angela:** oh5p9gAABugHBje

Para obtener la contraseña del usuario **angela** podemos utilizar el comando **find** con los siguientes parámetros:

* **-type:** Permite indicar el tipo, ejemplo: fichero, directorio...
* **-name:** Permite indicar el nombre del recurso que se busca.

Paralelamente con un pipe utilizamos el comando **xargs** el cual nos permite ejecutar un comando a través de la entrada estándar en este caso usaré el comando **cat** para mostar el contenido del fichero **whereismypazz.txt**

![image](https://github.com/user-attachments/assets/9b74bc89-4b53-4e37-ac67-4063851a530b)

### Level 2 -> Level 3
* **Misión:** La password de la usuaria emma esta en la linea 4069 del fichero findme.txt
* **Contraseña emma:** fIvltaGaq0OUH8O

Utilizamos el comando **sed** combinado de los siguientes parámetros:

* **-n:** Indica a sed que no imprima automáticamente todas las líneas del archivo
* **4069p:** Indica a sed que imprima la línea número 4069 del archivo.

![image](https://github.com/user-attachments/assets/25ee38ac-b5f7-4ea6-b10f-492c4e5bf1fb)

### Level 3 -> Level 4
* **Misión:** La usuaria mia ha dejado su password en el fichero -
* **Contraseña mia:** iKXIYg0pyEH2Hos

En **OverTheWire:Bandit** nos encontramos con un caso igual, lo que sucede cuando hacemos **cat -** es que Linux quiero interpretar el input que estamos escribiendo. Para ver el archivo tenemos diferentes opciones como por ejemplo indicar la ruta absoluta hasta el mismo, en este caso sería /pwned/emma/-

![image](https://github.com/user-attachments/assets/627d422e-92f8-46e7-b6da-2392a2a05279)

### Level 4 -> Level 5
* **Misión:** Parece que la usuaria camila ha dejado su password dentro de una carpeta llamada hereiam 
* **Contraseña camila:** F67aDmCAAgOOaOc

Para obtener donde se encientra la carpeta hereiam del usuario **camila** podemos utilizar el comando **find** con los siguientes parámetros:

* **-type:** Permite indicar el tipo, ejemplo: fichero, directorio...
* **-name:** Permite indicar el nombre del recurso que se busca.

![image](https://github.com/user-attachments/assets/751ed4cd-70b4-46ba-9698-3e57e0c69a3b)

Nos dirigimos al directorio resultante **/opt/hereiam** y utilizamos el comando **ls -a** para mostrar todo el contenido del directorio observando así un archivo oculto llamado .here al cual si hacemos cat contiene la contraseña de **camila**

![image](https://github.com/user-attachments/assets/e95b2930-2bd0-44cd-81fd-19608998d4fa)
