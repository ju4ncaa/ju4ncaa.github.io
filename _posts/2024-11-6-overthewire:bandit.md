---
title: Resolución CTF OverTheWire:Bandit, Level 0-33 Write-Up
description: En este apartado se resuleven los 33 niveles del CTF de OverTheWire Bandit.
date: 2024-11-6
categories: [CTFs]
tags: [CTFs, Linux]
img_path: https://i.ibb.co/3kF0PSm/2024-11-06-19-19.png
image: https://i.ibb.co/3kF0PSm/2024-11-06-19-19.png
---

## **Introducción**
En este apartado se resuelven los 33 niveles del CTF de OverTheWire Bandit, estos retos están diseñados para principiantes con el objetivo de enseñar los fundamentos del uso del sistema operativo Linux y la línea de comandos. A lo largo de estos niveles puedes familiarizarte con una variedad de comandos, herramientas y técnicas que son esenciales para la administración de sistemas y la seguridad informática. Cada nivel tiene un desafío específico que va desde tareas simples como leer un archivo hasta desafíos más complejos que requieren de habilidades en administración de sistemas, manipulación de permisos, análisis de archivos, y encriptación.

### Level 0 -> Level 1
**Objetivo:** Conectarse al juego usando SSH y obtener la contraseña de bandit 1.
* **Host:** bandit.labs.overthewire.org
* **Puerto:** 2220
* **Nombre de usuario** bandit0
* **Contraseña bandit0:** bandit0
* **Contraseña bandit1:** ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If

Utilizamos ssh para conectarnos remotamente al CTF utilizando los siguientes parámetros:
* **-p:** Indicasr puerto al que conectarse en el host remoto.
* **-q:** Modo silencioso para suprimir la mayoría de los mensajes de advertencia y diagnóstico.

![image](https://github.com/user-attachments/assets/d2798188-b943-4837-a140-96383b2b8223)

Una vez hemos accedido remotamente procedemos a cambiar la variable de entorno **$TERM** a valor **xterm**, lo cual nos va a permitir tener mas movilidad en la terminal y poder realizar atajos de teclado como ctrl+l para borrar el contenido de la terminal.

![image](https://github.com/user-attachments/assets/1c1f6cd6-03b3-4a3d-bc8b-39586122c224)
![image](https://github.com/user-attachments/assets/1c8f593e-446c-4c5c-86ea-b025e5f7ab3b)

### Level 1 -> Level 2
**Objetivo:** Visualizar la contraseña para el siguiente nivel, la cual se almacena en un archivo llamado **-** ubicado en el directorio home.
* **Contraseña bandit2:** 263JGJPfgU6LtdEvgfWU1XP5yac29mFx

Una vez hemos migrado al usuario **bandit1** podemos ver que si utilizamos el comandos **ls** para listar el contenido del directorio visualizamos el fichero **-**. Probamos a utilizar el comando cat para mostrar el contenido del fichero pero entramos en un modo el cual nos lee la entrada estándar. En muchos sistemas operativos Unix/Linux el guión **(-)** se interpreta como leer la entrada estándar.

![image](https://github.com/user-attachments/assets/4f4246e4-60f5-489d-b680-3fcd83110636)

Podemos visualizar el archivo indicando la ruta absoluta hasta el mismo, o partiendo desde el directorio en el que estamos con el **./** e indicar el fichero llamado **'-'**

![image](https://github.com/user-attachments/assets/b3fa37f0-1552-4ce2-8ad6-8d35c482465a)

### Level 2 -> Level 3
**Objetivo:** Visualizar la contraseña para el siguiente nivel, la cual se almacena en un archivo llamado **'spaces in this filename'** ubicado en el directorio raíz.
* **Contraseña bandit3:** MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx

![image](https://github.com/user-attachments/assets/698c1970-a93e-4193-b833-f96605c6f12a)

Para visualizar el archivo podemos utilizar el comando cat e indicar el nombre del fichero entre comillas **""** o **''**

![image](https://github.com/user-attachments/assets/a028c56c-3d85-4c89-943b-af669b78b377)
