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
* **Objetivo:** Conectarse al juego usando SSH y obtener la contraseña de bandit 1.
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
* **Objetivo:** Visualizar la contraseña para el siguiente nivel, la cual se almacena en un archivo llamado **-** ubicado en el directorio home.
* **Contraseña bandit2:** 263JGJPfgU6LtdEvgfWU1XP5yac29mFx

Una vez hemos migrado al usuario **bandit1** podemos ver que si utilizamos el comandos **ls** para listar el contenido del directorio visualizamos el fichero **-**. Probamos a utilizar el comando cat para mostrar el contenido del fichero pero entramos en un modo el cual nos lee la entrada estándar. En muchos sistemas operativos Unix/Linux el guión **(-)** se interpreta como leer la entrada estándar.

![image](https://github.com/user-attachments/assets/4f4246e4-60f5-489d-b680-3fcd83110636)

Podemos visualizar el archivo indicando la ruta absoluta hasta el mismo, o partiendo desde el directorio en el que estamos con el **./** e indicar el fichero llamado **'-'**

![image](https://github.com/user-attachments/assets/b3fa37f0-1552-4ce2-8ad6-8d35c482465a)

### Level 2 -> Level 3
* **Objetivo:** Visualizar la contraseña para el siguiente nivel, la cual se almacena en un archivo llamado **'spaces in this filename'** ubicado en el directorio raíz.
* **Contraseña bandit3:** MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx

![image](https://github.com/user-attachments/assets/698c1970-a93e-4193-b833-f96605c6f12a)

Para visualizar el archivo podemos utilizar el comando cat e indicar el nombre del fichero entre comillas **""** o **''**

![image](https://github.com/user-attachments/assets/a028c56c-3d85-4c89-943b-af669b78b377)

### Level 3 -> Level 4
* **Objetivo:** Visualizar la contraseña para el siguiente nivel, la cual se almacena en archivo oculto en el directorio inhere.
* **Contraseña bandit4:** 2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ

Dentro del sistema como el usuario bandit3 si listamos los directorios que se encuentran podemos observar el directorio **inhere**, si accedemos al mismo y realizamos nuevamente **ls** no observamos ningun archivo ni directorio

![image](https://github.com/user-attachments/assets/48504fc8-c5da-4c7a-88e3-d3854d9df442)

Para visualizar si dentro del directorio **inhere** existen directorios o ficheros ocultos podemos utilizar el comando **ls** combinado con el parámetro **-a** o **--all** el cual permite no ignorar las entradas que empiezan por **'.'**, en Linux si utilizamos un **'.'** delante del nombre de un archivo o carpeta conseguimos ocultar las mismas.

![image](https://github.com/user-attachments/assets/82af43f6-75ac-4017-80ef-26599719ff64)

### Level 4 -> Level 5
* **Objetivo:** Visualizar la contraseña para el siguiente nivel, la cual se almacena en el único archivo legible por humanos en el directorio inhere.
* **Contraseña bandit5:** 4oQYVPkxZOOEOO5pTW81FB8j8lxXGUQw

Como el usuario **bandit4** accedemos al directorio **inhere** y observamos 9 archivos que siguen la estructura de nombre **-file00** hasta **-file09**

![image](https://github.com/user-attachments/assets/e9aca7c7-e2f6-4c0a-93fd-422048fd32c9)

Podemos utilizar el comando **file** el cual permite determinar el tipo y formato de un archivo, finalmente podemos visualizar que el unico archivo legible es **-file07** tipo **ASCII text** 

![image](https://github.com/user-attachments/assets/3cb4ee31-c3fa-4273-96bb-c2be96265c56)

### Level 5 -> Level 6
* **Objetivo:** Obtener la contraseña de  un archivo el cual se encuentra en algún lugar bajo el directorio inhere y tiene todas las siguientes características:
  
  * legible por humanos
  * 1033 bytes de tamaño
  * no ejecutable
    
* **Contraseña bandit6:** HWasnPhtq9AVKe0dmk45nxy20cvUa6EG

Como el usuario **bandit5** dentro del directorio **inhere** si listamos con el comando **ls** el contenido disponibles observamos multiples directorios, el archivo el cual contiene la contraseña se debe de encontrar dentro de alguno de todos estos directorios.

![image](https://github.com/user-attachments/assets/8c3582b3-7fc1-402b-9d14-4aaed76f1080)

Para encontrar el archivo el cual contiene la contraseña del usuario **bandit6** utilizaremos el comando **find** el cual permite buscar archivos y directorios con diferentes características, emplearemos los siguientes parámetros:

* **-readable:** Buscar archivos que puedan ser leídos por el usuario actual.
* **-size:** Permite buscar archivos en función de su tamaño, es posible especificar el tamaño utilizando varios sufijos:
  * **-c:** Bytes
  * **-k:** Kilobytes
  * **-M:** Megabytes
  * **-G:** Gigabytes
    
* **! -executable:** Busca archivos que no son ejecutables por el usuario actual.

![image](https://github.com/user-attachments/assets/85e87094-80a8-4274-bb31-a1a6aa480ca6)

### Level 6 -> Level 7
* **Objetivo:** Obtener la contraseña de un archivo el cual se encuentra en algún lugar bajo el servidor y tiene todas las siguientes características:
  
  * propiedad del usuario bandit7
  * propiedad del grupo bandit6
  * 33 bytes de tamaño
    
* **Contraseña bandit7:** morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj

Para encontrar el archivo el cual contiene la contraseña del usuario **bandit7** utilizaremos el comando **find** empleando los siguientes parámetros:

* **-user:** Permite indicar el usuario propietario del archivo.
* **-group:** Permite indicar el grupo propietario del archivo
* **-size:** Permite buscar archivos en función de su tamaño, es posible especificar el tamaño utilizando varios sufijos:
  * **-c:** Bytes
  * **-k:** Kilobytes
  * **-M:** Megabytes
  * **-G:** Gigabytes

![image](https://github.com/user-attachments/assets/eae1c4bc-d7dd-4d4b-a72b-a554a334e84e)

### Level 7 -> Level 8
* **Objetivo:** Obtener la contraseña la cual se encuentra en el archivo data.txt junto a la palabra millionth
* **Contraseña bandit8:** dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc

Conectados como el usuario bandit7 si listamos el directorio en el que nos encontramos observamos el archivo data.txt

![image](https://github.com/user-attachments/assets/be2f2e0c-ecc8-4e5a-953f-cbfc990c5f0b)

Para obtener existosamente la contraseña debemos de utilizar el comando **grep** el cual permite buscar lineas de un archivo mediante expresiones regualres, seguido filtrar el resultado con el comando **awk** para manipular la salida. Si se desea obtener una información mas detallada sobre los comandos es posible utilizar **man** o **--help**

![image](https://github.com/user-attachments/assets/0acaabb7-653b-4fbd-b9c6-10de83a8994e)

### Level 8 -> Level 9
* **Objetivo:** Encontrar la contraseña para el siguiente nivel la cual se almacena en el archivo data.txt y es la única línea de texto que aparece una sola vez.
* **Contraseña bandit8:** 
