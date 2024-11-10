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

Para obtener donde se encuentra la carpeta **hereiam** del usuario **camila** podemos utilizar el comando **find** con los siguientes parámetros:

* **-type:** Permite indicar el tipo, ejemplo: fichero, directorio...
* **-name:** Permite indicar el nombre del recurso que se busca.

![image](https://github.com/user-attachments/assets/751ed4cd-70b4-46ba-9698-3e57e0c69a3b)

Nos dirigimos al directorio resultante **/opt/hereiam** y utilizamos el comando **ls -a** para mostrar todo el contenido del directorio observando así un archivo oculto llamado .here al cual si hacemos cat contiene la contraseña de **camila**

![image](https://github.com/user-attachments/assets/e95b2930-2bd0-44cd-81fd-19608998d4fa)

### Level 5 -> Level 6
* **Misión:** La usuaria luna ha dejado su password en algun fichero dentro de la carpeta muack
* **Contraseña luna:** j3vkuoKQwvbhkMc

Como el usuario **camila** realizamos un **ls** para observar el contenido del directorio actual, nos encontramos con una carpeta llamada **muack**, la cual si listamos su contenido tiene muchas mas carpetas donde dentro de esas carpetas hay muchas más carpetas.

![image](https://github.com/user-attachments/assets/d60fcef0-4c4c-454b-aa65-eaa9a85889c4)

Para obtener donde se encuentra el fichero que contiene la password dentro de la carpeta **muack** del usuario **luna** podemos utilizar el comando **find** indicándole que queremos buscar todos los ficheros recursivamente dentro de la carpeta **muack**, se emplean los siguientes parámetros:

* **-type:** Permite indicar el tipo, ejemplo: fichero, directorio...

![image](https://github.com/user-attachments/assets/39d5c653-40f8-4015-b44e-f5fcba7204b6)

### Level 6 -> Level 7
* **Misión:** La usuaria eleanor ha dejado su password en un fichero que ocupa 6969 bytes.
* **Contraseña eleanor:** UNDchvln6Bmtu7b

Para obtener donde se encuentra la password del usuario **eleanor** podemos utilizar el comando **find** con los siguientes parámetros:

* **-type:** Permite indicar el tipo, ejemplo: fichero, directorio...
* **-size:** Permite indicar el tamaño del archivo:
  
    * **-c:** Bytes
    * **-k:** Kilobytes
    * **-G:** Gigabytes
    * **-M:** Megabytes
       
![image](https://github.com/user-attachments/assets/b6e8a20c-b1a8-4740-b71a-89bf040e23b2)

### Level 7 -> Level 8
* **Misión:** La usuaria victoria ha dejado su password en un fichero en el cual el propietario es el usuario violin.
* **Contraseña victoria:** pz8OqvJBFxH0cSj

Para obtener la password del usuario **victoria** podemos utilizar el comando **find** con los siguientes parámetros:

* **-type:** Permite indicar el tipo, ejemplo: fichero, directorio...
* **-user:** Permite indicar el usuario propietario del archivo

![image](https://github.com/user-attachments/assets/d43502f1-acf1-42ee-a510-f85e84a38cf4)

### Level 8 -> Level 9
* **Misión:** La usuaria isla ha dejado su password en un fichero zip.
* **Contraseña isla:** D3XTob0FUImsoBb

Como el usuario **victoria** utilizamos el comando **ls** para listar el contenido del directorio actual, observamos en fichero con extensión **.zip** llamado **passw0rd.zip**

![image](https://github.com/user-attachments/assets/67e995f2-a85e-4292-99a9-7d240546a74f)

Podemos utilizar el comando **unzip** para descomprimir la data del archivo **passw0rd.zip**, encontramos como resultado que no tenemos permisos para descomprimir en el directorio que nos encontramos.

![image](https://github.com/user-attachments/assets/e67bb38e-a5d8-4868-9776-67447f5907c3)

Para poder descomprimir la data del archivo **passw0rd.zip** utilizaremos el comando **mktemp -d**, creando así un direcorio temporal donde poder extraear la data. Utilizaremos nuevamente el comando **unzip** con el parámetro **-d**, el cual permitirá indicar el directorio donde se quiere extraer.

![image](https://github.com/user-attachments/assets/738f041d-af3b-4a38-9c3e-0bef204d3f05)

### Level 9 -> Level 10
* **Misión:** El password de la usuaria violet esta en la linea que empieza por a9HFX (sin ser estos 5 caracteres parte de su password.).
* **Contraseña violet:** WKINVzNQLKLDVAc

Como el usuario **isla** utilizamos el comando **ls** para lisar el contenido del directorio actual, observamos un archivo llamado **passy**, al cual si hacemos un **cat** para mostrar su contenido contiene un monton de lineas con contraseñas.

![image](https://github.com/user-attachments/assets/763a8cc3-baf3-407b-88c5-7c0077907dab)

Si tenemos curiosidad y queremos saber cuantas líneas tiene el archivo **passy** podemos utilizar el comando **wc (word count)** combinado del parámetro **-l** que nos permitira contar la líneas de un archivo dado.

![image](https://github.com/user-attachments/assets/fb45bbb4-d027-41fd-9474-2b6d19b16fb5)

Para obtener la contraseña del usuario **violet** podemos utilizar el comando **grep** empleando la expresión regular **^** la cual permite indicar que empieza por **a9HFX**, por otro lado podemos utilizar el comando **cut** o **awk** para excluir los primeros 5 carácteres los cuales no forman parte de la password.

![image](https://github.com/user-attachments/assets/e64fca9d-7ecb-463b-a58d-47fb70737302)

### Level 10 -> Level 11
* **Misión:** El password de la usuaria lucy se encuentra en la linea que acaba por 0JuAZ (sin ser estos ultimos 5 caracteres parte de su password)
* **Contraseña lucy:** OCmMUjebG53giud

Como el usuario **violet** utilizamos el comando **ls** para lisar el contenido del directorio actual, observamos un archivo llamado **end**, al cual si hacemos un **cat** para mostrar su contenido contiene un monton de lineas con contraseñas.

![image](https://github.com/user-attachments/assets/449d5710-af28-4258-8726-117d1463dd18)


Si tenemos curiosidad y queremos saber cuantas líneas tiene el archivo **end** podemos utilizar el comando **wc (word count)** combinado del parámetro **-l** que nos permitira contar la líneas de un archivo dado.

![image](https://github.com/user-attachments/assets/b2665221-11ca-40c1-b388-1a56098940da)

Para obtener la contraseña del usuario **lucy** podemos utilizar el comando **grep** empleando la expresión regular **$** la cual permite indicar que termina por **0JuAZ**, por otro lado podemos utilizar el comando **cut** o **awk** para excluir los últimos 5 carácteres los cuales no forman parte de la password.

![image](https://github.com/user-attachments/assets/806f9ffb-15bb-4527-b52e-730def8df208)


### Level 11 -> Level 12
* **Misión:** El password de la usuaria elena esta entre los caracteres fu y ck
* **Contraseña elena:** 4xZ5lIKYmfPLg9t

Como el usuario **lucy** utilizamos el comando **ls** para lisar el contenido del directorio actual, observamos un archivo llamado **file.yo**, al cual si hacemos un **cat** para mostrar su contenido contiene un monton de lineas con contraseñas.

![image](https://github.com/user-attachments/assets/22613a7f-5880-4581-8bcd-f28f4484722f)

Si tenemos curiosidad y queremos saber cuantas líneas tiene el archivo **file.yo** podemos utilizar el comando **wc (word count)** combinado del parámetro **-l** que nos permitira contar la líneas de un archivo dado.

![image](https://github.com/user-attachments/assets/9232b801-132c-4003-a382-bd2ad4d1e993)

Para obtener la contraseña del usuario **elena** podemos utilizar el comando **grep** empleando la expresión regular **'.*'** la cual permite indicar que entre las letras **fu** y **ck** hay data, por otro lado podemos utilizar el comando **sed** para excluir las letras **fu** y **ck** las cuales no forman parte de la password.

![image](https://github.com/user-attachments/assets/65c3e803-7128-47b6-b950-c14be07fd302)

### Level 12 -> Level 13
* **Misión:** La password de alice esta en una variable de entorno.
* **Contraseña alice:** Cgecy2MY2MWbaqt

Como el usuario **elena** podemos utilizar el comando **env** para listar las variables de entorno actuales en el sistema, obervamos una variable entorno llamada **PASS**

![image](https://github.com/user-attachments/assets/a7e893ad-20f8-4332-b263-439d7f034334)

Podemos utilizar de nuevo el comando **env** combinádolo con **grep** y **cut** o **awk**, para filtrar simplemente por el password, que es la data que nos interesa obtener.

![image](https://github.com/user-attachments/assets/3f6b2dc0-26cd-47a4-a439-7a0359620c30)

### Level 13 -> Level 14
* **Misión:** El admin ha dejado la password de anna como comentario en el fichero passwd.
* **Contraseña anna:** w8NvY27qkpdePox

Como el usuario **alice** utilizamos el comando **cat** para visualizar el contenido del fichero **/etc/passwd**, si lo combinamos con el comando **grep** para filtrar por nuestro usuario **alice**, encontramos que en el quinto campo se encuentra un texto el cual es la contraseña del usuario **anna**

![image](https://github.com/user-attachments/assets/7f30410e-a809-46ce-861c-78dbae101cf7)

Por otro lado si queremos obtener simplemente la contraseña, que es la data que nos interesa, podemos utilizar los comando **cut** o **awk** para filtrar entre los dos puntos **':'** en el quinto campo.

![image](https://github.com/user-attachments/assets/32b867c2-37ef-48f6-a517-3af1235e8730)


### Level 14 -> Level 15
* **Misión:** Puede que sudo te ayude para ser natalia.
* **Contraseña natalia:** NMuc4DkYKDsmZ5z

Como el usuario **anna** utilizamos el comando **sudo -l**, el cual nos permite listar los privielgios y comandos que podemos ejecutar en el sistema como el usuario **anna**, vemos que podemos ejecutar como el usuario **natalia** sin proporcionar contraseña el binario **/bin/bash**, lo cual permite spawnear un shell tipo **bash**

![image](https://github.com/user-attachments/assets/aae2b387-57b7-48fc-8be6-daf430d4e85b)

Para convertirnos en el usuario **natalia** podemos utilizar el comando **sudo -u** y llamar al binario **/bin/bash** indicando que lo queremos ejecutar como **natalia**

![image](https://github.com/user-attachments/assets/a29c9d59-c70e-4dd2-8d88-c395c6ce1e90)
