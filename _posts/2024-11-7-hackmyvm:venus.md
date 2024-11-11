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


### Level 15 -> Level 16
* **Misión:** El password de eva esta encodeado en el fichero base64.txt
* **Contraseña eva:** upsCA3UFu10fDAO

Como el usuario **eva** utilizammos el comando **ls** para listar el contenido del directorio en el que nos encontramos, encontramos un fichero llamado **base64.txt** al cual si realizamos un cat para visualizar su contenido vemos una cadena codeada en **base64**.

![image](https://github.com/user-attachments/assets/67efd5a9-0d85-4bc4-b49b-458e6a3762a8)

Si queremos decodear el texto para obtener la contraseña del usuario **eva** podemos utilizar el comando **'base64 -d'**

![image](https://github.com/user-attachments/assets/cea2b969-1866-4d7f-b43b-4a6ee2cf823c)


### Level 16 -> Level 17
* **Misión:** La password de la usuaria clara se encuentra en un fichero modificado el 01 de Mayo de 1968.
* **Contraseña clara:** 39YziWp5gSvgQN9

Para calcular los días que han pasado desde que se modificó el archivo debemos de utilizar la siguiente operación **```(2024-1970)*365```**

![image](https://github.com/user-attachments/assets/d783b24e-e979-4b6a-9758-7b873ff4f7f1)

Para obtener la contraseña del usuario **clara** podemos utilizar el comando **find** con los siguientes parámetros:

* **-mtime:** Permite buscar archivos basándose en la fecha de modificación en días.

![image](https://github.com/user-attachments/assets/b0990975-f9e7-4feb-ad3b-e8dee8437470)

### Level 17 -> Level 18
* **Misión:** La password de frida esta en el zip protegido con password.(rockyou.txt puede ayudarte)
* **Contraseña frida:** Ed4ErEUJEaMcXli

Como el usuario **frida** utilizamos el comando **ls** para listar el contenido del directorio actual, observamos un fichero **.zip** llamado **'protected.zip'**.

![image](https://github.com/user-attachments/assets/a5a37d22-328c-49c0-abcc-40f592726512)

Podemos utilizar el comando **scp** para trasladar el archivo **protected.zip** a nuestra máquina local y trabajar comodamente. Y utilizar el comando **md5sum** para comprobar que la data se ha trasladado integramente y no ha sido alterada.

![image](https://github.com/user-attachments/assets/e506174a-c3c5-4735-b8b4-17395ce5add0)

![image](https://github.com/user-attachments/assets/b8a4e195-0def-4ece-a36c-dd82ba271251)

Una vez trasladado el fichero **protected.zip** podemos utilizar la herramienta **7z** con el parámetro **l** para listar el contenido del comprimido.

![image](https://github.com/user-attachments/assets/e5cb2253-38c7-4149-b794-2d361c2a2ef5)

Probamos a descomprimir el .zip con la herramienta **7z** empleando el parámetro **x**, obtenemos como resultado que el fichero se encuentra protegido por contraseña.

![image](https://github.com/user-attachments/assets/b2153853-a496-4423-affa-3e5ed8cb286e)

Utilizaremos la herramienta **zip2john** la cual nos va a permitir extraer el **hash** de la contraseña del fichero **protected.zip**

![image](https://github.com/user-attachments/assets/1aab7440-4007-47ba-b32d-957a69a748ca)

Una vez extraído el **hash** utilizaremos le herramienta **John The Ripper** la cual nos permitira crackear el hash obtenido anteriomente y obtener la contraseña en texto claro.

![image](https://github.com/user-attachments/assets/f4889f89-2643-49c5-aff0-6f8646a0475e)

Utilizamos la contraseña **pass123** para descomprimir el contenido del fichero **protected.zip** con la herramienta **7z**.

![image](https://github.com/user-attachments/assets/4fa9fabe-e3e5-44bf-8cc6-5e6cf83260c2)

Por último ya podemos visualizar la contraseña del usuario **frida**

![image](https://github.com/user-attachments/assets/4c4ca26c-fe96-401e-be42-a9e4c6cbcd14)

### Level 18 -> Level 19
* **Misión:** La password de eliza es el unico string que se repite (sin estar ordenado) en repeated.txt.
* **Contraseña eliza:** Fg6b6aoksceQqB9

Como el usuario **frida** utilizamos el comando **ls** para listar el contenido del directorio actual donde nos encontramos, donde podemos observar el fichero **'repeated.txt'**

![image](https://github.com/user-attachments/assets/e30c8aca-bf03-4b60-a61d-ac9907c5b8c8)

Podemos utilizar el comando **uniq **con el parámetro **-d**, el cual imprime las líneas duplicadas de un archivo dado.

![image](https://github.com/user-attachments/assets/d2a8c6f9-500c-4183-b188-673b8cf9fe8e)

### Level 19 -> Level 20
* **Misión:** La usuaria iris me ha dejado su key.
* **Contraseña iris:** kYjyoLcnBZ9EJdz

Como el usuario **eliza** utilizamos el comando **ls -a** para listar todo el contenido del directorio actual en el que nos encontramos, observamos un archivo llamado **'.iris_key'**, si realizamos un **cat** sobre el fichero **.iris_key** observamos que se trata de una **clave SSH privada**

![image](https://github.com/user-attachments/assets/29d91b04-8772-405f-bcd6-099f5203af20)

Podemos utilizar el comando **ssh** acompañado del parametroo **-i** para indicar la **clave SSH privada** e iniciar sesión como el usuario **iris**.

![image](https://github.com/user-attachments/assets/f0eb4984-611b-44a9-b2dd-4aecb90aa77c)

Finalmente conseguimos migrar satisfactoriamente al usuario **iris** y podemso visualizar la password.

![image](https://github.com/user-attachments/assets/3a9486d1-2422-4fdb-81fe-f1a1b3c5d981)

### Level 20 -> Level 21
* **Misión:** La usuaria eloise ha guardado su password de una forma particular.
* **Contraseña eloise:** yOUJlV0SHOnbSPm
  
Como el usuario **iris** utilizamos el comando **ls** para listar el contenido del directorio en el que nos encontramos, como resultado podemos observar un fichero llamado **eloise**, si realizamos un **cat** sobre este fichero podemos vizualizar una cadena en **base64**

![image](https://github.com/user-attachments/assets/f262a35e-c6cf-4a6e-a1e5-440d7c9a4a80)

Podemos utilizar el comando **base64 -d** para decodear la data del fichero **eloise**, como resultado obtenemos texto ilegible, pero al principio de la cadena obtenido se puede observar que es un formato JFIF, esto quiere decir que es un un formato de fichero estándar de imagen. 

![image](https://github.com/user-attachments/assets/cf67a0a0-408a-47ac-97ec-13fd6beea568)

Si queremos obtener de que tipo de archivo del que se trata en concreto podemos utilizar un **pipe** y combinar el comando **file**, obteniendo como resultado que se trata de un archivo **JPEG**

![image](https://github.com/user-attachments/assets/53134bb8-a958-4b35-8b88-ce8c934a905c)

Para trabajar mas comodamente utilizamos el comando **scp** para trasladar el archivo **eloise** a nuestra máquina loca, una vez extraído utilizamos el comando **md5sum** para comprobar que el hash **md5** es el mismo y la data no se ha visto alterada.

![image](https://github.com/user-attachments/assets/49b9bc76-bebb-43a1-b5b0-5d59be1f94ef)

![image](https://github.com/user-attachments/assets/780c88bf-60da-4cc1-b98e-039f804679b1)

Utilizamos el comando **base64 -d** para decodear la data del archivo **eloise**, acto seguido redireccionamos el output a un archivo llamado **eloisepass.jpeg**

![image](https://github.com/user-attachments/assets/eabb1efa-6bc8-451c-a45a-09240a97826e)

Podemos utilizar un gestor de imágenes GUI o si nos encontramos en un terminal kitty utilizamos el comando **'kitty +kitten icat eloisepass.jpeg'**

![image](https://github.com/user-attachments/assets/5a5fbbc0-2ef0-4560-b4f1-21ff81f7f9c3)

### Level 21 -> Level 22
* **Misión:** La usuaria lucia ha sido creativa en la forma de guardar su password.
* **Contraseña lucia:** uvMwFDQrQWPMeGP

Como el usuario **eloise** utilizamos el comando **ls** para listar el contenido del directorio actual, observamos un fichero llamado **hi**, si realizamos un **cat** sobre el mismo para observar un volcado en hexadecimal

![image](https://github.com/user-attachments/assets/a0033da6-6110-46a8-9ca5-cf6c69152ae9)

Para obtener la contraseña del usuario **lucia** podemos utilizar el comando **xxd** con los siguientes parámetros:

* **-r:** Permite revertir la operación y convertir el hexdump a binario.

![image](https://github.com/user-attachments/assets/adbbcf3e-2c0d-450f-8d4f-450a6d7bb50c)

### Level 22 -> Level 23
* **Misión:** La usuaria isabel ha dejado su password en un fichero en la carpeta /etc/xdg pero no recuerda el nombre, sin embargo tiene dict.txt que puede ayudarle a recordar.
* **Contraseña isabel:** H5ol8Z2mrRsorC0

Podemos utilizar un bucle **for** con bash el cual busque en la carpeta **/etc/xdg** cada uno de los nombres de archivo listados en **dict.txt**, una vez obtenido el fichero podemos realizar un **cat** o concatenar un **xargs** con un **cat** con un pipe con un bucle

```bash
for file in `cat dict.txt`; do ls /etc/xdg/$file 2>/dev/null; done
```

![image](https://github.com/user-attachments/assets/db1acdba-4cc2-49d6-8124-7dd3f5a20cdb)


### Level 23 -> Level 24
* **Misión:** La password de la usuaria freya es el unico string que no se repite en different.txt
* **Contraseña freya:** EEDyYFDwYsmYawj

Como el usuario **isabel** utilizamos  el comando **ls** para listar el contenido del directorio actual, observamos un fichero de texto con el nombre **different.txt**

![image](https://github.com/user-attachments/assets/8e1ecc7e-3fbc-4cfc-aeb8-62aef9fa24e2)

Podemos utilizar el comando **uniq -u** el cual nos va a permitir imprimir las líneas unicas de un archivo dado.

![image](https://github.com/user-attachments/assets/0e37c1e3-4cc5-4a7e-b01e-52a789fae1e1)

### Level 24 -> Level 25
* **Misión:** La usuaria alexa pone su password en un fichero .txt en la carpeta /free cada minuto y luego lo borra.
* **Contraseña alexa:** mxq9O3MSxxX9Q3S

Como el usuario freya podemos utilizar el comando watch, el cual nos va a permitir ejecutar un comando de forma periódica, debemos de añadir los siguiente parámetros:

* **-n:**

![image](https://github.com/user-attachments/assets/d5346f8c-c660-40e5-a2f6-3edb928a1ffb)

Esperamos ejecutando el comando **cat** cada segundo hasta obtener la contraseña del usuario **alexa** con éxito.

![image](https://github.com/user-attachments/assets/f07f1f99-9b34-4495-b168-5e99ed963bcf)

### Level 24 -> Level 25
* **Misión:** El password de la usuaria ariel esta online! (HTTP)
* **Contraseña ariel:** 33EtHoz9a0w2Yqo

Como el usuario **alexa** podemos utilizar el comando **curl**, este nos va a permitir realizar una petición web, en este caso a nuestra propia máquina o a la interfaz de red **loopback** que es lo mismo y equivale a la dirección IP **127.0.0.1**, en este caso el **curl** se realiza contra el puerto por defecto ya que no se ha indicado otro, este es el **puerto 80** el mismo en el cual trabaja el protocolo **HTTP** por defecto.

![image](https://github.com/user-attachments/assets/3ccbf3fd-2f07-4fb5-9daf-e282cb11f81e)

### Level 25 -> Level 26
* **Misión:** Parece ser que a ariel no le dio tiempo a guardar la password de lola... menosmal que hay un temporal!
* **Contraseña lola:** d3LieOzRGX5wud6

Como el usuario **ariel** realizamos un **ls -a** para lista todo el contenido del directorio actual en el que nos encontramos, podemos observar un archivo tanto peculiar llamado **'.goas.swp'**.

![image](https://github.com/user-attachments/assets/a7cd4979-bee8-4bde-ac96-62a6cabce6ee)

La extensión **.swp** es un **archivo de intercambio** utilizado por el editor de texto **Vim**, estos archivos se crean automáticamente cuando se edita un archivo en Vim y sirven como una **copia de seguridad temporal**. Podemos utilizar el comando **vim** con los siguientes parámetros:

* **-r:** Permite listar el contenido de archivos swap.

![image](https://github.com/user-attachments/assets/6e1a38dd-554c-43c1-b481-dec1bf32624b)


Obtenemos un diccionario de contraseñas antiguas y actuales del usuario **lola**

![image](https://github.com/user-attachments/assets/0baff960-da1c-44bd-aee1-9a1e4c08e260)

Guardamos el contenido del fichero **.goas.swp** en un archivo llamado **dict.txt** en el directorio **/tmp**

![image](https://github.com/user-attachments/assets/c498374d-34d2-4f01-82cd-a96c5450aa6a)

Si visualizamos el fichero dict.txt existe mucho texto el cual no deseamos, ya que solo necesitmas las contraseñas para poder ir probando en el futuro con cada una de ellas.


Para obtener solo las contraseñas podemos utilizar el comando **sed** el cual nos permitirá sustituir ciertos carácteres, por otro lado podemos redireccionar el output a un nuevo fichero de texto llamado **passwords.txt**

![image](https://github.com/user-attachments/assets/618cd733-53a3-4eed-94f0-d2fb8cfae61c)

![image](https://github.com/user-attachments/assets/687fbf44-166d-40b5-a7e1-fa160fe23a03)


Una vez obtenido el fichero **passwords.txt** utilizamos el comando scp y nos trasladamos el fichero **passwords.txt** a nuestro equipo local

![image](https://github.com/user-attachments/assets/5a33d42c-b6d5-45cc-a74d-596e7f153a87)

Empleamos el uso de la herramienta **hydra** para realizar un ataque de fuerza bruta con el diccionario **passwords.txt** contra el protocolo **ssh** y así poder obtener la contraseña del usuario **lola**

![image](https://github.com/user-attachments/assets/9eee46c9-5a94-4fb9-8d66-bc4edd9d091b)

### Level 26 -> Level 27
* **Misión:** La usuaria celeste ha dejado un listado de nombres de posibles paginas .html donde encontrar su password.
* **Contraseña celeste:** VLSNMTKwSV2o8Tn

Como el usuario **lola** realizamos un **ls** para obtener el contenido del directorio actual, observamos un fichero de texto llamado **pages.txt**, si realizamos un **cat** sobre el mismo visualizamos posibles páginas donde podemos encontrar la password.

![image](https://github.com/user-attachments/assets/89513ff7-ad5c-4364-91f7-5a512e3d832b)

Si tenemos curiosidad de saber cuantas líneas existen en el fichero **pages.txt** podemos utilizar el comando **wc** acompañado del parámetros **-l (lines)**, e inidicar el archivo **pages.txt**.

![image](https://github.com/user-attachments/assets/fcbfc966-24f1-4ad4-ad14-2b8a5d9cfc8c)


Podemos realizar un **Local Port Forwarding** con **SSH** y traer el puerto **80 (HTTP)** de la máquina remota **SSH** a nuestra máquina local como el **puerto 9090**

![image](https://github.com/user-attachments/assets/3d457b2b-19c2-4129-a4aa-5f3097cdb87b)

Una vez realizado el **Local Port Forwarding** utilizamos el comando scp para trasladar el ficheor **pages.txt** a nuestra máquina local.

![image](https://github.com/user-attachments/assets/4383bb61-64dc-4967-b25e-5add1bcf70c8)

Utilizaremos la herramienta **gobuster** para realizar un ataque de fuerza bruta contra directorios utilizando el diccionario **pages.txt**, para ello se usaran los siguientes parámetros:

* **dir:** Especificar que se debe realizar una búsqueda de directorios y archivos en un servidor web.
* **-w:** Indicar la ruta a la lista de palabras que se va a utilizar para realizar la fuerza bruta.
* **-u:** Especificar la URL del objetivo que queremos escanear.
* **-x:** Permite especificar extensiones de archivo como .php, .html ...

![image](https://github.com/user-attachments/assets/1b36c5d0-bc15-4972-9d70-ca6ddcfd385b)

Obtenemos un resultado el cual es **'cebolla.html'**, realizaremos un **curl (petición web)** a la siguiente dirección URL **http://127.0.0.1:9090/cebolla.html** para obtener la password del usuario **celeste**

![image](https://github.com/user-attachments/assets/fdef90c8-f072-4e8c-9925-2217ae9f827c)
