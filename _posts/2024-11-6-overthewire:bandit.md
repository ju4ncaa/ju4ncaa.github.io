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
* **Contraseña bandit9:** 4CKMh1JI91bUIZZPXDqGanal4xvAg0JM

Conectados como el usuario **bandit8** si listamos el directorio en el que nos encontramos observamos el archivo data.txt

![image](https://github.com/user-attachments/assets/af3e2ff2-f273-44c2-b232-14cc807866a7)

Para obtener la contraseña del usuario bandit9 podemos utilizar el comando **cat**, **uniq -u** el cual permite mostrar líneas únicas de un archivo, combinándolo con **sort** para ordenador alfabeticamente las líneas.

![image](https://github.com/user-attachments/assets/3e756cf9-ee70-4df7-a4d6-a3f77f30d6a4)

### Level 9 -> Level 10
* **Objetivo:** Encontrar la contraseña para el siguiente nivel la cual se almacena en el archivo data.txt en una de las pocas cadenas legibles por humanos, precedida de varios caracteres «=».
* **Contraseña bandit10:** FGUW5ilLVJrxX9kMYMmlN4MgbpfMiqey

Conectados como el usuario **bandit9** si listamos el directorio en el que nos encontramos observamos el archivo **data.txt**

![image](https://github.com/user-attachments/assets/f2db3cf5-1cde-4382-9271-c8dbb9217b3a)

Utilizamos el comando ```bash strings data.txt | grep == | sed -n 4p | awk '{print $2}'``` el cual realiza lo siguiente:

* **strings:** Extrae las cadenas de texto legibles del archivo data.txt
* **grep:** Filtra por las líneas que contienen == 
* **sed:** Selecciona la cuarta línea de las filtradas
* **awk:** Imprime el segundo campo

![image](https://github.com/user-attachments/assets/2c269724-17ed-4060-8596-1f00243040ab)


### Level 10 -> Level 11
* **Objetivo:** Encontrar la contraseña para el siguiente nivel la cual se almacena en el archivo data.txt, que contiene datos codificados en base64.
* **Contraseña bandit11:** dtR173fZKb0RRsDFSGsg2RWnpNVj3qRr

Como el usuario **bandit10** listamos el contenido del directorio en el que nos encontramos y observamos el archivo data.txt, si realizamos un cat sobre el fichero observamos una cadena codificada en base64

![image](https://github.com/user-attachments/assets/d3ed651b-e0d5-446b-a14d-7180f6adba36)

Podemos utilizar comando **base64** empleando el parámetro **-d** el cual permite decodear la data y obtener la contraseña del usuario **bandit11**

![image](https://github.com/user-attachments/assets/cacbe1cd-4c63-42eb-a113-09bd3b63bdb0)

### Level 11 -> Level 12
* **Objetivo:** Obtener la contraseña para el siguiente nivel que se almacena en el archivo data.txt, donde todas las letras minúsculas (a-z) y mayúsculas (A-Z) se han girado 13 posiciones.
* **Contraseña bandit12:** 7x16WNeHIi5YkIhWsfFIqoognUTyj9Q4

Como el usuario **bandit11** listamos el contenido del directorio en el que nos encontramos y observamos el archivo data.txt, si realizamos un cat sobre el fichero observamos una cadena la cual de la a-z ha sido rotada 13 posiciones

![image](https://github.com/user-attachments/assets/2c3388fb-bf45-49cc-99aa-b7eab02c9c19)

Podemos utilizar el comando **tr** para transformar ciertos carácteres. La letra A se encuentra a 13 posiciones de la letra M y la letra N se encuentra a 13 posiciones de la letra Z por lo tante usaremos el comando tr para sustituir todas la letras de la a-z tanto en mayúsculas como minúsculas y rotar 13 posiciones es decir: de la **'a-zA-Z'** voy a rotar a **'n-za-mN-ZA-M'** obteniendo finalmente la contraseña.

![image](https://github.com/user-attachments/assets/d031ace8-d699-47f5-8e5b-1ad17e824c4f)


### Level 12 -> Level 13
* **Objetivo:** Obtener la contraseña para el siguiente nivel la cual se almacena en el archivo data.txt, que es un hexdump de un archivo que ha sido comprimido repetidamente.
* **Contraseña bandit13:** FO5dwFsc0cbaIiH0h8J2eUks2vdTDwAn

Como el usuario bandit12 listamos el contenido del directorio actual y observamos que existe un archivo llamado **data.txt** al cual si realizamos un **cat** vemos contenido en formato hexadecimal.

![image](https://github.com/user-attachments/assets/ecd945b4-b979-4ff9-a0c0-6252f468ce43)

Para trabajar mas comodamente utilizaré el comando **scp** el cual me va a permitir copiar archivos del sistema remoto a mi sistema local.

![image](https://github.com/user-attachments/assets/19e06c34-265e-4fbf-93c2-79b82cc23246)

Si utilizamos el comando **xxd** con la opción **-r** y reenviamos el output a un archivo llamado por ejemplo **data** conseguimos revertir el volcado hexadecimal a su forma binaria. Por último aplicando el comando **file** el cual permite identificar el tipo de archivo que se está tratando a través de los magic numbers puedo identificar que se trata de un archivo comprimido **.gzip**

![image](https://github.com/user-attachments/assets/ca6b3980-053b-4b07-ad5a-19e610786c74)

Desrrollaré un script en Bash el cual automatice el proceso de descomprimir los archivos, por lo que creamos un archivo llamado **descomprimir.sh** y le otorgamos permisos de ejecución.

![image](https://github.com/user-attachments/assets/6cfef5a5-cad1-4a08-8297-8a37c0e2bb03)

```bash
#!/bin/bash
nombre_comprimido=$(7z l data.gzip | grep "Name" -A 2 | tail -n 1 | awk 'NF{print $NF}')
7z x data.gzip > /dev/null 2>&1

while true; do
        7z l $nombre_comprimido > /dev/null 2>&1

        if [ "$(echo $?)" == "0" ]; then
                descomprimir_siguiente=$(7z l $nombre_comprimido | grep "Name" -A 2 | tail -n 1 | awk 'NF{print $NF}')
                7z x $nombre_comprimido > /dev/null 2>&1 && nombre_comprimido=$descomprimir_siguiente
        else
                cat $nombre_comprimido && rm data*
                break
        fi
done
```

![image](https://github.com/user-attachments/assets/5692b79a-1c49-4f5a-9a87-097519dde294)

### Level 13 -> Level 14
* **Objetivo:** Obtener la contraseña para el siguiente nivel la cual se almacena en /etc/bandit_pass/bandit14 y sólo puede ser leída por el usuario bandit14. Para este nivel, no obtienes la contraseña, pero obtienes una clave SSH privada que puede ser usada para iniciar sesión en el siguiente nivel.
* **Contraseña bandit14:** MU4VWeTyJk8ROof1qqmcBPaLh7lDCPvS

Una vez conectados en el servidor SSH como el usuario **bandit13** si listamos el contenido del directorio actual se observa una clave privada SSH.

![image](https://github.com/user-attachments/assets/70323c39-7d16-4195-b023-f7d10538c7dc)

Usaremos esta clave para iniciar sesion con **ssh** en el usuario **bandit14** indicando el parámetro **-i** el cual permite seleccionar un archivo del que se lee la identidad clave privada para la autenticación de clave pública.

![image](https://github.com/user-attachments/assets/1c134fde-9ea6-41db-8e28-f20161f0e5f9)

Hemos accedido como el usuario bandit14, si queremos visualizar la contraseña de este usuario podemos realizar un cat de la siguiente ruta: **/etc/bandit_pass/bandit14**

![image](https://github.com/user-attachments/assets/0ba0f938-e5ff-4c56-ac49-d775b57d95c9)

### Level 14 -> Level 15
* **Objetivo:** Obtener la contraseña de bandit15, la cual se puede recuperar enviando la contraseña del nivel actual (bandit14) al puerto 30000 en localhost.
* **Contraseña bandit15:** 8xCjnmgoKbGLhHFAZlGE5Tmu4M2tKJQo

Podemos obtener la contraseña utilizando los comandos **echo** y **nc** lo cuales nos van a permitir interactuar con el puerto 30000 del localhost

![image](https://github.com/user-attachments/assets/2cb38fbc-4799-4a2e-aa7f-bf3f8b87a390)

### Level 15 -> Level 16
* **Objetivo:** Obtener la contraseña de bandit15, la cual se puede recuperar enviando la contraseña del nivel actual al puerto 30001 en localhost utilizando encriptación SSL/TLS.
* **Contraseña bandit16:** kSkvUpMQ7lBYyCM4GBPvCvT1BfWRy0Dx

Nos conenctamos con **openssl** al puerto 30001 con el parámetro **-connect**

![image](https://github.com/user-attachments/assets/81831e0b-85b1-43aa-8a84-4248a4956c2b)

Pegamos la contraseña de **bandit15** y obtenemos como respuesta la contraseña de **bandit16**

![image](https://github.com/user-attachments/assets/80639535-dd84-4ddc-98fc-90ee02a125c3)

### Level 16 -> Level 17
* **Objetivo:** Obtener las credenciales para el siguiente nivel, para ello se puede enviar la contraseña del nivel actual a un puerto en localhost en el rango 31000 a 32000. Primero averigua cuáles de estos puertos tienen un servidor escuchando en ellos. Luego averigua cuáles de ellos hablan SSL/TLS y cuáles no. Sólo hay 1 servidor que te dará las siguientes credenciales, los demás simplemente te devolverán lo que le envíes.
* **Contraseña bandit17:** EReVavePLFHtFlFsjn3hyzMlvSuSAcRD

Para realizar el descubrimiento de puertos abiertos desde **31000** hasta **32000** en el localhost voy a programar un sencillo script en bash el cual utiliza el comando **nc -zv** que permite realizar un escaneo de puertos sin enviar datos.

```bash
#!/bin/bash
for port in $(seq 31000 32000); do
	nc -zv 127.0.0.1 $port 2>/dev/null && echo "[+] Puerto $port abierto"
done
```

Con el script completo, procedemos a ejecutarlo y obtener los puertos abiertos en el localhost.

![image](https://github.com/user-attachments/assets/8e3470ce-2be2-4bc0-831a-5204b49b021d)

Los puertos abiertos son: **{31046, 31518, 31691, 31790, 31960}** intentaremos conectarnos con **openssl** a los mismos y proporcionar la contraseña de **bandit16**, dandonos cuenta de que el puerto correcto es **31790**. Cuando introducimos la contraseña de **bandit16** obtenemos una clave id_rsa.

![image](https://github.com/user-attachments/assets/67aa3d61-e7ef-43cf-a9f5-92a472b80e83)

Copiamos la clave rsa en un archivo llamado **id_rsa** y le asignamos los permisos correctos con **chmod** para poder utilizarla y conectarnos por SSH.

![image](https://github.com/user-attachments/assets/b7c25755-0461-4692-8904-23dcdac8414e)

Nos conectamos al usuario **bandit17** con SSH utilizando el parámetro **-i**

![image](https://github.com/user-attachments/assets/a8d3e1c6-986e-439a-bad0-88de7679baa3)

Para obtener la contraseña de **bandit17** podemos utilizar el comando **cat** para visualizar el fichero **/etc/bandit_pass/bandit17**

![image](https://github.com/user-attachments/assets/cf050e24-3974-4fb4-87a4-503b5736981d)

### Level 17 -> Level 18
* **Objetivo:** Obtener la contraseña de bandit18 la cual se encuentra en el directorio principal donde hay dos archivos: passwords.old y passwords.new, la contraseña está en passwords.new y es la única línea que ha cambiado entre passwords.old y passwords.new.
* **Contraseña bandit18:** x2gLTTjFwMOhQ8oWNbMN362QKxfRqGlO

Para obtener cual es la línea diferente en el archivo **passwords.new** podemos utilizar el comando **diff** el cual permite mostrar diferencias entre archivos comparándolos línea por línea.

![image](https://github.com/user-attachments/assets/36b375ba-7ebf-467d-9635-89b0e5f705b5)

### Level 18 -> Level 19
* **Objetivo:** Obtener la contraseña para el siguiente nivel la cual se almacena en un archivo readme en el **homedirectory**, desafortunadamente alguien ha modificado **.bashrc** para cerrar la sesión cuando te conectas con SSH.
* **Contraseña bandit19:** cGWpMaKXVwDUNgPAVJbWYuGHVn9zl3j8

Podemos spawnear un shell bash añadiendo al final del comando ssh **`bash`**, pudiendo asi leer el archivo readme y obtener la contraseña del usuario **bandit19**

![image](https://github.com/user-attachments/assets/af021ec7-b439-4d14-8e8c-0bb93764e2dc)

### Level 19 -> Level 20
* **Objetivo:** Acceder al siguiente nivel utilizando el binario setuid del directorio home. Ejecútalo sin argumentos para saber cómo usarlo.
* **Contraseña bandit20:** 0qXahG8ZjOVMN9Ghs7iOWsCfZyXOUbYO

Como el usuario **bandit19** si listamos el contenido del directorio actual observamos un binario **SUID** llamado **bandit20-do** y el cual es propietario **bandit20**

![image](https://github.com/user-attachments/assets/3e1a0b61-4e31-4d33-aae5-3dc3cd23a314)

Ejecutamos el script **bandit20-do** sin especificar ningun parámetro y obtenemos la respuesta de que podemos ejecutar comandos como otro usuario, por ejemplo: ./bandit20-do whoami

![image](https://github.com/user-attachments/assets/3c08bdc6-2004-40d3-a98e-3e9a78376f9c)

![image](https://github.com/user-attachments/assets/020ecb08-686f-4b50-9486-9fc0af5d58b3)

Para obtener la contraseña de **bandit20**debemos de utilizar el binario SUID y especificar que queremos utilizar el comando **cat** para visualizar el contenido del directorio **/etc/bandit_pass/bandit20**

![image](https://github.com/user-attachments/assets/eab5f503-217d-4605-a759-ef2126f4db03)

### Level 20 -> Level 21
* **Objetivo:** Acceder al siguiente nivel utilizando el binario setuid en el directorio home. Ejecútalo sin argumentos para saber cómo usarlo.
* **Contraseña bandit21:** EeoULMCra2q0dSkYj561DX7s1CpBuOBt

Como el usuario **bandit20** si listamos el contenido que del directorio actual podemos observar un binario **SUID** llamado **suconnect**

![image](https://github.com/user-attachments/assets/f0346597-6142-4456-ae73-9db7cbe44ed1)

Ejecuto el binario **suconnect** para observar su funcionamiento, basicamente consiste en que se conectará al puerto dado en localhost usando TCP y si recibe la contraseña correcta del otro lado, la del usuario **bandit21** transmite de vuelta.

![image](https://github.com/user-attachments/assets/dfd7b532-b6ab-42dd-a099-bf1e1add8c27)

Utilizamos el comando **nc** para poder abrir un puerto y ponernos en escucha por ejemplo el puerto **1234**, con los siguientes parámetros
* **-l:** Activar modo escucha.
* **-v:** Ver más detalles de la operación (verbose).
* **-n:** No aplicar resolucion DNS.
* **-p:** Indicar el puerto 

![image](https://github.com/user-attachments/assets/fd8c278d-3423-44e0-b8a2-3dfcd892b3ab)

Ejecutamos el binario SUID **suconnect** indicando el puerto en escucha en este el **1234**

![image](https://github.com/user-attachments/assets/0fe818c3-cdab-48b9-bb7d-a0dc6fd45833)


Probamos a pasar la contraseña de **bandit20** y obtenemos como respuesta la contraseña de **bandit21**


![image](https://github.com/user-attachments/assets/27ce0009-d239-4115-ac7e-0017057154b2)


![image](https://github.com/user-attachments/assets/d4a4e953-c959-4379-9670-aef1026d4c25)

### Level 21 -> Level 22
* **Objetivo:** Obtener la contraseña de bandit22 a través de un programa que se está ejecutando automáticamente a intervalos regulares desde cron, el programador de trabajos basado en tiempo, busca en /etc/cron.d/ la configuración y observa qué comando se está ejecutando.
* **Contraseña bandit22:** tRae0UfB9v0UzbCdn9cY0gQnds9GF58Q

Listando el contenido del directorio **/etc/cron.d** se pueden observar diferentes tares cron, suponemos que la de la cual nos tenemos que aprovechar es **cronjob_bandit22**

![image](https://github.com/user-attachments/assets/6769ffb6-0f23-4963-afe5-69cc5d0731ac)

Mostrando el contenido de **/etc/cron.d/cronjob_bandit22** con el comando **cat** se puede observar que la tarea se ejecuta a intervalos de un minuto y se esta haciendo referencia a un script llamado **cronjob_bandit22.sh** almacenado en **/usr/bin**

![image](https://github.com/user-attachments/assets/a88cdb3b-b2f8-4aa9-83cf-3d3ff2323585)

Si mostramos el contenido del script **cronjob_bandit22.sh** podemos ver que se están cambiando los permisos del archivo **tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv** donde los usuarios pueden leer y modificar, los grupos leer y otros leer, acto seguido se está visualizando la contraseña de **bandit22** alojada en el archivo **/etc/bandit_pass/bandit22** y se redirige el output hacia **/tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv**

![image](https://github.com/user-attachments/assets/4690ca4b-152d-4e8b-9552-e5f36056f005)

Podemos utilizar el comando **watch** e indicarle con el parámetro **-n** que a intervalos de un segundo queremos visualizar el contenido del fichero **tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv** con el comando **cat**.

![image](https://github.com/user-attachments/assets/879feeb9-daa1-4636-8421-9b13e7dbec66)

Finalmente obtenemos la contraseña del usuario **bandit22**

![image](https://github.com/user-attachments/assets/99e85572-954b-421d-a2de-1818834d8a45)

### Level 22 -> Level 23
* **Objetivo:** Obtener la contraseña de bandit23 a través de un programa que se está ejecutando automáticamente a intervalos regulares desde cron, el programador de trabajos basado en tiempo, busca en /etc/cron.d/ la configuración y observa qué comando se está ejecutando.
* **Contraseña bandit23:** 0Zf11ioIjMVN551jX3CmStKLYqjk54Ga

Listando el contenido del directorio **/etc/cron.d** se pueden observar diferentes tares cron, suponemos que la de la cual nos tenemos que aprovechar es **cronjob_bandit23**

![image](https://github.com/user-attachments/assets/d5ae3837-f79d-4ff6-9302-41e256e12e4c)

Mostrando el contenido de **/etc/cron.d/cronjob_bandit23** con el comando **cat** se puede observar que la tarea se ejecuta a intervalos de un minuto y se esta haciendo referencia a un script llamado **cronjob_bandit23.sh** almacenado en **/usr/bin**

![image](https://github.com/user-attachments/assets/0b3d2620-a1c6-4633-ae0c-c265c72e2ad9)

Si mostramos el contenido del script **cronjob_bandit23.sh** se están declarando dos varibale una llamada **myname** que ejecuta el comando whoami, seguido se convierta la cadena de texto **"I am user $myname"** a md5, por último se copia la contraseña de **/etc/bandit_pass/$myname** en /**tmp/$mytarget**

![image](https://github.com/user-attachments/assets/cd4a9014-191b-440b-a0ce-3bc981436456)

Si cambiamos de usuario y en vez de poner **bandit22** ponemos **bandit23** obtendremos el hash **md5** de **bandit23** con el cual podremos consultar la contraseña en el directorio **/tmp**

![image](https://github.com/user-attachments/assets/cd48d7b3-ae28-4a4c-90d4-6a29728f4eb4)


### Level 23 -> Level 24
* **Objetivo:** Obtener la contraseña de bandit24 a través de un programa que se está ejecutando automáticamente a intervalos regulares desde cron, el programador de trabajos basado en tiempo, busca en /etc/cron.d/ la configuración y observa qué comando se está ejecutando.
* **Contraseña bandit24:** gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8

Listando el contenido del directorio **/etc/cron.d** se pueden observar diferentes tares cron, suponemos que la de la cual nos tenemos que aprovechar es **cronjob_bandit24**

![image](https://github.com/user-attachments/assets/8357245a-a6ba-4550-830b-e6c715225277)

Mostrando el contenido de **/etc/cron.d/cronjob_bandit24** con el comando **cat** se puede observar que la tarea se ejecuta a intervalos de un minuto y se esta haciendo referencia a un script llamado **cronjob_bandit24.sh** almacenado en **/usr/bin**

![image](https://github.com/user-attachments/assets/2a735603-17a8-4536-902b-44d66b19e607)

Si mostramos el contenido del script **cronjob_bandit24.sh** se declara una variable **$myname** que equivale a el comando **whoami** luego se está accediendo a el directorio **/var/spool/$myname/foo** y si dentro de ese directorio existe algun archivo el cual el propierario sea bandit23 lo va a ejecutar.

![image](https://github.com/user-attachments/assets/082344a8-b282-49c9-9eb1-9c908059e54a)

Podemos aprovecharnos creando un directorio temporal con el comando **mktemp -d** dandole permisos de lectura y ejecución con el comando **chmod +xr** y copiando el script en **/var/spool/bandit24/foo**

![image](https://github.com/user-attachments/assets/8575a8ef-e352-490e-bb5a-61c04aa0bc16)

```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/tmp.s8svzAOPxT/bandit24_pass.txt
```

![image](https://github.com/user-attachments/assets/f6f7be96-234d-400f-8c75-b8474ccf94b7)

Finalmente obtenemos la contraseña del usuario **bandit24**

![image](https://github.com/user-attachments/assets/6b5e53d7-96ba-4fd1-a970-188de7bd37e0)

### Level 24 -> Level 25
* **Objetivo:** Obtener la contraseña de bandit25 a través de un demonio que está escuchando en el puerto 30002 al cual si se le da la contraseña para bandit24 y un código secreto numérico de 4 dígitos devuelve de vuelta la contraseña correcta para bandit25
* **Contraseña bandit25:** iCi86ttT4KSNe1armKiwbQNmB3YJP3q4

Intentamos obtener la contraseña de **bandit25** realizando una prueba para ver como funciona, debemos de especificar una contraseña en este caso usaré la del usuario bandit24 y un pin de 4 digitos que puede ir desde el **0000** hasta el **9999**

![image](https://github.com/user-attachments/assets/82f03474-0928-46ef-bc79-ec52db0040a1)

Podemos crear un diccionario con un one-liner de bash con el cual en un futuro aplicar fuerza bruta sobre el puerto 30002.

```bash
for i in $(seq 0000 9999); do echo gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8 $i; done > combinations.txt
```

Despues tenemos que pasarle el archivo al servicio del puerto **30002** con el comando **cat** y **nc**

![image](https://github.com/user-attachments/assets/e3407c6a-9e15-46fe-9fb9-5c406fdb339a)

Finalmente obtenemos la contraseña del usuario **bandit25**

![image](https://github.com/user-attachments/assets/b209517b-4f49-4ac0-b7a3-2f1388a6ff7e)

### Level 25 -> Level 26
* **Objetivo:** Acceder a bandit26 desde bandit25 debería ser bastante fácil... pero el shell para el usuario bandit26 no es /bin/bash, sino otra cosa, debes de everiguar qué es, cómo funciona y cómo salir de él.
* **Contraseña bandit26:** s0773xxkk0MXfdqOfPRVr9L3jJBUOgCZ

Como el usuario **bandit25** listamos el contenido del directorio en el que nos encontramos y observamos una clave privada SSH.

![image](https://github.com/user-attachments/assets/12036521-ce0b-4420-b1c9-540169260ef4)

Utilizamos la clave privada SSH para iniciar sesión como **bandit26**, pero automaticamente somos expulsados de la sesión.

![image](https://github.com/user-attachments/assets/f7818f8e-4380-46e5-9c8e-a8b985345a7a)

![image](https://github.com/user-attachments/assets/25e4ae68-d097-439d-8824-bafefaced7e7)

Visualizamos el archivo **/etc/passwd** para comprobar que valor tiene la shell de **bandit26**, observando que recibe el valor de **/usr/bin/showtext**

![image](https://github.com/user-attachments/assets/b9241b16-cc90-4c61-8318-d92d12de85a5)

Si visualizamos el fichero **/usr/bin/showtext**, podemos ver que iguala la variable de entorno **TERM** a el valor **linux**, luego visualiza de forma paginada con el comando **more** un fichero que esta en el directorio **home** de **bandit26** llamado **text.txt**, por ultimo realiza un exit 0

![image](https://github.com/user-attachments/assets/4a8f20f4-2efb-47e7-8ddc-927e3bffd977)

Se nos esta expulsando de la sesion por que el comando **more** necesita un mínimo de texto para entrar en ejecución, lo que podemos hacer es más pequeña la ventana de la terminal y estaria resuelto.

![image](https://github.com/user-attachments/assets/bac38aac-6eca-4f72-b1a2-4484fcc479c6)

Ya hemos entrado en la ejecucion del comando **more** como se puede observar

![image](https://github.com/user-attachments/assets/d921ffd7-3919-4041-83dc-71a4a5de274c)

Si pulsamos la letra **V** entramos en un modo donde podemos ejecutar comandos y obtener una shell

![image](https://github.com/user-attachments/assets/23983343-382f-4b1f-863f-04b90a8c8f2d)

![image](https://github.com/user-attachments/assets/a94113cf-d3ab-4f32-8abd-cbe6caf7d210)

Finalmente podemos leer el fichero **/etc/bandit_pass/bandit26** que contiene la contraseña del usuario **bandit26**.

![image](https://github.com/user-attachments/assets/8632171e-a882-4bdb-8a02-3729adbb0647)

### Level 26 -> Level 27
* **Objetivo:** ¡Buen trabajo consiguiendo el shell! ¡Ahora date prisa y consigue la contraseña para bandit27!
* **Contraseña bandit27:** upsNCc7vzaRDx6oZC6GiR6ERwe1MowGB

Como el usuario bandit26 listamos el contenido del directorio actual y se puede observarun binario SUID llamado **bandit27-do** el cual el propietario es **bandit27** y el grupo **bandit26** y tenemos solo permisos de ejecución.

![image](https://github.com/user-attachments/assets/42d7177c-3808-4b37-82bd-0d783a089752)

Ejecutando el fichero SUID **bandit27-do** observamos que permite ejecutar comandos como el usuario **bandit27**

![image](https://github.com/user-attachments/assets/4aef5579-701d-4d05-999d-d34b0830eac6)

Por lo que simplemente tenemos que usar el comando **cat** para visualizar la contraseña la cual se encuentra en el fichero **/etc/bandit_pass/bandit27**

![image](https://github.com/user-attachments/assets/0281d831-df13-4fec-be76-481d7819b6d2)


### Level 27 -> Level 28
* **Objetivo:** Hay un repositorio git en ssh://bandit27-git@localhost/home/bandit27-git/repo a través del puerto 2220. La contraseña para el usuario bandit27-git es la misma que para el usuario bandit27.
* **Contraseña bandit28:** Yz9IpL0sBcCeuG7m9uQFt8ZNpS4HZRcN

Clonamos el repositorio de GitHub con el comando **git clone** en un directorio temporal creado con **mktemp**

![image](https://github.com/user-attachments/assets/579f7280-dcb8-4787-b0ee-aa05b6c3e78d)

Accedemos al directorio **repo** clonado anteriormente donde al hacer **ls** observamos un fichero **README** al cual si realizamos un **cat** para visualizar el contenido nos proporciona la contraseña del usuario **bandit28**

![image](https://github.com/user-attachments/assets/0f454089-5b25-41c8-8263-fdef25e52903)

### Level 28 -> Level 29
* **Objetivo:** Hay un repositorio git en ssh://bandit28-git@localhost/home/bandit28-git/repo a través del puerto 2220. La contraseña para el usuario bandit28-git es la misma que para el usuario bandit28.
* **Contraseña bandit29:** 4pT1t5DENaYuqnqvadYs1oE4QLCdjmJ7

Clonamos el repositorio con **git clone** y accedemos dentro del mismo.

![image](https://github.com/user-attachments/assets/caf75070-6469-4500-9db6-f74f4aa7767f)

Si listamos el contenido del repositorio obervamos que existe un fichero **README.md**, procedemos a realizar una visualizacion del contenido del mismo con el comando **cat**

![image](https://github.com/user-attachments/assets/c59d166a-4b71-4109-af2c-7a75cdb45021)

Existe un comando en **git** el cual es **git log** el cual permite ver el historial del proyecto, filtrarlo y buscar cambios concretos. Aplicando este comando podemos observar que hay un cambio que llama la atencion el cual pone **fix info leak**

![image](https://github.com/user-attachments/assets/6bc48ed6-8db5-44e4-b90d-7ebbed9bdc28)

Con el comando **git show** podemos ver los cambios que se han realizado pasándole el identificador del commit, observamos que antes la contraseña se encontraba en texto claro y la han remplazado por varias **X**, conseguimos obtener la contraseña del usuario **bandit29** satisfactoriamente

![image](https://github.com/user-attachments/assets/9329b60e-4693-48f5-b8e3-2c2ecf37ed61)

### Level 29 -> Level 30
* **Objetivo:** Hay un repositorio git en ssh://bandit29-git@localhost/home/bandit29-git/repo a través del puerto 2220. La contraseña para el usuario bandit29-git es la misma que para el usuario bandit29.
* **Contraseña bandit30:** qp30ex3VLz5MDG1n91YowTv4Q8l7CDZL

Clonamos el repositorio con **git clone** y accedemos dentro del mismo.

![image](https://github.com/user-attachments/assets/4863fd79-662c-4223-9eac-928d01b3033d)

Si listamos el contenido del repositorio obervamos que existe un fichero **README.md**, procedemos a realizar una visualizacion del contenido del mismo con el comando **cat**

![image](https://github.com/user-attachments/assets/71f618b0-fa14-40fb-896f-b51591af7111)

No se encuentran contraseñas en producción, con esa pista podemos utilizar el comando **git branch -a** el cual nos permite listar todas las ramas existentes en el proyecto.

![image](https://github.com/user-attachments/assets/6a289bf7-343c-4bbf-8d15-683e794de4cd)

Me llama la atención la rama **dev** que lo asocio a **developers** y si no se encuentran contraseñas en producción puede que aqui sí, migramos a la rama **dev** con el comando **git checkout**, y observamos un fichero README.md el cual si hacemos **cat** contiene la contraseña del usuario **bandit30**

![image](https://github.com/user-attachments/assets/095610dd-a5d0-434b-a6da-b7982680ffa9)

### Level 30 -> Level 31
* **Objetivo:** Hay un repositorio git en ssh://bandit30-git@localhost/home/bandit30-git/repo a través del puerto 2220. La contraseña para el usuario bandit30-git es la misma que para el usuario bandit30.
* **Contraseña bandit31:** fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy

Como el usuario **bandit30** clonamos el repositorio con **git clone** y accedemos dentro del mismo.

![image](https://github.com/user-attachments/assets/4f16bfcb-3999-43c9-b0c4-bee797ca4100)

Listamos el contenido del repositorio y vemos un fichero **README.md**, al cual si aplicamos un comando cat para ver el contenido vemos que se están riendo en nuestra cara con la siguiente frase **`just an epmty file... muahaha`**

![image](https://github.com/user-attachments/assets/50b5582c-5f08-4aad-895f-901e5ef828c7)

No existen ni **commits** ni difernetes **ramas** del repositorio

![image](https://github.com/user-attachments/assets/449dc3d8-3b2b-440d-b65b-da8d4d7a7ff3)

Existe un comando **git tag** el cual permite la creeación, modificación y eliminación de una etiqueta, utilizando este comanndo vemos un tag llamado **secret**

![image](https://github.com/user-attachments/assets/55599626-abb7-4f07-8493-7251ff004305)

Podemos visualizar el contenido del tag con el comando **git show** obteniendo asi la contraseña del usuario **bandit31**

![image](https://github.com/user-attachments/assets/4097eedc-6c17-432d-a4ba-92e29a713932)

### Level 31 -> Level 32
* **Objetivo:** Hay un repositorio git en ssh://bandit31-git@localhost/home/bandit31-git/repo a través del puerto 2220. La contraseña para el usuario bandit31-git es la misma que para el usuario bandit31.
* **Contraseña bandit32:** 3O9RfhqyAlVBEZpVb6LYStshZoqoSx5K

Clonamos el repositorio con **git clone** y accedemos dentro del mismo.

![image](https://github.com/user-attachments/assets/2b723236-d138-4095-a103-a420d9a3fb6c)

Listamos el contenido del repositorio y vemos un fichero **README.md**, al cual si aplicamos un comando cat para ver el contenido nos dice que tenemos que subir un fichero con el nombre **key.txt** al repositorio con el texto **May I come in?** en la rama **master**

![image](https://github.com/user-attachments/assets/dd97b2af-880d-4269-ace8-12308366a19e)

Cremoa el fichero **key.txt** con el comando **touch** e introducimos el texto **May I come in?** con el comando **echo**, al realizar un **git add** nos avisa de que el el fichero **.gitignore** tiene implantado ignorar los ficheros **.txt**

![image](https://github.com/user-attachments/assets/5300dea6-644d-487e-b2b9-1bc299ce9720)

![image](https://github.com/user-attachments/assets/f16a9d69-d5d7-4f2e-8fbb-64fd198392ae)

Borramos el fichero **.gitignore** para que no aplique.

![image](https://github.com/user-attachments/assets/e4510f96-06e9-48fd-9528-56a26d3fbff5)

Subimos el commit y obtenemos el contraseña del usuario **bandit32**

![image](https://github.com/user-attachments/assets/865a7825-d58a-4d10-99db-118f2fa94d78)

### Level 32 -> Level 33
* **Objetivo:** Después de tanto git, es hora de otra escapada. ¡Buena suerte!
* **Contraseña bandit33:** tQdtbs5D5i2vJwkO8mEyYEyTL8izoeJ0

Al conectarnos remotamente como el usuario **bandit32** obtenemos un shell el cual convierte el input que se pasa en minúsculas a mayúsculas

![image](https://github.com/user-attachments/assets/5f8a21af-fcef-4110-8760-db2646e842cf)

Si visualizamos el fichero /etc/passwd y grepeamos por el usuario bandit32 podemos ver que la shell vale /home/bandit32/upershell

![image](https://github.com/user-attachments/assets/f97320dc-8c5e-4076-b554-b2d4e4b81eba)

Podemos escapar del UPPERCASE SHELL indicando el parámetro **$0** el cual hace referencia al script que se ejecuta o al terminal que se utiliza por lo que sería equivalente a escribir bash en la terminal.

![image](https://github.com/user-attachments/assets/21d7b79e-654a-4792-940b-87ae0868d916)

Por ultimo visualizamos la contraseña del usuario final **bandit33**

![image](https://github.com/user-attachments/assets/5f589d5a-ac7c-4542-a811-e3dbe7e983f0)
