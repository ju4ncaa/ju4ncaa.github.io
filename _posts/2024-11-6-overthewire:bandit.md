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
