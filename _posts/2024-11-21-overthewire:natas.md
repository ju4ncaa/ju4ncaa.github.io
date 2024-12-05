---
title: Resolución CTF OverTheWire:Natas, Level 0-34 Write-Up
description: En este apartado se resuleven los 34 niveles del CTF de OverTheWire Natas.
date: 2024-11-21
categories: [CTFs, Hacking Web]
tags: [CTFs, Hacking web]
img_path: https://i.ibb.co/NsS3QzS/natas.png
image: https://i.ibb.co/NsS3QzS/natas.png
---

## **Introducción**
En este apartado se resuelven los 34 niveles del CTF de OverTheWire Natas. Estos retos están diseñados para principiantes con el objetivo de enseñar los fundamentos de la seguridad web y la explotación de vulnerabilidades. A lo largo de estos niveles, puedes familiarizarte con una variedad de conceptos y técnicas esenciales en el ámbito de la ciberseguridad, como la inyección de código, la manipulación de sesiones y la gestión de autenticaciones. Cada nivel presenta un desafío específico que va desde tareas simples, como la identificación de vulnerabilidades en aplicaciones web, hasta desafíos más complejos que requieren habilidades en análisis de seguridad, explotación de fallos y comprensión de protocolos de comunicación. Natas es una excelente manera de aprender y practicar habilidades críticas en un entorno seguro y controlado.

### Level 0 -> Level 1
* **Nombre de usuario** natas0
* **Contraseña natas0:** natas0
* **URL:** http://natas0.natas.labs.overthewire.org
* **Misión:** Encontrar la contraseña para el siguiente nivel (natas1) en esta página.
* **Contraseña natas1:** 0nzCigAq7t2iALyvU9xcHlYN4MlkIwlq


Utilizamos el shortcut **Ctrl + U**, esto nos permite visualizar el codigo fuente de la página donde en un comentario HTML se encuentra la contraseña de **natas1**

![image](https://github.com/user-attachments/assets/b58d1b7f-51a8-47f1-aeca-147f3a04d039)

### Level 1 -> Level 2
* **Contraseña natas2:** TguMNxKo1DSa1tujBLuZJnDUlCcUAPlI
* **URL:** http://natas1.natas.labs.overthewire.org
* **Misión:** Encontrar la contraseña para el siguiente nivel en esta página, ¡pero el botón derecho del ratón ha sido bloqueado!

Utilizamos el shortcut **Ctrl + U**, esto nos permite visualizar el codigo fuente de la página de la misma forma que haciendo clic derecho y seleccionar **View Page Source**, observamos que en un comentario HTML se encuentra la contraseña de **natas2**

![image](https://github.com/user-attachments/assets/fd24ea3e-74e4-4418-8512-e8759604f9a0)

### Level 2 -> Level 3
* **Contraseña natas3:** 3gqisGdR0pjm6tpkDKdIWO2hSvchLeYH
* **URL:** http://natas2.natas.labs.overthewire.org
* **Misión:**  No hay nada en esta página

Observamos el codigo fuente y observamos que hay una imagen llamado **pixel.png** que se carga desde el directorio **/files**

![image](https://github.com/user-attachments/assets/eb92e349-fbf3-4e65-9e41-59caf1b01b2f)

Nos dirigimos a el directorio **/files** donde podemos observar un fichero de texto llamado **users.txt**, dentro del mismo se encuentra la contraseña de **natas3**.

![image](https://github.com/user-attachments/assets/444ea6fb-7230-4879-9346-5190b11420f4)

![image](https://github.com/user-attachments/assets/c8394321-ea92-40fa-9388-d421f87fcfa2)

### Level 3 -> Level 4
* **Contraseña natas4:** QryZXc2e0zahULdHrtHxzyYkj59kUxLQ
* **URL:** http://natas3.natas.labs.overthewire.org
* **Misión:**  No hay nada en esta página

Utilizamos el shortcut **Ctrl + U** para inspeccionar el codigo fuente de la página pero no encontramos ninguna fuga de información.

![image](https://github.com/user-attachments/assets/765b0549-34fc-40ad-bae7-2eeccf330d80)

Existe un archivo llamado **robots.txt** el cual contiene estructura de un sitio web, si este se encuentra habilitado puede contener información valiosa.

![image](https://github.com/user-attachments/assets/8902600d-02d1-4849-9a71-4147d45ad2c2)

En el archivo **robots.txt** podemos observar un directorio llamado **s3cr3t** al cual si accedemos podemos ver un fichero llamado **users.txt** dentro del mismo se encuentra la contraseña de **natas4**.

![image](https://github.com/user-attachments/assets/8963064a-396c-4680-b7ef-8b63a411fdd2)

![image](https://github.com/user-attachments/assets/525380a3-2cee-4200-8b74-b735838d31e7)

### Level 4 -> Level 5
* **Contraseña natas5:** 0n35PkggAPm2zbEpOU802c0x0Msn1ToK
* **URL:** http://natas4.natas.labs.overthewire.org
* **Misión:** Acceso denegado, estás visitando desde `"http://natas4.natas.labs.overthewire.org/"` mientras que los usuarios autorizados deben venir sólo de `"http://natas5.natas.labs.overthewire.org/"`

Podemos observar las **cabeceras de solicitud** en concreto el **Referer** que es la dirección de la página web desde la que se realiza la solicitud.

![image](https://github.com/user-attachments/assets/2cc9f763-7740-46af-9574-e79b84745bf5)

Interceptamos la petición con el proxy BurpSuite y cambiamos el Referer a **http://natas5.natas.labs.overthewire.org/**

![image](https://github.com/user-attachments/assets/b50f2d73-84e7-40e4-b38a-34b211ee9e6a)

### Level 5 -> Level 6
* **Contraseña natas6:** 0RoJwHdSKWFTYR5WuiAewauSuNaBXned
* **URL:** http://natas5.natas.labs.overthewire.org
* **Misión:**  Acceso denegado, no has iniciado sesión

Interceptamos la petiicón con el proxy BurpSuite y observamos que el Header Cookie tiene el paráemtro `logeddin=0`

![image](https://github.com/user-attachments/assets/efda2130-6213-44d1-9aaa-9afac32fdf00)

Supongo que `**0 es igual a False**` y `**1 es igual a True**`, lo que me permitirá indicar que si esto logeado como el usuario **natas5**

![image](https://github.com/user-attachments/assets/4f144080-26e0-4f58-aa99-78b851267aad)

### Level 6 -> Level 7
* **Contraseña natas7:** bmg8SvU1LizuWjx3y7xkNERkHxGre0GS
* **URL:** http://natas6.natas.labs.overthewire.org
* **Misión:** Introduce el secreto para obtener la contraseña del usuario natas7

Observamos un campo donde se nos permite introducir una frase secreta.

![image](https://github.com/user-attachments/assets/0f7d6943-63eb-4845-8813-1e28eecc8c15)

Observamos el codigo fuente, podemos ver un codigo **PHP** el cual se encarga de validar a través del método **POST** que lo que introducimos en el input equivale a la frase secreta, de ser así nos muestra la contraseña de **natas7** y si no es así se nos muestra `Wrong secret`, por ultimo y lo mas importante es que al princpio del codigo se incluye el siguiente archivo `"includes/secret.inc"`

![image](https://github.com/user-attachments/assets/c6e6ff76-d95c-4ad0-80fc-dad7429332af)

Intentamos ver que contiene el archivo `"includes/secret.inc"`, no observamos nada, si utilizamos el shortcut **Ctrl + U** podemos ver en el codigo fuente la frase secreta.

![image](https://github.com/user-attachments/assets/b4a5c739-705e-41e3-b46a-0e2d2a4bc9b1)

![image](https://github.com/user-attachments/assets/c24c25ca-e605-4f29-82c2-d4145c0d4a56)

Introducimos la frase secrete y obtenemos la contraseña de **natas7**

![image](https://github.com/user-attachments/assets/63dbc6d5-1ccc-4890-a88b-280005c8dc2e)

### Level 7 -> Level 8
* **Contraseña natas8:** xcoXLmzMkoIP9D7hlgPlh9XD7OgLAe5Q 
* **URL:** http://natas7.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas8 a través de un LFI (Local File Inclusion)

En la página principal observamos dos enlaces uno llamado **Home** y otro **About**

![image](https://github.com/user-attachments/assets/6415b849-1b4a-4e7b-a976-3ed7f9ca89d7)

Si nos fijamos en la url se apunta hacia estos enlaces a través de un parámetro por GET llamado **?page=**

![image](https://github.com/user-attachments/assets/6cff0f55-f730-4aed-a8ee-283a54eeed40)

Se están cargando archivos del sistema a través del parametro GET **?page=**, esta mala practica es tipica de la vulnerabilidad LFI (Local File Inclusion) la cual nos permite como atacantes apuntar hacia archivos locales del sistema y ver su contenido, por ejemplo **(/etc/passwd)**

![image](https://github.com/user-attachments/assets/81df185d-1702-4635-bd6c-7a7ccc1301d3)

Si visualizamos el codigo fuente podemos ver un comentario HTML el cual contiene una filtración de información donde indica que la contraseña de **natas8** se encuentra en **/etc/natas_webpass/natas8**

![image](https://github.com/user-attachments/assets/70d1acbc-c10b-4fac-b615-571679291540)

Intentamos listar la contraseña de **natas8** en **/etc/natas_webpass/natas8** igual que hicimos con **/etc/passwd**, conseguimos obtener la contraseña con éxito.

![image](https://github.com/user-attachments/assets/fb0d3d1b-ba35-4d53-a0ba-577863e799c3)

### Level 8 -> Level 9
* **Contraseña natas9:** ZE1ck82lmdGIoErlhQgWND6j2Wzz6b6t
* **URL:** http://natas8.natas.labs.overthewire.org
* **Misión:** Introduce el secreto para obtener la contraseña del usuario natas9

Observamos un campo donde se nos permite introducir una frase secreta.

![image](https://github.com/user-attachments/assets/be59b792-66a0-4085-93b4-bf56656a0056)


Observamos el codigo fuente, podemos ver un codigo **PHP** este tiene una función llamada **encodeSecret** y una variable **encodedSecret**

![image](https://github.com/user-attachments/assets/1aec429e-ec64-4f9a-9f16-02db9751d148)

En la función **encodedSecret** se estan utilizando la funciónes **bin2hex()** la cual convierte datos binarios en su representación hexadecimal, y por otro lado **strrev()** la cual invierte una string, por ultimo la función **base64_encode()** la cual convierte la cadena a base64, para obtener la frase secreta debemos de realizar el proceos inverso. 

![image](https://github.com/user-attachments/assets/8b4fff4c-2835-41f2-af64-4d229d9aa01e)

![image](https://github.com/user-attachments/assets/29b2b6cb-1bd6-4d76-8a0b-f1dfa394c7bf)

Introducimos la frase secreta y obtenemos ls contraseña de **natas9**

![image](https://github.com/user-attachments/assets/baf55b74-dbfe-4587-bbf3-2214123a6d1d)

### Level 9 -> Level 10
* **Contraseña natas10:** t7I5VHvpa14sJTUGV0cbEsbYfFP2dmOu
* **URL:** http://natas9.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas10 a través de una inyección de comandos

Observamos un campo que nos permite buscar palabras que contengan que contenga las letras que le indiquemos.

![image](https://github.com/user-attachments/assets/810d256a-e4a5-4401-9d85-026c4ab536dd)

Si revisamos el codigo **PHP** podemos observar que se está utilizando la función **passthru()**, esta función permite ejecutar un programa externo y muestra la salida en bruto, en este case se utiliza el comando grep y se muestra su salida en el navegador.

![image](https://github.com/user-attachments/assets/c9c8dd64-6f90-435a-952d-4522c2a83c4f)

Se nos permite ingresar comandos los cuales se pasan a **passthru()**, lo cual puede desembocar en una inyección de comandos, para evitar estas situaciones se recomienda utilizar la función **escapecmdshell()** sanitizando cualquier entrada del usuario antes de pasarla a **passthru()**

![image](https://github.com/user-attachments/assets/50d17d73-f04f-4ab5-a076-e09817c13723)

![image](https://github.com/user-attachments/assets/45047a87-73dc-4c51-b289-bc3f9d0d6242)

La contraseña de **natas8**  se encontraba en **/etc/natas_webpass/natas8**, por lo que aprovechare el command injection para mediante el comando **cat** mostrar la contraseña de **natas 10** en **/etc/natas_webpass/natas10**

![image](https://github.com/user-attachments/assets/e8b22015-feb2-4064-9b9e-b68e2cec4bbe)

![image](https://github.com/user-attachments/assets/e50a2fed-90ec-4289-8d1d-473ee9e680fe)

### Level 10 -> Level 11
* **Contraseña natas11:** UJdqkK1pTu6VLt9UHWAgRZz6sVUZ3lEk
* **URL:** http://natas10.natas.labs.overthewire.org
* **Misión:**  Obtener la contraseña de natas11 a través de expresión regular con grep

Observamos un campo que nos permite buscar palabras que contengan que contenga las letras que le indiquemos.

![image](https://github.com/user-attachments/assets/5ef066ff-6905-4677-9dcc-ebd0fce4153c)

Si revisamos el codigo PHP podemos observar que se está utilizando la función **preg_match()**, esta función permite a través de una expresión regular obtener coincidencias, en este caso si se detectan estos carácteres `;|&` se devuelve el texto `Input contains an illegal character!`, por otro lado tenemos la función **passthru()**, esta función permite ejecutar un programa externo y muestra la salida en bruto, en este case se utiliza el comando grep y se muestra su salida en el navegador.

![image](https://github.com/user-attachments/assets/35368031-d745-47f4-8e19-9016a51a6458)

El comando **grep** permite mediante expresiones regulares buscar cadenas de texto, una de las expresiones regulares que tiene es el  punto `.` que permite hacer **match** con cualquier resultado introducido, por otro lado le pasaremos el archivo que queremos leer con grep en este caso el que contiene la contraseña de natas11 **/etc/natas_webpass/natas11**, por ultimo utilizamos el caracter almohadilla `#` url encodeado que sería `%23f`, esto nos va a permite omitir el resto del output que viene despues del archivo que queremos leer.

![image](https://github.com/user-attachments/assets/8904b6bc-97e4-454b-a68c-c74265c58010)

![image](https://github.com/user-attachments/assets/01a5b0f4-bbca-4cfa-abc1-eadfe72f1f61)

### Level 11 -> Level 12
* **Contraseña natas12:** yZdkjAYZRd3R7tq7T5kXMjMJlOIkzDeB
* **URL:** http://natas11.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas12 a través del cifrado XOR

Observamos un input en la página el cual nos permite cambiar el color de fondo de la misma.

![image](https://github.com/user-attachments/assets/f0427a4d-50da-4587-8902-2c88ef59c776)

![image](https://github.com/user-attachments/assets/621ec638-392b-453c-bfb1-7f01b479ac8b)

Por otro lado tambien se indica que las cookies de sesion se encuentras cifradas con XOR. 

![image](https://github.com/user-attachments/assets/dd2e95f3-3332-4195-88a5-1f279da04305)

Analizaremos el código PHP función por función ya que se trata de un código mas complejo.

![image](https://github.com/user-attachments/assets/1b1becbe-ae0f-43fc-b2f5-1dcc91f6cec7)

Comenzamos con una data por defecto, donde el color de fondo y la inclusion de la contraseña se almacenan en el mismo array.

![image](https://github.com/user-attachments/assets/6a0b511a-890c-47b7-a9bc-c590acad8257)

Tenemos una función llamada **xor_encrypt()**, esta se encarga de cifrar la clave, por lo que encontrarla es un paso crucial.

![image](https://github.com/user-attachments/assets/344db2e5-12cb-46ad-bb53-c4eb4f4a8064)

A continuación tenemos una función llamada **loadData()**, esta toma el valor de la cookie, lo decodifica y luego lo utiliza para establecer los valores de la web **(el color de fondo y si podemos ver la contraseña)**

![image](https://github.com/user-attachments/assets/d288b043-38bb-42ee-a3a7-043e3afeb145)

Otra función llamada **saveData()** la cual cifra la matriz y la guarda como cookie en el navegador del usuario.

![image](https://github.com/user-attachments/assets/b8f6e7bc-04f2-4cdb-9912-d97dad120128)

Por último hay una petición del usuario que se tramita por get para conseguir el color de fondo.

![image](https://github.com/user-attachments/assets/4948babd-704e-4efe-9113-40bd39b161cf)

Abrimos el inspector de página y nos dirigimos a la pestaña **Storage** y vemos que el valor de la cookie para el color blanco es **HmYkBwozJw4WNyAAFyB1VUcqOE1JZjUIBis7ABdmbU1GIjEJAyIxTRg%3D**

![image](https://github.com/user-attachments/assets/a8a76793-dd44-45b3-a336-05bc3c3369f7)

La cookie incluye **showpassword=no** y queremos cambiarlo a **showpassword=yes**, para ello tenemos que descifrarlo con XOR, pero el problema es que no tenemos la llave, por ello en primer lugar crearemos una cookie sin cifrado XOR

![image](https://github.com/user-attachments/assets/0e48817e-8a6e-4814-8112-6475740b5487)

![image](https://github.com/user-attachments/assets/d4cd3c98-8428-43dd-9661-14afe41e907f)

Utilizaremos la herramienta **CyberChef** la cual nos va a permitir obtener la **clave XOR**

![image](https://github.com/user-attachments/assets/959dbf69-0592-4ebb-b74c-778f5913df56)

Utilizamos la **clave XOR** para descifrar la cookie y comprobar que los valores que contiene son **showpassword** y **bgcolor**

![image](https://github.com/user-attachments/assets/28bf797e-a7f3-4219-97b6-44b922b21f84)

Una vez tenemos la **clave XOR** ya podemos crear una cookie que contenga el siguientes objeto JSON  **{"showpassword":"yes","bgcolor":"#ffffff"}**

![image](https://github.com/user-attachments/assets/5e9e5003-4d60-469e-be25-a9ad9fbb650d)

La cookie de sesión obtenida con el valor **showpassword=yes** es **"HmYkBwozJw4WNyAAFyB1VUc9MhxHaHUNAic4Awo2dVVHZzEJAyIxCUc5"**, abrimos el inspector de página y en la pestaña **Storage** reemplazamos la cookie.

![image](https://github.com/user-attachments/assets/4031787d-1729-4199-854b-7748733db167)

Recargamos la página con F5 y obtenemos la contraseña de **natas12**

![image](https://github.com/user-attachments/assets/f60352ed-f701-49c8-a4fe-be5d4cff4fbe)

### Level 12 -> Level 13
* **Contraseña natas13:** trbs5pCjCrkuSknBBKHhaBxq6Wm1j3LC
* **URL:** http://natas12.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas13 a través de un File Upload

Observamos un campo donde se nos permite subir una imagen con extensión **JPEG** de máximo **1KB** de tamaño

![image](https://github.com/user-attachments/assets/860c1038-c606-4e16-97d5-dc4f2f277934)

Analizamos el código PHP y vemos que si es correcto que el archivo no puede superar 1KB de tamaño, y que se utiliza la función **makeRandomPath()** donde se generar un nombre de archivo aleatorio y al final siempre se le añade la extensión **.jpg**

![image](https://github.com/user-attachments/assets/f98f6889-8fc5-46c0-b3e0-9c45a7b3c0ce)

Crearemos un archivo PHP con código malicioso simplificado el cual permita a través de un parámetro por **GET** llamado **cmd** ejecutar comandos.

![image](https://github.com/user-attachments/assets/e9a69196-c484-4a87-bf24-df7bc3e18ad0)

Interceptamos con **BurpSuite** la subida del archivo **cmd.php** y cambiamos la extensión **.jpeg** con la que se nos va a guardar el archivo a **.php**

![image](https://github.com/user-attachments/assets/a199d5c2-be81-4f47-b3bd-655469dfc0d7)

![image](https://github.com/user-attachments/assets/8622ae59-e809-4901-a87a-032316ca8b75)

![image](https://github.com/user-attachments/assets/794d61eb-e362-4950-8371-2bbcd1363920)

![image](https://github.com/user-attachments/assets/489d88c3-3142-47f4-9bea-7e6fff7ddb5e)

Accedemos a **/upload/gnrgxmlmth.php** y vemos que podemos ejecutar comandos.

![image](https://github.com/user-attachments/assets/48a5bdb4-b03b-41e7-81c8-6c2fc8460db1)

Visualizamos la contraseña de **natas13** que está en **/etc/natas_webpass/natas13** con el comando **cat**

![image](https://github.com/user-attachments/assets/1230a770-6135-467b-8802-b49600447de4)

### Level 13 -> Level 14
* **Contraseña natas14:** z3UYcr4v4uBpeX8f7EZbMHlzK4UR2XtQ
* **URL:** http://natas13.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas14 a través de un File Upload

Observamos un campo donde se nos permite subir una imagen con extension **JPEG** de máximo **1KB** de tamaño

![image](https://github.com/user-attachments/assets/3cffc2a7-ed13-4201-a5db-9addd60f66d5)

Interceptamos la petición con BurpSuite y realizamos lo mismo que con natas12, cambiamos la extensión de **.jpg** a **.php** y dejamos continuar la petición.

![image](https://github.com/user-attachments/assets/85636f43-1ae3-42c6-b024-8672df2a50b8)

![image](https://github.com/user-attachments/assets/fa3830e7-c3d1-4bd1-b572-1b0c5465ae03)

Obtenemos el mensaje **"For security reasons, we now only accept image files!"**

![image](https://github.com/user-attachments/assets/2c3df4ad-0959-4787-ad3c-c5943e83272f)

Podemos añadir a el archivo cmd.php un **magic header** que corresponda a el del un archivo **GIF** para engañar al servidor y que crea que estamos subiendo un archivo de tipo imagen.

![image](https://github.com/user-attachments/assets/f36a5c27-8c86-489f-a058-358bc7c23e28)

Volvemos a intentar subir el archivo e interceptamos la petición con BurpSuite para cambiarle la extensión de subida de **.jpg** a **.php**, dejamos correr la petición.

![image](https://github.com/user-attachments/assets/2957d3c0-c1c0-4eb0-a403-338c47eb0252)

![image](https://github.com/user-attachments/assets/520afcc6-923f-44a9-9341-17fb2431e53c)

Accedemos a **/upload/h998ds74ey.php** y vemos que podemos ejecutar comandos.

![image](https://github.com/user-attachments/assets/e8b43927-4a1e-4b4e-bf47-dbb2f19aee15)

Visualizamos la contraseña de **natas14** que está en **/etc/natas_webpass/natas14** con el comando **cat**

![image](https://github.com/user-attachments/assets/d324c811-80fa-40ee-a75f-19634eb69d72)

### Level 14 -> Level 15
* **Contraseña natas15:** SdqIqBsFcz3yotlNYErZSZwblkm0lrvx
* **URL:** http://natas14.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas15 a través de un SQLInjection Error Based

Observamos un panel donde se nos permite introducir un usuario y una contraseña.

![image](https://github.com/user-attachments/assets/37ce9807-c985-462f-8460-5200388ae8f2)

Introducimos un usuario y contraseña de prueba por ejemplo **test:test**

![image](https://github.com/user-attachments/assets/ec7785cf-086b-4295-a2d5-46de54afaa44)

Obtenemos el mensaje donde se nos indica que tenemos el acceso denegado ya que las credenciales son inválidas.

![image](https://github.com/user-attachments/assets/ecdb0461-80ad-4e3e-ab74-21e0b2736b6b)

Revisamos el código PHP y de primeras ya vemos una variable llamada **$query**, a través de está se tramita una consulta **SQL** vulnerable a **SQLInjection** ya que concatena directamente la entrada del usuario **($_REQUEST["username"]** y **$_REQUEST["password"])** en la consulta SQL sin ninguna sanitización. 

![image](https://github.com/user-attachments/assets/268f8096-3a9b-45d5-ad26-27d76aba0dd2)

Podemos incluir una comilla en el login para comprobar si es vulnerable a inyección SQL basada en error, incluir una comilla rompera la consulta SQL

![image](https://github.com/user-attachments/assets/ab85952d-6736-4da2-94ad-b1c4a033b615)

Observamos un error de MySQL lo cual es que la web es vulnerable a SQLInjection Error Based.

![image](https://github.com/user-attachments/assets/57d88290-fc99-4eaf-9f4c-f58fe2c262fe)

Podemos realizar una inyección SQL básica como **OR 1=1 #** que lo que hara es que la consulta SQL se evalue siempre como verdadera, con la almohadilla **"#"** conseguiremos omitir el campo password, pudiendo asi bypassear el login

![image](https://github.com/user-attachments/assets/4f16af96-c94f-4433-9a71-cbcdce8b2f8b)

Obtenemos la contraseña de **natas15** con éxito.

![image](https://github.com/user-attachments/assets/432b649d-26f8-4c7d-9996-fdde7a4695ab)

### Level 15 -> Level 16
* **Contraseña natas16:** hPkjKYviLQctEW33QmuXL6eDVfMW4sGo
* **URL:** http://natas15.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas16 a través de un Blind SQLInjection Boolean Based

Observamos un panel donde se nos permite introducir un usuario para verificar su existencia

![image](https://github.com/user-attachments/assets/5c5c642c-d747-447d-b596-620deb0550da)

Introducimos el usuario **natas16**, ya que es el usuario objetivo, obtenemos la respuesta de que el usuario si existe.

![image](https://github.com/user-attachments/assets/91fd9cba-03bd-41e2-b600-377c0abb0a80)

![image](https://github.com/user-attachments/assets/ac6588b4-3ef9-43b2-8548-24461c6eb930)

Intorducimos un parámetro **"?debug=test"** en el **action** del formulario para poder debugear y observar cual es la query que se esta procesando por detrás.

![image](https://github.com/user-attachments/assets/81948cac-c978-48f3-94b9-8b354cfaf49b)

Introducimos de nuevo el usuario **natas16**, pero esta vez podemos ver cual es la query que se está realizando para validar si el usuario es correcto. **SELECT * from users where username="natas16"**, introduciendo una comilla seriamos capaces de romper la consulta y comprobar si es vulnerable a inyeccion SQL

![image](https://github.com/user-attachments/assets/78a0b2b7-65b6-4184-a743-3b398a011c8c)

![image](https://github.com/user-attachments/assets/57c4c5ba-6eae-4110-b24c-435cae36ff05)

Podemos ver que es una inyeccion SQL blind basada en condiciones booleanas ya que a través de si el usuario existe podemos concatenar diferentes consultas con el operador **AND** y obtener por ejemplo la longitud de la contraseña del usuario **natas16**, para agilizar el proceso creamos un script en Python que automatize el proceso.

![image](https://github.com/user-attachments/assets/7539ee3d-2732-4e4d-aed5-477053486668)

![image](https://github.com/user-attachments/assets/0b389b61-324e-471f-9a56-c0544b7f3277)

![image](https://github.com/user-attachments/assets/e43f1a96-2c01-4192-9ad6-d2809b23ec34)

Obtenemos que la longitud del usuario **natas16** es de **32 carácteres**, ahora nos queda adivinar cual es la contraseña del usuario, para ello creamos un script en Python que automatize el proceso. Utilizaremos la siguiente query: **natas16"and password like "W%"#**

![image](https://github.com/user-attachments/assets/9f3d2164-b1d1-465f-8db8-169b0be9c68e)

![image](https://github.com/user-attachments/assets/529d3d8f-17eb-41c8-be9d-99d59b71b233)

### Level 16 -> Level 17
* **Contraseña natas17:** EqjHJbo7LFNb8vwhHb9s75hokh5TF0OC
* **URL:** http://natas16.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas17 a través de un Blind Command Injection Boolean Based

Al igual que en el **nivel 10** podemos observar un campo que nos permite buscar palabras que contengan las letras que le indiquemos, pero ahora se realizan mas validaciones de seguridad.

![image](https://github.com/user-attachments/assets/436967a5-1efc-4dd7-9f9f-b1e6d75080cc)

![image](https://github.com/user-attachments/assets/7d10bbbf-f326-4deb-8043-784c5a7330a8)

Si revisamos el **codigo PHP** podemos ver que se aplica una validación con la función **preg_match()**, si se encuentra en el input los carácteres **/[;|&`\'"]/** se nos muestra por pantalla el mensaje **"Input contains an illegal character!"**

![image](https://github.com/user-attachments/assets/d4c07cc1-5e9f-4456-b95a-ae2dcb570ebf)

No se está filtrando adecuadamente los carácteres que no se pueden utilizar, por ello podemo aprovecharnos de **$(command)** para realizar un **Blind Command Injection Boolean Based**, nos aprovecharemos de una palabra, la cual si la letra que grepeamos no existe en el archivo **/etc/natas_webpass/natas17** se mostrará, de lo contrario no se mostrará nada en la parte del cliente, pero si en la parte del servidor.

**Payload:** doomed$(grep ' + char + ' /etc/natas_webpass/natas17)
**Ejemplo:** doomed$(grep a /etc/natas_webpass/natas17)

![image](https://github.com/user-attachments/assets/82de10f6-b372-45c7-b3ff-8ad927e70470)

Para aligerar el proceso crearemos un script en Python para obtener los carácteres y una vez obtenidos ordenar la password con **grep** y la expresion regular **^** para indicar si la password comienza por dicho carácter.

![image](https://github.com/user-attachments/assets/1241abf7-440e-40e4-bb12-46896e69df5d)

![image](https://github.com/user-attachments/assets/8954fece-b893-44d5-b9c2-827378655be5)

### Level 17 -> Level 18
* **Contraseña natas18:** 6OG1PbKdVjyBlpxgD4DDbRG6ZLlCGgCJ
* **URL:** http://natas17.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas16 a través de un Blind SQLInjection Time Based

Observamos un panel donde se nos permite introducir un usuario para verificar su existencia

![image](https://github.com/user-attachments/assets/21c47b4a-8936-46ba-832c-d3b35fc2eb5b)

Introducimos el usuario **natas18**, ya que es el usuario objetivo, no obtenemos ninguna respuesta visible en la parte del cliente.

![image](https://github.com/user-attachments/assets/459ed269-afe6-4dd2-b18a-b9fa59d289d4)

![image](https://github.com/user-attachments/assets/906ac8d9-7439-4019-a709-c33bbf5a445d)

Intorducimos un parámetro **"?debug=test"** en el **action** del formulario para poder debugear y observar cual es la query que se esta procesando por detrás.

![image](https://github.com/user-attachments/assets/edb648a8-e2cc-4701-89b3-ae908348f1ae)

Introducimos de nuevo el usuario **natas18**, pero esta vez podemos ver cual es la query que se está realizando para validar si el usuario es correcto. **SELECT * from users where username="natas16"**, introduciendo una comilla seriamos capaces de romper la consulta y comprobar si es vulnerable a inyeccion SQL

![image](https://github.com/user-attachments/assets/db96f3d5-8f72-4d00-9c60-8212db002395)

Introducimos de nuevo el usuario **natas18** pero con una comilla al final para romper la query, pero no obtenemos ninguna respuesta de error.

![image](https://github.com/user-attachments/assets/c16a27e1-b5b0-4803-a1f4-eaff1a09f6a0)

![image](https://github.com/user-attachments/assets/04a4f3dc-c3d4-462e-b303-3d1f900fa15e)

Revisamos el codigo PHP, podemos observar que es vulnerable a SQLInjection, pero deberemos de jugar con el tiempo, es decir, Blind SQLInjection Time Based ya que al no obtener ningun tipo de respuesta por que los **echo** se encuentran comentados, jugando con el tiempo seriamos capaces de determinar si la query es correcta.

![image](https://github.com/user-attachments/assets/c5288b4b-5393-438c-8259-d28144e627b4)

Para jugar con el tiempo usaremos la función sleep(), empezaremos detectando la longitud de la contraseña del usuario **natas18**, el payload que usaremos es **natas18"and length(password) = {length} and sleep(seconds)#**. Para automatizar el proceso creamos un script en Python.

![image](https://github.com/user-attachments/assets/bfcd7085-88bb-4f51-a756-1ea34c983ee5)

![image](https://github.com/user-attachments/assets/df64c1df-e27f-48dd-8838-a52744ee047b)

Una vez hemos obtenido la longitud de la contraseña del usuario **natas18**, nos interesa obtener la contraseña del mismo, para ello usaremos el payload **natas18"and password like binary '{char}%' and sleep(seconds)#**. Para automatizar el proceso creamos un script en Python.

![image](https://github.com/user-attachments/assets/8cb5366f-0612-48e2-958e-536a8118faef)

![image](https://github.com/user-attachments/assets/09432e97-cab9-4254-b9f9-dfc833bdb3cf)

### Level 18 -> Level 19
* **Contraseña natas19:** tnwER7PdfWkxsG4FNWUtoAZ9VyZTJqJr
* **URL:** http://natas18.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas19 a través de un Brute-Force Session Hijacking

Observamos un panel donde se nos indica que debemos de iniciar sesion con la cuenta de administrador para obtener las credenciales del usuario **natas19**

![image](https://github.com/user-attachments/assets/7d1e2c6b-6dcc-4b42-b124-f33ca759e862)

Introducimos **admin:admin**, obtenemos como respuesta que hemos iniciado sesion como un usuario normal que debemos de iniciar sesion como el usuario **admin** para obtener las credenciales de **natas19**

![image](https://github.com/user-attachments/assets/cfa71d8d-787a-402b-b40e-b6a0e188f03a)

![image](https://github.com/user-attachments/assets/6993f1ca-eee3-44da-85e0-bed70d013d46)


Revisamos el codigo PHP, podemos observar una variable llamada **$maxid** con un valor de **640**, al lado tiene un comentario que dice: **Deberian de bastar para todos**

![image](https://github.com/user-attachments/assets/70a51f5b-1b0e-49c4-95f1-45ab7305c765)

Por otro lado tenemos una función llamada **isValidID()**, esta verifica que el **id** sea vaĺido es decir que se encuentra en el rango de **1-640**

![image](https://github.com/user-attachments/assets/ae391099-b42d-4025-8352-89d1946baa51)

La siguiente función se llama **CreateID()**, esta se encarga de asignar un **id** aleatorio al usuario que se encuentre entre **1 y $maxid**

![image](https://github.com/user-attachments/assets/069f328a-3dcd-407c-8899-b9eabf793069)

Interceptamos la petición con **BurpSuite** siendo ya el usuario normal **admin:admin**, podemos ver que se tramtia una cookie de sesión con un valor **PHPSESSID=552**

![image](https://github.com/user-attachments/assets/c81a3eb2-8621-4e0d-9420-c115712f0ebb)

Relizaremos un ataque de fuerza bruta en el **Intruder** contra el id de la cookie, con un payload de números desde el **1 hasta el 640**

![image](https://github.com/user-attachments/assets/9cb5588c-cd19-42f4-b18b-f374d66e87fc)

![image](https://github.com/user-attachments/assets/05e62559-831f-4ce3-a0de-d772c57f7b2c)

Filtramos por la longitud de la respuesta y observamos que con **PHPSESSID=119** obtenemos la contraseña del usuario **natas19**

![image](https://github.com/user-attachments/assets/7fd5e30a-2f44-45f7-a95e-cf9a70567c94)

### Level 19 -> Level 20
* **Contraseña natas20:** p5mCvP7GS2K6Bmt3gqhM2Fc1A5T8MVyw
* **URL:** http://natas19.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas20 a través de un Brute-Force Session Hijacking

Observamos un panel donde se nos indica que debemos de iniciar sesion con la cuenta de administrador para obtener las credenciales del usuario **natas20**, Por otra lado un mensaje que dice que la página utiliza prácticamente el mismo código que el nivel anterior, pero los identificadores de sesión ya no son secuenciales.

![image](https://github.com/user-attachments/assets/a09ca10a-bf04-4e57-84b3-959a0bd60ae7)

Introducimos **admin:admin**, obtenemos como respuesta que hemos iniciado sesion como un usuario normal que debemos de iniciar sesion como el usuario **admin** para obtener las credenciales de **natas19**

![image](https://github.com/user-attachments/assets/f821a506-fe79-4dcb-8a36-559fdd73c6cd)

![image](https://github.com/user-attachments/assets/c44caa1e-12c1-43d8-88ea-a3c8caf0e610)

Interceptamos la petición con **BurpSuite** siendo ya el usuario normal **admin:admin**, podemos ver que se tramtia una cookie de sesión con un valor **PHPSESSID=3539372d61646d696e**

![image](https://github.com/user-attachments/assets/7b5a62ed-065d-46bc-8e5d-94efec59ff76)

Utilizamos el **Decoder** para descifrar la cookie de sesion. Podemos ver que el valor de la cookie es **597-admin**

![image](https://github.com/user-attachments/assets/3d917ab5-ba6e-478a-a6ba-1e4c3efdec47)

Realizarmos un ataque de fuerza bruta en el **Intruder** contra el id de la cookie, con un payload de números desde el **1 hasta el 640** que tiene que quedar algo así **1-640-admin**

![image](https://github.com/user-attachments/assets/5ac6e15f-f854-4da6-8c0f-a94f1b51fb2e)

![image](https://github.com/user-attachments/assets/d49b8e9e-afd9-4673-ab95-afbd951e8520)

![image](https://github.com/user-attachments/assets/b059ed67-db03-45ba-ae27-daa55c9e0d6b)

Filtramos por la longitud de la respuesta y observamos que con **PHPSESSID=3238312d61646d696e** obtenemos la contraseña del usuario **natas20**

![image](https://github.com/user-attachments/assets/5ce38356-bb72-47fa-b251-759b1e090aa9)

### Level 20 -> Level 21
* **Contraseña natas21:** BPhv63cKE1lkQl04cE5CuFTzXe15NfiH
* **URL:** http://natas20.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas21 a través de la manipulación de sesiones

Observamos un panel donde ya nos encontramos logueados como un usuario normal y debemos de ser administrador para obtener las contraseña de natas21, tambien hay un campo donde podemos introducir nuestro nombre para cambiarlo.

![image](https://github.com/user-attachments/assets/ed0e5290-de7a-43c4-898d-229a2d6db6ef)

Introducimos el nombre admin en el campo input, al darle clic a simple vista no sucede nada

![image](https://github.com/user-attachments/assets/ee657d41-ac5a-4e95-a773-0fb8064cad56)

Intorducimos un parámetro **"?debug=test"** en el **action** del formulario para poder debugear y observar que es lo que está sucediendo por detrás.

![image](https://github.com/user-attachments/assets/e6132865-c658-4abd-b4a6-d950e2a18870)

Introducimos nuevamente el nombre admin en el campo input, al darle podemos observar

![image](https://github.com/user-attachments/assets/750355fd-f698-4bc1-a7ce-9779b1e5cae3)

![image](https://github.com/user-attachments/assets/255fd623-aff2-44f8-b8eb-c628114f2404)

El objetivo es loguearse como **admin** para obtener las credenciales de **natas21**. Revisamos el código PHP de la página y eso sucede en la función **print_credentials()**, observamos que para ver la contraseña de **natas21** necesitamos tener la variable **$_SESSION** con un par **clave-valor** que sea **admin:1**

![image](https://github.com/user-attachments/assets/a07819c9-df6f-4a80-9341-de771d6d7e37)

Observamos que la función **myread()** se encarga de leer los archivos de sesión y convertirlos de vuelta en el array $_SESSION.

![image](https://github.com/user-attachments/assets/9a39df5a-4f21-4bce-9cda-fe9ed0254b7a)

En la función **mywrite()**, se guarda la sesión en el archivo tomando el array **$_SESSION**, lo convierte en una serie de pares **clave-valor** y lo guarda en el archivo de sesión, esto es explotable, ya que no está sucediendo ningún filtrado en nuestra entrada de nombre.

![image](https://github.com/user-attachments/assets/79d9aafc-cdf4-410b-94f2-669e43b968b5)

Interceptamos la petición con **BurpSuite** y la enviamos al **Repeater**

![image](https://github.com/user-attachments/assets/e500f1bc-6948-442a-b2d3-e9e2e8f36264)

Tenemos que cambiar **name=test** para que sea **test\nadmin 1** para que no de ningun error URL encodearlo, por ultimo enviamos la petición.

![image](https://github.com/user-attachments/assets/d88c4391-2ccc-4a7c-86f1-eda2bc880773)

Obtenemos en la respuesta la contraseña de **natas21**

![image](https://github.com/user-attachments/assets/88eea806-9e10-4d1a-8a62-9d423f0241c0)

### Level 21 -> Level 22
* **Contraseña natas22:** d8rwGBl0Xslg3b76uh3fEbSlnOUBlozz
* **URL:** http://natas21.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas22 a través de la manipulación de sesiones

Observamos una página la cual nos indica que estamos logueados como un usuario normal, que debemos de ser **admin** para ver la contraseña de **natas22**, por otro lado se nos indica que la página está vinculada con **"http://natas21-experimenter.natas.labs.overthewire.org"**

![image](https://github.com/user-attachments/assets/7caa1452-000d-43b0-81b6-450b5a603a5e)

Antes de acceder a **"http://natas21-experimenter.natas.labs.overthewire.org"** revisamos el código fuente de la página principal, podemos observar que simplemente se encarga de validar que la variable $_SESSION sea **admin** con valor **1** y si es así nos muestra las credenciales de **natas22**

![image](https://github.com/user-attachments/assets/0afd3b06-9d1a-4381-a87a-b8c63ff09089)

Accedemoos a **"http://natas21-experimenter.natas.labs.overthewire.org"** podemos observar diferentes campos que nos permiten modificar propiedades css y se ven reflejadas en pantalla.

![image](https://github.com/user-attachments/assets/5f737200-574e-4e9c-b0dd-5ee05225cf68)

Revisamos el codigo PHP, podemos observar que el código itera sobre todos los elementos de **$_REQUEST**, que es un array que contiene todos los parámetros recibidos en la solicitud y sin ninguna validación ni sanitización, asigna los valores recibidos directamente en la variable global **$_SESSION**

![image](https://github.com/user-attachments/assets/6826246a-8a21-4b3c-8f81-dab2f6c0bc9a)

Esto nos va a permitir inyectar claves arbitrarias en **$_SESSION**, en este caso **admin=1**, interceptamos la petición con **BurpSuite** y la enviamos al **Repeater**

![image](https://github.com/user-attachments/assets/f689a700-b160-4b81-b363-1d30a9962ea7)

Añadimos **?debug** para observar que sucede al inyectar el nuevo valor.

![image](https://github.com/user-attachments/assets/36000ed8-df26-4faa-9f78-269a4a91e0c5)

Inyectamos el valor con el operador and, es decir, **&admin=1**, por ultimo enviamos la petición.

![image](https://github.com/user-attachments/assets/2ea0b57e-2880-4e43-a1d8-d9bf58c806e8)

En la respuesta observamos que hemos inyectado el valor admin=1 satisfactoriamente

![image](https://github.com/user-attachments/assets/59daf6b8-0716-463e-a773-ada160806fa0)

Ahora tenemos que utilizar la misma cookie de sesión de la página **"http://natas21-experimenter.natas.labs.overthewire.org"** para tramitar una petición a **"http://natas21.natas.labs.overthewire.org/"** ya que se encuentran vinculadas.

![image](https://github.com/user-attachments/assets/e8c8435d-038c-4f45-b4f2-56f359191686)

Tramitamos la petición y obtenemos la contraseña de **natas22**

![image](https://github.com/user-attachments/assets/db631c6e-792f-41ba-90fa-b76bb68d69b3)

### Level 22 -> Level 23
* **Contraseña natas23:** dIUQcI3uSus1JEOSSWRAEXBG8KbR8tRs
* **URL:** http://natas22.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas23 a través de un parámetro GET

No observamos aparentemente nada en la parte web

![image](https://github.com/user-attachments/assets/c705a009-f654-4202-a10c-88d54dd54992)

Revisamos el código de la página, podemos ver que si se tramita el parámetro **?revelio** por GET obtenemos la contraseña de **natas23**

![image](https://github.com/user-attachments/assets/7fd07fcb-e51a-45ff-a4b6-54d7fa91d2c3)

Interceptamos la petición con **BurpSuite** y la enviamos al **Repeater** añadimos el parámetro y tramitamos la solicitud

![image](https://github.com/user-attachments/assets/65334ef2-5433-4b0f-a18b-2082df4d10a7)

Obtenemos con exito la contraseña de **natas23**

![image](https://github.com/user-attachments/assets/35571e37-f1c0-41db-bef4-c9e3e7518f72)

### Level 23 -> Level 24
* **Contraseña natas24:** MeuqmfJ8DDKuTr5pcvzFKSwlxedZYEWd
* **URL:** http://natas23.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas24 a través de una mala validación del input

Observamos un campo donde se nos permite introducir una contraseña.

![image](https://github.com/user-attachments/assets/ffc1a414-78e2-45a6-b5bf-f3324fb4a373)

Introducimos una contraseña por ejemplo **test**, observamos que por pantalla obtenemos el mensaje **Wrong!**

![image](https://github.com/user-attachments/assets/edc38380-da14-4c44-8ffe-651236f89257)

Revisamos el código PHP, podemos observamos que se verifica si el parámetro **passwd** existe, si es así verifica que passwd contiene el valor **iloveyou**, por ultimo compara el valor de **passwd** con el número **10**, si es mayor que 10 será true y se mostrará la contraseña.

![image](https://github.com/user-attachments/assets/15ea5024-e637-4230-a43d-e95eb28d78e3)

Una vez comprendido inyectamos en el input **11iloveyou** y obtenemos la contraseña de **natas24**

![image](https://github.com/user-attachments/assets/156019f5-3f3e-408b-8ae7-8ba12fe68726)

### Level 24 -> Level 25
* **Contraseña natas25:** ckELKUWZUfpOv6uxS6M7lXBpBssJZ4Ws
* **URL:** http://natas24.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas25 a través de la mala validación del input

Observamos un campo donde se nos permite introducir una contraseña, introducimos una contraseña por ejemplo **test**, observamos que por pantalla obtenemos el mensaje **Wrong!**

![image](https://github.com/user-attachments/assets/ae4e978b-36ee-46f6-bc2a-5a18f48b8210)

Revisamos el código PHP, podemos ver que la contraseña que introducimos se valida con la función **strcmp()**, es un función delicada y vulnerable, ya que si conseguimos inyectar un valor nulo evitaremos la validación de la contraseña.

![image](https://github.com/user-attachments/assets/d6f963f7-5ea1-4643-be3f-4059ade329ea)

Si usamos **passwd[]** en la URL, convierte el array a NULL para la comparación con strcmp(), esto genera un comportamiento inesperado y permitir eludir la verificación de la contraseña.

![image](https://github.com/user-attachments/assets/4234b1be-c07b-4f26-bf02-6b673726dc32)

Obtenemos la contraseña de **natas25**, al inyectar **passwd[]=test**

![image](https://github.com/user-attachments/assets/bd855be9-3459-40db-93a0-ab857fb38fe1)

### Level 25 -> Level 26
* **Contraseña natas26:** cVXXwxMS3Y26n5UZU89QgpGmWCelaQlE
* **URL:** http://natas25.natas.labs.overthewire.org
* **Misión:** Obtener la contraseña de natas26 a través de un LFI

Observamos un texto con un desplegable que nos permite cambiar el idioma del mismo.

![image](https://github.com/user-attachments/assets/627f167a-dbe6-4fc9-9a06-35e3a7cf9dbf)

Revisamos el codigo PHP y observamos que nos encontramos ante la vulnerabilidad **Path Traversal** que nos permite incluir archivos locales del sistema interno, pero se realizan algunas validaciones como que no podemos realizar **../** y que si accedemos a **natas_webpass** no imprimira un texto de error

![image](https://github.com/user-attachments/assets/5cd3175a-8944-40e6-aa84-3bb4860e4daf)

Para comprobar que es vulnerable comenzamos mostrande el archivo **/etc/passwd** pero tenemos que añadir doble puntos y doble barras ya que se reemplaza al añadir solo **../** tiene que se **....//**

![image](https://github.com/user-attachments/assets/379727ab-4eb4-4d63-ad75-959f03b19f2b)

![image](https://github.com/user-attachments/assets/fb858731-0d2d-4ead-a34e-01f04a16deb5)

Conseguimos listar correctamente el archivo **/etc/passwd** ahora nos queda bypassear que no podemos acceder a **/etc/natas_webpass/natas26**, si revisamos de nuevo el codigo PHP, observamos que las peticiones que realizamos se estan almacenando en **/var/www/natas/natas25/logs/natas25_** el **session_id()** y **.log**, es decir, en **/var/www/natas/natas25/logs/natas25_d6l9qdfb6gp73cd0q8d2i27vmp.log**

![image](https://github.com/user-attachments/assets/0825c3b0-f979-413b-ba7f-69a992015473)

![image](https://github.com/user-attachments/assets/13863e09-fa2f-4486-a8f3-cac506743b0a)

![image](https://github.com/user-attachments/assets/8bcb8e92-973a-43d2-abba-da854b51c291)

Podemos interceptar la petición con **BurpSuite*** y enviar una cabecera con codigo PHP malicioso que nos permite ejecutar comandos, así convertimos el **LFI en RCE**

![image](https://github.com/user-attachments/assets/92ea1302-0e59-4507-8fd5-a3ca42dd2909)

Ahora podemos ejecutar comandos a través del parámetro **cmd**, por ejemplo el comando **id**

![image](https://github.com/user-attachments/assets/71f75087-3355-4877-adbf-ff6a0dc41888)

![image](https://github.com/user-attachments/assets/198402fd-33d3-48b7-a891-b1aa94cf00e6)

Visualizamos la contraseña de **natas26** en /etc/natas_webpass/natas26 usando el comando **cat**

![image](https://github.com/user-attachments/assets/e89a9b9e-e85d-41c2-a79e-9b3347415efd)

![image](https://github.com/user-attachments/assets/9ee6eaa9-9989-4ea3-9cad-ac8920d4d42b)
