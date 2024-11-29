---
title: Resolución CTF OverTheWire:Natas, Level 0-34 Write-Up
description: En este apartado se resuleven los 34 niveles del CTF de OverTheWire Natas.
date: 2024-11-21
categories: [CTFs]
tags: [CTFs, Linux]
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
* **Misión:** Obtener la contraseá de natas10 a través de una inyección de comandos

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
* **Misión:** Obtener la contraseña de natas15 a través de un SQLInjection

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

Podemos realizar una inyección SQL básica como **OR 1=1 #** que lo que hara es que la consulta SQL se evalue siempre como verdadera, con la almohadilla **"#"** conseguiriamos omitir el campo password, pudiendo asi bypassear el login

![image](https://github.com/user-attachments/assets/4f16af96-c94f-4433-9a71-cbcdce8b2f8b)

Obtenemos la contraseña de **natas15** con éxito.

![image](https://github.com/user-attachments/assets/432b649d-26f8-4c7d-9996-fdde7a4695ab)

### Level 15 -> Level 16
* **Contraseña natas16:** 
* **URL:** http://natas15.natas.labs.overthewire.org
* **Misión:**
