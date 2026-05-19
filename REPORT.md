# Reporte Copy Fail Challenge

## Pregunta 1: Análisis del Vector de Ataque y la Vulnerabilidad

### ¿Cuál es la raíz técnica del fallo descubierto en el subsistema criptográfico del kernel (`crypto/algif_aead.c`)?

La raíz del problema está en una optimización de rendimiento tipo *in-place* (en el mismo lugar) que se introdujo en el kernel en 2017. Para ahorrar memoria y tiempo de CPU, el código asumía que los buffers de origen (los datos que entran a cifrar/descifrar) y los de destino (el resultado) podían compartir exactamente el mismo espacio físico en la memoria RAM si se daban ciertas condiciones. 

El fallo humano o imprevisto ocurre porque, al tratar ambos buffers como una sola entidad solapada, el kernel pierde el control estricto de las referencias de memoria. Si un atacante altera maliciosamente el flujo conceptual, puede hacer que el subsistema criptográfico use punteros idénticos para funciones de lectura y escritura concurrentes, provocando que se sobrescriban o reutilicen datos en estructuras que el kernel creía aisladas.

### ¿Cómo interactúa la llamada de sistema `splice()` de UNIX con el Page Cache para permitir este bypass?

El *Page Cache* es el mecanismo que usa Linux para acelerar el sistema: cuando abres un archivo, el kernel guarda una copia de sus bloques en la memoria RAM (la caché de páginas) para no tener que leer el disco duro físico cada vez. 

La llamada de sistema `splice()` es una herramienta de UNIX diseñada para mover datos entre descriptores de archivos (como un socket y un archivo) de forma ultra rápida "cero-copia", es decir, moviendo solo los punteros en la RAM sin duplicar los datos reales. 

El exploit aprovecha esto de forma brillante: abre un socket criptográfico (`AF_ALG`) y usa `splice()` para redirigir datos manipulados directamente hacia las páginas del *Page Cache* de un binario del sistema. Debido al fallo *in-place*, el kernel se confunde y permite que los bytes inyectados modifiquen la copia en la memoria RAM del archivo de solo lectura. Lo crucial aquí es que **el disco duro nunca se entera ni se modifica**, por lo que las herramientas de integridad tradicionales no detectan nada, pero el programa que corre en memoria ya está corrompido.

---

## Pregunta 2: Impacto en la Seguridad de UNIX

### ¿Por qué se seleccionó el binario `/usr/bin/su` como objetivo para demostrar la escalada de privilegios?

En los sistemas UNIX, el bit **SetUID** (Set User ID) es un permiso especial que permite que un archivo ejecutable se corra con los privilegios del *dueño* del archivo, en lugar de los privilegios del usuario que lo invoca. El binario `/usr/bin/su` tiene este bit activo porque necesita, por diseño, privilegios de `root` para verificar contraseñas y cambiar de identidad en el sistema.

Seleccionar `/usr/bin/su` como objetivo es el escenario perfecto para demostrar el peligro real de la vulnerabilidad. Al usar el exploit para alterar temporalmente el *Page Cache* de `/usr/bin/su` en la memoria RAM (inyectando ceros en su lógica de verificación), obligamos al binario a saltarse la validación de la contraseña. Como el programa tiene el bit SetUID, la vulnerabilidad rompe la barrera más sagrada de UNIX: un usuario común (`student`) termina ejecutando un proceso corrupto que le hereda inmediatamente una Shell con control total (`root`), destruyendo por completo la confidencialidad y la integridad del sistema operativo.

---

## Pregunta 3: Mecanismo de Remediación Permanente

### ¿Qué corrección estructural introduce el parche (`fix_algif_aead.patch`) en la función `_aead_recvmsg`?

La solución definitiva no fue simplemente poner un parche estético, sino reestructurar cómo el kernel maneja la memoria en la función vulnerable. Lo que hicimos en nuestro parche fue eliminar por completo la peligrosa optimización *in-place* dentro de `_aead_recvmsg`.

El parche introduce un aislamiento de buffers forzado (*out-of-place*). Modificamos la macro encargada de configurar la operación criptográfica:

```diff
-	aead_request_set_crypt(req, rsgl_src, rsgl_src, crlen, iv);
+	aead_request_set_crypt(req, tsgl_src, rsgl_dst, crlen, iv);
