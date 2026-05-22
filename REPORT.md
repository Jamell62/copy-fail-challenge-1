# Reporte Técnico CVE-2026-31431

## 1. Bug raíz
El bug está en `crypto/algif_aead.c`, función `_aead_recvmsg()`. Cuando no hay RX SGL presente, la variable `rsgl_src` se asigna al TX SGL (`rsgl_src = areq->tsgl`), haciendo que src y dst apunten al mismo scatterlist.

## 2. Por qué es peligroso
Cuando páginas del page cache entran por `splice()`, quedan en el scatterlist de escritura. La función de descifrado escribe fuera de los límites del área de salida, aterrizando en esas páginas del page cache de `/usr/bin/su`.

## 3. Por qué es stealthy
El exploit no modifica el archivo en disco. Solo corrompe la copia en memoria (page cache) de `/usr/bin/su`. Al reiniciar, el archivo vuelve a su estado original sin rastro del ataque.

## 4. Conexión con clase
El page cache es la copia en memoria de archivos del disco. Los binarios setuid-root como `su` tienen el bit setuid activado, lo que hace que se ejecuten con privilegios de root independientemente de quién los llame. Al corromper `su` en el page cache, el kernel ejecuta código malicioso con uid=0.

## 5. Lección aprendida
Una optimización aparentemente razonable en 2017 (reutilizar el mismo scatterlist para src y dst) creó una vulnerabilidad grave 9 años después al combinarse con splice() y el page cache. Cambios pequeños en subsistemas críticos pueden tener consecuencias de seguridad no obvias.
