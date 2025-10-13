# ============================================
# SECCIÓN 1: CONEXIÓN Y AUTENTICACIÓN
# ============================================

# 1. Conectar a un servidor FTP
ftp 192.168.1.100

# Usuario y contraseña
Name: admin
Password: ********

# 2. Ver estado de la conexión
ftp> status
# Output: Connected to 192.168.1.100
#         Mode: stream; Type: ascii; Form: non-print

# 3. Ver información del sistema remoto
ftp> system
# Output: 215 UNIX Type: L8

# ============================================
# SECCIÓN 2: NAVEGACIÓN Y EXPLORACIÓN
# ============================================

# 4. Ver directorio actual remoto
ftp> pwd
# Output: 257 "/home/admin" is current directory

# 5. Listar archivos remotos
ftp> ls
# Output: documentos
#         imagenes
#         backups
#         archivo.txt

# 6. Listar con detalles completos
ftp> ls -la
# Output: drwxr-xr-x   3 admin  admin     4096 Oct 13 16:00 documentos
#         drwxr-xr-x   2 admin  admin     4096 Oct 13 15:30 imagenes
#         -rw-r--r--   1 admin  admin    12548 Oct 13 14:20 archivo.txt

# 7. Ver directorio local actual
ftp> lpwd
# Output: Local directory now /home/kali

# 8. Listar archivos en directorio local
ftp> !ls
# Output: Desktop  Documents  Downloads  Pictures

# 9. Cambiar directorio local
ftp> lcd /home/kali/Downloads
# Output: Local directory now /home/kali/Downloads

# 10. Cambiar a directorio remoto específico
ftp> cd documentos
# Output: 250 Directory successfully changed

# 11. Listar contenido del nuevo directorio
ftp> dir
# Output: -rw-r--r--   1 admin  admin     2048 Oct 13 10:00 informe.pdf
#         -rw-r--r--   1 admin  admin     5120 Oct 13 11:30 reporte.docx
#         -rw-r--r--   1 admin  admin     1024 Oct 13 12:00 notas.txt

# ============================================
# SECCIÓN 3: CONFIGURACIÓN DE TRANSFERENCIA
# ============================================

# 12. Activar modo binario (para archivos no texto)
ftp> binary
# Output: 200 Switching to Binary mode

# 13. Activar hash marks para ver progreso
ftp> hash
# Output: Hash mark printing on (1024 bytes/hash mark)

# 14. Activar modo verbose para detalles
ftp> verbose
# Output: Verbose mode on

# 15. Activar modo pasivo (importante para firewalls)
ftp> passive
# Output: Passive mode on

# ============================================
# SECCIÓN 4: DESCARGA DE ARCHIVOS
# ============================================

# 16. Ver tamaño de archivo antes de descargar
ftp> size informe.pdf
# Output: 213 2048

# 17. Ver fecha de modificación
ftp> modtime informe.pdf
# Output: 213 20251013100000

# 18. Descargar un archivo simple
ftp> get informe.pdf
# Output: local: informe.pdf remote: informe.pdf
#         200 PORT command successful
#         150 Opening BINARY mode data connection
#         ####
#         226 Transfer complete
#         2048 bytes received in 0.05 secs (40.96 KB/s)

# 19. Descargar archivo con nuevo nombre
ftp> get reporte.docx mi_reporte.docx
# Output: local: mi_reporte.docx remote: reporte.docx
#         ########
#         226 Transfer complete
#         5120 bytes received in 0.08 secs (64.00 KB/s)

# 20. Desactivar confirmaciones para descargas múltiples
ftp> prompt off
# Output: Interactive mode off

# 21. Descargar múltiples archivos con comodín
ftp> mget *.txt
# Output: local: notas.txt remote: notas.txt
#         ##
#         226 Transfer complete
#         1024 bytes received in 0.02 secs (51.20 KB/s)

# 22. Volver al directorio raíz remoto
ftp> cd /
# Output: 250 Directory successfully changed

# 23. Entrar a directorio de imágenes
ftp> cd imagenes
# Output: 250 Directory successfully changed

# 24. Listar imágenes disponibles
ftp> ls *.jpg
# Output: foto1.jpg
#         foto2.jpg
#         logo.jpg
#         banner.jpg

# 25. Cambiar a modo ASCII para archivos de texto
ftp> ascii
# Output: 200 Switching to ASCII mode

# 26. Volver a modo binario para imágenes
ftp> binary
# Output: 200 Switching to Binary mode

# 27. Descargar todas las imágenes JPG
ftp> mget *.jpg
# Output: local: foto1.jpg remote: foto1.jpg
#         ##########
#         226 Transfer complete
#         (descarga foto2.jpg, logo.jpg, banner.jpg...)

# ============================================
# SECCIÓN 5: VERIFICACIÓN LOCAL
# ============================================

# 28. Verificar archivos descargados localmente
ftp> !ls -lh
# Output: -rw-r--r-- 1 kali kali 2.0K Oct 13 16:15 informe.pdf
#         -rw-r--r-- 1 kali kali 5.0K Oct 13 16:15 mi_reporte.docx
#         -rw-r--r-- 1 kali kali 1.0K Oct 13 16:16 notas.txt
#         -rw-r--r-- 1 kali kali 45K  Oct 13 16:17 foto1.jpg

# 29. Ejecutar comando local para verificar espacio
ftp> !df -h /home/kali/Downloads
# Output: Filesystem      Size  Used Avail Use% Mounted on
#         /dev/sda1       100G   45G   50G  48% /

# 30. Abrir shell local temporal para organizar archivos
ftp> !bash
# (En la shell local)
kali@kali:~/Downloads$ mkdir imagenes_descargadas
kali@kali:~/Downloads$ mv *.jpg imagenes_descargadas/
kali@kali:~/Downloads$ exit
# (De vuelta en FTP)

# ============================================
# SECCIÓN 6: SUBIDA DE ARCHIVOS
# ============================================

# 31. Cambiar al directorio local con archivos a subir
ftp> lcd /home/kali/Documents
# Output: Local directory now /home/kali/Documents

# 32. Ver archivos locales disponibles para subir
ftp> !ls *.pdf
# Output: presentacion.pdf
#         manual.pdf
#         guia.pdf

# 33. Navegar a directorio remoto para uploads
ftp> cd /backups
# Output: 250 Directory successfully changed

# 34. Crear nuevo directorio remoto para organizar
ftp> mkdir octubre_2025
# Output: 257 "octubre_2025" directory created

# 35. Entrar al nuevo directorio
ftp> cd octubre_2025
# Output: 250 Directory successfully changed

# 36. Verificar directorio actual
ftp> pwd
# Output: 257 "/backups/octubre_2025" is current directory

# 37. Subir un archivo individual
ftp> put presentacion.pdf
# Output: local: presentacion.pdf remote: presentacion.pdf
#         200 PORT command successful
#         150 Ok to send data
#         ##########
#         226 Transfer complete
#         10240 bytes sent in 0.12 secs (85.33 KB/s)

# 38. Subir archivo con nombre diferente
ftp> put manual.pdf manual_backup.pdf
# Output: local: manual.pdf remote: manual_backup.pdf
#         ############
#         226 Transfer complete
#         15360 bytes sent in 0.15 secs (102.40 KB/s)

# 39. Reactivar prompts para confirmar subidas
ftp> prompt on
# Output: Interactive mode on

# 40. Subir múltiples archivos con confirmación
ftp> mput *.pdf
# Output: mput guia.pdf? y
#         local: guia.pdf remote: guia.pdf
#         ########
#         226 Transfer complete

# 41. Desactivar prompts de nuevo
ftp> prompt off
# Output: Interactive mode off

# 42. Cambiar directorio local a carpeta con imágenes
ftp> lcd /home/kali/Pictures
# Output: Local directory now /home/kali/Pictures

# 43. Crear directorio remoto para imágenes
ftp> cd /
ftp> mkdir uploads_imagenes
# Output: 257 "uploads_imagenes" directory created

# 44. Entrar al directorio creado
ftp> cd uploads_imagenes
# Output: 250 Directory successfully changed

# 45. Subir todas las imágenes PNG
ftp> mput *.png
# Output: local: captura1.png remote: captura1.png
#         ###########
#         226 Transfer complete
#         (sube captura2.png, captura3.png...)

# ============================================
# SECCIÓN 7: GESTIÓN DE ARCHIVOS REMOTOS
# ============================================

# 46. Listar archivos subidos
ftp> ls -l
# Output: -rw-r--r-- 1 admin admin 25600 Oct 13 16:30 captura1.png
#         -rw-r--r-- 1 admin admin 30720 Oct 13 16:31 captura2.png
#         -rw-r--r-- 1 admin admin 28160 Oct 13 16:31 captura3.png

# 47. Renombrar archivo remoto
ftp> rename captura1.png screenshot_principal.png
# Output: 350 Ready for RNTO
#         250 Rename successful

# 48. Verificar el cambio
ftp> ls screenshot*
# Output: -rw-r--r-- 1 admin admin 25600 Oct 13 16:30 screenshot_principal.png

# 49. Eliminar un archivo remoto específico
ftp> delete captura2.png
# Output: 250 Delete operation successful

# 50. Verificar eliminación
ftp> ls
# Output: screenshot_principal.png
#         captura3.png

# ============================================
# SECCIÓN 8: OPERACIONES AVANZADAS
# ============================================

# 51. Navegar a directorio temporal
ftp> cd /tmp
# Output: 250 Directory successfully changed

# 52. Crear archivo de prueba localmente
ftp> !echo "Archivo de prueba" > test.txt

# 53. Subir archivo de prueba
ftp> put test.txt
# Output: #
#         226 Transfer complete
#         18 bytes sent in 0.01 secs (1.80 KB/s)

# 54. Descargar el mismo archivo con otro nombre
ftp> get test.txt test_descargado.txt
# Output: #
#         226 Transfer complete
#         18 bytes received in 0.01 secs (1.80 KB/s)

# 55. Comparar archivos local y remoto
ftp> !diff test.txt test_descargado.txt
# Output: (sin output = archivos idénticos)

# 56. Activar debug para ver comandos enviados
ftp> debug
# Output: Debugging on (debug=1)

# 57. Ejecutar comando con debug activo
ftp> pwd
# Output: ---> PWD
#         257 "/tmp" is current directory

# 58. Desactivar debug
ftp> debug
# Output: Debugging off (debug=0)

# ============================================
# SECCIÓN 9: LIMPIEZA Y MANTENIMIENTO
# ============================================

# 59. Navegar a directorio de backups
ftp> cd /backups/octubre_2025
# Output: 250 Directory successfully changed

# 60. Listar archivos para limpieza
ftp> ls
# Output: presentacion.pdf
#         manual_backup.pdf
#         guia.pdf

# 61. Eliminar múltiples archivos antiguos
ftp> mdelete manual*
# Output: mdelete manual_backup.pdf? y
#         250 Delete operation successful

# 62. Verificar eliminación
ftp> ls
# Output: presentacion.pdf
#         guia.pdf

# 63. Subir un nivel en directorios
ftp> cd ..
# Output: 250 Directory successfully changed

# 64. Verificar ubicación actual
ftp> pwd
# Output: 257 "/backups" is current directory

# 65. Intentar eliminar directorio vacío
ftp> rmdir octubre_2025
# Output: 550 Directory not empty

# 66. Entrar de nuevo al directorio
ftp> cd octubre_2025
# Output: 250 Directory successfully changed

# 67. Eliminar archivos restantes
ftp> mdelete *
# Output: mdelete presentacion.pdf? y
#         250 Delete operation successful
#         mdelete guia.pdf? y
#         250 Delete operation successful

# 68. Salir del directorio
ftp> cd ..
# Output: 250 Directory successfully changed

# 69. Ahora eliminar directorio vacío
ftp> rmdir octubre_2025
# Output: 250 Remove directory operation successful

# ============================================
# SECCIÓN 10: TRANSFERENCIAS INTERRUMPIDAS
# ============================================

# 70. Cambiar al directorio local
ftp> lcd /home/kali/Downloads
# Output: Local directory now /home/kali/Downloads

# 71. Navegar a directorio con archivos grandes
ftp> cd /isos
# Output: 250 Directory successfully changed

# 72. Listar archivos grandes disponibles
ftp> ls -lh
# Output: -rw-r--r-- 1 admin admin 4.5G Oct 13 10:00 ubuntu.iso
#         -rw-r--r-- 1 admin admin 3.2G Oct 13 11:00 kali.iso

# 73. Verificar tamaño exacto
ftp> size ubuntu.iso
# Output: 213 4831838208

# 74. Activar hash para monitorear progreso
ftp> hash
# Output: Hash mark printing on

# 75. Intentar descargar archivo grande (simulando interrupción)
ftp> get ubuntu.iso
# Output: local: ubuntu.iso remote: ubuntu.iso
#         ############### (Ctrl+C para simular interrupción)
#         426 Connection closed; transfer aborted

# 76. Verificar descarga parcial
ftp> !ls -lh ubuntu.iso
# Output: -rw-r--r-- 1 kali kali 1.2G Oct 13 16:45 ubuntu.iso

# 77. Reanudar descarga interrumpida
ftp> reget ubuntu.iso
# Output: local: ubuntu.iso remote: ubuntu.iso
#         REST 1258291200
#         ########################
#         226 Transfer complete
#         3573547008 bytes received in 450.32 secs (7.94 MB/s)

# ============================================
# SECCIÓN 11: ACCESO ANÓNIMO (PENTESTING)
# ============================================

# 78. Cerrar conexión actual
ftp> close
# Output: 221 Goodbye

# 79. Conectar a servidor con acceso anónimo
ftp> open ftp.example.com
# Output: Connected to ftp.example.com
#         220 FTP Server ready

# 80. Autenticarse como anónimo
Name: anonymous
Password: (presionar Enter)
# Output: 230 Anonymous access granted

# 81. Explorar directorios disponibles
ftp> ls
# Output: drwxr-xr-x   2 ftp  ftp   4096 Oct 13 08:00 pub
#         drwxr-xr-x   3 ftp  ftp   4096 Oct 13 09:00 incoming

# 82. Navegar a directorio público
ftp> cd pub
# Output: 250 Directory successfully changed

# 83. Buscar archivos sensibles
ftp> ls -la
# Output: -rw-r--r-- 1 ftp ftp  1024 Oct 13 08:15 README.txt
#         -rw-r--r-- 1 ftp ftp  5120 Oct 13 08:20 passwords.bak

# 84. Descargar archivo sensible encontrado
ftp> get passwords.bak
# Output: ####
#         226 Transfer complete
#         5120 bytes received in 0.05 secs (102.40 KB/s)

# 85. Intentar subir archivo de prueba
ftp> cd /incoming
ftp> put test.txt
# Output: 550 Permission denied (o éxito si el servidor lo permite)

# ============================================
# SECCIÓN 12: INFORMACIÓN Y AYUDA
# ============================================

# 86. Ver todos los comandos disponibles
ftp> help
# Output: Commands may be abbreviated. Commands are:
#         !        debug    mdir     sendport  site
#         $        dir      mget     put       size
#         account  disconnect mkdir  pwd       status
#         append   exit     mls      quit      struct
#         ascii    form     mode     quote     system
#         (más comandos...)

# 87. Ayuda específica para comando 'get'
ftp> help get
# Output: get         receive file
#         Usage: get remote-file [local-file]

# 88. Ayuda para comando 'mget'
ftp> help mget
# Output: mget        get multiple files
#         Usage: mget remote-files

# 89. Ver estado completo de conexión
ftp> status
# Output: Connected to ftp.example.com
#         No proxy connection
#         Mode: stream; Type: binary; Form: non-print
#         Verbose: on; Bell: off; Prompting: off; Globbing: on
#         Hash mark printing: on; Use of PORT cmds: on
#         Passive mode: on

# ============================================
# SECCIÓN 13: COMANDOS LOCALES ÚTILES
# ============================================

# 90. Ver espacio en disco local
ftp> !df -h
# Output: Filesystem      Size  Used Avail Use% Mounted on
#         /dev/sda1       100G   48G   47G  51% /

# 91. Ver procesos locales relacionados con FTP
ftp> !ps aux | grep ftp
# Output: kali  12345  0.0  0.1  12345  6789 pts/0 S+ 16:50 0:00 ftp

# 92. Comprimir archivos descargados localmente
ftp> !tar -czf backups.tar.gz *.pdf
# Output: (crea archivo comprimido)

# 93. Verificar integridad con checksum local
ftp> !md5sum informe.pdf
# Output: a1b2c3d4e5f6g7h8i9j0 informe.pdf

# 94. Crear directorio local para organizar
ftp> !mkdir -p /home/kali/FTP_Downloads/$(date +%Y-%m-%d)

# 95. Cambiar al nuevo directorio
ftp> lcd /home/kali/FTP_Downloads/2025-10-13
# Output: Local directory now /home/kali/FTP_Downloads/2025-10-13

# ============================================
# SECCIÓN 14: OPERACIONES EN LOTE
# ============================================

# 96. Navegar a directorio con muchos archivos
ftp> cd /logs
# Output: 250 Directory successfully changed

# 97. Listar solo archivos .log
ftp> ls *.log
# Output: system.log
#         error.log
#         access.log
#         debug.log

# 98. Descargar todos los logs sin confirmación
ftp> prompt off
ftp> mget *.log
# Output: (descarga system.log, error.log, access.log, debug.log)
#         ################################
#         226 Transfer complete (x4)

# 99. Comprimir logs descargados
ftp> !gzip *.log
# Output: (comprime todos los archivos .log a .log.gz)

# 100. Verificar compresión
ftp> !ls -lh *.gz
# Output: -rw-r--r-- 1 kali kali 2.1K Oct 13 17:00 system.log.gz
#         -rw-r--r-- 1 kali kali 1.8K Oct 13 17:00 error.log.gz
#         -rw-r--r-- 1 kali kali 3.5K Oct 13 17:00 access.log.gz

# ============================================
# SECCIÓN 15: FINALIZACIÓN Y CIERRE
# ============================================

# 101. Volver al directorio raíz remoto
ftp> cd /
# Output: 250 Directory successfully changed

# 102. Hacer un último listado general
ftp> ls -la
# Output: drwxr-xr-x   8 root root  4096 Oct 13 15:00 .
#         drwxr-xr-x   8 root root  4096 Oct 13 15:00 ..
#         drwxr-xr-x   2 admin admin 4096 Oct 13 16:00 documentos
#         drwxr-xr-x   2 admin admin 4096 Oct 13 16:15 imagenes
#         drwxr-xr-x   3 admin admin 4096 Oct 13 16:30 backups
#         drwxr-xr-x   2 admin admin 4096 Oct 13 16:40 uploads_imagenes

# 103. Verificar estadísticas finales
ftp> status
# Output: Connected to 192.168.1.100
#         Verbose: on; Bell: off; Prompting: off
#         Hash mark printing: on
#         Total files transferred: 28
#         Total bytes transferred: 52,428,800

# 104. Desactivar hash marks
ftp> hash
# Output: Hash mark printing off

# 105. Desactivar verbose
ftp> verbose
# Output: Verbose mode off

# 106. Cerrar conexión sin salir del cliente
ftp> close
# Output: 221 Goodbye

# 107. Intentar reconectar a otro servidor
ftp> open 192.168.1.200
# Output: Connected to 192.168.1.200
#         220 ProFTPD Server ready

# 108. Cerrar esta conexión también
ftp> close
# Output: 221 Goodbye

# 109. Salir del cliente FTP completamente
ftp> bye
# Output: 221 Goodbye

# De vuelta en shell de Kali
kali@kali:~$ 

# ============================================
# VERIFICACIÓN POST-SESIÓN
# ============================================

# 110. Verificar archivos descargados
kali@kali:~$ ls -lh ~/Downloads/
# Output: total 4.7G
#         -rw-r--r-- 1 kali kali 4.5G Oct 13 16:50 ubuntu.iso
#         -rw-r--r-- 1 kali kali 2.0K Oct 13 16:15 informe.pdf
#         (más archivos...)

# 111. Verificar logs de transferencia
kali@kali:~$ cat ~/.netrc
# Output: (credenciales guardadas si se configuraron)

# 112. Generar reporte de actividad
kali@kali:~$ history | grep ftp
# Output: 1234  ftp 192.168.1.100
#         1235  ftp ftp.example.com
