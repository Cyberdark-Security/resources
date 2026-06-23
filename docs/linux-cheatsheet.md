# Linux Administration Cheat Sheet

| [Inicio](index.md) | [Linux](linux-cheatsheet.md) · [Puertos](ports.md) · [FTP](ftp-cheatsheet.md) |
| :--- | :--- |

> [!NOTE]
> **29 secciones** · Referencia de comandos para administración diaria y pentesting en Kali/Ubuntu.

## Referencia rápida

| Comando | Descripción |
| :--- | :--- |
| `pwd` | Directorio actual |
| `ls -lah` | Listar con detalles, ocultos y tamaños legibles |
| `cd ~` / `cd -` | Home / directorio anterior |
| `chmod 755 archivo` | Permisos rwxr-xr-x |
| `chown usuario:grupo archivo` | Cambiar propietario |
| `ps aux` | Procesos en ejecución |
| `systemctl status servicio` | Estado de servicio systemd |
| `grep -r "texto" /ruta` | Búsqueda recursiva |
| `find / -name "*.conf" 2>/dev/null` | Buscar archivos por nombre |
| `ssh usuario@host` | Conexión SSH |
| `tar -czvf backup.tar.gz dir/` | Archivar y comprimir |
| `tail -f /var/log/syslog` | Seguir log en vivo |

## Table of Contents
1. [NAVEGACIÓN Y EXPLORACIÓN BÁSICA](#seccion-1)
2. [CREACIÓN Y GESTIÓN DE DIRECTORIOS](#seccion-2)
3. [COPIAR Y MOVER ARCHIVOS](#seccion-3)
4. [ELIMINACIÓN DE ARCHIVOS](#seccion-4)
5. [CREAR Y MODIFICAR ARCHIVOS](#seccion-5)
6. [VISUALIZACIÓN DE CONTENIDO](#seccion-6)
7. [EDITORES DE TEXTO](#seccion-7)
8. [PERMISOS DE ARCHIVOS](#seccion-8)
9. [IDENTIDAD DE USUARIO](#seccion-9)
10. [GESTIÓN DE PROCESOS](#seccion-10)
11. [GESTIÓN DE SERVICIOS (SYSTEMD)](#seccion-11)
12. [REDIRECCIONES Y PIPES](#seccion-12)
13. [BÚSQUEDA DE ARCHIVOS](#seccion-13)
14. [PROCESAMIENTO DE TEXTO CON AWK](#seccion-14)
15. [PROCESAMIENTO CON SED](#seccion-15)
16. [OTROS COMANDOS DE TEXTO](#seccion-16)
17. [CONECTIVIDAD Y RED](#seccion-17)
18. [CONEXIONES SSH Y TRANSFERENCIAS](#seccion-18)
19. [COMPRESIÓN Y ARCHIVADO](#seccion-19)
20. [GESTIÓN DE PAQUETES](#seccion-20)
21. [DISCOS Y SISTEMAS DE ARCHIVOS](#seccion-21)
22. [GESTIÓN DE USUARIOS](#seccion-22)
23. [TRABAJOS EN SEGUNDO PLANO](#seccion-23)
24. [LOGS Y MONITOREO DEL SISTEMA](#seccion-24)
25. [SEGURIDAD SSH Y FIREWALL](#seccion-25)
26. [HERRAMIENTAS DE PENTESTING](#seccion-26)
27. [SCRIPTING Y AUTOMATIZACIÓN](#seccion-27)
28. [ALIAS Y VARIABLES DE ENTORNO](#seccion-28)
29. [HISTORIAL DE COMANDOS](#seccion-29)

---

## SECCIÓN 1: NAVEGACIÓN Y EXPLORACIÓN BÁSICA {#seccion-1}

### 1. Ver directorio actual

```bash
pwd
Output: /home/kali
```


### 2. Listar archivos básico

```bash
ls
Output: Desktop  Documents  Downloads  Music  Pictures  Videos
```


### 3. Listar con detalles

```bash
ls -l
Output: drwxr-xr-x 2 kali kali 4096 Oct 13 10:00 Desktop
#         drwxr-xr-x 5 kali kali 4096 Oct 13 11:30 Documents
#         drwxr-xr-x 3 kali kali 4096 Oct 13 12:15 Downloads
```


### 4. Listar incluyendo archivos ocultos

```bash
ls -la
Output: drwxr-xr-x 18 kali kali 4096 Oct 13 16:40 .
#         drwxr-xr-x  3 root root 4096 Oct 10 09:00 ..
#         -rw-------  1 kali kali 5234 Oct 13 16:35 .bash_history
#         -rw-r--r--  1 kali kali  220 Oct 10 09:00 .bash_logout
#         drwxr-xr-x  2 kali kali 4096 Oct 13 10:00 Desktop
```


### 5. Listar con tamaños legibles

```bash
ls -lh
Output: drwxr-xr-x 2 kali kali 4.0K Oct 13 10:00 Desktop
#         drwxr-xr-x 5 kali kali 4.0K Oct 13 11:30 Documents
#         -rw-r--r-- 1 kali kali 2.5M Oct 13 14:20 archivo_grande.zip
```


### 6. Listar ordenado por tiempo (más reciente primero)

```bash
ls -lt
Output: -rw-r--r-- 1 kali kali 1024 Oct 13 16:45 ultimo_archivo.txt
#         drwxr-xr-x 2 kali kali 4096 Oct 13 16:40 nuevo_directorio
#         -rw-r--r-- 1 kali kali 2048 Oct 13 15:30 documento.pdf
```


### 7. Listar con colores automáticos

```bash
ls --color=auto
Output: (archivos en diferentes colores según tipo)
```


### 8. Cambiar a directorio específico

```bash
cd /var/log
pwd
Output: /var/log
```


### 9. Subir un nivel de directorio

```bash
cd ..
pwd
Output: /var
```


### 10. Volver al directorio anterior

```bash
cd -
Output: /var/log
pwd
Output: /var/log
```


### 11. Ir al directorio home del usuario

```bash
cd ~
pwd
Output: /home/kali
```


### 12. Ir directamente a un subdirectorio del home

```bash
cd ~/Documents
pwd
Output: /home/kali/Documents
```


## SECCIÓN 2: CREACIÓN Y GESTIÓN DE DIRECTORIOS {#seccion-2}

### 13. Crear directorio simple

```bash
mkdir proyectos
ls -ld proyectos
Output: drwxr-xr-x 2 kali kali 4096 Oct 13 16:50 proyectos
```


### 14. Crear estructura de directorios anidados

```bash
mkdir -p /home/kali/trabajo/2025/octubre/reportes
ls -R trabajo/
Output: trabajo/:
#         2025
#         trabajo/2025:
#         octubre
#         trabajo/2025/octubre:
#         reportes
```


### 15. Crear múltiples directorios a la vez

```bash
mkdir dir1 dir2 dir3
ls -d dir*
Output: dir1  dir2  dir3
```


### 16. Crear directorio con permisos específicos

```bash
mkdir -m 700 privado
ls -ld privado
Output: drwx------ 2 kali kali 4096 Oct 13 16:52 privado
```


## SECCIÓN 3: COPIAR Y MOVER ARCHIVOS {#seccion-3}

### 17. Crear archivo de prueba

```bash
echo "Contenido de prueba" > archivo1.txt
cat archivo1.txt
Output: Contenido de prueba
```


### 18. Copiar archivo simple

```bash
cp archivo1.txt archivo2.txt
ls -l archivo*.txt
Output: -rw-r--r-- 1 kali kali 20 Oct 13 16:53 archivo1.txt
#         -rw-r--r-- 1 kali kali 20 Oct 13 16:53 archivo2.txt
```


### 19. Copiar directorio recursivamente

```bash
mkdir carpeta_original
echo "dato1" > carpeta_original/file1.txt
echo "dato2" > carpeta_original/file2.txt
cp -r carpeta_original carpeta_copia
ls -R carpeta_copia/
Output: carpeta_copia/:
#         file1.txt  file2.txt
```


### 20. Copiar con confirmación interactiva

```bash
echo "nuevo contenido" > archivo2.txt
cp -i archivo1.txt archivo2.txt
Output: cp: overwrite 'archivo2.txt'? y
cat archivo2.txt
Output: Contenido de prueba
```


### 21. Copiar preservando atributos

```bash
cp -p archivo1.txt archivo_backup.txt
ls -l archivo1.txt archivo_backup.txt
Output: (ambos tienen mismo timestamp y permisos)
```


### 22. Mover/renombrar archivo

```bash
mv archivo2.txt archivo_renombrado.txt
ls archivo*.txt
Output: archivo1.txt  archivo_backup.txt  archivo_renombrado.txt
```


### 23. Mover a otro directorio

```bash
mv archivo_renombrado.txt proyectos/
ls proyectos/
Output: archivo_renombrado.txt
```


### 24. Mover múltiples archivos

```bash
touch file1.log file2.log file3.log
mkdir logs
mv *.log logs/
ls logs/
Output: file1.log  file2.log  file3.log
```


## SECCIÓN 4: ELIMINACIÓN DE ARCHIVOS {#seccion-4}

### 25. Crear archivos de prueba para eliminar

```bash
touch basura1.txt basura2.txt basura3.txt
ls basura*.txt
Output: basura1.txt  basura2.txt  basura3.txt
```


### 26. Eliminar archivo individual

```bash
rm basura1.txt
ls basura*.txt
Output: basura2.txt  basura3.txt
```


### 27. Eliminar directorio vacío con rmdir

```bash
mkdir directorio_vacio
rmdir directorio_vacio
ls -d directorio_vacio 2>/dev/null || echo "Directorio eliminado"
Output: Directorio eliminado
```


### 28. Eliminar directorio con contenido

```bash
mkdir -p carpeta_temporal/subcarpeta
touch carpeta_temporal/archivo.txt
rm -r carpeta_temporal/
ls -d carpeta_temporal 2>/dev/null || echo "Carpeta eliminada"
Output: Carpeta eliminada
```


### 29. Eliminar forzadamente sin confirmación (¡PELIGROSO!)

```bash
mkdir -p peligro/datos
touch peligro/datos/importante.txt
rm -rf peligro/
# ⚠️ Sin output, elimina todo inmediatamente
```


### 30. Eliminar con confirmación interactiva

```bash
touch archivo_importante.txt
rm -i archivo_importante.txt
Output: rm: remove regular file 'archivo_importante.txt'? n
ls archivo_importante.txt
Output: archivo_importante.txt
```


## SECCIÓN 5: CREAR Y MODIFICAR ARCHIVOS {#seccion-5}

### 31. Crear archivo vacío o actualizar timestamp

```bash
touch nuevo.txt
ls -l nuevo.txt
Output: -rw-r--r-- 1 kali kali 0 Oct 13 17:00 nuevo.txt
```


### 32. Actualizar timestamp sin crear si no existe

```bash
touch -c archivo_inexistente.txt
ls archivo_inexistente.txt 2>/dev/null || echo "No se creó"
Output: No se creó
```


### 33. Crear múltiples archivos

```bash
touch file{1..5}.txt
ls file*.txt
Output: file1.txt  file2.txt  file3.txt  file4.txt  file5.txt
```


### 34. Establecer timestamp específico

```bash
touch -t 202510011200 archivo_viejo.txt
ls -l archivo_viejo.txt
Output: -rw-r--r-- 1 kali kali 0 Oct  1 12:00 archivo_viejo.txt
```


## SECCIÓN 6: VISUALIZACIÓN DE CONTENIDO {#seccion-6}

### 35. Crear archivo con contenido para pruebas

```bash
cat > documento.txt << EOF
Línea 1: Introducción
Línea 2: Desarrollo
Línea 3: ERROR crítico encontrado
Línea 4: Continuación normal
Línea 5: Conclusión
EOF
```


### 36. Ver contenido completo de archivo

```bash
cat documento.txt
Output: Línea 1: Introducción
#         Línea 2: Desarrollo
#         Línea 3: ERROR crítico encontrado
#         Línea 4: Continuación normal
#         Línea 5: Conclusión
```


### 37. Ver contenido en orden inverso

```bash
tac documento.txt
Output: Línea 5: Conclusión
#         Línea 4: Continuación normal
#         Línea 3: ERROR crítico encontrado
#         Línea 2: Desarrollo
#         Línea 1: Introducción
```


### 38. Ver con números de línea

```bash
nl documento.txt
Output:      1  Línea 1: Introducción
#              2  Línea 2: Desarrollo
#              3  Línea 3: ERROR crítico encontrado
#              4  Línea 4: Continuación normal
#              5  Línea 5: Conclusión
```


### 39. Crear archivo de log grande para pruebas

```bash
for i in {1..200}; do echo "Log entry $i: $(date)" >> sistema.log; done
```


### 40. Ver archivo con paginación (less)

```bash
less sistema.log
# (Presionar q para salir, / para buscar, espacio para siguiente página)
```


### 41. Ver con paginación simple (more)

```bash
more sistema.log
# (Similar a less pero con menos funcionalidades)
```


### 42. Ver primeras 20 líneas

```bash
head -n 20 sistema.log
Output: Log entry 1: Mon Oct 13 17:05:32 -05 2025
#         Log entry 2: Mon Oct 13 17:05:32 -05 2025
#         ... (20 líneas en total)
```


### 43. Ver últimas 100 líneas

```bash
tail -n 100 sistema.log
Output: (últimas 100 líneas del archivo)
```


### 44. Monitorear archivo en tiempo real

```bash
# En otra terminal: echo "Nueva entrada" >> sistema.log
tail -f sistema.log
Output: (muestra nuevas líneas conforme se agregan)
# Presionar Ctrl+C para salir
```


### 45. Monitorear con recreación de archivo

```bash
tail -F /var/log/syslog
# (útil cuando el archivo puede ser rotado/recreado)
```


## SECCIÓN 7: EDITORES DE TEXTO {#seccion-7}

### 46. Editar archivo con nano (editor simple)

```bash
nano config.txt
# Escribir: server=192.168.1.100
# Ctrl+O para guardar, Enter para confirmar, Ctrl+X para salir

cat config.txt
Output: server=192.168.1.100
```


### 47. Editar con vim (editor avanzado)

```bash
vim script.sh
# Presionar 'i' para modo inserción
# Escribir: #!/bin/bash
#           echo "Hola Mundo"
# Presionar ESC, luego :wq para guardar y salir

cat script.sh
Output: #!/bin/bash
#         echo "Hola Mundo"
```


## SECCIÓN 8: PERMISOS DE ARCHIVOS {#seccion-8}

### 48. Verificar permisos actuales

```bash
ls -l script.sh
Output: -rw-r--r-- 1 kali kali 33 Oct 13 17:10 script.sh
```


### 49. Hacer ejecutable un script (notación octal)

```bash
chmod 755 script.sh
ls -l script.sh
Output: -rwxr-xr-x 1 kali kali 33 Oct 13 17:10 script.sh
```


### 50. Establecer permisos de lectura/escritura (notación octal)

```bash
chmod 644 archivo1.txt
ls -l archivo1.txt
Output: -rw-r--r-- 1 kali kali 20 Oct 13 16:53 archivo1.txt
```


### 51. Agregar permiso de ejecución (notación simbólica)

```bash
chmod +x script.sh
ls -l script.sh
Output: -rwxr-xr-x 1 kali kali 33 Oct 13 17:10 script.sh
```


### 52. Cambiar permisos recursivamente

```bash
mkdir -p datos_sensibles/subdirectorio
touch datos_sensibles/archivo.txt datos_sensibles/subdirectorio/secreto.txt
chmod -R 700 datos_sensibles/
ls -lR datos_sensibles/
Output: datos_sensibles/:
#         total 4
#         -rwx------ 1 kali kali    0 Oct 13 17:12 archivo.txt
#         drwx------ 2 kali kali 4096 Oct 13 17:12 subdirectorio
```


### 53. Cambiar propietario de archivo (requiere sudo)

```bash
sudo chown root:root archivo1.txt
ls -l archivo1.txt
Output: -rw-r--r-- 1 root root 20 Oct 13 16:53 archivo1.txt
```


### 54. Restaurar propietario original

```bash
sudo chown kali:kali archivo1.txt
ls -l archivo1.txt
Output: -rw-r--r-- 1 kali kali 20 Oct 13 16:53 archivo1.txt
```


### 55. Cambiar propietario recursivamente

```bash
sudo chown -R www-data:www-data datos_sensibles/
ls -l datos_sensibles/
Output: total 4
#         -rwx------ 1 www-data www-data    0 Oct 13 17:12 archivo.txt
#         drwx------ 2 www-data www-data 4096 Oct 13 17:12 subdirectorio
```


### 56. Restaurar permisos

```bash
sudo chown -R kali:kali datos_sensibles/
```


### 57. Ver ACL (Access Control List) de archivo

```bash
getfacl archivo1.txt
Output: # file: archivo1.txt
#         # owner: kali
#         # group: kali
#         user::rw-
#         group::r--
#         other::r--
```


### 58. Establecer ACL para usuario específico

```bash
setfacl -m u:root:rwx archivo1.txt
getfacl archivo1.txt
Output: # file: archivo1.txt
#         # owner: kali
#         # group: kali
#         user::rw-
#         user:root:rwx
#         group::r--
#         mask::rwx
#         other::r--
```


### 59. Remover ACL específica

```bash
setfacl -x u:root archivo1.txt
getfacl archivo1.txt
Output: (ACL de root removida)
```


### 60. Establecer sticky bit en directorio

```bash
mkdir compartido
chmod +t compartido
ls -ld compartido
Output: drwxr-xr-t 2 kali kali 4096 Oct 13 17:15 compartido
```


### 61. Establecer SUID en binario (ejemplo educativo)

```bash
cp /bin/bash mi_bash
sudo chmod u+s mi_bash
ls -l mi_bash
Output: -rwsr-xr-x 1 kali kali 1234567 Oct 13 17:16 mi_bash
```


### 62. Remover SUID por seguridad

```bash
sudo chmod u-s mi_bash
ls -l mi_bash
Output: -rwxr-xr-x 1 kali kali 1234567 Oct 13 17:16 mi_bash
rm mi_bash
```


### 63. Establecer SGID en directorio

```bash
mkdir grupo_compartido
chmod g+s grupo_compartido
ls -ld grupo_compartido
Output: drwxr-sr-x 2 kali kali 4096 Oct 13 17:17 grupo_compartido
```


## SECCIÓN 9: IDENTIDAD DE USUARIO {#seccion-9}

### 64. Ver información completa del usuario actual

```bash
id
Output: uid=1000(kali) gid=1000(kali) groups=1000(kali),27(sudo),116(wireshark)
```


### 65. Ver solo el nombre del usuario

```bash
whoami
Output: kali
```


### 66. Ver grupos del usuario

```bash
groups
Output: kali sudo wireshark
```


### 67. Ver información de otro usuario

```bash
id root
Output: uid=0(root) gid=0(root) groups=0(root)
```


## SECCIÓN 10: GESTIÓN DE PROCESOS {#seccion-10}

### 68. Ver todos los procesos (formato BSD)

```bash
ps aux | head -n 10
Output: USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
#         root         1  0.0  0.1 169324 11234 ?        Ss   09:00   0:03 /sbin/init
#         root         2  0.0  0.0      0     0 ?        S    09:00   0:00 [kthreadd]
#         kali      1234  0.5  2.1 523456 87654 ?        Sl   16:40   0:12 firefox
```


### 69. Ver procesos (formato System V)

```bash
ps -ef | head -n 10
Output: UID        PID  PPID  C STIME TTY          TIME CMD
#         root         1     0  0 09:00 ?        00:00:03 /sbin/init
#         root         2     0  0 09:00 ?        00:00:00 [kthreadd]
```


### 70. Buscar proceso específico

```bash
ps aux | grep sshd
Output: root      1523  0.0  0.1  12345  6789 ?        Ss   09:15   0:00 /usr/sbin/sshd -D
#         kali      8901  0.0  0.0   6420   892 pts/0    S+   17:20   0:00 grep --color=auto sshd
```


### 71. Monitor interactivo de procesos

```bash
top
# (Presionar q para salir, M para ordenar por memoria, P por CPU)
Output: (interfaz interactiva mostrando procesos en tiempo real)
```


### 72. Monitor mejorado (si está instalado)

```bash
htop
# (Interfaz más visual y amigable, F10 para salir)
```


### 73. Ejecutar comando con prioridad baja

```bash
nice -n 10 tar -czf backup.tar.gz /home/kali/Documents &
ps aux | grep tar
Output: kali     12345  5.2  0.5  12345  6789 pts/0    SN   17:22   0:01 tar -czf backup.tar.gz
```


### 74. Cambiar prioridad de proceso existente

```bash
sudo renice -n -5 -p 12345
ps -p 12345 -o pid,ni,cmd
Output:   PID  NI CMD
#         12345  -5 tar -czf backup.tar.gz /home/kali/Documents
```


### 75. Enviar señal TERM a proceso (terminación limpia)

```bash
sleep 100 &
Output: [1] 12456
kill 12456
Output: [1]+  Terminated              sleep 100
```


### 76. Forzar terminación de proceso (SIGKILL)

```bash
sleep 200 &
Output: [1] 12457
kill -9 12457
Output: [1]+  Killed                  sleep 200
```


### 77. Terminar proceso por nombre

```bash
firefox &
Output: [1] 12500
pkill -f firefox
Output: [1]+  Terminated              firefox
```


### 78. Terminar todos los procesos con nombre específico

```bash
sleep 30 &
sleep 40 &
sleep 50 &
jobs
Output: [1]   Running                 sleep 30 &
#         [2]-  Running                 sleep 40 &
#         [3]+  Running                 sleep 50 &
killall sleep
Output: [1]   Terminated              sleep 30
#         [2]-  Terminated              sleep 40
#         [3]+  Terminated              sleep 50
```


## SECCIÓN 11: GESTIÓN DE SERVICIOS (SYSTEMD) {#seccion-11}

### 79. Ver estado de servicio

```bash
sudo systemctl status ssh
Output: ● ssh.service - OpenBSD Secure Shell server
#         Loaded: loaded (/lib/systemd/system/ssh.service; enabled)
#         Active: active (running) since Mon 2025-10-13 09:00:00 -05
#         Process: 1523 ExecStartPre=/usr/sbin/sshd -t (code=exited, status=0/SUCCESS)
#         Main PID: 1523 (sshd)
```


### 80. Iniciar servicio

```bash
sudo systemctl start apache2
sudo systemctl status apache2 | head -n 5
Output: ● apache2.service - The Apache HTTP Server
#         Loaded: loaded (/lib/systemd/system/apache2.service)
#         Active: active (running)
```


### 81. Detener servicio

```bash
sudo systemctl stop apache2
sudo systemctl status apache2 | grep Active
Output: Active: inactive (dead)
```


### 82. Reiniciar servicio

```bash
sudo systemctl restart ssh
sudo systemctl status ssh | grep Active
Output: Active: active (running)
```


### 83. Habilitar servicio al inicio

```bash
sudo systemctl enable nginx
Output: Created symlink /etc/systemd/system/multi-user.target.wants/nginx.service → /lib/systemd/system/nginx.service
```


### 84. Deshabilitar servicio al inicio

```bash
sudo systemctl disable nginx
Output: Removed /etc/systemd/system/multi-user.target.wants/nginx.service
```


### 85. Recargar configuración de systemd

```bash
sudo systemctl daemon-reload
# (Sin output si es exitoso)
```


### 86. Ver todos los servicios activos

```bash
systemctl list-units --type=service --state=running | head -n 10
Output: UNIT                     LOAD   ACTIVE SUB     DESCRIPTION
#         ssh.service             loaded active running OpenBSD Secure Shell server
#         systemd-journald.service loaded active running Journal Service
```


### 87. Usar comando service (legacy)

```bash
sudo service apache2 restart
Output: * Restarting Apache httpd web server apache2
#         * Apache httpd restarted
```


## SECCIÓN 12: REDIRECCIONES Y PIPES {#seccion-12}

### 88. Redirigir salida a archivo (sobrescribe)

```bash
echo "Primera línea" > salida.txt
cat salida.txt
Output: Primera línea
```


### 89. Redirigir salida a archivo (añade al final)

```bash
echo "Segunda línea" >> salida.txt
cat salida.txt
Output: Primera línea
#         Segunda línea
```


### 90. Redirigir errores a archivo

```bash
ls /directorio/inexistente 2> errores.log
cat errores.log
Output: ls: cannot access '/directorio/inexistente': No such file or directory
```


### 91. Redirigir salida y errores al mismo archivo

```bash
comando_inexistente &> salida_completa.log 2>&1
cat salida_completa.log
Output: bash: comando_inexistente: command not found
```


### 92. Usar pipe para filtrar procesos

```bash
ps aux | grep sshd | grep -v grep
Output: root      1523  0.0  0.1  12345  6789 ?  Ss   09:15   0:00 /usr/sbin/sshd -D
```


### 93. Pipeline complejo: buscar, contar y ordenar

```bash
cat documento.txt | grep ERROR | wc -l
Output: 1
```


### 94. Guardar salida y mostrar simultáneamente con tee

```bash
echo "Información importante" | tee importante.log
Output: Información importante
cat importante.log
Output: Información importante
```


### 95. Usar xargs para operaciones en lote

```bash
find . -name "*.log" -print0 | xargs -0 gzip
ls *.log.gz 2>/dev/null
Output: file1.log.gz  file2.log.gz  file3.log.gz
```


### 96. Pipeline para análisis de logs

```bash
cat sistema.log | grep -i error | awk '{print $1, $2, $3}' | sort | uniq -c
Output: (cuenta de errores únicos por timestamp)
```


## SECCIÓN 13: BÚSQUEDA DE ARCHIVOS {#seccion-13}

### 97. Buscar archivo por nombre

```bash
find /home/kali -name "config.txt"
Output: /home/kali/config.txt
```


### 98. Buscar solo directorios

```bash
find /home/kali -type d -name "proyectos"
Output: /home/kali/proyectos
```


### 99. Buscar archivos modificados en último día

```bash
find /home/kali -type f -mtime -1
Output: /home/kali/salida.txt
#         /home/kali/errores.log
#         /home/kali/importante.log
```


### 100. Buscar binarios SUID (seguridad)

```bash
sudo find / -perm -4000 -type f 2>/dev/null | head -n 10
Output: /usr/bin/sudo
#         /usr/bin/passwd
#         /usr/bin/chfn
#         /usr/bin/newgrp
#         /usr/bin/gpasswd
```


### 101. Buscar y eliminar archivos

```bash
find /tmp -name "*.tmp" -type f -delete
# (Elimina todos los archivos .tmp en /tmp)
```


### 102. Buscar archivos por tamaño

```bash
find /home/kali -type f -size +10M
Output: /home/kali/backup.tar.gz
```


### 103. Buscar con grep en archivos

```bash
grep "palabra" archivo1.txt
Output: (líneas que contienen "palabra")
```


### 104. Buscar recursivamente en directorio

```bash
grep -r "ERROR" /var/log/ 2>/dev/null | head -n 5
Output: /var/log/syslog:Oct 13 10:23:45 kali kernel: ERROR: Device not found
#         /var/log/kern.log:Oct 13 10:23:45 kali kernel: ERROR: Device not found
```


### 105. Buscar mostrando números de línea

```bash
grep -n "ERROR" documento.txt
Output: 3:Línea 3: ERROR crítico encontrado
```


### 106. Buscar con expresión regular extendida

```bash
grep -E "err|fail|crit" sistema.log | head -n 3
Output: (líneas que contienen err, fail o crit)
```


### 107. Actualizar base de datos de locate

```bash
sudo updatedb
# (Sin output, puede tardar varios minutos)
```


### 108. Buscar rápidamente con locate

```bash
locate config.txt
Output: /home/kali/config.txt
#         /etc/systemd/system/config.txt.backup
```


## SECCIÓN 14: PROCESAMIENTO DE TEXTO CON AWK {#seccion-14}

### 109. Imprimir primera columna

```bash
ps aux | awk '{print $1}' | head -n 10
Output: USER
#         root
#         root
#         kali
```


### 110. Procesar archivo con delimitador personalizado

```bash
awk -F: '{print $1":"$3}' /etc/passwd | head -n 5
Output: root:0
#         daemon:1
#         bin:2
#         sys:3
#         sync:4
```


### 111. Filtrar líneas con condición

```bash
awk '$3 > 1000' archivo_numeros.txt
# (Muestra líneas donde tercera columna > 1000)
```


### 112. Sumar valores de columna

```bash
echo -e "10\n20\n30\n40" | awk '{sum+=$1} END {print "Total:", sum}'
Output: Total: 100
```


## SECCIÓN 15: PROCESAMIENTO CON SED {#seccion-15}

### 113. Reemplazar texto (primera ocurrencia por línea)

```bash
echo "hola mundo, hola universo" | sed 's/hola/adiós/'
Output: adiós mundo, hola universo
```


### 114. Reemplazar todas las ocurrencias (flag global)

```bash
echo "hola mundo, hola universo" | sed 's/hola/adiós/g'
Output: adiós mundo, adiós universo
```


### 115. Extraer rango de líneas

```bash
sed -n '1,5p' sistema.log
Output: (primeras 5 líneas del archivo)
```


### 116. Eliminar líneas que contengan patrón

```bash
sed '/ERROR/d' documento.txt
Output: Línea 1: Introducción
#         Línea 2: Desarrollo
#         Línea 4: Continuación normal
#         Línea 5: Conclusión
```


### 117. Editar archivo in-place (con backup)

```bash
sed -i.bak 's/viejo/nuevo/g' config.txt
cat config.txt
Output: (contenido modificado)
cat config.txt.bak
Output: (contenido original)
```


## SECCIÓN 16: OTROS COMANDOS DE TEXTO {#seccion-16}

### 118. Extraer campos específicos

```bash
cut -d: -f1 /etc/passwd | head -n 5
Output: root
#         daemon
#         bin
#         sys
#         sync
```


### 119. Ordenar líneas alfabéticamente

```bash
cat /etc/passwd | cut -d: -f1 | sort | head -n 5
Output: _apt
#         avahi
#         backup
#         bin
#         colord
```


### 120. Contar líneas únicas

```bash
echo -e "apple\nbanana\napple\norange\nbanana" | sort | uniq -c
Output:       2 apple
#               2 banana
#               1 orange
```


### 121. Ordenar por frecuencia (más común primero)

```bash
echo -e "apple\nbanana\napple\norange\nbanana\napple" | sort | uniq -c | sort -nr
Output:       3 apple
#               2 banana
#               1 orange
```


### 122. Convertir minúsculas a mayúsculas

```bash
echo "texto en minúsculas" | tr '[:lower:]' '[:upper:]'
Output: TEXTO EN MINÚSCULAS
```


### 123. Eliminar caracteres específicos

```bash
echo "tel: 555-1234" | tr -d '-'
Output: tel: 5551234
```


### 124. Buscar con ripgrep (si está instalado)

```bash
rg "TODO" /home/kali/proyectos/ 2>/dev/null | head -n 3
Output: (búsqueda ultrarrápida de "TODO" en archivos)
```


### 125. Buscar con ag / silver searcher (si está instalado)

```bash
ag "function" /home/kali/proyectos/ 2>/dev/null | head -n 3
Output: (búsqueda rápida de "function")
```


## SECCIÓN 17: CONECTIVIDAD Y RED {#seccion-17}

### 126. Hacer ping a servidor (4 paquetes)

```bash
ping -c 4 8.8.8.8
Output: PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
#         64 bytes from 8.8.8.8: icmp_seq=1 ttl=118 time=15.2 ms
#         64 bytes from 8.8.8.8: icmp_seq=2 ttl=118 time=14.8 ms
#         --- 8.8.8.8 ping statistics ---
#         4 packets transmitted, 4 received, 0% packet loss
```


### 127. Ver interfaces de red (comando moderno)

```bash
ip a
Output: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
#            inet 127.0.0.1/8 scope host lo
#         2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
#            inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0
```


### 128. Ver interfaces de red (comando legacy)

```bash
ifconfig
Output: eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
#               inet 192.168.1.100  netmask 255.255.255.0
```


### 129. Activar interfaz de red

```bash
sudo ip link set eth0 up
# (Sin output si es exitoso)
```


### 130. Ver tabla de enrutamiento

```bash
ip route show
Output: default via 192.168.1.1 dev eth0
#         192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100
```


### 131. Descargar archivo con wget

```bash
wget https://example.com/archivo.zip
Output: --2025-10-13 17:45:00--  https://example.com/archivo.zip
#         Resolving example.com... 93.184.216.34
#         Connecting to example.com|93.184.216.34|:443... connected.
#         HTTP request sent, awaiting response... 200 OK
#         archivo.zip saved [12345/12345]
```


### 132. Reanudar descarga interrumpida

```bash
wget -c https://example.com/archivo_grande.iso
Output: (continúa desde donde se detuvo)
```


### 133. Ver encabezados HTTP con curl

```bash
curl -I https://www.google.com
Output: HTTP/2 200
#         content-type: text/html; charset=ISO-8859-1
#         date: Mon, 13 Oct 2025 22:45:00 GMT
```


### 134. Obtener IP pública

```bash
curl -sS https://ifconfig.me
Output: 203.0.113.45
```


### 135. Hacer petición POST con JSON

```bash
curl -X POST -H "Content-Type: application/json" -d '{"user":"kali","pass":"secret"}' https://api.example.com/login
Output: {"status":"success","token":"abc123xyz"}
```


### 136. Ver conexiones de red activas (netstat legacy)

```bash
netstat -tulnp 2>/dev/null | head -n 10
Output: Active Internet connections (only servers)
#         Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
#         tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1523/sshd
#         tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      2345/cupsd
```


### 137. Ver conexiones con ss (moderno)

```bash
ss -tuln | head -n 10
Output: Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port
#         tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*
#         tcp   LISTEN 0      128    127.0.0.1:631      0.0.0.0:*
```


### 138. Ver procesos escuchando en puertos

```bash
sudo ss -tulpn | grep :22
Output: tcp   LISTEN 0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1523,fd=3))
```


### 139. Trazar ruta a host

```bash
traceroute google.com
Output: traceroute to google.com (142.250.185.46), 30 hops max
#          1  192.168.1.1  1.234 ms  1.123 ms  1.089 ms
#          2  10.0.0.1     5.678 ms  5.432 ms  5.321 ms
#         ...
```


### 140. Alternativa a traceroute

```bash
tracepath google.com
Output: (similar a traceroute)
```


### 141. Consultar DNS con dig

```bash
dig +short google.com
Output: 142.250.185.46
```


### 142. Consultar registros MX (correo)

```bash
dig mx gmail.com +short
Output: 5 gmail-smtp-in.l.google.com.
#         10 alt1.gmail-smtp-in.l.google.com.
```


### 143. Consultar DNS con nslookup

```bash
nslookup google.com
Output: Server:         192.168.1.1
#         Address:        192.168.1.1#53
#         Non-authoritative answer:
#         Name:   google.com
#         Address: 142.250.185.46
```


### 144. Capturar tráfico de red (requiere sudo)

```bash
sudo tcpdump -i eth0 port 80 -w captura.pcap -c 10
Output: tcpdump: listening on eth0, link-type EN10MB
#         10 packets captured
```


### 145. Capturar todo el tráfico con detalles

```bash
sudo tcpdump -i any -nn -s0 -w /tmp/cap.pcap
# (Presionar Ctrl+C para detener)
```


### 146. Escanear puertos con nmap (básico)

```bash
nmap -sS -Pn -p 1-1000 192.168.1.1
Output: Starting Nmap 7.94
#         PORT    STATE SERVICE
#         22/tcp  open  ssh
#         80/tcp  open  http
#         443/tcp open  https
```


### 147. Escaneo con detección de versiones

```bash
nmap -sV -A 192.168.1.100
Output: (información detallada de servicios y SO)
```


### 148. Detección de sistema operativo

```bash
sudo nmap -O 192.168.1.1
Output: Running: Linux 5.X
#         OS details: Linux 5.4 - 5.10
```


## SECCIÓN 18: CONEXIONES SSH Y TRANSFERENCIAS {#seccion-18}

### 149. Conectar por SSH

```bash
ssh usuario@192.168.1.50
Output: usuario@192.168.1.50's password:
#         (después de autenticación)
#         usuario@servidor:~$
```


### 150. SSH con puerto específico

```bash
ssh -p 2222 usuario@servidor.com
Output: (conexión en puerto 2222)
```


### 151. SSH con clave privada

```bash
ssh -i ~/.ssh/id_rsa usuario@servidor.com
Output: (autenticación con clave RSA)
```


### 152. Copiar archivo con SCP

```bash
echo "Archivo local" > local_file.txt
scp local_file.txt usuario@192.168.1.50:/home/usuario/
Output: local_file.txt                    100%   14     0.5KB/s   00:00
```


### 153. Copiar directorio recursivamente con SCP

```bash
mkdir -p carpeta_local/subcarpeta
echo "contenido" > carpeta_local/subcarpeta/file.txt
scp -r carpeta_local usuario@192.168.1.50:/tmp/
Output: file.txt                          100%   10     0.3KB/s   00:00
```


### 154. Descargar archivo desde servidor remoto

```bash
scp usuario@192.168.1.50:/var/log/syslog /tmp/syslog_remoto
Output: syslog                            100% 2048KB   1.5MB/s   00:01
```


### 155. Sincronizar directorios con rsync

```bash
rsync -avz /home/kali/Documents/ usuario@192.168.1.50:/backups/documents/
Output: sending incremental file list
#         ./
#         file1.txt
#         file2.pdf
#         sent 12,345 bytes  received 89 bytes  8,289.33 bytes/sec
```


### 156. Rsync con eliminación de archivos no presentes en origen

```bash
rsync -avz --delete /home/kali/web/ usuario@192.168.1.50:/var/www/html/
Output: (sincroniza y elimina archivos extras en destino)
```


### 157. Usar SFTP interactivo

```bash
sftp usuario@192.168.1.50
Output: Connected to 192.168.1.50
#         sftp> ls
#         Documents    Downloads    Pictures
#         sftp> get archivo.txt
#         Fetching /home/usuario/archivo.txt to archivo.txt
#         sftp> put local.txt
#         Uploading local.txt to /home/usuario/local.txt
#         sftp> bye
```


## SECCIÓN 19: COMPRESIÓN Y ARCHIVADO {#seccion-19}

### 158. Crear directorio con archivos de prueba

```bash
mkdir archivos_prueba
echo "contenido1" > archivos_prueba/file1.txt
echo "contenido2" > archivos_prueba/file2.txt
echo "contenido3" > archivos_prueba/file3.txt
```


### 159. Crear archivo TAR sin comprimir

```bash
tar -cvf archivos.tar archivos_prueba/
Output: archivos_prueba/
#         archivos_prueba/file1.txt
#         archivos_prueba/file2.txt
#         archivos_prueba/file3.txt
```


### 160. Extraer archivo TAR

```bash
tar -xvf archivos.tar
Output: archivos_prueba/
#         archivos_prueba/file1.txt
#         archivos_prueba/file2.txt
#         archivos_prueba/file3.txt
```


### 161. Crear TAR con compresión gzip

```bash
tar -czvf archivos.tar.gz archivos_prueba/
Output: archivos_prueba/
#         archivos_prueba/file1.txt
#         archivos_prueba/file2.txt
#         archivos_prueba/file3.txt

ls -lh archivos.tar.gz
Output: -rw-r--r-- 1 kali kali 234 Oct 13 18:00 archivos.tar.gz
```


### 162. Extraer TAR.GZ

```bash
tar -xzvf archivos.tar.gz
Output: (extrae con verbose)
```


### 163. Crear TAR con compresión XZ (mejor compresión)

```bash
tar -cJvf archivos.tar.xz archivos_prueba/
Output: archivos_prueba/
#         archivos_prueba/file1.txt
#         archivos_prueba/file2.txt
#         archivos_prueba/file3.txt
```


### 164. Extraer TAR.XZ

```bash
tar -xJvf archivos.tar.xz
Output: (extrae archivo XZ)
```


### 165. Comprimir archivo individual con gzip

```bash
gzip archivo1.txt
ls archivo1.txt.gz
Output: archivo1.txt.gz
```


### 166. Descomprimir gzip

```bash
gunzip archivo1.txt.gz
ls archivo1.txt
Output: archivo1.txt
```


### 167. Comprimir con bzip2 (mejor compresión que gzip)

```bash
bzip2 archivo1.txt
ls archivo1.txt.bz2
Output: archivo1.txt.bz2
```


### 168. Descomprimir bzip2

```bash
bunzip2 archivo1.txt.bz2
ls archivo1.txt
Output: archivo1.txt
```


### 169. Comprimir con xz (mejor compresión)

```bash
xz archivo1.txt
ls archivo1.txt.xz
Output: archivo1.txt.xz
```


### 170. Descomprimir xz

```bash
unxz archivo1.txt.xz
ls archivo1.txt
Output: archivo1.txt
```


### 171. Crear archivo ZIP

```bash
zip -r archivos.zip archivos_prueba/
Output:   adding: archivos_prueba/ (stored 0%)
#           adding: archivos_prueba/file1.txt (stored 0%)
#           adding: archivos_prueba/file2.txt (stored 0%)
```


### 172. Extraer ZIP a directorio específico

```bash
unzip archivos.zip -d /tmp/extraido
Output: Archive:  archivos.zip
#            creating: /tmp/extraido/archivos_prueba/
#          inflating: /tmp/extraido/archivos_prueba/file1.txt
```


### 173. Listar contenido de archivo comprimido sin extraer

```bash
tar -tzvf archivos.tar.gz
Output: drwxr-xr-x kali/kali         0 2025-10-13 18:00 archivos_prueba/
#         -rw-r--r-- kali/kali        11 2025-10-13 18:00 archivos_prueba/file1.txt
```


## SECCIÓN 20: GESTIÓN DE PAQUETES {#seccion-20}

### 174. Actualizar lista de paquetes (Debian/Ubuntu/Kali)

```bash
sudo apt-get update
Output: Hit:1 http://kali.download/kali kali-rolling InRelease
#         Get:2 http://kali.download/kali kali-rolling/main amd64 Packages [18.5 MB]
#         Fetched 18.5 MB in 5s (3,700 kB/s)
#         Reading package lists... Done
```


### 175. Actualizar paquetes instalados

```bash
sudo apt-get upgrade
Output: Reading package lists... Done
#         Building dependency tree... Done
#         Calculating upgrade... Done
#         The following packages will be upgraded:
#           package1 package2 package3
#         3 upgraded, 0 newly installed
```


### 176. Actualización completa del sistema

```bash
sudo apt-get dist-upgrade
Output: (actualiza todo incluyendo kernel)
```


### 177. Instalar paquete

```bash
sudo apt-get install nmap
Output: Reading package lists... Done
#         The following NEW packages will be installed:
#           nmap
#         Do you want to continue? [Y/n] Y
#         Setting up nmap (7.94)
```


### 178. Remover paquete (mantiene configuración)

```bash
sudo apt-get remove nmap
Output: The following packages will be REMOVED:
#           nmap
#         Do you want to continue? [Y/n] Y
```


### 179. Remover paquetes no necesarios

```bash
sudo apt-get autoremove
Output: The following packages will be REMOVED:
#           lib1 lib2 lib3
#         After this operation, 123 MB disk space will be freed
```


### 180. Buscar paquete disponible

```bash
apt-cache search metasploit
Output: metasploit-framework - Framework for penetration testing
#         armitage - Graphical cyber attack management tool
```


### 181. Instalar paquete .deb local

```bash
sudo dpkg -i /tmp/paquete.deb
Output: Selecting previously unselected package paquete.
#         Unpacking paquete (1.0) ...
#         Setting up paquete (1.0) ...
```


### 182. Listar paquetes instalados

```bash
dpkg -l | grep ssh
Output: ii  openssh-client  1:9.2p1-2  amd64  secure shell client
#         ii  openssh-server  1:9.2p1-2  amd64  secure shell server
```


### 183. Remover paquete con dpkg

```bash
sudo dpkg -r paquete
Output: Removing paquete (1.0) ...
```


### 184. Gestión con yum (RedHat/CentOS - si aplicara)

```bash
# sudo yum update
# sudo yum install httpd
# sudo yum remove httpd
```


### 185. Gestión con dnf (Fedora - si aplicara)

```bash
# sudo dnf install nginx
# sudo dnf remove nginx
```


### 186. Instalar RPM (RedHat - si aplicara)

```bash
# sudo rpm -ivh paquete.rpm
```


### 187. Gestión con pacman (Arch - si aplicara)

```bash
# sudo pacman -S paquete
# sudo pacman -R paquete
```


## SECCIÓN 21: DISCOS Y SISTEMAS DE ARCHIVOS {#seccion-21}

### 188. Listar dispositivos de bloque

```bash
lsblk
Output: NAME   MAJ:MIN RM   SIZE RO TYPE MOUNTPOINT
#         sda      8:0    0   100G  0 disk
#         ├─sda1   8:1    0    99G  0 part /
#         └─sda2   8:2    0     1G  0 part [SWAP]
#         sr0     11:0    1  1024M  0 rom
```


### 189. Ver información de particiones

```bash
sudo fdisk -l
Output: Disk /dev/sda: 100 GiB
#         Device     Boot  Start       End   Sectors  Size Id Type
#         /dev/sda1  *      2048 207618047 207616000   99G 83 Linux
#         /dev/sda2      207618048 209715199   2097152    1G 82 Linux swap
```


### 190. Ver con parted

```bash
sudo parted /dev/sda print
Output: Model: ATA VBOX HARDDISK (scsi)
#         Disk /dev/sda: 107GB
#         Number  Start   End     Size    Type     File system  Flags
#          1      1049kB  106GB   106GB   primary  ext4         boot
#          2      106GB   107GB   1074MB  primary  linux-swap
```


### 191. Ver UUIDs de particiones

```bash
sudo blkid
Output: /dev/sda1: UUID="12345678-1234-1234-1234-123456789abc" TYPE="ext4"
#         /dev/sda2: UUID="abcdef12-3456-7890-abcd-ef1234567890" TYPE="swap"
```


### 192. Crear sistema de archivos ext4

```bash
# sudo mkfs.ext4 /dev/sdb1
Output: mke2fs 1.46.5 (30-Dec-2021)
#         Creating filesystem with 26214400 4k blocks
#         Writing superblocks and filesystem accounting information: done
```


### 193. Crear sistema de archivos XFS

```bash
# sudo mkfs.xfs /dev/sdb2
Output: meta-data=/dev/sdb2
#         data     =
#         naming   =version 2
```


### 194. Montar partición

```bash
sudo mkdir -p /mnt/datos
sudo mount /dev/sdb1 /mnt/datos
df -h | grep /mnt/datos
Output: /dev/sdb1        99G  1.2G   93G   2% /mnt/datos
```


### 195. Desmontar partición

```bash
sudo umount /mnt/datos
# (Sin output si es exitoso)
```


### 196. Montar con opciones específicas

```bash
sudo mount -o rw,noatime /dev/sdb1 /mnt/datos
# (monta con lectura/escritura y sin actualizar access time)
```


### 197. Ver puntos de montaje activos

```bash
df -h
Output: Filesystem      Size  Used Avail Use% Mounted on
#         /dev/sda1        99G   45G   49G  48% /
#         tmpfs           7.8G  1.2M  7.8G   1% /dev/shm
#         /dev/sdb1        99G  1.2G   93G   2% /mnt/datos
```


### 198. Ver uso de disco por directorio

```bash
du -sh /home/kali/*
Output: 1.2G    /home/kali/Documents
#         523M    /home/kali/Downloads
#         89M     /home/kali/Pictures
#         12K     /home/kali/Desktop
```


### 199. Ver uso de disco con detalles

```bash
du -h --max-depth=1 /var/log
Output: 45M     /var/log/apt
#         123M    /var/log/journal
#         12M     /var/log/nginx
#         180M    /var/log
```


### 200. LVM - Crear volumen físico (ejemplo educativo)

```bash
# sudo pvcreate /dev/sdc
Output: Physical volume "/dev/sdc" successfully created
```


### 201. LVM - Crear grupo de volúmenes

```bash
# sudo vgcreate vg_datos /dev/sdc
Output: Volume group "vg_datos" successfully created
```


### 202. LVM - Crear volumen lógico

```bash
# sudo lvcreate -L 10G -n lv_apps vg_datos
Output: Logical volume "lv_apps" created
```


### 203. LVM - Extender volumen lógico

```bash
# sudo lvextend -L +5G /dev/vg_datos/lv_apps
Output: Size of logical volume vg_datos/lv_apps changed from 10.00 GiB to 15.00 GiB
```


### 204. LVM - Redimensionar sistema de archivos

```bash
# sudo resize2fs /dev/vg_datos/lv_apps
Output: Resizing the filesystem to 3932160 blocks
```


## SECCIÓN 22: GESTIÓN DE USUARIOS {#seccion-22}

### 205. Crear nuevo usuario

```bash
sudo useradd -m -s /bin/bash testuser
Output: (sin output si es exitoso)
```


### 206. Verificar creación

```bash
id testuser
Output: uid=1001(testuser) gid=1001(testuser) groups=1001(testuser)
```


### 207. Establecer contraseña para usuario

```bash
sudo passwd testuser
Output: Enter new UNIX password:
#         Retype new UNIX password:
#         passwd: password updated successfully
```


### 208. Agregar usuario a grupo sudo

```bash
sudo usermod -aG sudo testuser
id testuser
Output: uid=1001(testuser) gid=1001(testuser) groups=1001(testuser),27(sudo)
```


### 209. Bloquear cuenta de usuario

```bash
sudo usermod -L testuser
Output: (sin output si es exitoso)
```


### 210. Desbloquear cuenta de usuario

```bash
sudo usermod -U testuser
Output: (sin output si es exitoso)
```


### 211. Eliminar usuario (mantiene home)

```bash
sudo userdel testuser
Output: (sin output si es exitoso)
```


### 212. Eliminar usuario con su directorio home

```bash
sudo useradd -m testuser2
sudo userdel -r testuser2
Output: userdel: testuser2 mail spool (/var/mail/testuser2) not found
```


### 213. Ver información de usuario desde /etc/passwd

```bash
getent passwd kali
Output: kali:x:1000:1000:Kali,,,:/home/kali:/usr/bin/zsh
```


### 214. Ver grupos del usuario

```bash
groups kali
Output: kali sudo wireshark
```


### 215. Editar configuración de sudo de forma segura

```bash
sudo visudo
# (abre /etc/sudoers en editor seguro)
# Agregar línea: testuser ALL=(ALL:ALL) NOPASSWD: /usr/bin/nmap
```


### 216. Cambiar shell del usuario

```bash
sudo usermod -s /bin/zsh kali
getent passwd kali | cut -d: -f7
Output: /bin/zsh
```


## SECCIÓN 23: TRABAJOS EN SEGUNDO PLANO {#seccion-23}

### 217. Ejecutar comando en background

```bash
sleep 60 &
Output: [1] 23456
```


### 218. Ver trabajos activos

```bash
jobs
Output: [1]+  Running                 sleep 60 &
```


### 219. Traer trabajo a foreground

```bash
fg %1
# (El comando sleep 60 ahora está en primer plano)
# Presionar Ctrl+Z para suspender
```


### 220. Reanudar trabajo suspendido en background

```bash
bg %1
jobs
Output: [1]+  Running                 sleep 60 &
```


### 221. Desvincular trabajo del terminal

```bash
disown -h %1
# (El proceso continúa aunque se cierre el terminal)
```


### 222. Ejecutar comando que persiste tras cerrar sesión

```bash
nohup tar -czf backup.tar.gz /home/kali &
Output: nohup: ignoring input and appending output to 'nohup.out'
#         [1] 23567

cat nohup.out
Output: (salida del comando tar)
```


### 223. Múltiples trabajos en background

```bash
sleep 100 &
sleep 200 &
sleep 300 &
jobs
Output: [1]   Running                 sleep 100 &
#         [2]-  Running                 sleep 200 &
#         [3]+  Running                 sleep 300 &
```


### 224. Terminar trabajo específico

```bash
kill %2
jobs
Output: [1]   Running                 sleep 100 &
#         [2]-  Terminated              sleep 200
#         [3]+  Running                 sleep 300 &
```


## SECCIÓN 24: LOGS Y MONITOREO DEL SISTEMA {#seccion-24}

### 225. Ver logs del sistema con journalctl

```bash
sudo journalctl -xe
Output: (logs recientes con explicaciones extendidas)
```


### 226. Ver logs de servicio específico

```bash
sudo journalctl -u ssh.service
Output: Oct 13 09:00:15 kali systemd[1]: Starting OpenBSD Secure Shell server...
#         Oct 13 09:00:15 kali sshd[1523]: Server listening on 0.0.0.0 port 22
```


### 227. Seguir logs en tiempo real con journalctl

```bash
sudo journalctl -f
Output: (muestra logs conforme se generan)
# Presionar Ctrl+C para salir
```


### 228. Ver logs desde un tiempo específico

```bash
sudo journalctl --since "2025-10-13 16:00:00"
Output: (logs desde las 16:00 del 13 de octubre)
```


### 229. Ver logs de hoy

```bash
sudo journalctl --since today
Output: (todos los logs de hoy)
```


### 230. Monitorear log tradicional en tiempo real

```bash
tail -f /var/log/syslog
Output: Oct 13 18:25:34 kali systemd[1]: Started Session 123 of user kali
# Presionar Ctrl+C para salir
```


### 231. Monitorear log de autenticación

```bash
sudo tail -f /var/log/auth.log
Output: Oct 13 18:26:12 kali sudo: kali : TTY=pts/0 ; PWD=/home/kali ; USER=root
```


### 232. Ver mensajes del kernel

```bash
dmesg | tail -n 20
Output: [    5.234567] usb 1-1: new high-speed USB device number 2 using ehci-pci
#         [    5.456789] input: USB Optical Mouse as /devices/pci0000:00
```


### 233. Buscar errores en dmesg

```bash
dmesg | grep -i error
Output: [    2.345678] ACPI Error: Could not enable RealTimeClock event
#         [    3.456789] pci 0000:00:01.0: Error sending command
```


### 234. Ver memoria disponible

```bash
free -h
Output:               total        used        free      shared  buff/cache   available
#         Mem:            15Gi       3.2Gi       8.1Gi       156Mi       4.2Gi        11Gi
#         Swap:          1.0Gi          0B       1.0Gi
```


### 235. Ver uptime del sistema

```bash
uptime
Output: 18:30:45 up  9:30,  2 users,  load average: 0.52, 0.58, 0.62
```


### 236. Ver estadísticas de memoria virtual

```bash
vmstat 1 5
Output: procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----
#          r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st
#          1  0      0 8456789 123456 4567890    0    0    12    45  234  567  5  2 93  0  0
```


### 237. Ver estadísticas de I/O (si sysstat está instalado)

```bash
iostat -x 1 3
Output: avg-cpu:  %user   %nice %system %iowait  %steal   %idle
#                    5.23    0.00    2.45    0.12    0.00   92.20
```


### 238. Ver procesos con más uso de CPU

```bash
ps aux --sort=-%cpu | head -n 10
Output: USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
#         kali     12345 25.5  3.2 2345678 234567 ?      Sl   17:45   5:23 /usr/bin/firefox
```


### 239. Ver procesos con más uso de memoria

```bash
ps aux --sort=-%mem | head -n 10
Output: USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
#         kali     23456  2.3 15.8 3456789 1234567 ?     Sl   16:30  12:34 /opt/app
```


## SECCIÓN 25: SEGURIDAD SSH Y FIREWALL {#seccion-25}

### 240. Generar par de claves SSH (Ed25519 - recomendado)

```bash
ssh-keygen -t ed25519 -C "kali@localhost"
Output: Generating public/private ed25519 key pair.
#         Enter file in which to save the key (/home/kali/.ssh/id_ed25519):
#         Enter passphrase (empty for no passphrase):
#         Your identification has been saved in /home/kali/.ssh/id_ed25519
#         Your public key has been saved in /home/kali/.ssh/id_ed25519.pub
```


### 241. Generar claves RSA 4096 bits

```bash
ssh-keygen -t rsa -b 4096 -C "kali@localhost"
Output: (similar a ed25519)
```


### 242. Copiar clave pública a servidor remoto

```bash
ssh-copy-id usuario@192.168.1.50
Output: /usr/bin/ssh-copy-id: INFO: attempting to log in
#         usuario@192.168.1.50's password:
#         Number of key(s) added: 1
```


### 243. Verificar configuración SSH

```bash
cat /etc/ssh/sshd_config | grep -E "PermitRootLogin|PasswordAuthentication|Port"
Output: Port 22
#         PermitRootLogin no
#         PasswordAuthentication yes
```


### 244. Cambiar puerto SSH (editar configuración)

```bash
sudo sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
sudo grep "^Port" /etc/ssh/sshd_config
Output: Port 2222
```


### 245. Deshabilitar autenticación por contraseña

```bash
sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo grep "^PasswordAuthentication" /etc/ssh/sshd_config
Output: PasswordAuthentication no
```


### 246. Reiniciar servicio SSH para aplicar cambios

```bash
sudo systemctl restart sshd
sudo systemctl status sshd | grep Active
Output: Active: active (running)
```


### 247. Habilitar firewall UFW

```bash
sudo ufw enable
Output: Firewall is active and enabled on system startup
```


### 248. Permitir SSH en firewall

```bash
sudo ufw allow 22/tcp
Output: Rule added
#         Rule added (v6)
```


### 249. Permitir HTTP y HTTPS

```bash
sudo ufw allow 80,443/tcp
Output: Rule added
#         Rule added (v6)
```


### 250. Ver estado del firewall

```bash
sudo ufw status
Output: Status: active
#         To                         Action      From
#         --                         ------      ----
#         22/tcp                     ALLOW       Anywhere
#         80,443/tcp                 ALLOW       Anywhere
```


### 251. Ver reglas numeradas

```bash
sudo ufw status numbered
Output: Status: active
#              To                         Action      From
#              --                         ------      ----
#         [ 1] 22/tcp                     ALLOW IN    Anywhere
#         [ 2] 80,443/tcp                 ALLOW IN    Anywhere
```


### 252. Eliminar regla específica

```bash
sudo ufw delete 2
Output: Deleting:
#          allow 80,443/tcp
#         Proceed with operation (y|n)? y
```


### 253. Ver reglas de iptables

```bash
sudo iptables -L -n -v
Output: Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
#          pkts bytes target     prot opt in     out     source      destination
#           123 12345 ACCEPT     tcp  --  *      *       0.0.0.0/0   0.0.0.0/0
```


### 254. Agregar regla de iptables

```bash
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
sudo iptables -L INPUT -n | grep 8080
Output: ACCEPT     tcp  --  0.0.0.0/0      0.0.0.0/0      tcp dpt:8080
```


### 255. Ver reglas de nftables (si está en uso)

```bash
sudo nft list ruleset
Output: (muestra todas las reglas de nftables)
```


## SECCIÓN 26: HERRAMIENTAS DE PENTESTING {#seccion-26}

### 256. Escaneo básico con nmap

```bash
nmap -sC -sV -oN escaneo.txt 192.168.1.1
Output: Starting Nmap 7.94
#         PORT    STATE SERVICE VERSION
#         22/tcp  open  ssh     OpenSSH 8.9p1
#         80/tcp  open  http    Apache httpd 2.4.54
#         443/tcp open  ssl/http Apache httpd 2.4.54
```


### 257. Enumeración de subdominios con amass

```bash
amass enum -d example.com -o subdominios.txt
Output: www.example.com
#         mail.example.com
#         ftp.example.com
```


### 258. Enumeración con subfinder

```bash
subfinder -d example.com -o subs.txt
Output: [INF] Enumerating subdomains for example.com
#         www.example.com
#         api.example.com
```


### 259. Recolección de información con theHarvester

```bash
theHarvester -d example.com -b all -l 500 -f harvester.html
Output: [*] Target: example.com
#         [*] Searching in: all sources
#         Emails found: 15
#         Hosts found: 23
```


### 260. Identificar tecnologías web con whatweb

```bash
whatweb https://example.com
Output: https://example.com [200 OK] Apache[2.4.54], Country[US],
#         HTML5, HTTPServer[Apache/2.4.54], IP[93.184.216.34]
```


### 261. Escaneo de WordPress con wpscan

```bash
wpscan --url https://example.com --enumerate u,vp,vt
Output: [+] WordPress version 6.2.2
#         [+] WordPress theme in use: twentytwentythree
#         [+] Username: admin
```


### 262. Enumeración de directorios con gobuster

```bash
gobuster dir -u https://example.com -w /usr/share/wordlists/dirb/common.txt -k
Output: ===============================================================
#         /.git                 (Status: 301) [Size: 234]
#         /admin                (Status: 200) [Size: 1234]
#         /backup               (Status: 403) [Size: 567]
```


### 263. Capturar tráfico HTTP

```bash
sudo tcpdump -i eth0 -w captura_http.pcap port 80
Output: tcpdump: listening on eth0, link-type EN10MB
#         (Ctrl+C para detener)
```


### 264. Ver archivos abiertos por proceso

```bash
sudo lsof -i :80
Output: COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
#         apache2  1234   root    4u  IPv6  12345      0t0  TCP *:http (LISTEN)
```


### 265. Rastrear llamadas al sistema

```bash
strace -f -o salida.strace -p 1234
Output: (genera archivo con todas las syscalls del proceso 1234)
```


### 266. Buscar binarios SUID (escalada de privilegios)

```bash
find / -perm -4000 -type f 2>/dev/null > binarios_suid.txt
head -n 10 binarios_suid.txt
Output: /usr/bin/sudo
#         /usr/bin/passwd
#         /usr/bin/gpasswd
#         /usr/bin/newgrp
```


### 267. Buscar archivos escribibles por todos

```bash
find / -type f -perm -002 2>/dev/null | head -n 10
Output: /tmp/archivo_publico.txt
#         /var/tmp/compartido.log
```


### 268. Verificar rootkits con chkrootkit

```bash
sudo chkrootkit
Output: ROOTDIR is `/'
#         Checking `amd'... not found
#         Checking `basename'... not infected
#         Checking `ls'... not infected
```


### 269. Escanear rootkits con rkhunter

```bash
sudo rkhunter --check --skip-keypress
Output: [ Rootkit Hunter version 1.4.6 ]
#         Checking system commands...
#         [Press <ENTER> to continue]
#         Warning: Hidden files found
```


## SECCIÓN 27: SCRIPTING Y AUTOMATIZACIÓN {#seccion-27}

### 270. Crear script básico de backup

```bash
cat > backup_script.sh << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SRC="/home/kali/Documents"
DST="/backups/$(date +%F)"
mkdir -p "$DST"
rsync -av --delete "$SRC/" "$DST/"

echo "Backup completado: $DST"
EOF
```


### 271. Dar permisos de ejecución al script

```bash
chmod +x backup_script.sh
ls -l backup_script.sh
Output: -rwxr-xr-x 1 kali kali 234 Oct 13 18:45 backup_script.sh
```


### 272. Ejecutar script

```bash
./backup_script.sh
Output: sending incremental file list
#         ./
#         file1.txt
#         ...
#         Backup completado: /backups/2025-10-13
```


### 273. Crear script con función

```bash
cat > funciones.sh << 'EOF'
#!/bin/bash

backup_dir() {
    local src=$1
    local dst=$2
    echo "Respaldando $src -> $dst"
    rsync -av "$src/" "$dst/"
}

backup_dir "/home/kali/Documents" "/tmp/backup_docs"
EOF

chmod +x funciones.sh
./funciones.sh
Output: Respaldando /home/kali/Documents -> /tmp/backup_docs
```


### 274. Script con validación de argumentos

```bash
cat > validar.sh << 'EOF'
#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Uso: $0 <origen> <destino>"
    exit 1
fi

echo "Origen: $1"
echo "Destino: $2"
EOF

chmod +x validar.sh
./validar.sh
Output: Uso: ./validar.sh <origen> <destino>

./validar.sh /home /backup
Output: Origen: /home
#         Destino: /backup
```


### 275. Script con bucle

```bash
cat > procesar_logs.sh << 'EOF'
#!/bin/bash

for log in /var/log/*.log; do
    echo "Procesando: $log"
    lines=$(wc -l < "$log")
    echo "  Líneas: $lines"
done
EOF

chmod +x procesar_logs.sh
sudo ./procesar_logs.sh | head -n 6
Output: Procesando: /var/log/apt/history.log
#           Líneas: 1234
#         Procesando: /var/log/auth.log
#           Líneas: 5678
```


## SECCIÓN 28: ALIAS Y VARIABLES DE ENTORNO {#seccion-28}

### 276. Crear alias temporal

```bash
alias ll='ls -lah'
ll
Output: (equivalente a ls -lah)
```


### 277. Crear alias para comandos comunes

```bash
alias gs='git status'
alias gp='git push'
alias update='sudo apt-get update && sudo apt-get upgrade'
```


### 278. Ver todos los alias definidos

```bash
alias
Output: alias gs='git status'
#         alias gp='git push'
#         alias ll='ls -lah'
#         alias update='sudo apt-get update && sudo apt-get upgrade'
```


### 279. Eliminar alias

```bash
unalias ll
alias | grep ll
Output: (sin resultado)
```


### 280. Establecer variable de entorno

```bash
export EDITOR=vim
echo $EDITOR
Output: vim
```


### 281. Agregar directorio al PATH

```bash
export PATH="$HOME/bin:$PATH"
echo $PATH
Output: /home/kali/bin:/usr/local/bin:/usr/bin:/bin
```


### 282. Hacer cambios permanentes (agregar a .bashrc)

```bash
echo 'export EDITOR=vim' >> ~/.bashrc
echo 'alias ll="ls -lah"' >> ~/.bashrc
tail -n 2 ~/.bashrc
Output: export EDITOR=vim
#         alias ll="ls -lah"
```


### 283. Recargar configuración de bash

```bash
source ~/.bashrc
# (Sin output, recarga la configuración)
```


## SECCIÓN 29: HISTORIAL DE COMANDOS {#seccion-29}

### 284. Ver historial completo

```bash
history | tail -n 20
Output: 1234  ls -la
#         1235  cd /var/log
#         1236  tail -f syslog
```


### 285. Ejecutar comando del historial por número

```bash
!
```

---

## Siguiente lectura

| Guía | Enlace |
| :--- | :--- |
| Puertos de red y Nmap | [Network Ports Reference](ports.md) |
| Cliente FTP y transferencias | [FTP Cheat Sheet](ftp-cheatsheet.md) |
| Índice general | [Inicio](index.md) |