# Network Ports Reference

| [Inicio](index.md) | [Linux](linux-cheatsheet.md) · [Puertos](ports.md) · [FTP](ftp-cheatsheet.md) |
| :--- | :--- |

> [!NOTE]
> **19 secciones** · Catálogo de puertos, escaneo, firewall y herramientas de auditoría.

## Referencia rápida — puertos críticos

| Puerto | Servicio | Protocolo | Seguridad |
| :---: | :--- | :---: | :--- |
| 21 | FTP | TCP | ⚠️ Texto claro — usar SFTP |
| 22 | SSH | TCP | ✅ Cifrado |
| 23 | Telnet | TCP | ⚠️ Obsoleto — usar SSH |
| 25 | SMTP | TCP | Email saliente |
| 53 | DNS | TCP/UDP | Resolución de nombres |
| 80 | HTTP | TCP | ⚠️ Sin cifrado |
| 443 | HTTPS | TCP | ✅ Web cifrada |
| 445 | SMB | TCP | Compartición Windows |
| 3306 | MySQL | TCP | Base de datos |
| 3389 | RDP | TCP | Escritorio remoto |
| 8080 | HTTP-Alt | TCP | Servicios web alternativos |

| Herramienta | Uso |
| :--- | :--- |
| `nmap -sV -p- objetivo` | Escaneo completo con versiones |
| `nmap -sC -sV objetivo` | Scripts por defecto + versiones |
| `ss -tulpn` | Puertos locales en escucha |
| `netstat -tulpn` | Alternativa a `ss` |

## Table of Contents
1. [PUERTOS TCP FUNDAMENTALES](#seccion-1)
2. [PUERTOS DE BASES DE DATOS](#seccion-2)
3. [PUERTOS DE VPN Y TÚNELES](#seccion-3)
4. [PUERTOS DE ESCRITORIO REMOTO](#seccion-4)
5. [PUERTOS UDP IMPORTANTES](#seccion-5)
6. [PUERTOS DE SERVICIOS WEB](#seccion-6)
7. [PUERTOS DE JUEGOS Y P2P](#seccion-7)
8. [ESCANEO MASIVO DE PUERTOS](#seccion-8)
9. [DETECCIÓN DE SERVICIOS](#seccion-9)
10. [ANÁLISIS DE TRÁFICO](#seccion-10)
11. [NETSTAT Y SS (PUERTOS LOCALES)](#seccion-11)
12. [LSOF (LIST OPEN FILES)](#seccion-12)
13. [FIREWALL Y GESTIÓN DE PUERTOS](#seccion-13)
14. [PORT FORWARDING (REENVÍO)](#seccion-14)
15. [HERRAMIENTAS DE PENTESTING](#seccion-15)
16. [METASPLOIT PARA PUERTOS](#seccion-16)
17. [AUTOMATIZACIÓN CON SCRIPTS](#seccion-17)
18. [MONITOREO CONTINUO](#seccion-18)
19. [EXPORTAR Y DOCUMENTAR](#seccion-19)

---

## SECCIÓN 1: PUERTOS TCP FUNDAMENTALES {#seccion-1}

### 1. PUERTO 21 - FTP (File Transfer Protocol)

```bash
Descripción: Transferencia de archivos entre equipos
Protocolo: TCP
Seguridad: ⚠️ INSEGURO (No cifrado). Use SFTP o SCP en su lugar.

# Conectar a servidor FTP
ftp 192.168.1.100
Output: Connected to 192.168.1.100
#         220 FTP Server ready

# Verificar si el puerto 21 está abierto
nmap -p 21 192.168.1.100
Output: PORT   STATE SERVICE
#         21/tcp open  ftp

# Escanear con detección de versión
nmap -sV -p 21 192.168.1.100
Output: 21/tcp open  ftp     vsftpd 3.0.3

# Intentar conexión anónima
ftp 192.168.1.100
# Name: anonymous
# Password: [Enter]
Output: 230 Anonymous access granted
```


### 2. PUERTO 22 - SSH (Secure Shell)

```bash
Descripción: Acceso remoto seguro y cifrado
Protocolo: TCP
Seguridad: MUY SEGURO (cifrado end-to-end)

# Conectar por SSH
ssh usuario@192.168.1.50
Output: usuario@192.168.1.50's password:
#         Welcome to Ubuntu 22.04 LTS

# Conectar con puerto específico
ssh -p 2222 usuario@servidor.com
Output: (conexión en puerto personalizado)

# Verificar puerto SSH abierto
nmap -p 22 192.168.1.50
Output: 22/tcp open  ssh

# Escanear con scripts NSE
nmap -p 22 --script ssh-auth-methods 192.168.1.50
Output: | ssh-auth-methods:
#         |   Supported authentication methods:
#         |     publickey
#         |     password

# Brute force SSH con Metasploit
msfconsole
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.1.50
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME admin
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/rockyou.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run
Output: [+] 192.168.1.50:22 - Success: 'admin:password123'
```


### 3. PUERTO 23 - TELNET

```bash
Descripción: Acceso remoto NO cifrado (obsoleto)
Protocolo: TCP
Seguridad: ⚠️ PELIGROSO (Texto claro). Use SSH (Puerto 22) en su lugar.

# Conectar por Telnet
telnet 192.168.1.10
Output: Trying 192.168.1.10...
#         Connected to 192.168.1.10
#         login:

# Escanear puerto Telnet
nmap -p 23 192.168.1.10
Output: 23/tcp open  telnet

# Capturar credenciales Telnet con Wireshark
sudo tcpdump -i eth0 port 23 -w telnet_capture.pcap
# (Las credenciales se verán en texto plano)
```


### 4. PUERTO 25 - SMTP (Simple Mail Transfer Protocol)

```bash
Descripción: Envío de correos electrónicos
Protocolo: TCP
# Puertos alternativos: 26, 2525, 587 (SMTP SSL)

# Conectar a servidor SMTP
telnet mail.example.com 25
Output: 220 mail.example.com ESMTP Postfix
HELO kali
Output: 250 mail.example.com
MAIL FROM:<test@kali.local>
Output: 250 Ok
RCPT TO:<admin@example.com>
Output: 250 Ok

# Escanear SMTP
nmap -p 25 --script smtp-commands mail.example.com
Output: | smtp-commands: mail.example.com, SIZE 10240000, VRFY, ETRN
#         |_ AUTH PLAIN LOGIN

# Enumeración de usuarios SMTP
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t mail.example.com
Output: admin@example.com exists
#         root@example.com exists
```


### 5. PUERTO 53 - DNS (Domain Name System)

```bash
Descripción: Resolución de nombres de dominio
Protocolo: TCP y UDP
# Puerto DNS over TLS: 853

# Consulta DNS simple
dig google.com
Output: ;; ANSWER SECTION:
#         google.com.  300  IN  A  142.250.185.46

# Consulta DNS con servidor específico
dig @8.8.8.8 example.com
Output: ;; SERVER: 8.8.8.8#53(8.8.8.8)

# Enumeración DNS
nmap -p 53 --script dns-zone-transfer 192.168.1.5
Output: (intenta transferencia de zona)

# Consultar registros MX (correo)
dig mx gmail.com
Output: gmail.com.  3600  IN  MX  5 gmail-smtp-in.l.google.com.

# Consultar registros TXT
dig txt example.com
Output: example.com.  300  IN  TXT  "v=spf1 mx ~all"

# DNSRecon para enumeración completa
dnsrecon -d example.com
Output: [*] Performing General Enumeration
#         [*] A example.com 93.184.216.34
#         [*] MX mail.example.com 10
```


### 6. PUERTO 80 - HTTP (HyperText Transfer Protocol)

```bash
Descripción: Navegación web NO cifrada
Protocolo: TCP
Seguridad: ⚠️ INSEGURO (No cifrado). Use HTTPS (Puerto 443) en su lugar.

# Solicitud HTTP con curl
curl http://example.com
Output: <!doctype html><html>...</html>

# Ver encabezados HTTP
curl -I http://example.com
Output: HTTP/1.1 200 OK
#         Server: Apache/2.4.54
#         Content-Type: text/html

# Escanear puerto 80
nmap -p 80 -sV 192.168.1.100
Output: 80/tcp open  http    Apache httpd 2.4.54

# Escanear vulnerabilidades HTTP
nmap -p 80 --script http-vuln* 192.168.1.100
Output: (lista de vulnerabilidades encontradas)

# Enumeración de directorios con Gobuster
gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt
Output: /.git                 (Status: 301)
#         /admin                (Status: 200)
#         /backup               (Status: 403)

# Nikto web scanner
nikto -h http://192.168.1.100
Output: - Nikto v2.5.0
#         + Server: Apache/2.4.54
#         + OSVDB-3233: /icons/README: Apache default file found
```


### 7. PUERTO 110 - POP3 (Post Office Protocol v3)

```bash
Descripción: Recepción de correo electrónico
Protocolo: TCP
# Puerto seguro: 995 (POP3 SSL)

# Conectar a servidor POP3
telnet mail.example.com 110
Output: +OK POP3 server ready
USER usuario
Output: +OK
PASS password123
Output: +OK Logged in
LIST
Output: +OK 3 messages
#         1 2048
#         2 4096

# Escanear POP3
nmap -p 110 --script pop3-capabilities mail.example.com
Output: | pop3-capabilities:
#         |   USER
#         |   TOP
#         |_  UIDL
```


### 8. PUERTO 143 - IMAP (Internet Message Access Protocol)

```bash
Descripción: Gestión de correo electrónico (más avanzado que POP3)
Protocolo: TCP
# Puerto seguro: 993 (IMAP SSL)

# Conectar a IMAP
telnet mail.example.com 143
Output: * OK IMAP4rev1 Service Ready
a001 LOGIN usuario password123
Output: a001 OK LOGIN completed
a002 LIST "" "*"
Output: * LIST () "/" INBOX
#         * LIST () "/" Sent

# Escanear IMAP
nmap -p 143 --script imap-capabilities mail.example.com
Output: | imap-capabilities:
#         |   IMAP4rev1
#         |   LITERAL+
#         |_  IDLE
```


### 9. PUERTO 443 - HTTPS (HTTP Secure)

```bash
Descripción: Navegación web cifrada con TLS/SSL
Protocolo: TCP
Seguridad: SEGURO (cifrado end-to-end)

# Solicitud HTTPS
curl https://example.com
Output: (contenido HTML cifrado en tránsito)

# Ver certificado SSL
openssl s_client -connect example.com:443
Output: Certificate chain
#         0 s:CN = example.com
#         i:C = US, O = Let's Encrypt

# Escanear HTTPS con SSLyze
sslyze --regular example.com:443
Output: * SSL 2.0 Cipher Suites: Server rejected all cipher suites
#         * TLS 1.3 Cipher Suites: Server supports TLS 1.3

# Testear vulnerabilidades SSL
nmap -p 443 --script ssl-heartbleed example.com
Output: (detecta Heartbleed si existe)

# Verificar certificado con curl
curl -vI https://example.com 2>&1 | grep -i "SSL\|TLS"
Output: * SSL connection using TLSv1.3 / TLS_AES_256_GCM_SHA384
```


### 10. PUERTO 445 - SMB (Server Message Block)

```bash
Descripción: Compartición de archivos en Windows
Protocolo: TCP
# También usado por: Active Directory, CIFS

# Enumerar recursos compartidos SMB
smbclient -L //192.168.1.10 -N
Output: Sharename       Type      Comment
#         ---------       ----      -------
#         ADMIN$          Disk      Remote Admin
#         C$              Disk      Default share
#         IPC$            IPC       Remote IPC
#         Users           Disk

# Conectar a recurso compartido
smbclient //192.168.1.10/Users -U usuario
# Password: [ingresar]
Output: smb: \>

# Escanear SMB con Nmap
nmap -p 445 --script smb-enum-shares 192.168.1.10
Output: | smb-enum-shares:
#         |   account_used: guest
#         |   \\192.168.1.10\Users:
#         |     Type: STYPE_DISKTREE

# Detectar versión SMB
nmap -p 445 --script smb-protocols 192.168.1.10
Output: | smb-protocols:
#         |   dialects:
#         |     2.0.2
#         |     2.1
#         |     3.0
#         |_    3.1.1

# Enum4linux para enumeración completa
enum4linux -a 192.168.1.10
Output: [+] Got OS info for 192.168.1.10 from smbclient:
#         [+] OS: Windows 10 Pro
#         [+] Domain: WORKGROUP
#         [+] Users: Administrator, Guest, usuario1
```


## SECCIÓN 2: PUERTOS DE BASES DE DATOS {#seccion-2}

### 11. PUERTO 3306 - MySQL/MariaDB

```bash
Descripción: Base de datos relacional
Protocolo: TCP

# Conectar a MySQL
mysql -h 192.168.1.25 -u root -p
# Password: [ingresar]
Output: mysql>

# Escanear MySQL
nmap -p 3306 --script mysql-info 192.168.1.25
Output: | mysql-info:
#         |   Protocol: 10
#         |   Version: 8.0.32-0ubuntu0.22.04.2
#         |_  Thread ID: 12

# Brute force MySQL
nmap -p 3306 --script mysql-brute 192.168.1.25
Output: | mysql-brute:
#         |   Accounts:
#         |     root:toor - Valid credentials
#         |_  Statistics: Performed 150 guesses

# Enumeración de bases de datos
nmap -p 3306 --script mysql-databases --script-args mysqluser=root,mysqlpass=password 192.168.1.25
Output: | mysql-databases:
#         |   information_schema
#         |   mysql
#         |   production_db
#         |_  test
```


### 12. PUERTO 5432 - PostgreSQL

```bash
Descripción: Base de datos relacional avanzada
Protocolo: TCP

# Conectar a PostgreSQL
psql -h 192.168.1.30 -U postgres -d postgres
# Password: [ingresar]
Output: postgres=#

# Escanear PostgreSQL
nmap -p 5432 --script pgsql-brute 192.168.1.30
Output: | pgsql-brute:
#         |   Accounts:
#         |     postgres:postgres - Valid credentials
```


### 13. PUERTO 1433 - Microsoft SQL Server (MSSQL)

```bash
Descripción: Base de datos de Microsoft
Protocolo: TCP

# Conectar con mssqlclient
mssqlclient.py sa:Password123@192.168.1.35
Output: SQL>

# Escanear MSSQL
nmap -p 1433 --script ms-sql-info 192.168.1.35
Output: | ms-sql-info:
#         |   Windows server name: SQLSERVER01
#         |   Instance name: MSSQLSERVER
#         |_  Version: Microsoft SQL Server 2019

# Enumeración con Metasploit
msfconsole
msf6 > use auxiliary/scanner/mssql/mssql_login
msf6 auxiliary(scanner/mssql/mssql_login) > set RHOSTS 192.168.1.35
msf6 auxiliary(scanner/mssql/mssql_login) > set USERNAME sa
msf6 auxiliary(scanner/mssql/mssql_login) > set PASSWORD Password123
msf6 auxiliary(scanner/mssql/mssql_login) > run
Output: [+] 192.168.1.35:1433 - Login Successful: WORKSTATION\sa:Password123
```


### 14. PUERTO 27017 - MongoDB

```bash
Descripción: Base de datos NoSQL
Protocolo: TCP

# Conectar a MongoDB
mongo --host 192.168.1.40
Output: MongoDB shell version v5.0.15
#         connecting to: mongodb://192.168.1.40:27017/

# Escanear MongoDB
nmap -p 27017 --script mongodb-info 192.168.1.40
Output: | mongodb-info:
#         |   MongoDB Build info:
#         |     version = 5.0.15
#         |_  Server status: OK

# Enumeración de bases de datos
mongo 192.168.1.40
> show dbs
Output: admin     0.000GB
#         config    0.000GB
#         local     0.000GB
#         users_db  0.050GB
```


### 15. PUERTO 6379 - Redis

```bash
Descripción: Base de datos en memoria (clave-valor)
Protocolo: TCP

# Conectar a Redis
redis-cli -h 192.168.1.45
Output: 192.168.1.45:6379>

# Listar todas las claves
192.168.1.45:6379> KEYS *
Output: 1) "user:1000"
#         2) "session:abc123"
#         3) "cache:homepage"

# Escanear Redis
nmap -p 6379 --script redis-info 192.168.1.45
Output: | redis-info:
#         |   Version: 7.0.8
#         |   Operating System: Linux 5.15.0-76-generic x86_64
#         |_  Architecture: 64 bits
```


## SECCIÓN 3: PUERTOS DE VPN Y TÚNELES {#seccion-3}

### 16. PUERTO 1194 - OpenVPN

```bash
Descripción: VPN de código abierto
Protocolo: TCP y UDP (UDP es más común)

# Conectar a OpenVPN
openvpn --config client.ovpn
Output: Initialization Sequence Completed

# Escanear OpenVPN
nmap -p 1194 --script openvpn-info 192.168.1.50
Output: | openvpn-info:
#         |   Protocol: OpenVPN 2.5
#         |_  Cipher: AES-256-GCM
```


### 17. PUERTO 1723 - PPTP VPN

```bash
Descripción: VPN obsoleta (insegura)
Protocolo: TCP

# Escanear PPTP
nmap -p 1723 192.168.1.55
Output: 1723/tcp open  pptp
```


### 18. PUERTO 500 y 4500 - IPsec VPN

```bash
Descripción: VPN corporativa segura
Protocolo: UDP

# Puerto 500: ISAKMP (fase 1 IPsec)
# Puerto 4500: NAT Traversal (fase 2 IPsec)

# Escanear IPsec
nmap -sU -p 500,4500 192.168.1.60
Output: 500/udp  open  isakmp
#         4500/udp open  nat-t-ike
```


### 19. PUERTO 51820 - WireGuard VPN

```bash
Descripción: VPN moderna y rápida
Protocolo: UDP

# Verificar WireGuard
sudo wg show
Output: interface: wg0
#         public key: abc123...
#         listening port: 51820

# Escanear WireGuard
nmap -sU -p 51820 192.168.1.65
Output: 51820/udp open|filtered unknown
```


## SECCIÓN 4: PUERTOS DE ESCRITORIO REMOTO {#seccion-4}

### 20. PUERTO 3389 - RDP (Remote Desktop Protocol)

```bash
Descripción: Escritorio remoto de Windows
Protocolo: TCP
Seguridad: ALTA PRIORIDAD para atacantes

# Conectar con RDP desde Linux
rdesktop 192.168.1.70
# (Abre ventana de escritorio remoto)

# O con xfreerdp (más moderno)
xfreerdp /v:192.168.1.70 /u:Administrator
# Password: [ingresar]

# Escanear RDP
nmap -p 3389 --script rdp-enum-encryption 192.168.1.70
Output: | rdp-enum-encryption:
#         |   Security layer: RDP Security Layer
#         |   RDP Protocol version: RDP 10.7
#         |_  Encryption level: High (128-bit)

# Detectar versión RDP
nmap -p 3389 --script rdp-ntlm-info 192.168.1.70
Output: | rdp-ntlm-info:
#         |   Target_Name: WORKSTATION
#         |   NetBIOS_Computer_Name: WIN10-PC
#         |_  DNS_Computer_Name: win10-pc.local

# Brute force RDP con Hydra
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.1.70
Output: [3389][rdp] host: 192.168.1.70   login: Administrator   password: P@ssw0rd
```


### 21. PUERTO 5900 - VNC (Virtual Network Computing)

```bash
Descripción: Escritorio remoto multiplataforma
Protocolo: TCP
# Puertos: 5900-5906 (múltiples sesiones)

# Conectar con VNC
vncviewer 192.168.1.75:5900
# Password: [ingresar]

# Escanear VNC
nmap -p 5900-5906 --script vnc-info 192.168.1.75
Output: | vnc-info:
#         |   Protocol version: 3.8
#         |   Security types:
#         |_    VNC Authentication (2)

# Brute force VNC
nmap -p 5900 --script vnc-brute 192.168.1.75
Output: | vnc-brute:
#         |   Accounts:
#         |     password123 - Valid credentials
```


## SECCIÓN 5: PUERTOS UDP IMPORTANTES {#seccion-5}

### 22. PUERTO 67/68 - DHCP (Dynamic Host Configuration Protocol)

```bash
Descripción: Asignación automática de IPs
Protocolo: UDP
# Puerto 67: Servidor DHCP
# Puerto 68: Cliente DHCP

# Escanear DHCP
nmap -sU -p 67 192.168.1.1
Output: 67/udp open  dhcps

# Capturar tráfico DHCP
sudo tcpdump -i eth0 port 67 or port 68 -v
Output: DHCP-Message Option 53, length 1: Discover
#         DHCP-Message Option 53, length 1: Offer
```


### 23. PUERTO 69 - TFTP (Trivial File Transfer Protocol)

```bash
Descripción: Transferencia simple de archivos
Protocolo: UDP
Seguridad: SIN autenticación

# Descargar archivo con TFTP
tftp 192.168.1.80
tftp> get config.txt
Output: Received 1024 bytes in 0.1 seconds

# Subir archivo
tftp> put backup.txt
Output: Sent 2048 bytes in 0.2 seconds

# Escanear TFTP
nmap -sU -p 69 --script tftp-enum 192.168.1.80
Output: | tftp-enum:
#         |   config.txt
#         |   firmware.bin
#         |_  passwords.txt
```


### 24. PUERTO 123 - NTP (Network Time Protocol)

```bash
Descripción: Sincronización de tiempo
Protocolo: UDP

# Consultar servidor NTP
ntpdate -q pool.ntp.org
Output: server 162.159.200.123, stratum 3, offset 0.001234

# Sincronizar hora
sudo ntpdate -s pool.ntp.org
# (Sin output si es exitoso)

# Escanear NTP
nmap -sU -p 123 --script ntp-info 192.168.1.85
Output: | ntp-info:
#         |   receive time stamp: 2025-10-13T22:15:30
#         |   version: ntpd 4.2.8p15
#         |_  processor: x86_64

# Ataque de amplificación NTP
nmap -sU -p 123 --script ntp-monlist 192.168.1.85
Output: (lista de hosts que han consultado el servidor)
```


### 25. PUERTO 161/162 - SNMP (Simple Network Management Protocol)

```bash
Descripción: Monitoreo y gestión de dispositivos de red
Protocolo: UDP
# Puerto 161: Consultas SNMP
# Puerto 162: Traps SNMP

# Enumeración SNMP con onesixtyone
onesixtyone 192.168.1.90 -c /usr/share/doc/onesixtyone/dict.txt
Output: Scanning 1 hosts, 2 communities
#         192.168.1.90 [public] Linux router 3.10.0

# Enumeración detallada con snmpwalk
snmpwalk -v 2c -c public 192.168.1.90
Output: SNMPv2-MIB::sysDescr.0 = STRING: Linux router 3.10.0
#         SNMPv2-MIB::sysObjectID.0 = OID: NET-SNMP-MIB::netSnmpAgentOIDs.10
#         SNMPv2-MIB::sysUpTime.0 = Timeticks: (123456789) 14 days, 6:56:07

# Obtener información del sistema
snmpget -v 2c -c public 192.168.1.90 1.3.6.1.2.1.1.1.0
Output: SNMPv2-MIB::sysDescr.0 = STRING: Cisco IOS Software

# Brute force community strings
nmap -sU -p 161 --script snmp-brute 192.168.1.90
Output: | snmp-brute:
#         |   public - Valid credentials
#         |_  private - Valid credentials
```


## SECCIÓN 6: PUERTOS DE SERVICIOS WEB {#seccion-6}

### 26. PUERTO 8080 - HTTP Alternativo

```bash
Descripción: Puerto web alternativo (testing, proxies)
Protocolo: TCP

# Solicitar contenido en puerto 8080
curl http://192.168.1.95:8080
Output: <!DOCTYPE html>...

# Escanear puerto 8080
nmap -p 8080 -sV 192.168.1.95
Output: 8080/tcp open  http-proxy Squid http proxy 5.7
```


### 27. PUERTO 8443 - HTTPS Alternativo

```bash
Descripción: HTTPS alternativo
Protocolo: TCP

# Solicitud HTTPS en 8443
curl -k https://192.168.1.95:8443
Output: (contenido web)
```


### 28. PUERTO 2082/2083 - cPanel

```bash
Descripción: Panel de control de hosting
Protocolo: TCP
# 2082: HTTP
# 2083: HTTPS

# Acceder a cPanel
curl https://servidor.com:2083
Output: (página de login cPanel)
```


### 29. PUERTO 10000 - Webmin

```bash
Descripción: Panel de administración web para Linux
Protocolo: TCP

# Escanear Webmin
nmap -p 10000 --script http-title 192.168.1.100
Output: | http-title: Login to Webmin
#         |_Requested resource was https://192.168.1.100:10000/
```


## SECCIÓN 7: PUERTOS DE JUEGOS Y P2P {#seccion-7}

### 30. PUERTO 3074 - Xbox Live

```bash
Descripción: Servicio online de Xbox
Protocolo: TCP y UDP

# Verificar puerto Xbox
nmap -p 3074 192.168.1.105
Output: 3074/tcp open  xbox
```


### 31. PUERTO 25565 - Minecraft

```bash
Descripción: Servidor de Minecraft Java Edition
Protocolo: TCP

# Conectar a servidor Minecraft (desde cliente)
# Server: minecraft.ejemplo.com:25565

# Escanear Minecraft
nmap -p 25565 --script minecraft-ping minecraft.ejemplo.com
Output: | minecraft-ping:
#         |   Version: 1.20.1
#         |   Protocol: 763
#         |   Players: 15/100
#         |_  MOTD: Welcome to my server
```


### 32. PUERTOS 6881-6889 - BitTorrent

```bash
Descripción: Protocolo P2P para descargas
Protocolo: TCP y UDP

# Verificar puertos BitTorrent
nmap -p 6881-6889 192.168.1.110
Output: 6881/tcp open  bittorrent
#         6889/tcp open  bittorrent
```


### 33. PUERTO 4662/4672 - eMule

```bash
Descripción: Cliente P2P clásico
Protocolo: TCP (4662) y UDP (4672)

# Escanear eMule
nmap -p 4662,4672 192.168.1.115
Output: 4662/tcp open  edonkey
#         4672/udp open  edonkey
```


## SECCIÓN 8: ESCANEO MASIVO DE PUERTOS {#seccion-8}

### 34. Escaneo rápido de puertos comunes

```bash
nmap --top-ports 100 192.168.1.0/24
Output: (escanea los 100 puertos más comunes en toda la red)
```


### 35. Escaneo completo de todos los puertos

```bash
nmap -p- 192.168.1.50
Output: (escanea los 65535 puertos)
```


### 36. Escaneo agresivo con detección de OS

```bash
sudo nmap -A 192.168.1.50
Output: PORT     STATE SERVICE VERSION
#         22/tcp   open  ssh     OpenSSH 8.9p1
#         80/tcp   open  http    Apache httpd 2.4.54
#         443/tcp  open  ssl/http Apache httpd 2.4.54
#         OS details: Linux 5.15
```


### 37. Escaneo con scripts NSE

```bash
nmap -p 80,443 --script http-enum,http-vuln* 192.168.1.50
Output: (detecta vulnerabilidades web)
```


### 38. Escaneo UDP (más lento)

```bash
sudo nmap -sU --top-ports 20 192.168.1.50
Output: PORT    STATE         SERVICE
#         53/udp  open          domain
#         67/udp  open|filtered dhcps
#         123/udp open          ntp
#         161/udp open          snmp
```


### 39. Escaneo sigiloso (SYN Scan)

```bash
sudo nmap -sS 192.168.1.50
Output: (escaneo sin completar handshake TCP)
```


### 40. Escaneo con evasión de firewall

```bash
nmap -f -D RND:10 192.168.1.50
Output: (fragmenta paquetes y usa señuelos)
```


## SECCIÓN 9: DETECCIÓN DE SERVICIOS {#seccion-9}

### 41. Detección de versiones de servicios

```bash
nmap -sV --version-intensity 5 192.168.1.50
Output: 22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux)
#         80/tcp open  http    Apache httpd 2.4.54 ((Ubuntu))
```


### 42. Fingerprinting de OS

```bash
sudo nmap -O 192.168.1.50
Output: Running: Linux 5.X
#         OS details: Linux 5.10 - 5.15
#         Network Distance: 1 hop
```


### 43. Detección de firewall

```bash
nmap -sA -p 80,443 192.168.1.50
Output: PORT    STATE      SERVICE
#         80/tcp  unfiltered http
#         443/tcp unfiltered https
```


## SECCIÓN 10: ANÁLISIS DE TRÁFICO {#seccion-10}

### 44. Capturar tráfico en puerto específico

```bash
sudo tcpdump -i eth0 port 80 -w http_traffic.pcap
Output: tcpdump: listening on eth0
#         ^C (Ctrl+C para detener)
#         15 packets captured
```


### 45. Capturar múltiples puertos

```bash
sudo tcpdump -i eth0 'port 22 or port 80 or port 443' -w multi_port.pcap
Output: (captura tráfico de SSH, HTTP y HTTPS)
```


### 46. Filtrar por protocolo

```bash
sudo tcpdump -i eth0 tcp port 3389 -w rdp_traffic.pcap
Output: (solo tráfico RDP)
```


### 47. Ver tráfico en tiempo real

```bash
sudo tcpdump -i eth0 -n -A port 80
Output: (muestra contenido HTTP en ASCII)
```


### 48. Analizar archivo PCAP con Wireshark

```bash
wireshark http_traffic.pcap
# (Abre interfaz gráfica)

# O desde terminal con tshark
tshark -r http_traffic.pcap -Y "http.request.method == GET"
Output: (muestra solo peticiones GET HTTP)
```


## SECCIÓN 11: NETSTAT Y SS (PUERTOS LOCALES) {#seccion-11}

### 49. Ver todos los puertos escuchando (TCP)

```bash
sudo netstat -tlnp
Output: Proto Recv-Q Send-Q Local Address   Foreign Address State    PID/Program
#         tcp        0      0 0.0.0.0:22      0.0.0.0:*       LISTEN   1523/sshd
#         tcp        0      0 127.0.0.1:631   0.0.0.0:*       LISTEN   2345/cupsd
#         tcp        0      0 0.0.0.0:80      0.0.0.0:*       LISTEN   3456/apache2
```


### 50. Ver conexiones activas

```bash
netstat -ant
Output: Proto Recv-Q Send-Q Local Address    Foreign Address   State
#         tcp        0      0 192.168.1.100:45678 93.184.216.34:80 ESTABLISHED
```


### 51. Ver puertos UDP

```bash
sudo netstat -ulnp
Output: Proto Recv-Q Send-Q Local Address Foreign Address State   PID/Program
#         udp        0      0 0.0.0.0:68    0.0.0.0:*               987/dhclient
#         udp        0      0 127.0.0.1:53  0.0.0.0:*               654/systemd-r
```


### 52. Usar ss (comando moderno, más rápido)

```bash
ss -tlnp
Output: State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
#         LISTEN 0      128    0.0.0.0:22          0.0.0.0:*     users:(("sshd",pid=1523))
#         LISTEN 0      128    0.0.0.0:80          0.0.0.0:*     users:(("apache2",pid=3456))
```


### 53. Ver solo procesos escuchando en puerto específico

```bash
sudo ss -tlnp | grep :80
Output: LISTEN 0  128  0.0.0.0:80  0.0.0.0:*  users:(("apache2",pid=3456))
```


### 54. Ver estadísticas de puertos

```bash
ss -s
Output: Total: 542 (kernel 0)
#         TCP:   15 (estab 5, closed 2, orphaned 0, synrecv 0, timewait 2/0)
#         UDP:   8
```


## SECCIÓN 12: LSOF (LIST OPEN FILES) {#seccion-12}

### 55. Ver qué proceso usa un puerto específico

```bash
sudo lsof -i :80
Output: COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
#         apache2  3456   root    4u  IPv6  12345      0t0  TCP *:http (LISTEN)
```


### 56. Ver todos los puertos TCP escuchando

```bash
sudo lsof -iTCP -sTCP:LISTEN
Output: COMMAND  PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
#         sshd    1523  root    3u  IPv4  11111      0t0  TCP *:ssh (LISTEN)
#         apache2 3456  root    4u  IPv6  12345      0t0  TCP *:http (LISTEN)
```


### 57. Ver conexiones de un proceso específico

```bash
sudo lsof -i -a -p 3456
Output: (conexiones del proceso Apache con PID 3456)
```


### 58. Ver puertos usados por usuario específico

```bash
lsof -i -u kali
Output: (puertos abiertos por el usuario kali)
```


## SECCIÓN 13: FIREWALL Y GESTIÓN DE PUERTOS {#seccion-13}

### 59. Ver reglas de firewall (UFW)

```bash
sudo ufw status
Output: Status: active
#         To                         Action      From
#         --                         ------      ----
#         22/tcp                     ALLOW       Anywhere
#         80,443/tcp                 ALLOW       Anywhere
```


### 60. Permitir puerto específico

```bash
sudo ufw allow 8080/tcp
Output: Rule added
#         Rule added (v6)
```


### 61. Permitir rango de puertos

```bash
sudo ufw allow 6000:6100/tcp
Output: Rule added
#         Rule added (v6)
```


### 62. Denegar puerto

```bash
sudo ufw deny 23/tcp
Output: Rule added
#         Rule added (v6)
```


### 63. Eliminar regla de puerto

```bash
sudo ufw delete allow 8080/tcp
Output: Rule deleted
#         Rule deleted (v6)
```


### 64. Ver reglas con iptables

```bash
sudo iptables -L -n -v
Output: Chain INPUT (policy ACCEPT 0 packets, 0 bytes)
#          pkts bytes target     prot opt in     out     source      destination
#           123 12345 ACCEPT     tcp  --  *      *       0.0.0.0/0   0.0.0.0/0   tcp dpt:22
```


### 65. Bloquear puerto con iptables

```bash
sudo iptables -A INPUT -p tcp --dport 23 -j DROP
Output: (sin salida si es exitoso)
```


### 66. Permitir puerto con iptables

```bash
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
Output: (sin salida si es exitoso)
```


### 67. Guardar reglas de iptables

```bash
sudo iptables-save > /etc/iptables/rules.v4
Output: (reglas guardadas)
```


## SECCIÓN 14: PORT FORWARDING (REENVÍO) {#seccion-14}

### 68. Reenvío de puerto con SSH (Local Port Forwarding)

```bash
ssh -L 8080:localhost:80 usuario@192.168.1.50
# Ahora localhost:8080 -> 192.168.1.50:80

# Verificar
curl http://localhost:8080
Output: (contenido del servidor remoto en puerto 80)
```


### 69. Reenvío remoto (Remote Port Forwarding)

```bash
ssh -R 9090:localhost:3000 usuario@servidor.com
# servidor.com:9090 -> localhost:3000
```


### 70. Túnel dinámico (SOCKS Proxy)

```bash
ssh -D 1080 usuario@192.168.1.50
# Ahora puedes usar localhost:1080 como proxy SOCKS

# Configurar navegador para usar proxy
curl --socks5 localhost:1080 http://example.com
Output: (tráfico pasa por el túnel SSH)
```


## SECCIÓN 15: HERRAMIENTAS DE PENTESTING {#seccion-15}

### 71. Masscan - Escaneo ultrarrápido

```bash
sudo masscan -p1-65535 192.168.1.0/24 --rate=1000
Output: Discovered open port 22/tcp on 192.168.1.50
#         Discovered open port 80/tcp on 192.168.1.50
#         Discovered open port 443/tcp on 192.168.1.50
```


### 72. Escaneo de puertos específicos con Masscan

```bash
sudo masscan -p22,80,443,3389,8080 192.168.1.0/24
Output: (escanea solo esos puertos en toda la red)
```


### 73. Unicornscan - Escaneo con correlación

```bash
sudo unicornscan -mT 192.168.1.50:1-1000
Output: TCP open                     ssh[   22]  from 192.168.1.50
#         TCP open                    http[   80]  from 192.168.1.50
```


### 74. Hping3 - Manipulación de paquetes

```bash
sudo hping3 -S 192.168.1.50 -p 80 -c 5
Output: HPING 192.168.1.50 (eth0 192.168.1.50): S set, 40 headers + 0 data bytes
#         len=46 ip=192.168.1.50 ttl=64 DF id=0 sport=80 flags=SA seq=0
```


### 75. Zmap - Escaneo de Internet masivo

```bash
sudo zmap -p 80 192.168.1.0/24
Output: (lista de IPs con puerto 80 abierto)
```


## SECCIÓN 16: METASPLOIT PARA PUERTOS {#seccion-16}

### 76. Escaneo de puertos con Metasploit

```bash
msfconsole
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 21,22,23,80,443,3389
msf6 auxiliary(scanner/portscan/tcp) > run
Output: [+] 192.168.1.50:22 - TCP OPEN
#         [+] 192.168.1.50:80 - TCP OPEN
#         [+] 192.168.1.75:3389 - TCP OPEN
```


### 77. Escaneo de servicios SMB

```bash
msf6 > use auxiliary/scanner/smb/smb_version
msf6 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.1.0/24
msf6 auxiliary(scanner/smb/smb_version) > run
Output: [+] 192.168.1.10:445 - Host is running Windows 10 Build 19041
```


### 78. Brute force de servicios

```bash
msf6 > use auxiliary/scanner/ssh/ssh_login
msf6 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.168.1.50
msf6 auxiliary(scanner/ssh/ssh_login) > set USERNAME root
msf6 auxiliary(scanner/ssh/ssh_login) > set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
msf6 auxiliary(scanner/ssh/ssh_login) > run
Output: [+] 192.168.1.50:22 - Success: 'root:toor'
```


## SECCIÓN 17: AUTOMATIZACIÓN CON SCRIPTS {#seccion-17}

### 79. Script Bash para escaneo de puertos comunes

```bash
cat > port_scan.sh << 'EOF'
#!/bin/bash

TARGET=$1
PORTS=(21 22 23 25 80 443 3389 3306 5432 8080)

echo "Escaneando puertos en $TARGET..."

for PORT in "${PORTS[@]}"; do
    timeout 1 bash -c "echo >/dev/tcp/$TARGET/$PORT" 2>/dev/null && \
        echo "Puerto $PORT: ABIERTO" || \
        echo "Puerto $PORT: CERRADO"
done
EOF

chmod +x port_scan.sh
./port_scan.sh 192.168.1.50
Output: Escaneando puertos en 192.168.1.50...
#         Puerto 21: CERRADO
#         Puerto 22: ABIERTO
#         Puerto 80: ABIERTO
```


### 80. Script Python para escaneo de puertos

```bash
cat > port_scanner.py << 'EOF'
#!/usr/bin/env python3
import socket
import sys

target = sys.argv[1]
ports = [21, 22, 23, 25, 80, 443, 3389, 3306]

print(f"Escaneando {target}...")

for port in ports:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    if result == 0:
        print(f"Puerto {port}: ABIERTO")
    sock.close()
EOF

chmod +x port_scanner.py
python3 port_scanner.py 192.168.1.50
Output: Escaneando 192.168.1.50...
#         Puerto 22: ABIERTO
#         Puerto 80: ABIERTO
#         Puerto 443: ABIERTO
```


## SECCIÓN 18: MONITOREO CONTINUO {#seccion-18}

### 81. Monitorear puertos con watch

```bash
watch -n 5 'ss -tlnp'
Output: (actualiza cada 5 segundos)
```


### 82. Monitorear conexiones activas

```bash
watch -n 2 'netstat -ant | grep ESTABLISHED'
Output: (muestra conexiones establecidas cada 2 segundos)
```


### 83. Alertas de nuevos puertos abiertos

```bash
# Script de monitoreo
cat > monitor_ports.sh << 'EOF'
#!/bin/bash
BASELINE="/tmp/ports_baseline.txt"
CURRENT="/tmp/ports_current.txt"

ss -tlnp | awk '{print $4}' | sort > "$CURRENT"

if [ -f "$BASELINE" ]; then
    diff "$BASELINE" "$CURRENT" | grep "^>" && echo "¡ALERTA: Nuevos puertos detectados!"
else
    cp "$CURRENT" "$BASELINE"
fi
EOF

chmod +x monitor_ports.sh
./monitor_ports.sh
Output: (detecta cambios en puertos abiertos)
```


## SECCIÓN 19: EXPORTAR Y DOCUMENTAR {#seccion-19}

### 84. Exportar resultados de Nmap a XML

```bash
nmap -p- -oX scan_completo.xml 192.168.1.50
Output: (genera archivo XML)
```


### 85. Exportar a formato grepable

```bash
nmap -p- -oG scan_grepable.txt 192.168.1.50
Output: (formato fácil de procesar con grep/awk)
```


### 86. Exportar a todos los formatos

```bash
nmap -p- -oA scan_completo 192.168.1.50
Output: (genera .nmap, .xml y .gnmap)
```


### 87. Convertir XML a HTML

```bash
xsltproc scan_completo.xml -o scan_report.html
Output: (genera reporte HTML legible)
```


### 88. Procesar resultados con grep

```bash
grep -E "open|filtered" scan_grepable.txt
Output: Host: 192.168.1.50 () Ports: 22/open/tcp//ssh///
```


### 90. Ver estadísticas de uso de puertos

```bash
TOP 10 PUERTOS MÁS UTILIZADOS EN INTERNET:

1. Puerto 80  (HTTP)   - 35% del tráfico
2. Puerto 443 (HTTPS)  - 30% del tráfico
3. Puerto 22  (SSH)    - 10% del tráfico
4. Puerto 21  (FTP)    - 5% del tráfico
5. Puerto 25  (SMTP)   - 4% del tráfico
6. Puerto 53  (DNS)    - 3% del tráfico
7. Puerto 3389 (RDP)   - 3% del tráfico
8. Puerto 445 (SMB)    - 2% del tráfico
9. Puerto 8080 (HTTP-Alt) - 2% del tráfico
10. Puerto 3306 (MySQL) - 1% del tráfico
EOF
```

---

## Siguiente lectura

| Guía | Enlace |
| :--- | :--- |
| Comandos Linux y pentesting | [Linux Cheat Sheet](linux-cheatsheet.md) |
| Cliente FTP (puerto 21) | [FTP Cheat Sheet](ftp-cheatsheet.md) |
| Índice general | [Inicio](index.md) |