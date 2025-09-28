# 📘 Guía Completa de Comandos Linux con Ejemplos




```bash
ls
ls -l
ls -la
ls -lh
ls -lt
ls --color=auto

cd /ruta/del/directorio
cd ..
cd -
cd ~

pwd

mkdir nombre_directorio
mkdir -p /ruta/nueva/carpeta

cp archivo1 archivo2
cp -r carpeta1 carpeta2
cp -i archivo destino

mv archivo nuevo_nombre
mv archivo /ruta/destino/

rm archivo.txt
rm -r carpeta/
rm -rf carpeta/      # ⚠️ peligroso
rm -i archivo.txt

touch nuevo.txt
touch -c archivo.txt

cat archivo.txt
tac archivo.txt
nl archivo.txt

less archivo.log
more archivo.txt
head -n 20 archivo.log
tail -n 100 archivo.log
tail -f /var/log/syslog
tail -F /var/log/syslog

nano archivo.txt
vim archivo.txt

---

chmod 755 script.sh
chmod 644 archivo.txt
chmod +x script.sh
chmod -R 700 carpeta/

sudo chown usuario:grupo archivo
sudo chown -R usuario:grupo carpeta/

getfacl archivo
setfacl -m u:juan:rwx archivo
setfacl -x u:juan archivo

chmod +t /tmp                     # sticky bit
chmod u+s /usr/bin/passwd         # SUID
chmod g+s carpeta                 # SGID

id
whoami

---
ps aux
ps -ef
ps aux | grep nginx

top
htop

nice -n 10 comando
renice -n -5 -p 12345

kill 1234
kill -9 1234
pkill -f nombre_proceso
killall nginx

sudo systemctl status nginx
sudo systemctl start nginx
sudo systemctl stop nginx
sudo systemctl restart sshd
sudo systemctl enable nginx
sudo systemctl disable servicio
sudo systemctl daemon-reload

sudo service apache2 restart   # legacy

----

comando > archivo
comando >> archivo
comando 2> error.log
comando &> salida.log

ps aux | grep sshd
cat archivo | grep ERROR | wc -l
comando | tee salida.txt

find . -name "*.log" -print0 | xargs -0 gzip


----

find /ruta -name "archivo"
find /ruta -type d
find /ruta -mtime -1
find / -perm -4000 -type f

grep "palabra" archivo
grep -r "palabra" directorio
grep -n "cadena" archivo
grep -E "err|fail|crit" archivo

sudo updatedb
locate archivo.txt

awk '{print $1}' archivo
awk -F: '{print $1":"$3}' /etc/passwd

sed 's/buscar/reemplazar/g' archivo
sed -n '1,50p' archivo

cut -d: -f1 /etc/passwd

sort archivo.txt | uniq -c | sort -nr

tr '[:lower:]' '[:upper:]' < archivo.txt

rg "TODO" src/      # si ripgrep está instalado
ag "function" .     # si the_silver_searcher está instalado

----

ping -c 4 google.com

ifconfig                 # legacy
ip a
ip link set eth0 up
ip route show

wget https://example.com/archivo.zip
wget -c https://example.com/archivo.zip

curl -I https://example.com
curl -sS https://ifconfig.me
curl -X POST -H "Content-Type: application/json" -d '{"k":"v"}' https://api.example.com

netstat -tulnp
ss -tuln
ss -tulpn | grep :22

traceroute google.com
tracepath google.com

dig +short example.com
dig mx example.com
nslookup google.com

sudo tcpdump -i eth0 port 80 -w capture.pcap
sudo tcpdump -i any -nn -s0 -w /tmp/cap.pcap

nmap -sS -Pn -p 1-65535 target.com
nmap -sV -A target.com
nmap -O target.com


---

ssh usuario@servidor
ssh -p 2222 usuario@servidor
ssh -i ~/.ssh/id_rsa usuario@servidor

scp archivo usuario@host:/ruta
scp -r carpeta usuario@host:/ruta
scp usuario@host:/ruta/remota/archivo.txt /local/

rsync -avz /ruta/local/ usuario@host:/ruta/remota/
rsync -avz --delete /ruta/local/ usuario@host:/ruta/remota/

sftp usuario@host
# dentro de sftp: put, get, ls, cd, mkdir, bye

---

tar -cvf archivo.tar carpeta/
tar -xvf archivo.tar

tar -czvf archivo.tar.gz carpeta/
tar -xvzf archivo.tar.gz

tar -cJvf archivo.tar.xz carpeta/
tar -xJvf archivo.tar.xz

gzip archivo.txt
gunzip archivo.txt.gz

bzip2 archivo.txt
bunzip2 archivo.txt.bz2

xz archivo.txt
unxz archivo.txt.xz

zip -r carpeta.zip carpeta/
unzip archivo.zip -d /ruta/salida

---

# Debian / Ubuntu
sudo apt-get update
sudo apt-get upgrade
sudo apt-get dist-upgrade
sudo apt-get install nombre_paquete
sudo apt-get remove nombre_paquete
sudo apt-get autoremove
apt-cache search paquete
dpkg -i paquete.deb
dpkg -l | grep paquete
dpkg -r paquete

# RedHat / CentOS / Fedora
sudo yum update
sudo yum install nombre_paquete
sudo yum remove nombre_paquete
sudo dnf install nombre_paquete
rpm -ivh paquete.rpm

# Arch
sudo pacman -S paquete
---

lsblk
sudo fdisk -l
sudo parted /dev/sda print
sudo blkid

sudo mkfs.ext4 /dev/sdb1
sudo mkfs.xfs /dev/sdb2

sudo mount /dev/sdb1 /mnt
sudo umount /mnt

sudo mount -o rw,noatime /dev/sdb1 /mnt

# LVM (mención de comandos)
pvcreate /dev/sdx
vgcreate vg_name /dev/sdx1
lvcreate -L 10G -n lv_name vg_name
lvextend -L +5G /dev/vg_name/lv_name
resize2fs /dev/vg_name/lv_name


----

sudo useradd -m -s /bin/bash juan
sudo passwd juan
sudo usermod -aG sudo juan
sudo usermod -L juan
sudo usermod -U juan
sudo userdel juan
sudo userdel -r juan

id juan
groups juan
getent passwd juan

sudo visudo
# editar reglas sudo de forma segura


---

comando &
jobs
fg %1
bg %1
disown -h %1
nohup comando &           # persiste tras cerrar sesión, salida a nohup.out


---

sudo journalctl -xe
sudo journalctl -u nginx.service
sudo journalctl -f

tail -f /var/log/syslog
tail -f /var/log/auth.log

dmesg | tail
dmesg | grep -i error

free -h
uptime
vmstat 1 5
iostat -x 1 3   # si sysstat está instalado

---
ssh-keygen -t ed25519 -C "tu_email@example.com"
ssh-keygen -t rsa -b 4096 -C "tu_email@example.com"
ssh-copy-id usuario@host

# Ejemplo de ajustes en /etc/ssh/sshd_config:
# PermitRootLogin no
# PasswordAuthentication no
# Port 2222
# AllowUsers juan

sudo systemctl restart sshd

# Firewall (ufw)
sudo ufw enable
sudo ufw allow 22/tcp
sudo ufw allow 80,443/tcp
sudo ufw status

# iptables ejemplo
sudo iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# nftables
sudo nft list ruleset
----
# Recon y escaneo (solo con permiso)
nmap -sC -sV -oN salida_nmap.txt example.com
amass enum -d example.com -o subdominios.txt
subfinder -d example.com -o subs.txt
theHarvester -d example.com -b all -l 500 -f harvester.html

# HTTP & enumeración web
whatweb https://example.com
wpscan --url https://example.com --enumerate u,vp,vt
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k

# Captura de tráfico
sudo tcpdump -i eth0 -w captura.pcap

# Forense / info local
sudo lsof -i :80
strace -f -o salida.strace -p 1234
find / -perm -4000 -type f 2>/dev/null

# Herramientas de sanity check
chkrootkit
rkhunter


---

#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SRC="/home/usuario"
DST="/backups/$(date +%F)"
mkdir -p "$DST"
rsync -av --delete "$SRC/" "$DST/"

echo "Backup completado: $DST"


---

alias ll='ls -lah'
alias gs='git status'
export EDITOR=vim
export PATH="$HOME/bin:$PATH"

history
!123        # ejecutar comando número 123 del history
HISTCONTROL=ignoredups:ignorespace
---
sudo lsof -iTCP -sTCP:LISTEN -P -n
strace -f -o salida.strace -p 1234
perf top
valgrind --leak-check=full ./programa
sudo chroot /mnt /bin/bash

# Buscar archivos grandes
sudo find / -type f -size +500M -exec ls -lh {} \; | awk '{ print $9 ": " $5 }'

# Mostrar procesos escuchando y ejecutar info del binario
sudo ss -tulpn | grep :80
sudo lsof -i :80
ps -p <PID> -o pid,user,cmd
ls -l $(readlink -f /proc/<PID>/exe)


---

pwd; whoami; ls -lah
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
tar -czvf /tmp/home-backup-$(date +%F).tar.gz /home/usuario
sudo -l            # ver qué puede ejecutar con sudo
# Documentar acciones: comando | tee -a /var/log/mi_actividad.log




