# Base de Conocimientos de Recursos Técnicos

> Referencia práctica para administración de sistemas, redes y auditoría de seguridad. Diseñada para consulta rápida en terminal y en el campo.

<p align="center">
  <a href="docs/index.md"><strong>📚 Explorar documentación</strong></a>
  &nbsp;·&nbsp;
  <a href="docs/linux-cheatsheet.md">Linux</a>
  &nbsp;·&nbsp;
  <a href="docs/ports.md">Puertos</a>
  &nbsp;·&nbsp;
  <a href="docs/ftp-cheatsheet.md">FTP</a>
</p>

---

## Guías disponibles

| Guía | Contenido | Ideal para |
| :--- | :--- | :--- |
| [**Linux Cheat Sheet**](docs/linux-cheatsheet.md) | Navegación, permisos, procesos, systemd, SSH, pentesting y scripting | Sysadmins y estudiantes de seguridad |
| [**Referencia de Puertos**](docs/ports.md) | Puertos TCP/UDP, escaneo con Nmap, firewall y herramientas de auditoría | Redes y pentesting |
| [**Guía FTP**](docs/ftp-cheatsheet.md) | Cliente FTP, transferencias, pentesting y alternativas seguras (SFTP/SCP) | Operaciones de archivos y CTF |
| [**Plan Maestro**](plan-maestro.md) | Roadmap del ecosistema Whoami-Labs (contexto del proyecto) | Desarrollo de la plataforma |

---

## Áreas de conocimiento

| Área | Temas clave |
| :--- | :--- |
| **Sistema** | Archivos, permisos (ACL, SUID/SGID), procesos, logs |
| **Servicios** | `systemd`, inicialización y gestión de daemons |
| **Red** | Puertos, protocolos, escaneo y análisis de tráfico |
| **Seguridad** | SSH hardening, firewalls, metodología de pentesting |
| **Transferencias** | FTP, SFTP, SCP y buenas prácticas de cifrado |

---

## Vista local (MkDocs)

Para leer la documentación con búsqueda, modo oscuro y navegación lateral en tu máquina:

```bash
pip install -r requirements-docs.txt
mkdocs serve
```

Abre `http://127.0.0.1:8000` en el navegador.

---

## Cómo usar este repositorio

1. **GitHub / editor** — Abre cualquier guía en `docs/`; cada archivo incluye tabla de contenidos y referencia rápida al inicio.
2. **Terminal** — Clona el repo y usa `grep` o tu editor favorito sobre los markdown.
3. **Sitio local** — `mkdocs serve` para buscar y filtrar sin salir del navegador.

---

*Documentación en evolución continua. Prioriza siempre prácticas de seguridad modernas (cifrado, mínimo privilegio, auditoría).*
