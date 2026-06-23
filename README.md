<picture>
  <img src="docs/assets/banner.svg" alt="resources — Linux, Redes, Pentesting" width="100%">
</picture>

<p align="center">
  <a href="docs/index.md"><img src="https://img.shields.io/badge/docs-3_guías-2563eb?style=flat-square" alt="3 guías"></a>
  <a href="docs/linux-cheatsheet.md"><img src="https://img.shields.io/badge/linux-29_secciones-7c3aed?style=flat-square" alt="Linux"></a>
  <a href="docs/ports.md"><img src="https://img.shields.io/badge/redes-puertos_·_nmap-0891b2?style=flat-square" alt="Redes"></a>
  <a href="https://github.com/Cyberdark-Security"><img src="https://img.shields.io/badge/org-Cyberdark_Security-0f172a?style=flat-square" alt="Cyberdark Security"></a>
</p>

<p align="center">
  <a href="docs/index.md"><strong>Explorar documentación</strong></a>
  &nbsp;·&nbsp;
  <a href="docs/linux-cheatsheet.md">Linux</a>
  &nbsp;·&nbsp;
  <a href="docs/ports.md">Puertos</a>
  &nbsp;·&nbsp;
  <a href="docs/ftp-cheatsheet.md">FTP</a>
  &nbsp;·&nbsp;
  <a href="plan-maestro.md">Plan Maestro</a>
</p>

---

## Guías

<table>
  <tr>
    <td align="center" width="33%">
      <a href="docs/linux-cheatsheet.md">
        <img src="docs/assets/card-linux.svg" alt="Linux Cheat Sheet" width="100%">
      </a>
      <br>
      <strong>Linux Administration</strong><br>
      <sub>Navegación, permisos, systemd, SSH, pentesting y scripting</sub>
    </td>
    <td align="center" width="33%">
      <a href="docs/ports.md">
        <img src="docs/assets/card-ports.svg" alt="Network Ports" width="100%">
      </a>
      <br>
      <strong>Network Ports</strong><br>
      <sub>Puertos TCP/UDP, Nmap, firewall y auditoría</sub>
    </td>
    <td align="center" width="33%">
      <a href="docs/ftp-cheatsheet.md">
        <img src="docs/assets/card-ftp.svg" alt="FTP Cheat Sheet" width="100%">
      </a>
      <br>
      <strong>FTP Cheat Sheet</strong><br>
      <sub>Cliente FTP, transferencias y alternativas SFTP/SCP</sub>
    </td>
  </tr>
</table>

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

## Metodología Pentesting

<p align="center">
  <img src="docs/assets/diagrama-pentest.png" alt="Diagrama ciclo de vida pentest" width="90%">
</p>

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

1. **GitHub** — Explora las guías con las cards de arriba o abre `docs/` directamente.
2. **Terminal** — Clona el repo y usa `grep` o tu editor favorito sobre los markdown.
3. **Local** — `mkdocs serve` para buscar y filtrar sin salir del navegador.

---

<p align="center">
  <sub>Documentación en evolución continua · Cifrado, mínimo privilegio y auditoría</sub>
</p>
