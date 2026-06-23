<p align="center">
  <img src="https://raw.githubusercontent.com/Cyberdark-Security/resources/main/docs/assets/banner.png" alt="resources - Linux, Redes, Pentesting" width="100%">
</p>

<p align="center">
  <a href="docs/index.md"><img src="https://img.shields.io/badge/docs-3_guias-2563eb?style=flat-square" alt="3 guias"></a>
  <a href="docs/linux-cheatsheet.md"><img src="https://img.shields.io/badge/linux-29_secciones-7c3aed?style=flat-square" alt="Linux"></a>
  <a href="docs/ports.md"><img src="https://img.shields.io/badge/redes-puertos_nmap-0891b2?style=flat-square" alt="Redes"></a>
  <a href="https://github.com/Cyberdark-Security"><img src="https://img.shields.io/badge/org-Cyberdark_Security-0f172a?style=flat-square" alt="Cyberdark Security"></a>
</p>

<p align="center">
  <a href="docs/index.md"><strong>Explorar documentacion</strong></a>
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

## Guias

<table>
  <tr>
    <td align="center" width="33%">
      <a href="docs/linux-cheatsheet.md">
        <img src="https://raw.githubusercontent.com/Cyberdark-Security/resources/main/docs/assets/card-linux.png" alt="Linux Cheat Sheet" width="100%">
      </a>
      <br>
      <strong>Linux Administration</strong><br>
      <sub>Navegacion, permisos, systemd, SSH, pentesting y scripting</sub>
    </td>
    <td align="center" width="33%">
      <a href="docs/ports.md">
        <img src="https://raw.githubusercontent.com/Cyberdark-Security/resources/main/docs/assets/card-ports.png" alt="Network Ports" width="100%">
      </a>
      <br>
      <strong>Network Ports</strong><br>
      <sub>Puertos TCP/UDP, Nmap, firewall y auditoria</sub>
    </td>
    <td align="center" width="33%">
      <a href="docs/ftp-cheatsheet.md">
        <img src="https://raw.githubusercontent.com/Cyberdark-Security/resources/main/docs/assets/card-ftp.png" alt="FTP Cheat Sheet" width="100%">
      </a>
      <br>
      <strong>FTP Cheat Sheet</strong><br>
      <sub>Cliente FTP, transferencias y alternativas SFTP/SCP</sub>
    </td>
  </tr>
</table>

---

## Areas de conocimiento

| Area | Temas clave |
| :--- | :--- |
| **Sistema** | Archivos, permisos (ACL, SUID/SGID), procesos, logs |
| **Servicios** | `systemd`, inicializacion y gestion de daemons |
| **Red** | Puertos, protocolos, escaneo y analisis de trafico |
| **Seguridad** | SSH hardening, firewalls, metodologia de pentesting |
| **Transferencias** | FTP, SFTP, SCP y buenas practicas de cifrado |

---

## Metodologia Pentesting

<p align="center">
  <img src="https://raw.githubusercontent.com/Cyberdark-Security/resources/main/docs/assets/diagrama-pentest.png" alt="Diagrama ciclo de vida pentest" width="90%">
</p>

---

## Vista local (MkDocs)

Para leer la documentacion con busqueda, modo oscuro y navegacion lateral en tu maquina:

```bash
pip install -r requirements-docs.txt
mkdocs serve
```

Abre `http://127.0.0.1:8000` en el navegador.

---

## Como usar este repositorio

1. **GitHub** — Explora las guias con las cards de arriba o abre `docs/` directamente.
2. **Terminal** — Clona el repo y usa `grep` o tu editor favorito sobre los markdown.
3. **Local** — `mkdocs serve` para buscar y filtrar sin salir del navegador.

---

<p align="center">
  <sub>Documentacion en evolucion continua · Cifrado, minimo privilegio y auditoria</sub>
</p>
