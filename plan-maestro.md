# 🌌 Plan Maestro - Whoami-Labs

> [!IMPORTANT]
> Documento principal de orquestación y roadmap del ecosistema Whoami-Labs.

## 🎯 Objetivo General
Mejorar y mantener la plataforma de laboratorios vulnerables en Docker, facilitando su gestión y optimizando su rendimiento, respetando la infraestructura actual (Hostinger).

---

## 🗺️ Fases del Proyecto (Roadmap)

### ✅ Fases Completadas (Core Security & DevSecOps)

- [x] **Fase 1**: Análisis de la estructura actual (frontend, backend, labs).
- [x] **Fase 2**: Despliegue automatizado DevSecOps en Hostinger vía GitHub Actions.
- [x] **Fase 3**: Pentesting estático (OWASP 2025) y parcheo de Lógica de Negocio (Infinite Points, Fuerza bruta, Logging).
- [x] **Fase 3.1**: Segunda auditoría PTES y Lógica de Negocio. Remediación de Zombie APIs (SSRF), DoS por métodos no implementados en JWT, y Hardening contra Information Disclosure.
- [x] **Fase 3.2**: Respuesta a Incidente de Seguridad (Fuzzing). Parcheo crítico del WAF (`.htaccess`) para bloquear acceso recursivo a carpetas y eliminación estricta de archivos expuestos (`test.http`). Política de Tolerancia Cero.
- [x] **Fase 3.3**: Auditoría PTES (Information Disclosure). Eliminación de Hardcoded Secrets (`recover_ruben.php`) y mitigación de fugas de excepciones BD.
- [x] **Fase 3.4**: Auditoría PTES y remediación P0. Eliminación de `scan_htaccess.php`, saneamiento de datos en JWT, política CORS wildcard `*`, y mitigación de fugas en encabezados 401.

### ✅ Fases Completadas (Features & Automatización)

- [x] **Fase 4**: Mejoras funcionales de la plataforma (Perfil 2.0 / Hacker Dashboard, Sistema de Notificaciones, Subida de Avatares y Certificados).
- [x] **Fase 4.1**: Optimización de SEO Técnico & LLM Crawlers, Favicons de alta resolución, "Copiar Link" en perfiles, solución pérdida de sesión F5, y contraste visual.
- [x] **Fase 5**: Implementación Threat Intelligence (AbuseIPDB), Cron Jobs Hostinger y Auditoría OWASP Top 10 (Zero Vulnerabilities).
- [x] **Fase 5.1**: Optimización Arquitectura Consultas (SQL Split LIKE). Buscador Inteligente Multi-palabra escalable.
- [x] **Fase 5.2**: Reestructuración Arquitectónica Notificaciones (Evolution API). Migración a Neon DB PostgreSQL. Persistencia WhatsApp 24/7 con UptimeRobot ($0 costo).
- [x] **Fase 5.3**: Robustecimiento Honeypot y detección User-Agent Spoofing. SQLite (`cache/fail2ban.sqlite`) asíncrono con `ipquery.io`.
- [x] **Resolución Límite Arquitectónico**: Bypass límite RAM (512MB) de Render para QR adoptando sesiones cruzadas.
- [x] **Integración Make.com (Webhooks)**: Despliegue Evolution API en VPS GCP. Proxy-SSL inverso en Cloudflare.
- [x] **Orquestador Social**: Router multi-plataforma. Solución Bug 479 Evolution API en WhatsApp vía OpenGraph (`linkPreview`).
- [x] **Automatización YouTube**: RSS Watchers en Make.com. Enrutamiento automático a RRSS.
- [x] **Integración YouTube Walkthrough**: Modal cyberpunk para videos, mitigación vulnerabilidad RCE `esbuild`. Ajuste CSP para YouTube.
- [x] **Rediseño Home Page**: Reestructuración central interactiva (Consola Operaciones), reubicación de YouTube para reducción de scroll.

### 🧠 Fase 6: Mentor IA RAG en Producción
> [!TIP]
> Desplegado el 18-19/06/2026

- [x] **Core**: Cloudflare Worker (`whoami-mentor`) con Vectorize + KV + Groq Llama 3.3 70B.
- [x] **Fase 6.1 (Parche Negocio)**: Eliminación Account Takeover en Onboarding Firebase. Prevención Infinite Points.
- [x] **Fase 6.2 (Seguridad)**: Validación HMAC-SHA256 (History Injection), Turnstile en OAuth, Verificación estricta (`is_verified = 1`). Auditoría 100/100.

---

## 🚀 Hoja de Ruta Actual

### 🤖 Mentor IA RAG: Tareas Secundarias (P2)
> Tareas opcionales, no bloqueantes para producción.

- [ ] Re-ingerir OKFs existentes si había flags sin redactar en Vectorize previo al parche.
- [ ] Disclaimer UI visible en el chat del Mentor.
- [ ] Revertir `last_request_time` en BD si el Worker falla tras incrementar contador.
- [ ] Quitar campo `text` de metadata Vectorize en `ingest_writeups.py` (reducir superficie de fuga).

### 📘 Fase 7: Migración de Ingesta a OneNote
> [!NOTE]
> Reemplazar ingesta local PDF por extracción directa de OneNote para Markdown estructurado y contextos de terminal limpios.

1. **Extractor OneNote**: Usar MCP o script Node/Python (Microsoft Graph API) para HTML a Markdown.
2. **Chunking Semántico**: División basada en encabezados (Nmap, Explotación), preservar bloques de código.
3. **Embeddings**: Modelo nativo `@cf/baai/bge-base-en-v1.5` de Cloudflare -> Vectorize/KV.

> [!WARNING]
> **Preguntas Abiertas (User Review):**
> 1. Autenticación MCP OneNote: ¿Revivimos MCP con script OAuth o usamos script local de Graph API?
> 2. Nomenclatura: ¿Cuál es el nombre exacto del índice Vectorize y namespace de KV?

### 🏆 CTF Arena (Fase 8)

> [!NOTE]
> Base de Datos, Backend PHP (Multi-Máquina) y Frontend React Cyberpunk ya implementados y funcionales.

#### Fase 8.1 - Próximos Pasos
- [ ] Construir **Panel de Administración (Admin Dashboard)** en React para gestión CRUD visual de Eventos/Máquinas.
- [ ] Ejecutar script SQL de creación en Hostinger de producción.

---

## 📚 Enlaces Útiles
- [recursos.md](file:///e:/CYBERDARK/DEVELOPER/whoami-labs/recursos.md) - Catálogo de recursos y herramientas externas del proyecto.
