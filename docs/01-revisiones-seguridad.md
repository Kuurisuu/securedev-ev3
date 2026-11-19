# Revisiones de seguridad

Cada commit en `main` pasa por cuatro revisiones automáticas dentro del pipeline.
Ninguna versión llega a producción sin pasar el Security Gate.

| Revisión | Herramienta | Momento | Reporte archivado |
|----------|-------------|---------|-------------------|
| Pruebas de seguridad | unittest | Etapa *Test* | `reports/unit-tests.txt` |
| Análisis estático (SAST) | SonarQube | Etapa *SAST* | Proyecto `securedev-ev3` en SonarQube |
| Análisis de dependencias (SCA) | pip-audit 2.10.1 | Etapa *SCA* | `reports/pip-audit.json` |
| Análisis de dependencias (SCA) | OWASP Dependency-Check 13.0.0 + NVD | Etapa *SCA* | `reports/dependency-check/*` |
| Análisis dinámico (DAST) | OWASP ZAP full scan | Etapa *DAST* (contra staging) | `reports/zap/*` |
| Decisión | `scripts/security_gate.py` | Etapa *Security Gate* | `reports/security-gate.md` |

Además, Dependabot revisa el repositorio en GitHub de forma continua.

## Revisión 1: versión vulnerable (builds #1 y #2)

### SonarQube: 3 issues

| Issue | Severidad | Ubicación |
|-------|-----------|-----------|
| Make sure disabling CSRF protection is safe here | Alta | `app.py` L3 |
| Make sure this debug feature is deactivated before delivering the code in production | Baja | `app.py` L11 |
| The "python" image runs with "root" as the default user | Baja | `Dockerfile` L2 |

### pip-audit: 13 vulnerabilidades

Flask 2.2.2 tiene 2 y Werkzeug 2.2.2 tiene 11. Entre ellas están CVE-2023-30861,
CVE-2023-25577, CVE-2023-46136 y CVE-2024-34069.

### OWASP Dependency-Check: 11 CVE, 4 con CVSS ≥ 7.0

| Componente | CVE | CVSS |
|------------|-----|------|
| Flask 2.2.2 | CVE-2023-30861 (cookie de sesión cacheada por proxies) | 7.5 |
| Werkzeug 2.2.2 | CVE-2023-25577 (DoS por multipart) | 7.5 |
| Werkzeug 2.2.2 | CVE-2023-46136 (DoS por multipart) | 7.5 |
| Werkzeug 2.2.2 | CVE-2024-34069 (RCE vía debugger) | 7.5 |

Las otras 7 son de severidad media o baja: CVE-2024-49767, CVE-2024-49766,
CVE-2025-66221, CVE-2026-21860, CVE-2026-27199, CVE-2023-23934 y CVE-2026-27205.

### OWASP ZAP: 3 altas, 2 medias, 6 bajas y 1 informativa

| Riesgo | Alerta | Regla |
|--------|--------|-------|
| Alto | Cross Site Scripting (Reflected) | 40012 |
| Alto | Cross Site Scripting (DOM Based) | 40026 |
| Alto | Source Code Disclosure - File Inclusion (**falso positivo**, ver abajo) | 43 |
| Medio | Content Security Policy (CSP) Header Not Set | 10038 |
| Medio | Missing Anti-clickjacking Header | 10020 |
| Bajo | COEP / COOP / CORP ausentes, Permissions-Policy ausente, X-Content-Type-Options ausente, versión del servidor expuesta | 90004, 10063, 10021, 10036 |

### Verificación manual

- `http://localhost:5010/hello?name=<script>alert(1)</script>` ejecutó el script en el navegador (XSS confirmado).
- `http://localhost:5010/console` mostró la consola del debugger de Werkzeug, que permite ejecutar código remoto.

### Dependabot: 12 alertas

Tres son de severidad alta: CVE-2023-25577, CVE-2023-30861 y CVE-2024-34069.

### Decisión del gate: **BLOQUEADO**

La versión no se desplegó a producción.

## Revisión 2: versión corregida (builds #3 y #4)

| Revisión | Resultado |
|----------|-----------|
| unittest | 9/9 pruebas OK, entre ellas XSS rechazado, debug desactivado, CSRF activo y cabeceras presentes |
| SonarQube | **0 issues** |
| pip-audit | 0 vulnerabilidades |
| Dependency-Check | 204 dependencias analizadas, 0 vulnerabilidades |
| OWASP ZAP | Alto 0, Medio 0, Bajo 0, Informativo 1 (*Non-Storable Content*, esperado por `Cache-Control: no-store`) |
| Dependabot | 12/12 alertas cerradas automáticamente como *fixed* |
| Gate | **APROBADO**: desplegado en producción |

## Gestión de falsos positivos

ZAP reportó la regla **43, *Source Code Disclosure - File Inclusion***, como Alta.
Se analizó y se descartó por estas razones:

- La regla compara la respuesta a `name=<archivo>` con la respuesta a un valor aleatorio.
  Como la versión vulnerable devuelve el parámetro tal cual (`Hello, <valor>!`),
  ambas respuestas siempre difieren, aunque no se haya leído ningún archivo.
- El campo *evidence* del reporte del build #1 está vacío. La aplicación no lee
  archivos del disco.

La decisión queda versionada en [`zap/zap-rules.conf`](../zap/zap-rules.conf) como
`IGNORE`, con su justificación, y se pasa a ZAP con `-c`. El XSS real que causaba el
reflejo sí se corrigió (V1). El falso positivo se excluye solo de esta regla, no
del escaneo completo.
