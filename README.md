# SecureDev EV3 – Pipeline DevSecOps

Aplicación Flask de ejemplo (`/hello?name=`) que parte de un código vulnerable y se
corrige siguiendo un ciclo DevSecOps completo: revisión continua de seguridad en
Jenkins, pruebas dinámicas con OWASP ZAP, gestión de dependencias y monitorización
de producción con Prometheus y Grafana.

## Pipeline (Jenkinsfile)

| # | Etapa | Herramienta | Qué valida |
|---|-------|-------------|------------|
| 1 | Trazabilidad | git | Registra build, commit, rama e imagen (`reports/build-info.txt`) |
| 2 | Build | Docker | Construye la imagen con etiquetas OCI `revision` (commit) y `version` (build) |
| 3 | Test | unittest | 9 pruebas funcionales y de seguridad |
| 4 | SAST | SonarQube | Análisis estático de `app.py` y `Dockerfile` |
| 5 | SCA | pip-audit + OWASP Dependency-Check | Vulnerabilidades conocidas en dependencias (PyPI/OSV y NVD) |
| 6 | Deploy Staging | Docker | Despliega en `localhost:5010` para las pruebas dinámicas |
| 7 | DAST | OWASP ZAP (full scan) | Ataca la aplicación en ejecución |
| 8 | Security Gate | `scripts/security_gate.py` | Bloquea si hay vulnerabilidades (criterio *fail closed*) |
| 9 | Deploy Production | Docker endurecido | `localhost:5020`, solo si el gate aprueba |
| 10 | Monitor | Prometheus API | Verifica que producción esté siendo monitoreada |

Todos los reportes se archivan en Jenkins como artefactos (`reports/**`).

**Criterios del Security Gate:** cualquier vulnerabilidad en pip-audit, CVSS ≥ 7.0
en Dependency-Check o cualquier alerta de riesgo Alto en ZAP → `BLOQUEADO`.
Si falta un reporte, también bloquea.

## Resultados

| Build | Commit | Versión | Resultado |
|-------|--------|---------|-----------|
| #1 | `86929af` | v1 vulnerable | **BLOQUEADO**: 13 vulns pip-audit, 4 CVE con CVSS ≥ 7, 3 alertas Altas en ZAP |
| #2 | `8fbacdc` | v1 vulnerable | **BLOQUEADO**: mismo resultado (reproducible) |
| #3 | `1805740` | v2 corregida | **APROBADO**: 0 vulnerabilidades, desplegado en producción |
| #4 | `ac05990` | v2 + monitorización | **APROBADO**: producción monitoreada (`up = 1`) |

## Documentación

- [Revisiones de seguridad](docs/01-revisiones-seguridad.md): qué detectó cada herramienta, antes y después.
- [Vulnerabilidades y correcciones](docs/02-vulnerabilidades.md): V1 a V7, con CWE, OWASP, corrección y verificación.
- [Gestión de dependencias](docs/03-gestion-dependencias.md): pip-tools con hashes, pip-audit, Dependency-Check y Dependabot.
- [Monitorización e incidentes](docs/04-monitorizacion-incidentes.md): Grafana, alertas e informe del incidente simulado.
- [Trazabilidad](docs/05-trazabilidad.md): relación entre commit, build, imagen y despliegue.

## Estructura

```
app.py, test_app.py        Aplicación corregida y pruebas
Dockerfile                 Imagen de la aplicación (usuario sin privilegios, gunicorn)
Dockerfile.jenkins         Imagen de Jenkins con cliente Docker
Jenkinsfile                Pipeline DevSecOps
requirements.in / .txt     Dependencias directas / fijadas con hash
.github/dependabot.yml     Actualizaciones automáticas de dependencias
zap/zap-rules.conf         Falsos positivos de ZAP justificados
scripts/                   Security gate, exportación de dependencias, simulación de incidente
monitoring/                Prometheus (scrape + alertas) y Grafana (datasource + dashboard)
docs/                      Documentación de seguridad
```

## Ejecución local

```bash
docker network create devsecops-lab                   # una sola vez
docker compose -f monitoring/docker-compose.yml up -d # Prometheus :9090, Grafana :3000
# Jenkins: job "Pipeline from SCM" apuntando a este repositorio -> Construir ahora
powershell -ExecutionPolicy Bypass -File scripts\simular_incidente.ps1
```
