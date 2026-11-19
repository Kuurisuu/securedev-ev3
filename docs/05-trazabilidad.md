# Trazabilidad

Cada versión desplegada se puede rastrear de punta a punta:

```
commit (GitHub)  ->  build N (Jenkins)  ->  imagen securedev-ev3:N  ->  contenedor en producción
```

Esa cadena se apoya en cinco mecanismos:

- **Jenkins:** la descripción de cada build muestra el commit (`commit 1805740`).
  `reports/build-info.txt` registra build, fecha, commit completo, rama, imagen y
  autor del último cambio.
- **Imagen Docker:** lleva las etiquetas OCI `org.opencontainers.image.revision`
  (commit) y `org.opencontainers.image.version` (número de build).
- **Producción:** `reports/production-deploy.txt` guarda la imagen y el commit del
  contenedor desplegado, que se leen con `docker inspect`.
- **Reportes:** todos los reportes de seguridad se archivan con *fingerprint* en
  cada build, y el Security Gate indica el build y el commit que evaluó.
- **Decisiones:** los falsos positivos (`zap/zap-rules.conf`) y la configuración de
  monitoreo (`monitoring/`) están versionados en Git.

## Matriz de trazabilidad

| Build | Fecha (UTC-3) | Commit | Cambio | Gate | Producción |
|-------|---------------|--------|--------|------|------------|
| #1 | 18-11-2026 17:45 | `86929af` | Versión inicial vulnerable y pipeline DevSecOps | BLOQUEADO | No desplegado |
| #2 | 18-11-2026 19:14 | `8fbacdc` | Mismo código que `86929af`; solo se reescribió el mensaje del commit | BLOQUEADO | No desplegado |
| #3 | 18-11-2026 19:34 | `1805740` | Corrige vulnerabilidades V1 a V7 | APROBADO | `securedev-ev3:3`, commit `18057405e508…` |
| #4 | 18-11-2026 21:44 | `ac05990` | Agrega monitorización con Prometheus y Grafana | APROBADO | `securedev-ev3:4`, commit `ac05990fa9d5…` |

## Relación entre vulnerabilidad, detección, corrección y verificación

| Vulnerabilidad | Detectada en | Corregida en | Verificada en |
|----------------|--------------|--------------|---------------|
| V1 XSS reflejado | Build #1 (ZAP 40012/40026) | `1805740` | Build #3 (ZAP, tests) |
| V2 Debug en producción | Build #1 (SonarQube) | `1805740` | Build #3 (SonarQube, tests) |
| V3 CSRF | Build #1 (SonarQube) | `1805740` | Build #3 (SonarQube, tests) |
| V4 Validación de entrada | Revisión de código | `1805740` | Build #3 (tests) |
| V5 Cabeceras de seguridad | Build #1 (ZAP) | `1805740` | Build #3 (ZAP, tests) |
| V6 Contenedor como root | Build #1 (SonarQube) | `1805740` | Build #3 (SonarQube) |
| V7 Dependencias vulnerables | Build #1 (pip-audit, Dependency-Check), Dependabot | `1805740` | Build #3 (SCA en 0), Dependabot 12/12 *fixed* |
| INC-001 Ataque simulado | Grafana y alertas Prometheus (18-11-2026 21:22) | No requirió cambios (controles efectivos) | Build #4 (Monitor `up = 1`) |
