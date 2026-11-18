"""Security gate del pipeline SecureDev.

Consolida los reportes de seguridad generados por el pipeline y decide si la
versión puede desplegarse en producción. Si falta un reporte, el gate falla
(criterio "fail closed"): sin evidencia no hay despliegue.

Criterios de bloqueo:
  - pip-audit: cualquier vulnerabilidad conocida en las dependencias.
  - OWASP Dependency-Check: vulnerabilidades con CVSS >= 7.0.
  - OWASP ZAP: alertas de riesgo Alto.
"""
import json
import os
import sys
from pathlib import Path

REPORTS = Path("reports")
CVSS_THRESHOLD = 7.0
ZAP_RISK = {"0": "Informativo", "1": "Bajo", "2": "Medio", "3": "Alto"}

lines = []
failures = []


def load_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        failures.append(f"No se pudo leer {path}: {exc}")
        lines.append(f"- ERROR: no se pudo leer `{path}`")
        return None


def review_pip_audit():
    lines.append("## SCA - pip-audit")
    data = load_json(REPORTS / "pip-audit.json")
    if data is None:
        return
    total = 0
    seen = set()
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            key = (dep["name"], vuln["id"])
            if key in seen:  # pip-audit puede repetir una misma entrada
                continue
            seen.add(key)
            total += 1
            aliases = ", ".join(vuln.get("aliases", [])) or "-"
            fixes = ", ".join(vuln.get("fix_versions", [])) or "sin corrección"
            lines.append(
                f"- {dep['name']} {dep['version']}: {vuln['id']} "
                f"({aliases}) -> corregido en {fixes}"
            )
    lines.append(f"Total: {total} vulnerabilidades conocidas")
    if total:
        failures.append(f"pip-audit encontró {total} vulnerabilidades")


def cvss_score(vuln):
    for key in ("cvssv4", "cvssv3", "cvssv2"):
        info = vuln.get(key) or {}
        score = info.get("baseScore", info.get("score"))
        if score is not None:
            return float(score)
    return 0.0


def review_dependency_check():
    lines.append("")
    lines.append("## SCA - OWASP Dependency-Check")
    data = load_json(REPORTS / "dependency-check" / "dependency-check-report.json")
    if data is None:
        return
    dependencies = data.get("dependencies", [])
    total = 0
    blocking = 0
    for dep in dependencies:
        for vuln in dep.get("vulnerabilities", []):
            total += 1
            score = cvss_score(vuln)
            if score >= CVSS_THRESHOLD:
                blocking += 1
            lines.append(
                f"- {dep.get('fileName')}: {vuln.get('name')} "
                f"[{vuln.get('severity')}, CVSS {score}]"
            )
    lines.append(
        f"Dependencias analizadas: {len(dependencies)} | "
        f"vulnerabilidades: {total} | CVSS >= {CVSS_THRESHOLD}: {blocking}"
    )
    if blocking:
        failures.append(
            f"Dependency-Check encontró {blocking} vulnerabilidades con "
            f"CVSS >= {CVSS_THRESHOLD}"
        )


def review_zap():
    lines.append("")
    lines.append("## DAST - OWASP ZAP")
    data = load_json(REPORTS / "zap" / "zap-report.json")
    if data is None:
        return
    counts = {code: 0 for code in ZAP_RISK}
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            code = str(alert.get("riskcode"))
            counts[code] = counts.get(code, 0) + 1
            lines.append(
                f"- [{ZAP_RISK.get(code, code)}] {alert.get('alert')} "
                f"(regla {alert.get('pluginid')}, instancias {alert.get('count')})"
            )
    summary = " | ".join(f"{ZAP_RISK[c]}: {counts[c]}" for c in ("3", "2", "1", "0"))
    lines.append(f"Resumen: {summary}")
    if counts["3"]:
        failures.append(f"ZAP encontró {counts['3']} alertas de riesgo Alto")


def main():
    lines.append("# Security gate - SecureDev EV3")
    lines.append(
        f"Build #{os.environ.get('BUILD_NUMBER', '?')} | "
        f"commit {os.environ.get('SHORT_COMMIT', '?')}"
    )
    lines.append("")
    review_pip_audit()
    review_dependency_check()
    review_zap()
    lines.append("")
    if failures:
        lines.append("## Resultado: BLOQUEADO (no se despliega a producción)")
        lines.extend(f"- {reason}" for reason in failures)
    else:
        lines.append("## Resultado: APROBADO (se permite desplegar a producción)")
    print("\n".join(lines))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
