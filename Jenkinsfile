// Pipeline DevSecOps - SecureDev (Evaluación Parcial 3)
// Build -> Test -> SAST -> SCA -> Deploy Staging -> DAST -> Security Gate
//       -> Deploy Production -> Monitor
pipeline {
    agent any

    options {
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    environment {
        APP_NAME          = 'securedev-ev3'
        IMAGE_NAME        = "securedev-ev3:${BUILD_NUMBER}"
        LAB_NETWORK       = 'devsecops-lab'
        STAGING_CONTAINER = 'securedev-staging'
        PROD_CONTAINER    = 'securedev-prod'
        ZAP_IMAGE         = 'ghcr.io/zaproxy/zaproxy:stable'
        PY_TOOLS_IMAGE    = 'python:3.12-slim'
        PIP_AUDIT_VERSION = '2.10.1'
    }

    stages {
        stage('Trazabilidad') {
            steps {
                script {
                    env.FULL_COMMIT  = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
                    env.SHORT_COMMIT = env.FULL_COMMIT.take(7)
                    currentBuild.description = "commit ${env.SHORT_COMMIT}"
                }
                sh '''
                    rm -rf reports dependency-input
                    mkdir -p reports
                    {
                        echo "Build: $BUILD_NUMBER"
                        echo "Fecha: $(date -Iseconds)"
                        echo "Commit: $FULL_COMMIT"
                        echo "Rama: ${GIT_BRANCH:-desconocida}"
                        echo "Imagen: $IMAGE_NAME"
                        echo "Ultimo cambio:"
                        git log -1 --pretty=format:"  %h | %an | %ad | %s" --date=iso
                        echo
                    } | tee reports/build-info.txt
                '''
            }
        }

        stage('Build') {
            steps {
                sh '''
                    docker build \
                        --label org.opencontainers.image.revision="$FULL_COMMIT" \
                        --label org.opencontainers.image.version="$BUILD_NUMBER" \
                        -t "$IMAGE_NAME" .
                '''
            }
        }

        stage('Test') {
            steps {
                sh '''
                    docker run --rm "$IMAGE_NAME" python -m unittest -v 2>&1 \
                        | tee reports/unit-tests.txt
                    grep -q "^OK" reports/unit-tests.txt
                '''
            }
        }

        stage('SAST - SonarQube') {
            steps {
                script {
                    def scannerHome = tool 'SonarScanner'
                    withEnv(["SCANNER_HOME=${scannerHome}"]) {
                        withSonarQubeEnv('SonarQubeLocal') {
                            withCredentials([string(credentialsId: 'sonarqube-token-ev3', variable: 'SONAR_TOKEN')]) {
                                sh '''
                                    "$SCANNER_HOME/bin/sonar-scanner" \
                                        -Dsonar.token="$SONAR_TOKEN" \
                                        -Dsonar.projectKey=securedev-ev3 \
                                        -Dsonar.projectName="SecureDev EV3" \
                                        -Dsonar.projectVersion="$BUILD_NUMBER-$SHORT_COMMIT" \
                                        -Dsonar.sources=app.py,Dockerfile \
                                        -Dsonar.tests=test_app.py \
                                        -Dsonar.python.version=3.12 \
                                        -Dsonar.sourceEncoding=UTF-8
                                '''
                            }
                        }
                    }
                }
            }
        }

        stage('SCA - Dependencias') {
            steps {
                // pip-audit: consulta la base de vulnerabilidades de PyPI/OSV.
                sh '''
                    docker run --rm -i "$PY_TOOLS_IMAGE" sh -c "
                        pip install -q --disable-pip-version-check --root-user-action=ignore \
                            pip-audit==$PIP_AUDIT_VERSION > /dev/null 2>&1 &&
                        cat > /tmp/requirements.txt &&
                        pip-audit -r /tmp/requirements.txt --progress-spinner off --desc on --format json
                    " < requirements.txt > reports/pip-audit.json || true
                '''

                // OWASP Dependency-Check: paquetes realmente instalados en la imagen
                // y el archivo requirements.txt, contrastados con la NVD.
                sh '''
                    mkdir -p dependency-input reports/dependency-check
                    docker run --rm -i "$IMAGE_NAME" python - \
                        < scripts/export_dependencies.py > dependency-metadata.tar
                    tar -xf dependency-metadata.tar -C dependency-input
                    rm dependency-metadata.tar
                    cp requirements.txt dependency-input/
                '''
                dependencyCheck(
                    odcInstallation: 'DependencyCheck',
                    nvdCredentialsId: 'nvd-api-key',
                    stopBuild: true,
                    additionalArguments: '''
                        --project securedev-ev3
                        --scan dependency-input
                        --enableExperimental
                        --format HTML
                        --format XML
                        --format JSON
                        --out reports/dependency-check
                        --data /var/jenkins_home/dependency-check-data
                    '''
                )
                dependencyCheckPublisher(
                    pattern: 'reports/dependency-check/dependency-check-report.xml'
                )
            }
        }

        stage('Deploy Staging') {
            steps {
                sh '''
                    docker rm -f "$STAGING_CONTAINER" > /dev/null 2>&1 || true
                    docker run -d --name "$STAGING_CONTAINER" \
                        --network "$LAB_NETWORK" \
                        -p 127.0.0.1:5010:5000 \
                        "$IMAGE_NAME"

                    for attempt in $(seq 1 30); do
                        if docker exec "$STAGING_CONTAINER" python -c \
                            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/hello?name=test', timeout=2)" \
                            > /dev/null 2>&1; then
                            echo "Staging listo en http://localhost:5010"
                            exit 0
                        fi
                        sleep 2
                    done
                    docker logs --tail 50 "$STAGING_CONTAINER"
                    exit 1
                '''
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                sh '''
                    docker rm -f zap-scan > /dev/null 2>&1 || true
                    set +e
                    # zap/zap-rules.conf (versionado) se entrega por stdin al contenedor.
                    docker run -i --name zap-scan --network "$LAB_NETWORK" "$ZAP_IMAGE" bash -c "
                        mkdir -p /zap/wrk &&
                        cat > /zap/wrk/zap-rules.conf &&
                        zap-full-scan.py -t 'http://$STAGING_CONTAINER:5000/hello?name=test' -m 1 \
                            -c zap-rules.conf \
                            -r zap-report.html -J zap-report.json -w zap-report.md -I
                    " < zap/zap-rules.conf
                    ZAP_EXIT=$?
                    set -e
                    mkdir -p reports/zap
                    docker cp zap-scan:/zap/wrk/. reports/zap/
                    docker rm -f zap-scan > /dev/null
                    echo "ZAP finalizo con codigo $ZAP_EXIT"
                    test "$ZAP_EXIT" -eq 0
                '''
            }
        }

        stage('Security Gate') {
            steps {
                sh '''
                    set +e
                    tar -cf - reports scripts/security_gate.py | docker run --rm -i \
                        -e BUILD_NUMBER -e SHORT_COMMIT "$PY_TOOLS_IMAGE" \
                        sh -c "mkdir -p /tmp/gate && cd /tmp/gate && tar -xf - && python scripts/security_gate.py" \
                        > reports/security-gate.md
                    GATE_EXIT=$?
                    set -e
                    cat reports/security-gate.md
                    exit $GATE_EXIT
                '''
            }
        }

        stage('Deploy Production') {
            steps {
                sh '''
                    docker rm -f "$PROD_CONTAINER" > /dev/null 2>&1 || true
                    docker run -d --name "$PROD_CONTAINER" \
                        --network "$LAB_NETWORK" \
                        -p 127.0.0.1:5020:5000 \
                        --restart unless-stopped \
                        --read-only --tmpfs /tmp \
                        --cap-drop ALL --security-opt no-new-privileges \
                        "$IMAGE_NAME"

                    for attempt in $(seq 1 30); do
                        if docker exec "$PROD_CONTAINER" python -c \
                            "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/hello?name=test', timeout=2)" \
                            > /dev/null 2>&1; then
                            echo "Produccion lista en http://localhost:5020"
                            docker inspect "$PROD_CONTAINER" \
                                --format 'Imagen: {{.Config.Image}} | commit: {{index .Config.Labels "org.opencontainers.image.revision"}}' \
                                | tee reports/production-deploy.txt
                            exit 0
                        fi
                        sleep 2
                    done
                    docker logs --tail 50 "$PROD_CONTAINER"
                    exit 1
                '''
            }
        }

        stage('Monitor') {
            steps {
                // Verifica que Prometheus esté recolectando métricas de producción.
                // No bloquea el pipeline: informa el estado del monitoreo.
                sh '''
                    docker run --rm --network "$LAB_NETWORK" "$PY_TOOLS_IMAGE" python -c "
import json, urllib.request
try:
    url = 'http://prometheus:9090/api/v1/query?query=up%7Bjob%3D%22securedev-prod%22%7D'
    data = json.load(urllib.request.urlopen(url, timeout=5))
    result = data['data']['result']
    state = result[0]['value'][1] if result else 'sin datos'
    print('Prometheus -> up{job=securedev-prod} =', state)
except Exception as exc:
    print('AVISO: Prometheus no disponible:', exc)
" | tee reports/monitor.txt
                '''
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
        }
        failure {
            echo 'Pipeline detenido: revisar reports/security-gate.md y los reportes archivados.'
        }
    }
}
