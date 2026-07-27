#!/bin/bash
# deploy-production.sh
# Deploy completo profissional do Cassandra-MatVerse

set -euo pipefail

# Segredos gerados durante o deploy nunca devem nascer com permissões amplas.
umask 077

ENVIRONMENT=${ENVIRONMENT:-production}
NETWORK=${NETWORK:-mainnet}
DEPLOY_MODE=${DEPLOY_MODE:-systemd}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_requirements() {
    log_info "Verificando requisitos..."

    local requirements=("python3" "openssl")

    case "$DEPLOY_MODE" in
        "systemd")
            requirements+=("systemctl")
            ;;
        "docker")
            requirements+=("docker")
            if ! docker compose version >/dev/null 2>&1 && ! command -v docker-compose >/dev/null 2>&1; then
                log_error "Docker Compose v2 ou docker-compose não encontrado"
                return 1
            fi
            ;;
        "kubernetes")
            requirements+=("kubectl")
            ;;
        *)
            log_error "Modo desconhecido: $DEPLOY_MODE"
            return 1
            ;;
    esac
    for cmd in "${requirements[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "$cmd não encontrado"
            return 1
        fi
    done

    log_info "✅ Requisitos atendidos"
}

generate_secrets() {
    log_info "Gerando segredos..."

    mkdir -p .secrets
    chmod 700 .secrets

    if [[ ! -f .secrets/api_token ]]; then
        openssl rand -hex 32 > .secrets/api_token
    fi

    if [[ ! -f .secrets/postgres_password ]]; then
        openssl rand -base64 32 > .secrets/postgres_password
    fi

    if [[ ! -f .secrets/redis_password ]]; then
        openssl rand -base64 32 > .secrets/redis_password
    fi
    if [[ ! -f .secrets/grafana_password ]]; then
        openssl rand -base64 32 > .secrets/grafana_password
    fi

    chmod 600 .secrets/*

    log_info "✅ Segredos gerados"
}

load_secrets() {
    log_info "Carregando segredos..."

    if [[ -f .secrets/api_token ]]; then
        export MATVERSE_API_TOKEN
        MATVERSE_API_TOKEN="$(< .secrets/api_token)"
    fi
    if [[ -f .secrets/postgres_password ]]; then
        export POSTGRES_PASSWORD
        POSTGRES_PASSWORD="$(< .secrets/postgres_password)"
    fi
    if [[ -f .secrets/redis_password ]]; then
        export REDIS_PASSWORD
        REDIS_PASSWORD="$(< .secrets/redis_password)"
    fi
    if [[ -f .secrets/grafana_password ]]; then
        export GRAFANA_PASSWORD
        GRAFANA_PASSWORD="$(< .secrets/grafana_password)"
    fi

    log_info "✅ Segredos carregados"
}

setup_environment() {
    log_info "Configurando ambiente..."

    if ! id cassandra &>/dev/null; then
        useradd -r -s /bin/false -m -d /opt/cassandra-matverse cassandra
    fi

    local dirs=(
        "/opt/cassandra-matverse"
        "/var/lib/cassandra-matverse"
        "/var/log/cassandra-matverse"
        "/etc/cassandra-matverse"
    )

    for dir in "${dirs[@]}"; do
        mkdir -p "$dir"
        chown -R cassandra:cassandra "$dir"
    done

    cat > /etc/security/limits.d/cassandra.conf << 'LIMITS'
cassandra soft nofile 65536
cassandra hard nofile 65536
cassandra soft nproc 65536
cassandra hard nproc 65536
LIMITS

    log_info "✅ Ambiente configurado"
}

deploy_systemd() {
    log_info "Deploy via Systemd..."

    cp -r bin/* /opt/cassandra-matverse/bin/
    cp -r config/production/* /etc/cassandra-matverse/
    cp deploy/systemd/*.service /etc/systemd/system/

    chown -R cassandra:cassandra /opt/cassandra-matverse
    chmod +x /opt/cassandra-matverse/bin/*

    systemctl daemon-reload

    systemctl enable cassandra-matverse.service
    systemctl enable cassandra-matverse-monitor.service

    log_info "✅ Systemd configurado"
}

run_compose() {
    if docker compose version >/dev/null 2>&1; then
        docker compose "$@"
    else
        docker-compose "$@"
    fi
}

deploy_docker() {
    log_info "Deploy via Docker Compose..."

    # O Compose interpola as variáveis exportadas; não materialize segredos em docker-compose.yml.
    run_compose -f docker-compose.production.yml up -d
    run_compose -f docker-compose.production.yml ps

    log_info "✅ Docker Compose configurado"
}

deploy_kubernetes() {
    log_info "Deploy via Kubernetes..."

    kubectl apply -f k8s/namespaces/

    kubectl create secret generic cassandra-secrets \
        --from-file=.secrets/api_token \
        --from-file=.secrets/postgres_password \
        --from-file=.secrets/redis_password \
        --namespace production \
        --dry-run=client -o yaml | kubectl apply -f -

    kubectl apply -k k8s/overlays/production/

    kubectl -n production get all

    log_info "✅ Kubernetes configurado"
}

setup_monitoring() {
    log_info "Configurando monitoramento..."

    if [[ ! -f /etc/prometheus/prometheus.yml ]]; then
        mkdir -p /etc/prometheus
        cp monitoring/prometheus.yml /etc/prometheus/
    fi

    if systemctl list-unit-files | grep -q grafana-server; then
        systemctl start grafana-server
    fi

    log_info "✅ Monitoramento configurado"
}

validate_deployment() {
    log_info "Validando deployment..."

    local checks_passed=0
    local total_checks=0

    if [[ "$DEPLOY_MODE" == "systemd" ]]; then
        if systemctl is-active --quiet cassandra-matverse.service; then
            log_info "✅ Serviço systemd ativo"
            ((++checks_passed))
        else
            log_error "❌ Serviço systemd inativo"
        fi
        ((++total_checks))
    fi

    if curl -s http://localhost:8545/health | grep -q "healthy"; then
        log_info "✅ API Health OK"
        ((++checks_passed))
    else
        log_error "❌ API Health falhou"
    fi
    ((++total_checks))

    if journalctl -u cassandra-matverse --since "5 minutes ago" | grep -q "ERROR"; then
        log_warn "⚠️  Erros encontrados nos logs"
    else
        log_info "✅ Logs limpos"
        ((++checks_passed))
    fi
    ((++total_checks))

    log_info "Resultado: $checks_passed/$total_checks checks passaram"

    if [[ $checks_passed -eq $total_checks ]]; then
        log_info "🎉 DEPLOYMENT COMPLETO COM SUCESSO!"
        return 0
    else
        log_error "⚠️  DEPLOYMENT COM PROBLEMAS"
        return 1
    fi
}

main() {
    log_info "🚀 Iniciando deploy Cassandra-MatVerse"
    log_info "Ambiente: $ENVIRONMENT"
    log_info "Rede: $NETWORK"
    log_info "Modo: $DEPLOY_MODE"

    check_requirements
    generate_secrets
    load_secrets
    setup_environment

    case "$DEPLOY_MODE" in
        "systemd")
            deploy_systemd
            ;;
        "docker")
            deploy_docker
            ;;
        "kubernetes")
            deploy_kubernetes
            ;;
        *)
            log_error "Modo desconhecido: $DEPLOY_MODE"
            exit 1
            ;;
    esac

    setup_monitoring

    sleep 10

    validate_deployment

    log_info "📋 Próximos passos:"
    log_info "1. Acesse a API: http://localhost:8545/docs"
    log_info "2. Monitoramento: http://localhost:9090 (Prometheus)"
    log_info "3. Dashboard: http://localhost:3000 (Grafana)"
    log_info "4. Verifique logs: journalctl -u cassandra-matverse -f"
}

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
