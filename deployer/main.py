#!/usr/bin/env python3
"""
matverse.deployer - Sistema Autônomo de Implantação
Produção Soberana | Versão 1.0.0
"""

import asyncio
import json
import logging
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import yaml

# ============================================================================
# CONFIGURAÇÃO DO SISTEMA
# ============================================================================


def _write_text_atomic(path: Path, content: str, mode: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        delete=False,
    ) as tmp_file:
        tmp_file.write(content)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
        tmp_path = Path(tmp_file.name)
    if mode is not None:
        tmp_path.chmod(mode)
    tmp_path.replace(path)
    if mode is not None:
        path.chmod(mode)


def _write_bytes_atomic(path: Path, content: bytes, mode: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "wb",
        dir=path.parent,
        delete=False,
    ) as tmp_file:
        tmp_file.write(content)
        tmp_file.flush()
        os.fsync(tmp_file.fileno())
        tmp_path = Path(tmp_file.name)
    if mode is not None:
        tmp_path.chmod(mode)
    tmp_path.replace(path)
    if mode is not None:
        path.chmod(mode)


def _copy_file_atomic(src: Path, dst: Path, mode: Optional[int] = None) -> None:
    _write_bytes_atomic(dst, src.read_bytes(), mode=mode)


@dataclass
class DeploymentConfig:
    """Configuração de deployment profissional"""

    environment: str = "production"
    network: str = "mainnet"
    deployment_mode: str = "systemd"  # systemd, docker, k8s, cloud

    # Diretórios
    base_dir: Path = Path("/opt/cassandra-matverse")
    data_dir: Path = Path("/var/lib/cassandra-matverse")
    log_dir: Path = Path("/var/log/cassandra-matverse")
    config_dir: Path = Path("/etc/cassandra-matverse")
    report_file: Optional[Path] = None

    # Artefatos de deployment
    docker_compose_file: Path = Path("docker-compose.production.yml")
    helm_chart_dir: Path = Path("k8s")
    helm_release_name: str = "cassandra-matverse"
    k8s_namespace: str = "production"

    # Segurança
    api_token: Optional[str] = None
    postgres_password: Optional[str] = None
    redis_password: Optional[str] = None
    grafana_password: Optional[str] = None
    require_authentication: bool = True
    ssl_enabled: bool = True

    # Performance
    max_connections: int = 1000
    cache_size_mb: int = 1024
    batch_size: int = 100

    # Cassandra Parameters
    psi_min: float = 0.82
    cvar_max: float = 0.18
    decision_timeout_ms: int = 100

    # Monitoramento
    prometheus_enabled: bool = True
    grafana_enabled: bool = True
    alertmanager_enabled: bool = True

    def __post_init__(self) -> None:
        """Pós-inicialização"""
        if isinstance(self.base_dir, str):
            self.base_dir = Path(self.base_dir)
        if isinstance(self.data_dir, str):
            self.data_dir = Path(self.data_dir)
        if isinstance(self.log_dir, str):
            self.log_dir = Path(self.log_dir)
        if isinstance(self.config_dir, str):
            self.config_dir = Path(self.config_dir)
        if isinstance(self.docker_compose_file, str):
            self.docker_compose_file = Path(self.docker_compose_file)
        if isinstance(self.helm_chart_dir, str):
            self.helm_chart_dir = Path(self.helm_chart_dir)
        if self.report_file is None:
            self.report_file = self.log_dir / "deployment-report.json"
        elif isinstance(self.report_file, str):
            self.report_file = Path(self.report_file)
        if not self.api_token:
            self.api_token = secrets.token_hex(32)
        if not self.postgres_password:
            self.postgres_password = self._generate_secret()
        if not self.redis_password:
            self.redis_password = self._generate_secret()
        if not self.grafana_password:
            self.grafana_password = self._generate_secret()

    @staticmethod
    def _generate_secret() -> str:
        return secrets.token_urlsafe(32)


# ============================================================================
# SISTEMA DE PATCHES AUTOMATIZADO
# ============================================================================


class PatchManager:
    """Gerenciador de patches automatizado"""

    def __init__(self, config: DeploymentConfig) -> None:
        self.config = config
        self.patches_applied: List[str] = []
        self.logger = logging.getLogger(__name__)

    def apply_all_patches(self) -> int:
        """Aplica todos os patches críticos"""
        patches = [
            self._apply_systemd_patch,
            self._apply_install_script_patch,
            self._apply_core_python_patch,
            self._apply_security_patch,
            self._apply_monitoring_patch,
        ]

        for patch_func in patches:
            try:
                result = patch_func()
                if result:
                    self.patches_applied.append(patch_func.__name__)
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error("Erro ao aplicar patch %s: %s", patch_func.__name__, exc)

        return len(self.patches_applied)

    def _apply_systemd_patch(self) -> bool:
        """Aplica patch no systemd service"""
        service_file = Path("/etc/systemd/system/cassandra-matverse.service")

        patch_content = """[Unit]
Description=Cassandra-MatVerse Sovereign Production System
Documentation=https://matverse.network/docs
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=cassandra
Group=cassandra
WorkingDirectory=/var/lib/cassandra-matverse
Environment="PATH=/opt/cassandra-matverse/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="MATVERSE_NETWORK={network}"
Environment="MATVERSE_STORAGE_PATH=/var/lib/cassandra-matverse"
Environment="MATVERSE_LOG_DIR=/var/log/cassandra-matverse"
Environment="MATVERSE_API_TOKEN={api_token}"

ExecStart=/opt/cassandra-matverse/venv/bin/python3 /opt/cassandra-matverse/bin/cassandra-matverse \
  --config /etc/cassandra-matverse/config.toml \
  --network {network}

ExecStartPre=/opt/cassandra-matverse/bin/health-check
ExecReload=/opt/cassandra-matverse/bin/reload-config

RuntimeDirectory=cassandra-matverse
RuntimeDirectoryMode=0755
StateDirectory=cassandra-matverse
StateDirectoryMode=0700

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictSUIDSGID=true
RestrictRealtime=true
RestrictNamespaces=true
SystemCallArchitectures=native
UMask=0077
ReadWritePaths=/var/lib/cassandra-matverse
ReadWritePaths=/var/log/cassandra-matverse
ReadWritePaths=/opt/cassandra-matverse/venv

ReadOnlyPaths=/etc/cassandra-matverse
ReadOnlyPaths=/usr
ReadOnlyPaths=/lib
ReadOnlyPaths=/lib64

LimitNOFILE=65536
LimitNPROC=65536
MemoryMax=4G
CPUQuota=200%

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""

        _write_text_atomic(
            service_file,
            patch_content.format(api_token=self.config.api_token, network=self.config.network),
            mode=0o644,
        )
        self.logger.info("✅ Patch systemd aplicado")
        return True

    def _apply_install_script_patch(self) -> bool:
        """Garante que o script de instalação esteja executável"""
        candidate_paths = [
            Path("scripts/deploy-production.sh"),
            self.config.base_dir / "bin" / "deploy-production.sh",
        ]
        patched = False
        for script_path in candidate_paths:
            if script_path.exists():
                current_mode = script_path.stat().st_mode
                script_path.chmod(current_mode | 0o111)
                patched = True
        if patched:
            self.logger.info("✅ Patch de script de instalação aplicado")
        return patched

    def _apply_core_python_patch(self) -> bool:
        """Aplica patches no código Python principal"""
        main_file = self.config.base_dir / "bin" / "cassandra-matverse"
        if not main_file.exists():
            self.logger.warning("Arquivo principal não encontrado: %s", main_file)
            return False

        patches = [
            (
                "# Configuração de logging de produção",
                """import os
# garantir diretório de log antes de criar FileHandler
_log_dir = os.environ.get("MATVERSE_LOG_DIR", "/var/log/cassandra-matverse")
os.makedirs(_log_dir, exist_ok=True)

# Configuração de logging de produção""",
            ),
            (
                'config_data = json.loads(config_path.read_text())',
                'config_data = json.loads(config_path.read_text(encoding="utf-8"))',
            ),
            (
                '''def _authenticate(self, token: str) -> bool:
        """Autenticação simples (em produção usar JWT/OAuth)"""
        _ = token
        return True''',
                '''def _authenticate(self, token: str) -> bool:
        """Autenticação por token"""
        import hmac
        import os

        expected = os.environ.get("MATVERSE_API_TOKEN")
        if not expected:
            logger.warning("MATVERSE_API_TOKEN não configurado")
            return False

        return hmac.compare_digest(token.encode(), expected.encode())''',
            ),
        ]

        content = main_file.read_text(encoding="utf-8")
        for old, new in patches:
            content = content.replace(old, new)

        mode = main_file.stat().st_mode & 0o777
        _write_text_atomic(main_file, content, mode=mode)
        self.logger.info("✅ Patches Python aplicados")
        return True

    def _apply_security_patch(self) -> bool:
        """Aplica hardening básico de permissões"""
        targets = [
            self.config.config_dir,
            self.config.log_dir,
            self.config.data_dir,
        ]
        patched = False
        for target in targets:
            if target.exists():
                target.chmod(0o750)
                patched = True
        if patched:
            self.logger.info("✅ Patch de segurança aplicado")
        return patched

    def _apply_monitoring_patch(self) -> bool:
        """Cria diretórios básicos de monitoramento quando aplicável"""
        if not self.config.prometheus_enabled:
            return False
        monitoring_dir = self.config.config_dir / "monitoring"
        monitoring_dir.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(monitoring_dir / ".keep", "monitoring\n", mode=0o644)
        self.logger.info("✅ Patch de monitoramento aplicado")
        return True


# ============================================================================
# ORQUESTRADOR DE DEPLOY
# ============================================================================


@dataclass
class DeploymentStepResult:
    """Resultado de um passo do deployment."""

    name: str
    success: bool
    duration_seconds: float
    started_at: str
    detail: str = ""


class DeploymentOrchestrator:
    """Orquestrador completo de deployment"""

    def __init__(self, config: DeploymentConfig) -> None:
        self.config = config
        self.patch_manager = PatchManager(config)
        self.logger = logging.getLogger(__name__)
        self.step_results: List[DeploymentStepResult] = []

        # Inicializar logging
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configura logging profissional"""
        log_file = self.config.log_dir / "deployment.log"
        log_file.parent.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[logging.FileHandler(str(log_file)), logging.StreamHandler(sys.stdout)],
        )

    async def deploy(self) -> None:
        """Executa deployment completo"""
        self.logger.info("🚀 Iniciando deployment Cassandra-MatVerse")

        steps = [
            self._validate_environment,
            self._apply_patches,
            self._configure_system,
            self._setup_directories,
            self._install_dependencies,
            self._deploy_application,
            self._setup_monitoring,
            self._validate_deployment,
        ]

        try:
            for step in steps:
                started_at = datetime.now(timezone.utc).isoformat()
                start_time = time.monotonic()
                try:
                    await step()
                    self._record_step_result(step.__name__, True, start_time, started_at)
                except Exception as exc:  # pylint: disable=broad-except
                    self.logger.error("❌ Erro no passo %s: %s", step.__name__, exc)
                    self._record_step_result(
                        step.__name__,
                        False,
                        start_time,
                        started_at,
                        detail=str(exc),
                    )
                    raise
        finally:
            self._write_deployment_report()

        self.logger.info("✅ Deployment completo com sucesso")

    async def _validate_environment(self) -> None:
        """Valida ambiente de produção"""
        requirements = {
            "python3": "3.8+",
            "docker": "20.10+ (opcional)",
            "systemctl": "systemd 240+",
            "openssl": "1.1.1+",
            "kubectl": "1.27+ (opcional)",
            "helm": "3.12+ (opcional)",
        }

        self.logger.info("🔍 Validando ambiente...")

        for cmd, version in requirements.items():
            if self.config.deployment_mode == "docker" and cmd in {"systemctl", "kubectl", "helm"}:
                continue
            if self.config.deployment_mode == "k8s" and cmd in {"systemctl", "docker"}:
                continue
            if self.config.deployment_mode == "systemd" and cmd in {"kubectl", "helm"}:
                continue
            result = subprocess.run(["which", cmd], capture_output=True, check=False)
            if result.returncode == 0:
                self.logger.info("✅ %s: encontrado", cmd)
            else:
                self.logger.warning("⚠️  %s: não encontrado (esperado %s)", cmd, version)

    async def _apply_patches(self) -> None:
        """Aplica patches críticos"""
        self.logger.info("🩹 Aplicando patches...")
        applied = self.patch_manager.apply_all_patches()
        self.logger.info("✅ %s patches aplicados", applied)

    async def _configure_system(self) -> None:
        """Configura sistema operacional"""
        self.logger.info("⚙️  Configurando sistema...")

        limits_content = """cassandra soft nofile 65536
cassandra hard nofile 65536
cassandra soft nproc 65536
cassandra hard nproc 65536
cassandra soft memlock unlimited
cassandra hard memlock unlimited
"""

        limits_file = Path("/etc/security/limits.d/cassandra.conf")
        _write_text_atomic(limits_file, limits_content, mode=0o644)

        sysctl_content = """net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
vm.swappiness = 1
vm.overcommit_memory = 1
"""

        sysctl_file = Path("/etc/sysctl.d/99-cassandra.conf")
        _write_text_atomic(sysctl_file, sysctl_content, mode=0o644)

        subprocess.run(["sysctl", "-p", str(sysctl_file)], check=False)

        self.logger.info("✅ Sistema configurado")

    async def _setup_directories(self) -> None:
        """Configura diretórios do sistema"""
        self.logger.info("📁 Configurando diretórios...")

        dirs = [
            self.config.base_dir,
            self.config.data_dir,
            self.config.log_dir,
            self.config.config_dir,
            self.config.data_dir / "ledger",
            self.config.data_dir / "states",
            self.config.data_dir / "blocks",
            self.config.data_dir / "snapshots",
            self.config.data_dir / "backups",
            self.config.log_dir / "archive",
        ]

        for dir_path in dirs:
            dir_path.mkdir(parents=True, exist_ok=True)

        subprocess.run(["chown", "-R", "cassandra:cassandra", str(self.config.base_dir)], check=False)
        subprocess.run(["chown", "-R", "cassandra:cassandra", str(self.config.data_dir)], check=False)
        subprocess.run(["chown", "-R", "cassandra:cassandra", str(self.config.log_dir)], check=False)
        subprocess.run(
            ["chown", "-R", "cassandra:cassandra", str(self.config.config_dir)], check=False
        )

        self.logger.info("✅ Diretórios configurados")

    async def _install_dependencies(self) -> None:
        """Instala dependências do sistema"""
        if self.config.deployment_mode != "systemd":
            self.logger.info("ℹ️  Dependências gerenciadas pelo modo %s", self.config.deployment_mode)
            return

        self.logger.info("📦 Instalando dependências...")

        subprocess.run(["apt-get", "update", "-y"], check=False)

        deps = [
            "python3-venv",
            "python3-pip",
            "python3-dev",
            "build-essential",
            "libssl-dev",
            "libffi-dev",
            "curl",
            "wget",
            "git",
            "bc",
        ]

        for dep in deps:
            subprocess.run(["apt-get", "install", "-y", dep], check=False)

        venv_path = self.config.base_dir / "venv"
        subprocess.run(["python3", "-m", "venv", str(venv_path)], check=False)

        pip_packages = [
            "fastapi",
            "uvicorn",
            "pydantic",
            "numpy",
            "scipy",
            "psutil",
            "aiohttp",
            "redis",
            "asyncpg",
            "prometheus-client",
            "cryptography",
            "pyyaml",
            "toml",
        ]

        pip_cmd = [str(venv_path / "bin" / "pip"), "install"] + pip_packages
        subprocess.run(pip_cmd, check=False)

        self.logger.info("✅ Dependências instaladas")

    async def _deploy_application(self) -> None:
        """Deploy da aplicação principal"""
        if self.config.deployment_mode == "systemd":
            await self._deploy_systemd()
        elif self.config.deployment_mode == "docker":
            await self._deploy_docker()
        elif self.config.deployment_mode == "k8s":
            await self._deploy_k8s()
        else:
            raise ValueError(f"Modo de deployment inválido: {self.config.deployment_mode}")

    async def _deploy_systemd(self) -> None:
        """Deploy via systemd"""
        self.logger.info("🚀 Deployando aplicação via systemd...")

        bin_files = ["cassandra-matverse", "health-check", "monitor", "reload-config"]
        for file in bin_files:
            src = Path(f"bin/{file}")
            dst = self.config.base_dir / "bin" / file
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                _copy_file_atomic(src, dst, mode=0o755)

        config_files = ["config.toml", "config.json", "config.yaml"]
        for file in config_files:
            src = Path(f"config/production/{file}")
            dst = self.config.config_dir / file
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                _copy_file_atomic(src, dst, mode=0o640)

        service_files = ["cassandra-matverse.service", "cassandra-matverse-monitor.service"]
        for file in service_files:
            src = Path(f"deploy/systemd/{file}")
            dst = Path(f"/etc/systemd/system/{file}")
            if src.exists():
                _copy_file_atomic(src, dst, mode=0o644)

        subprocess.run(["systemctl", "daemon-reload"], check=False)

        subprocess.run(["systemctl", "enable", "cassandra-matverse.service"], check=False)
        subprocess.run(["systemctl", "enable", "cassandra-matverse-monitor.service"], check=False)
        subprocess.run(["systemctl", "start", "cassandra-matverse.service"], check=False)

        self.logger.info("✅ Aplicação deployada via systemd")

    async def _deploy_docker(self) -> None:
        """Deploy via Docker Compose"""
        self.logger.info("🐳 Deployando aplicação via Docker Compose...")

        compose_source = self.config.docker_compose_file
        if not compose_source.exists():
            raise FileNotFoundError(f"Arquivo Docker Compose não encontrado: {compose_source}")
        compose_target = self.config.base_dir / "docker-compose.yml"
        compose_target.parent.mkdir(parents=True, exist_ok=True)
        _write_text_atomic(
            compose_target,
            compose_source.read_text(encoding="utf-8"),
            mode=0o640,
        )

        env_file = self.config.config_dir / "docker.env"
        env_file.parent.mkdir(parents=True, exist_ok=True)
        env_lines = [
            f"MATVERSE_NETWORK={self.config.network}",
            f"MATVERSE_API_TOKEN={self.config.api_token}",
            f"POSTGRES_PASSWORD={self.config.postgres_password}",
            f"REDIS_PASSWORD={self.config.redis_password}",
            f"GRAFANA_PASSWORD={self.config.grafana_password}",
        ]
        _write_text_atomic(env_file, "\n".join(env_lines) + "\n", mode=0o600)

        docker_compose_cmd = None
        if shutil.which("docker"):
            if subprocess.run(["docker", "compose", "version"], check=False).returncode == 0:
                docker_compose_cmd = ["docker", "compose"]
        if docker_compose_cmd is None and shutil.which("docker-compose"):
            if subprocess.run(["docker-compose", "version"], check=False).returncode == 0:
                docker_compose_cmd = ["docker-compose"]

        if not docker_compose_cmd:
            raise RuntimeError("Docker Compose não encontrado")

        subprocess.run(
            docker_compose_cmd
            + [
                "--env-file",
                str(env_file),
                "-f",
                str(compose_target),
                "up",
                "-d",
            ],
            check=False,
        )

        self.logger.info("✅ Aplicação deployada via Docker Compose")

    async def _deploy_k8s(self) -> None:
        """Deploy via Helm/Kubernetes"""
        self.logger.info("☸️  Deployando aplicação via Kubernetes...")

        if not self.config.helm_chart_dir.exists():
            raise FileNotFoundError(
                f"Chart Helm não encontrado: {self.config.helm_chart_dir}"
            )

        namespace = self.config.k8s_namespace
        subprocess.run(["kubectl", "create", "namespace", namespace], check=False)

        values_file = self.config.helm_chart_dir / "values-production.yaml"
        subprocess.run(
            [
                "helm",
                "upgrade",
                "--install",
                self.config.helm_release_name,
                str(self.config.helm_chart_dir),
                "--namespace",
                namespace,
                "-f",
                str(values_file),
            ],
            check=False,
        )

        self.logger.info("✅ Aplicação deployada via Kubernetes")

    async def _setup_monitoring(self) -> None:
        """Configura monitoramento"""
        if not self.config.prometheus_enabled:
            return

        if self.config.deployment_mode != "systemd":
            self.logger.info("ℹ️  Monitoramento gerenciado pelo modo %s", self.config.deployment_mode)
            return

        self.logger.info("📊 Configurando monitoramento...")

        prometheus_config = """global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'cassandra-matverse'
    static_configs:
      - targets: ['localhost:8545']
    metrics_path: '/metrics'

  - job_name: 'node-exporter'
    static_configs:
      - targets: ['localhost:9100']
"""

        prometheus_dir = Path("/etc/prometheus")
        prometheus_dir.mkdir(exist_ok=True)
        _write_text_atomic(prometheus_dir / "prometheus.yml", prometheus_config, mode=0o644)

        services = ["prometheus", "grafana-server", "node-exporter"]
        for service in services:
            try:
                subprocess.run(["systemctl", "enable", service], check=False)
                subprocess.run(["systemctl", "start", service], check=False)
            except Exception:
                continue

        self.logger.info("✅ Monitoramento configurado")

    async def _validate_deployment(self) -> bool:
        """Valida deployment completo"""
        self.logger.info("🧪 Validando deployment...")

        validation_tests = [
            self._test_service_running,
            self._test_api_health,
            self._test_database_connection,
            self._test_monitoring,
        ]

        results: List[bool] = []
        for test in validation_tests:
            try:
                results.append(await test())
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error("Teste falhou: %s - %s", test.__name__, exc)
                results.append(False)

        if all(results):
            self.logger.info("✅ Todos os testes passaram")
        else:
            self.logger.warning("⚠️  Alguns testes falharam")

        return all(results)

    async def _test_service_running(self) -> bool:
        """Testa se serviço está rodando"""
        if self.config.deployment_mode == "docker":
            return self._test_docker_services()
        if self.config.deployment_mode == "k8s":
            return self._test_k8s_services()
        result = subprocess.run(
            ["systemctl", "is-active", "cassandra-matverse.service"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip() == "active"

    async def _test_api_health(self) -> bool:
        """Testa API health endpoint"""
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("http://localhost:8545/health", timeout=5) as response:
                    return response.status == 200
        except Exception:
            return False

    async def _test_database_connection(self) -> bool:
        """Valida acesso TCP aos serviços de dados."""
        if self.config.deployment_mode != "docker":
            self.logger.info("ℹ️  Teste de dados ignorado no modo %s", self.config.deployment_mode)
            return True

        postgres_ok = await self._check_tcp_port("127.0.0.1", 5432)
        redis_ok = await self._check_tcp_port("127.0.0.1", 6379)

        if not postgres_ok:
            self.logger.warning("⚠️  Postgres não respondeu em 5432")
        if not redis_ok:
            self.logger.warning("⚠️  Redis não respondeu em 6379")

        return postgres_ok and redis_ok

    async def _test_monitoring(self) -> bool:
        """Valida endpoints básicos de monitoramento."""
        if not self.config.prometheus_enabled:
            return True

        checks = [
            await self._check_http_endpoint("http://localhost:9090/-/healthy"),
        ]
        if self.config.grafana_enabled:
            checks.append(await self._check_http_endpoint("http://localhost:3000/api/health"))
        checks.append(await self._check_tcp_port("127.0.0.1", 9100))

        if not checks[0]:
            self.logger.warning("⚠️  Prometheus não respondeu")
        if self.config.grafana_enabled and len(checks) > 1 and not checks[1]:
            self.logger.warning("⚠️  Grafana não respondeu")
        if not checks[-1]:
            self.logger.warning("⚠️  Node exporter não respondeu")

        return all(checks)

    async def _check_tcp_port(self, host: str, port: int, timeout: float = 2.0) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _check_http_endpoint(self, url: str, timeout: float = 3.0) -> bool:
        import aiohttp

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout) as response:
                    return response.status == 200
        except Exception:
            return False

    def _test_docker_services(self) -> bool:
        compose_target = self.config.base_dir / "docker-compose.yml"
        if not compose_target.exists():
            return False

        if shutil.which("docker") and subprocess.run(
            ["docker", "compose", "version"], check=False
        ).returncode == 0:
            cmd = ["docker", "compose"]
        elif shutil.which("docker-compose"):
            cmd = ["docker-compose"]
        else:
            return False

        result = subprocess.run(
            cmd + ["-f", str(compose_target), "ps"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0

    def _test_k8s_services(self) -> bool:
        result = subprocess.run(
            ["kubectl", "-n", self.config.k8s_namespace, "get", "pods"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode == 0

    def _record_step_result(
        self,
        step_name: str,
        success: bool,
        start_time: float,
        started_at: str,
        detail: str = "",
    ) -> None:
        duration = time.monotonic() - start_time
        self.step_results.append(
            DeploymentStepResult(
                name=step_name,
                success=success,
                duration_seconds=duration,
                started_at=started_at,
                detail=detail,
            )
        )

    def _write_deployment_report(self) -> None:
        report = {
            "environment": self.config.environment,
            "network": self.config.network,
            "deployment_mode": self.config.deployment_mode,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "steps": [
                {
                    "name": result.name,
                    "success": result.success,
                    "duration_seconds": round(result.duration_seconds, 3),
                    "started_at": result.started_at,
                    "detail": result.detail,
                }
                for result in self.step_results
            ],
        }
        report_file = self.config.report_file
        if report_file is None:
            return
        _write_text_atomic(report_file, json.dumps(report, indent=2), mode=0o600)


# ==========================================================================
# INTERFACE DE COMANDO
# ==========================================================================


def main() -> None:
    """Entrypoint principal"""
    import argparse

    parser = argparse.ArgumentParser(
        description="matverse.deployer - Sistema Autônomo de Implantação",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  %(prog)s --mode systemd --env production
  %(prog)s --mode docker --network testnet
  %(prog)s --validate-only
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["systemd", "docker", "k8s"],
        default="systemd",
        help="Modo de deployment",
    )

    parser.add_argument(
        "--env",
        choices=["production", "staging", "development"],
        default="production",
        help="Ambiente de deployment",
    )

    parser.add_argument(
        "--network",
        choices=["mainnet", "testnet", "devnet"],
        default="mainnet",
        help="Rede Cassandra-MatVerse",
    )

    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Apenas validar ambiente atual",
    )

    parser.add_argument(
        "--config-file",
        type=Path,
        help="Arquivo de configuração YAML/JSON",
    )
    parser.add_argument(
        "--report-file",
        type=Path,
        help="Caminho do relatório JSON de deployment",
    )

    args = parser.parse_args()

    if args.config_file and args.config_file.exists():
        if args.config_file.suffix == ".json":
            config_data = json.loads(args.config_file.read_text(encoding="utf-8"))
        elif args.config_file.suffix in {".yaml", ".yml"}:
            config_data = yaml.safe_load(args.config_file.read_text(encoding="utf-8"))
        else:
            raise ValueError("Formato de arquivo não suportado")

        config = DeploymentConfig(**config_data)
    else:
        config = DeploymentConfig(
            environment=args.env,
            network=args.network,
            deployment_mode=args.mode,
        )

    if args.report_file:
        config.report_file = args.report_file

    orchestrator = DeploymentOrchestrator(config)

    if args.validate_only:
        asyncio.run(orchestrator._validate_deployment())
    else:
        asyncio.run(orchestrator.deploy())


if __name__ == "__main__":
    main()
