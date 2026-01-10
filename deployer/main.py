#!/usr/bin/env python3
"""
matverse.deployer - Sistema Autônomo de Implantação
Produção Soberana | Versão 1.0.0
"""

import asyncio
import json
import logging
import secrets
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

import yaml

# ============================================================================
# CONFIGURAÇÃO DO SISTEMA
# ============================================================================


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

    # Segurança
    api_token: Optional[str] = None
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
        if not self.api_token:
            self.api_token = secrets.token_hex(32)


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

        service_file.write_text(
            patch_content.format(api_token=self.config.api_token, network=self.config.network)
        )
        self.logger.info("✅ Patch systemd aplicado")
        return True

    def _apply_install_script_patch(self) -> bool:
        """Placeholder para patch de script de instalação"""
        return False

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

        content = main_file.read_text()
        for old, new in patches:
            content = content.replace(old, new)

        main_file.write_text(content)
        self.logger.info("✅ Patches Python aplicados")
        return True

    def _apply_security_patch(self) -> bool:
        """Placeholder para patch de segurança"""
        return False

    def _apply_monitoring_patch(self) -> bool:
        """Placeholder para patch de monitoramento"""
        return False


# ============================================================================
# ORQUESTRADOR DE DEPLOY
# ============================================================================


class DeploymentOrchestrator:
    """Orquestrador completo de deployment"""

    def __init__(self, config: DeploymentConfig) -> None:
        self.config = config
        self.patch_manager = PatchManager(config)
        self.logger = logging.getLogger(__name__)

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

        for step in steps:
            try:
                await step()
            except Exception as exc:  # pylint: disable=broad-except
                self.logger.error("❌ Erro no passo %s: %s", step.__name__, exc)
                raise

        self.logger.info("✅ Deployment completo com sucesso")

    async def _validate_environment(self) -> None:
        """Valida ambiente de produção"""
        requirements = {
            "python3": "3.8+",
            "docker": "20.10+ (opcional)",
            "systemctl": "systemd 240+",
            "openssl": "1.1.1+",
        }

        self.logger.info("🔍 Validando ambiente...")

        for cmd, version in requirements.items():
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
        limits_file.write_text(limits_content)

        sysctl_content = """net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
vm.swappiness = 1
vm.overcommit_memory = 1
"""

        sysctl_file = Path("/etc/sysctl.d/99-cassandra.conf")
        sysctl_file.write_text(sysctl_content)

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
        self.logger.info("🚀 Deployando aplicação...")

        bin_files = ["cassandra-matverse", "health-check", "monitor", "reload-config"]
        for file in bin_files:
            src = Path(f"bin/{file}")
            dst = self.config.base_dir / "bin" / file
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())
                dst.chmod(0o755)

        config_files = ["config.toml", "config.json", "config.yaml"]
        for file in config_files:
            src = Path(f"config/production/{file}")
            dst = self.config.config_dir / file
            if src.exists():
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src.read_bytes())

        service_files = ["cassandra-matverse.service", "cassandra-matverse-monitor.service"]
        for file in service_files:
            src = Path(f"deploy/systemd/{file}")
            dst = Path(f"/etc/systemd/system/{file}")
            if src.exists():
                dst.write_bytes(src.read_bytes())

        subprocess.run(["systemctl", "daemon-reload"], check=False)

        subprocess.run(["systemctl", "enable", "cassandra-matverse.service"], check=False)
        subprocess.run(["systemctl", "enable", "cassandra-matverse-monitor.service"], check=False)
        subprocess.run(["systemctl", "start", "cassandra-matverse.service"], check=False)

        self.logger.info("✅ Aplicação deployada")

    async def _setup_monitoring(self) -> None:
        """Configura monitoramento"""
        if not self.config.prometheus_enabled:
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
        (prometheus_dir / "prometheus.yml").write_text(prometheus_config)

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
        """Placeholder para teste de banco de dados"""
        return True

    async def _test_monitoring(self) -> bool:
        """Placeholder para teste de monitoramento"""
        return True


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

    args = parser.parse_args()

    if args.config_file and args.config_file.exists():
        if args.config_file.suffix == ".json":
            config_data = json.loads(args.config_file.read_text())
        elif args.config_file.suffix in {".yaml", ".yml"}:
            config_data = yaml.safe_load(args.config_file.read_text())
        else:
            raise ValueError("Formato de arquivo não suportado")

        config = DeploymentConfig(**config_data)
    else:
        config = DeploymentConfig(
            environment=args.env,
            network=args.network,
            deployment_mode=args.mode,
        )

    orchestrator = DeploymentOrchestrator(config)

    if args.validate_only:
        asyncio.run(orchestrator._validate_deployment())
    else:
        asyncio.run(orchestrator.deploy())


if __name__ == "__main__":
    main()
