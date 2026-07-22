import argparse
import os
import re
import subprocess
import logging
import sys
import time
import yaml
from prometheus_client import start_http_server, Metric
from prometheus_client.core import REGISTRY

__version__ = "0.3.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DEFAULT_CONFIG_YAML = """# Динамическая конфигурация RAC Exporter

ras_host: "localhost"
ras_port: "1545"

default_credentials:
  user: "monitor_user"
  pwd: "${DEFAULT_1C_PWD}"

infobase_credentials:
  "a1d8ff58-df9e-4a94-8a75-517782d50357":
    user: "jenkins-dev"
    pwd: "${INFOBASE_PWD_DO}"

metrics:
  - name: "infobase_summary_list"
    help: "List of infobases in cluster"
    scope: "cluster"
    command: "infobase summary list --cluster={cluster_id}"
    labels:
      - "name"
      - "descr"
      - "infobase"
    default_value: 1.0

  - name: "infobase_info"
    help: "Detailed infobase settings"
    scope: "infobase"
    command: "infobase info --cluster={cluster_id} --infobase={infobase_id}"
    requires_auth: true
    split_metrics:
      - field: "sessions-deny"
        metric_suffix: "sessions_deny"
        labels: ["name"]
      - field: "scheduled-jobs-deny"
        metric_suffix: "scheduled_jobs_deny"
        labels: ["name"]
"""

def resolve_env_vars(data):
    """Подставляет переменные окружения формата ${VAR_NAME}."""
    pattern = re.compile(r"\$\{([^}]+)\}")
    if isinstance(data, dict):
        return {k: resolve_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [resolve_env_vars(item) for item in data]
    elif isinstance(data, str):
        def replace(match):
            env_var = match.group(1)
            val = os.getenv(env_var)
            if val is None:
                logging.warning(f"Environment variable '{env_var}' is not set!")
                return ""
            return val
        return pattern.sub(replace, data)
    return data

def parse_rac_output(output_text: str) -> list[dict]:
    """Универсальный парсер YAML-подобного вывода rac."""
    blocks, current_block = [], []
    for line in output_text.splitlines():
        line_str = line.strip()
        if not line_str:
            if current_block:
                blocks.append("\n".join(current_block))
                current_block = []
            continue
        # Любая строка вида "key :" без отступа от края считается началом нового блока
        if re.match(r"^[a-zA-Z0-9_-]+\s*:", line) and current_block and not line.startswith(" "):
            # Если встретили повторяющийся первый ключ или новую секцию
            if any(line_str.startswith(k) for k in ["infobase :", "cluster :", "process :", "session :"]):
                blocks.append("\n".join(current_block))
                current_block = [line]
            else:
                current_block.append(line)
        else:
            current_block.append(line)
            
    if current_block:
        blocks.append("\n".join(current_block))

    parsed_objects = []
    for block in blocks:
        try:
            data = yaml.safe_load(block)
            if isinstance(data, dict):
                clean_data = {str(k).strip(): str(v).strip() if v is not None else "" for k, v in data.items()}
                parsed_objects.append(clean_data)
        except Exception as e:
            logging.warning(f"Failed to parse rac output block: {e}")
            
    return parsed_objects

def cast_value_to_float(val: str) -> float:
    """Приводит значения on/off, yes/no, true/false и числа к float."""
    val_lower = str(val).lower()
    if val_lower in ["on", "yes", "true"]:
        return 1.0
    if val_lower in ["off", "no", "false"]:
        return 0.0
    try:
        return float(val)
    except ValueError:
        return 0.0

class DynamicRacCollector:
    def __init__(self, rac_path: str, config_path: str, prefix: str):
        self.rac_path = rac_path
        self.config_path = config_path
        self.prefix = prefix

    def load_config(self):
        if not os.path.exists(self.config_path):
            logging.error(f"Config file not found: {self.config_path}")
            return {}
        with open(self.config_path, "r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f) or {}
            return resolve_env_vars(raw_config)

    def run_rac(self, command_str: str, ras_target: str, auth: dict = None) -> str:
        cmd_args = command_str.split()
        cmd = [self.rac_path] + cmd_args
        
        if auth:
            if auth.get("user"):
                cmd.append(f"--infobase-user={auth['user']}")
            if auth.get("pwd"):
                cmd.append(f"--infobase-pwd={auth['pwd']}")
                
        cmd.append(ras_target)
        
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Error executing {' '.join(cmd)}: {e.stderr.strip()}")
            return ""

    def collect(self):
        config = self.load_config()
        if not config:
            return

        ras_target = f"{config.get('ras_host', 'localhost')}:{config.get('ras_port', '1545')}"
        default_auth = config.get("default_credentials", {})
        creds_config = config.get("infobase_credentials", {})

        # 1. Получаем список кластеров для базового контекста
        clusters_raw = self.run_rac("cluster list", ras_target)
        clusters = parse_rac_output(clusters_raw)

        for cluster in clusters:
            cluster_id = cluster.get("cluster")
            if not cluster_id:
                continue

            # Получаем список баз для итерации
            infobases_raw = self.run_rac(f"infobase summary list --cluster={cluster_id}", ras_target)
            infobases = parse_rac_output(infobases_raw)

            # 2. Обрабатываем правила метрик из конфигурационного файла
            for metric_cfg in config.get("metrics", []):
                metric_name = f"{self.prefix}{metric_cfg['name']}"
                scope = metric_cfg.get("scope", "cluster")
                cmd_template = metric_cfg["command"]
                requires_auth = metric_cfg.get("requires_auth", False)

                # Выполнение для уровня Кластера
                if scope == "cluster":
                    cmd_str = cmd_template.format(cluster_id=cluster_id)
                    raw_out = self.run_rac(cmd_str, ras_target)
                    items = parse_rac_output(raw_out)
                    
                    metric_obj = Metric(metric_name, metric_cfg.get("help", ""), "gauge")
                    for item in items:
                        labels = {lbl: item.get(lbl, "") for lbl in metric_cfg.get("labels", [])}
                        val = metric_cfg.get("default_value", 1.0)
                        metric_obj.add_sample(metric_name, value=float(val), labels=labels)
                    yield metric_obj

                # Выполнение для уровня Инфобазы
                elif scope == "infobase":
                    # Подготавливаем метрики
                    split_configs = metric_cfg.get("split_metrics", [])
                    metrics_to_yield = {}

                    for sc in split_configs:
                        full_name = f"{metric_name}_{sc['metric_suffix']}"
                        metrics_to_yield[sc['field']] = {
                            "name": full_name,
                            "labels_keys": sc.get("labels", ["name"]),
                            "metric": Metric(full_name, f"Field {sc['field']} from {metric_cfg['name']}", "gauge")
                        }

                    for ib in infobases:
                        ib_id = ib.get("infobase")
                        ib_name = ib.get("name")
                        
                        auth = None
                        if requires_auth:
                            auth = creds_config.get(ib_id) or creds_config.get(ib_name) or default_auth

                        cmd_str = cmd_template.format(cluster_id=cluster_id, infobase_id=ib_id)
                        raw_out = self.run_rac(cmd_str, ras_target, auth=auth)
                        info_items = parse_rac_output(raw_out)

                        if info_items:
                            item = info_items[0]
                            for field, m_data in metrics_to_yield.items():
                                if field in item:
                                    labels = {lbl: item.get(lbl, ib_name) for lbl in m_data["labels_keys"]}
                                    val = cast_value_to_float(item[field])
                                    m_data["metric"].add_sample(m_data["name"], value=val, labels=labels)

                    for m_data in metrics_to_yield.values():
                        yield m_data["metric"]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="1C Dynamic RAC Prometheus Exporter")
    parser.add_argument("--rac", default="/usr/local/bin/rac", help="Path to rac binary")
    parser.add_argument("--prefix", default="p1c_", help="Prometheus metric prefix")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--port", type=int, default=9161, help="Port to expose metrics")
    parser.add_argument("--init-config", action="store_true", help="Generate default config.yaml and exit")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    
    args = parser.parse_args()

    if args.init_config:
        if os.path.exists(args.config):
            logging.error(f"File {args.config} already exists!")
            sys.exit(1)
        with open(args.config, "w", encoding="utf-8") as f:
            f.write(DEFAULT_CONFIG_YAML)
        logging.info(f"Default dynamic configuration written to '{args.config}'")
        sys.exit(0)

    REGISTRY.register(DynamicRacCollector(rac_path=args.rac, config_path=args.config, prefix=args.prefix))
    
    start_http_server(args.port)
    logging.info(f"Rac Exporter v{__version__} started on port {args.port} with prefix '{args.prefix}'")
    
    while True:
        time.sleep(1)