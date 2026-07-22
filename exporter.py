import argparse
import subprocess
import logging
import sys
import time
import yaml
from prometheus_client import start_http_server, Metric
from prometheus_client.core import REGISTRY

__version__ = "0.1.0"  # Дефолтная версия, если не переопределена

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def parse_rac_output(output_text: str) -> list[dict]:
    """
    Преобразует специфичный вывод `rac` в список словарей через PyYAML.
    """
    blocks = []
    current_block = []
    
    for line in output_text.splitlines():
        line_str = line.strip()
        if not line_str:
            if current_block:
                blocks.append("\n".join(current_block))
                current_block = []
            continue
        # Если строка начинается с нового объекта (например, "cluster :" или "infobase :")
        if (line_str.startswith("infobase ") or line_str.startswith("cluster ")) and current_block:
            blocks.append("\n".join(current_block))
            current_block = [line]
        else:
            current_block.append(line)
            
    if current_block:
        blocks.append("\n".join(current_block))

    parsed_objects = []
    for block in blocks:
        try:
            # YAML отлично жрет форматирование rac, если очистить кавычки/пробелы
            data = yaml.safe_load(block)
            if isinstance(data, dict):
                # Приводим ключи и значения к нормализованному виду
                clean_data = {str(k).strip(): str(v).strip() if v is not None else "" for k, v in data.items()}
                parsed_objects.append(clean_data)
        except Exception as e:
            logging.warning(f"Failed to parse block via YAML: {e}")
            
    return parsed_objects

def cast_value_to_float(val: str) -> float:
    """Конвертирует on/off, yes/no, true/false и числа в float для Prometheus."""
    val_lower = str(val).lower()
    if val_lower in ["on", "yes", "true"]:
        return 1.0
    if val_lower in ["off", "no", "false"]:
        return 0.0
    try:
        return float(val)
    except ValueError:
        return 0.0

class RacCollector:
    def __init__(self, rac_path: str, config_path: str, prefix: str):
        self.rac_path = rac_path
        self.config_path = config_path
        self.prefix = prefix

    def load_config(self):
        with open(self.config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def run_rac(self, args_list: list[str]) -> str:
        cmd = [self.rac_path] + args_list
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Error running command {' '.join(cmd)}: {e.stderr}")
            return ""

    def collect(self):
        config = self.load_config()
        ras_target = f"{config.get('ras_host', 'localhost')}:{config.get('ras_port', '1545')}"
        
        # 1. Получаем список кластеров
        clusters_raw = self.run_rac(["cluster", "list", ras_target])
        clusters = parse_rac_output(clusters_raw)

        if not clusters:
            return

        for cluster in clusters:
            cluster_id = cluster.get("cluster")
            if not cluster_id:
                continue

            # 2. Получаем сводку по инфобазам
            infobases_raw = self.run_rac(["infobase", "summary", "list", f"--cluster={cluster_id}", ras_target])
            infobases = parse_rac_output(infobases_raw)

            # Метрика summary_list
            metric_name = f"{self.prefix}infobase_summary_list"
            summary_metric = Metric(metric_name, "List of infobases in cluster", "gauge")
            
            for ib in infobases:
                labels = {
                    "name": ib.get("name", ""),
                    "descr": ib.get("descr", ""),
                    "infobase": ib.get("infobase", "")
                }
                summary_metric.add_sample(metric_name, value=1.0, labels=labels)
            
            yield summary_metric

            # 3. Детальная информация по каждой базе (sessions-deny, scheduled-jobs-deny и т.д.)
            creds_config = config.get("infobase_credentials", {})
            
            # Делаем метрики для деталей
            sessions_deny_m = Metric(f"{self.prefix}infobase_info_sessions_deny", "Sessions deny status", "gauge")
            jobs_deny_m = Metric(f"{self.prefix}infobase_info_scheduled_jobs_deny", "Scheduled jobs deny status", "gauge")

            for ib in infobases:
                ib_id = ib.get("infobase")
                ib_name = ib.get("name")
                
                # Ищем пароли по ID или Имени
                auth = creds_config.get(ib_id) or creds_config.get(ib_name) or {}
                
                cmd_args = ["infobase", "info", f"--cluster={cluster_id}", f"--infobase={ib_id}"]
                if auth.get("user"):
                    cmd_args.append(f"--infobase-user={auth['user']}")
                if auth.get("pwd"):
                    cmd_args.append(f"--infobase-pwd={auth['pwd']}")
                cmd_args.append(ras_target)

                info_raw = self.run_rac(cmd_args)
                info_data = parse_rac_output(info_raw)

                if info_data:
                    data = info_data[0]
                    name_label = {"name": data.get("name", ib_name)}

                    if "sessions-deny" in data:
                        sessions_deny_m.add_sample(
                            f"{self.prefix}infobase_info_sessions_deny",
                            value=cast_value_to_float(data["sessions-deny"]),
                            labels=name_label
                        )
                    if "scheduled-jobs-deny" in data:
                        jobs_deny_m.add_sample(
                            f"{self.prefix}infobase_info_scheduled_jobs_deny",
                            value=cast_value_to_float(data["scheduled-jobs-deny"]),
                            labels=name_label
                        )

            yield sessions_deny_m
            yield jobs_deny_m

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="1C RAC Prometheus Exporter")
    parser.add_argument("--rac", default="/usr/local/bin/rac", help="Path to rac binary")
    parser.add_argument("--prefix", default="p1c_", help="Prometheus metric prefix")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--port", type=int, default=9161, help="Port to expose metrics")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    
    args = parser.parse_args()

    REGISTRY.register(RacCollector(rac_path=args.rac, config_path=args.config, prefix=args.prefix))
    
    start_http_server(args.port)
    logging.info(f"Rac Exporter v{__version__} started on port {args.port} with prefix '{args.prefix}'")
    
    while True:
        time.sleep(1)