import argparse
import os
import re
import signal
import subprocess
import logging
import sys
import time
import yaml
from http.server import HTTPServer, BaseHTTPRequestHandler
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from prometheus_client.core import REGISTRY

__version__ = "0.4.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DEFAULT_CONFIG_YAML = """# Конфигурация RAC Exporter

server:
  port: 9161
  metrics_path: "/metrics"
  prefix: "p1c_"

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
    blocks, current_block = [], []
    for line in output_text.splitlines():
        line_str = line.strip()
        if not line_str:
            if current_block:
                blocks.append("\n".join(current_block))
                current_block = []
            continue
        if re.match(r"^[a-zA-Z0-9_-]+\s*:", line) and current_block and not line.startswith(" "):
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
    def __init__(self, rac_path: str, config_path: str, override_prefix: str = None):
        self.rac_path = rac_path
        self.config_path = config_path
        self.override_prefix = override_prefix

    def load_config(self):
        if not os.path.exists(self.config_path):
            logging.error(f"Config file not found: {self.config_path}")
            return {}
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                raw_config = yaml.safe_load(f) or {}
                return resolve_env_vars(raw_config)
        except Exception as e:
            logging.error(f"Error loading config file: {e}")
            return {}

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
        except Exception as e:
            logging.error(f"Unexpected error executing rac: {e}")
            return ""

    def collect(self):
        try:
            config = self.load_config()
            if not config:
                return

            server_cfg = config.get("server", {})
            prefix = self.override_prefix or server_cfg.get("prefix", "p1c_")

            ras_target = f"{config.get('ras_host', 'localhost')}:{config.get('ras_port', '1545')}"
            default_auth = config.get("default_credentials", {})
            creds_config = config.get("infobase_credentials", {})

            clusters_raw = self.run_rac("cluster list", ras_target)
            clusters = parse_rac_output(clusters_raw)

            for cluster in clusters:
                cluster_id = cluster.get("cluster")
                if not cluster_id:
                    continue

                infobases_raw = self.run_rac(f"infobase summary list --cluster={cluster_id}", ras_target)
                infobases = parse_rac_output(infobases_raw)

                for metric_cfg in config.get("metrics", []):
                    metric_name = f"{prefix}{metric_cfg['name']}"
                    scope = metric_cfg.get("scope", "cluster")
                    cmd_template = metric_cfg["command"]
                    requires_auth = metric_cfg.get("requires_auth", False)

                    if scope == "cluster":
                        cmd_str = cmd_template.format(cluster_id=cluster_id)
                        raw_out = self.run_rac(cmd_str, ras_target)
                        items = parse_rac_output(raw_out)
                        
                        from prometheus_client.core import Metric
                        metric_obj = Metric(metric_name, metric_cfg.get("help", ""), "gauge")
                        for item in items:
                            labels = {lbl: item.get(lbl, "") for lbl in metric_cfg.get("labels", [])}
                            val = metric_cfg.get("default_value", 1.0)
                            metric_obj.add_sample(metric_name, value=float(val), labels=labels)
                        yield metric_obj

                    elif scope == "infobase":
                        split_configs = metric_cfg.get("split_metrics", [])
                        metrics_to_yield = {}

                        from prometheus_client.core import Metric
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
        except Exception as e:
            logging.error(f"Error during metrics collection: {e}")

def make_handler(metrics_path):
    class MetricsHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == metrics_path:
                try:
                    output = generate_latest(REGISTRY)
                    self.send_response(200)
                    self.send_header("Content-Type", CONTENT_TYPE_LATEST)
                    self.end_headers()
                    self.wfile.write(output)
                except Exception as e:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(f"Error generating metrics: {e}".encode("utf-8"))
            elif self.path == "/" or self.path == "":
                # Минималистичная HTML стартовая страница
                html = f"""<!DOCTYPE html>
<html>
<head>
    <title>1C RAC Exporter</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 40px; background: #f4f6f8; color: #333; }}
        .card {{ background: #fff; padding: 24px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); max-width: 600px; }}
        h1 {{ margin-top: 0; color: #2c3e50; font-size: 24px; }}
        a {{ color: #3498db; text-decoration: none; font-weight: bold; }}
        a:hover {{ text-decoration: underline; }}
        .footer {{ margin-top: 20px; font-size: 12px; color: #7f8c8d; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>1C RAC Prometheus Exporter</h1>
        <p>Exporter is running successfully.</p>
        <p><a href="{metrics_path}">Metrics ({metrics_path})</a></p>
        <div class="footer">Version: v{__version__}</div>
    </div>
</body>
</html>"""
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(html.encode("utf-8"))
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            # Отключаем спам стандартного HTTP-сервера в консоль
            return

    return MetricsHandler

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="1C Dynamic RAC Prometheus Exporter")
    parser.add_argument("--rac", default="/usr/local/bin/rac", help="Path to rac binary")
    parser.add_argument("--prefix", help="Prometheus metric prefix (overrides config)")
    parser.add_argument("--config", default="config.yaml", help="Path to config file")
    parser.add_argument("--port", type=int, help="Port to expose metrics (overrides config)")
    parser.add_argument("--metrics-path", help="Path for metrics endpoint, e.g. /metrics (overrides config)")
    parser.add_argument("--init-config", action="store_true", help="Generate default config.yaml and exit")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")
    
    args = parser.parse_args()

    if args.init_config:
        if os.path.exists(args.config):
            logging.error(f"File {args.config} already exists!")
            sys.exit(1)
        with open(args.config, "w", encoding="utf-8") as f:
            f.write(DEFAULT_CONFIG_YAML)
        logging.info(f"Default configuration written to '{args.config}'")
        sys.exit(0)

    # Читаем параметры из конфига для инициализации сервера
    config_data = {}
    if os.path.exists(args.config):
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                config_data = yaml.safe_load(f) or {}
        except Exception:
            pass

    server_cfg = config_data.get("server", {})
    port = args.port or server_cfg.get("port", 9161)
    metrics_path = args.metrics_path or server_cfg.get("metrics_path", "/metrics")

    REGISTRY.register(DynamicRacCollector(rac_path=args.rac, config_path=args.config, override_prefix=args.prefix))
    
    handler_class = make_handler(metrics_path)
    httpd = HTTPServer(("", port), handler_class)

    def shutdown_handler(signum, frame):
        logging.info("Shutting down exporter gracefully...")
        httpd.server_close()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    logging.info(f"Rac Exporter v{__version__} started on port {port}")
    logging.info(f"Metrics available at http://localhost:{port}{metrics_path}")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()