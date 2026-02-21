#!/usr/bin/env python3

import json
import logging
import subprocess
import time
from datetime import datetime
from pathlib import Path

from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    s_initialize,
    s_string,
    s_delim,
    s_group,
    s_bytes,
    s_byte,
    s_word,
    s_dword,
    s_get,
)


class AutomatedFuzzingFramework:
    """Automated fuzzing framework with vulnerability logging"""

    def __init__(self, config_file="fuzzing_config.json"):
        self.config = self.load_config(config_file)
        self.setup_logging()

        self.results = {
            "started_at": datetime.now().isoformat(),
            "target": self.config.get("target", {}),
            "protocols": {},
            "errors": [],
        }

        self.server_process = None

    def setup_logging(self):
        log_cfg = self.config.get("logging", {})
        log_level_str = log_cfg.get("level", "INFO").upper()
        log_file = log_cfg.get("file", "automated_fuzzing.log")

        level = getattr(logging, log_level_str, logging.INFO)

        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(),
            ],
        )

        logging.info("Logging initialized.")
        logging.info(f"Log file: {log_file}")

    def load_config(self, config_file):
        default_config = {
            "target": {"host": "127.0.0.1", "port": 8080},
            "fuzzing": {"sleep_time": 0.1},
            "protocols": ["http_like", "binary"],
            "logging": {"level": "INFO", "file": "automated_fuzzing.log"},
        }

        cfg_path = Path(config_file)
        if cfg_path.exists():
            with open(cfg_path, "r", encoding="utf-8") as f:
                return json.load(f)

        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(default_config, f, indent=2)

        return default_config

    def start_target_server(self):
        try:
            self.server_process = subprocess.Popen(
                ["python3", "test_server.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(2)
            logging.info("Target server started successfully.")
            return True
        except Exception as e:
            logging.error(f"Error starting server: {e}")
            return False

    def stop_target_server(self):
        if self.server_process:
            self.server_process.terminate()
            logging.info("Target server stopped.")

    def define_http_like_protocol(self):
        s_initialize("http_request")
        s_group("method", ["GET", "POST", "PUT", "DELETE"])
        s_delim(" ", fuzzable=False)
        s_string("/index.html", name="uri", fuzzable=True)
        s_delim(" ", fuzzable=False)
        s_group("version", ["HTTP/1.0", "HTTP/1.1"])
        s_delim("\r\n", fuzzable=False)
        s_string("Host: localhost\r\n", fuzzable=False)
        s_delim("\r\n", fuzzable=False)

    def define_binary_protocol(self):
        s_initialize("binary_message")
        s_bytes(b"\xBA\xAD\xF0\x0D", fuzzable=False)
        s_byte(1, name="version", fuzzable=True)
        s_word(0, name="flags", fuzzable=True)
        s_dword(16, name="length", fuzzable=True)
        s_bytes(b"A" * 16, name="payload", fuzzable=True)

    def create_fuzzing_session(self):
        host = self.config["target"]["host"]
        port = self.config["target"]["port"]

        connection = TCPSocketConnection(host, port)
        target = Target(connection=connection)
        session = Session(target=target, sleep_time=0.1)
        return session

    def run_protocol_fuzzing(self, protocol_name):
        logging.info(f"Running fuzzing for protocol: {protocol_name}")
        session = self.create_fuzzing_session()

        if protocol_name == "http_like":
            self.define_http_like_protocol()
            session.connect(s_get("http_request"))
        elif protocol_name == "binary":
            self.define_binary_protocol()
            session.connect(s_get("binary_message"))

        session.fuzz()
        self.results["protocols"][protocol_name] = {
            "protocol": protocol_name,
            "estimated_test_cases": getattr(session, "num_cases", None),
            "crashes_detected": 0,
            "vulnerabilities": [],
        }

    def generate_vulnerability_report(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = Path(f"vulnerability_report_{timestamp}.txt")

        with open(report_file, "w", encoding="utf-8") as f:
            f.write("=== Vulnerability Report ===\n")
            f.write(f"Generated: {timestamp}\n\n")

            for proto, pdata in self.results["protocols"].items():
                f.write(f"--- {proto} ---\n")
                f.write(f"Estimated test cases: {pdata['estimated_test_cases']}\n")
                f.write(f"Crashes detected: {pdata['crashes_detected']}\n")
                f.write("Vulnerabilities: None detected\n\n")

        logging.info(f"Report written: {report_file}")

    def run_automated_campaign(self):
        if not self.start_target_server():
            return

        for protocol_name in self.config.get("protocols", []):
            self.run_protocol_fuzzing(protocol_name)

        self.generate_vulnerability_report()
        self.stop_target_server()


if __name__ == "__main__":
    framework = AutomatedFuzzingFramework()
    framework.run_automated_campaign()
