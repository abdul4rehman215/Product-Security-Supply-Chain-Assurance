#!/usr/bin/env python3
import yaml
from pathlib import Path

class ConfigLoader:
    """Loads and validates configuration."""

    def __init__(self, config_path):
        self.config_path = Path(config_path)
        self.config = {}

    def load_config(self):
        """Load configuration from YAML file."""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Config file not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            self.config = yaml.safe_load(f)

        valid, issues = self.validate_config(self.config)
        if not valid:
            raise ValueError("Config validation failed: " + "; ".join(issues))

        return self.config

    def validate_config(self, config):
        """Validate configuration structure."""
        issues = []

        required_sections = ["data_sources", "threat_model", "alerting", "reporting", "monitoring"]
        for sec in required_sections:
            if sec not in config:
                issues.append(f"Missing required section: {sec}")

        if "data_sources" in config:
            for src_name, src_cfg in config["data_sources"].items():
                if "path" not in src_cfg:
                    issues.append(f"Missing path for data source: {src_name}")
                if "enabled" not in src_cfg:
                    issues.append(f"Missing enabled flag for data source: {src_name}")

        if "alerting" in config and "thresholds" in config["alerting"]:
            thresholds = config["alerting"]["thresholds"]
            for key, val in thresholds.items():
                if not isinstance(val, int) or val < 0:
                    issues.append(f"Invalid threshold {key}: must be non-negative integer")

        return (len(issues) == 0, issues)

    def get_data_source_config(self, source_name):
        """Get configuration for specific data source."""
        if not self.config:
            self.load_config()
        return self.config.get("data_sources", {}).get(source_name, {})

if __name__ == "__main__":
    loader = ConfigLoader("threat_intel_config.yaml")
    cfg = loader.load_config()
    print("Configuration loaded successfully!")
    print(cfg)
