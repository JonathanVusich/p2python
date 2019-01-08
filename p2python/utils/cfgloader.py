import yaml
import pkg_resources


def load_config(name: str) -> dict:
    config = pkg_resources.resource_string(name, "cfg.yaml")
    return yaml.safe_load(config)
