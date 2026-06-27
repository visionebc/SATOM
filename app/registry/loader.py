import yaml
import os

_registry = None

def load_registry():
    global _registry
    if _registry is None:
        yaml_path = os.path.join(os.path.dirname(__file__), '..', '..', 'endpoints.yaml')
        try:
            with open(yaml_path) as f:
                _registry = yaml.safe_load(f) or {}
        except FileNotFoundError:
            _registry = {}
    return _registry

def get_endpoints_by_section(section: str) -> list:
    reg = load_registry()
    from .categories import category_for
    result = []
    for name, urn in reg.items():
        sec, _ = category_for(urn)
        if sec and sec[0] == section:
            result.append({'name': name, 'urn': urn})
    return result

def get_all_sections() -> list:
    from .categories import SECTION_ORDER
    return SECTION_ORDER
