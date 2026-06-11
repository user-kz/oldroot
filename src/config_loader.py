"""
config_loader.py — загружает config/config.yaml.
Используй: from config_loader import cfg

Устойчив к отсутствию файла: если config.yaml нет (он в .gitignore),
возвращает {} и приложение работает на встроенных дефолтах из cfg.get(...).
"""
import yaml
from pathlib import Path

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"
_EXAMPLE_PATH = Path(__file__).parent.parent / "config" / "config.example.yaml"


def load_config(path: Path = _CONFIG_PATH) -> dict:
    """Читает config.yaml. При отсутствии пробует config.example.yaml,
    иначе возвращает пустой dict (везде в коде есть .get(...) с дефолтами)."""
    for candidate in (path, _EXAMPLE_PATH):
        try:
            with open(candidate, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                return data if isinstance(data, dict) else {}
        except FileNotFoundError:
            continue
        except yaml.YAMLError as e:
            print(f"[config_loader] Ошибка разбора {candidate}: {e}")
            return {}
    return {}


cfg = load_config()
