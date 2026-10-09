"""Prompt templates are versioned files in services/worker/src/prompts (ТЗ п. 4.1.3.5).
Placeholders use string.Template syntax ($name) so that JSON braces need no escaping."""
import os
from functools import lru_cache
from string import Template

PROMPTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts")


@lru_cache(maxsize=None)
def _template(name: str) -> Template:
    with open(os.path.join(PROMPTS_DIR, f"{name}.txt"), "r", encoding="utf-8") as f:
        return Template(f.read().strip())


def render(name: str, **values) -> str:
    return _template(name).safe_substitute(**{k: str(v) for k, v in values.items()})
