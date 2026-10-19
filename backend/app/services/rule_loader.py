
from pathlib import Path
from typing import Any

import yaml


RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def load_rule(rule_id: str) -> dict[str, Any]:
    """Load one detection rule from the app/rules directory."""

    rule_path = RULES_DIR / f"{rule_id}.yml"

    if not rule_path.is_file():
        raise FileNotFoundError(
            f"Detection rule not found: {rule_path}"
        )

    with rule_path.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError(
            f"Detection rule must contain a YAML mapping: {rule_id}"
        )

    if rule.get("id") != rule_id:
        raise ValueError(
            f"Rule ID in {rule_path.name} must be '{rule_id}'."
        )

    if not isinstance(rule.get("detection"), dict):
        raise ValueError(
            f"Rule '{rule_id}' must contain a detection section."
        )

    return rule
