from pathlib import Path
from typing import Any, List, Dict
import yaml

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def load_rule(rule_id: str) -> dict[str, Any]:
    """Load one detection rule from the app/rules directory."""
    rule_path = RULES_DIR / f"{rule_id}.yml"

    if not rule_path.is_file():
        raise FileNotFoundError(f"Detection rule not found: {rule_path}")

    with rule_path.open("r", encoding="utf-8") as file:
        rule = yaml.safe_load(file)

    if not isinstance(rule, dict):
        raise ValueError(f"Detection rule must contain a YAML mapping: {rule_id}")

    return rule


def load_all_rules() -> List[Dict[str, Any]]:
    """Loads all YAML Sigma-like rules from the app/rules directory."""
    rules = []
    if not RULES_DIR.exists():
        return rules

    for f in sorted(RULES_DIR.glob("*.yml")):
        try:
            with f.open("r", encoding="utf-8") as file:
                content = file.read()
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    data.setdefault("id", f.stem)
                    data.setdefault("title", data.get("title") or f.stem.replace("_", " ").title())
                    data.setdefault("severity", data.get("level", "medium"))
                    data.setdefault("description", data.get("description", ""))
                    data.setdefault("mitre_technique", data.get("tags", ["T1059"])[0] if data.get("tags") else "T1059")
                    data.setdefault("mitre_tactic", "Execution")
                    data["yaml_content"] = content
                    rules.append(data)
        except Exception:
            continue
    return rules
