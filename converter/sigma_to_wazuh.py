#!/usr/bin/env python3
"""
sigma_to_wazuh.py — SentryForge's constrained Sigma-subset -> Wazuh rule converter.

Deliberate scope (documented limitation, not an oversight):
  - Exactly one 'selection' block, condition must literally be 'selection' (flat AND only).
  - Every field under selection must be a single scalar (a list implies OR, which
    Wazuh's rule engine cannot express natively).
  - Only two selector prefixes are supported:
      'decoder.name'  -> Wazuh <decoded_as>
      'data.<field>'  -> Wazuh <field name="field">
    Anything else raises a hard error.
"""
import sys, json, yaml
from pathlib import Path
from xml.sax.saxutils import escape

RULE_ID_MIN, RULE_ID_MAX = 110000, 120000
ID_MAP_PATH = Path(__file__).parent / "rule_id_map.json"
LEVEL_MAP = {"informational": 3, "low": 5, "medium": 7, "high": 10, "critical": 13}


def load_id_map():
    return json.loads(ID_MAP_PATH.read_text()) if ID_MAP_PATH.exists() else {}


def save_id_map(m):
    ID_MAP_PATH.write_text(json.dumps(m, indent=2, sort_keys=True))


def assign_rule_id(sigma_id, id_map):
    if sigma_id in id_map:
        return id_map[sigma_id]
    used = set(id_map.values())
    candidate = RULE_ID_MIN
    while candidate in used:
        candidate += 1
    if candidate > RULE_ID_MAX:
        raise ValueError("Exhausted the reserved 100000-120000 custom rule ID range.")
    id_map[sigma_id] = candidate
    return candidate


def extract_mitre_ids(tags):
    out = []
    for tag in tags or []:
        t = tag.lower()
        if t.startswith("attack.t") and t[8:9].isdigit():
            out.append(tag.split(".", 1)[1].upper())
    return out


def convert_selection(selection):
    decoded_as, parent_id, fields = None, None, []
    for key, value in selection.items():
        if isinstance(value, list):
            raise ValueError(f"Field '{key}' has a list value {value!r} — implies OR, out of scope.")
        if key == "decoder.name":
            decoded_as = value
        elif key == "parent_id":
            parent_id = value
        elif key.startswith("data."):
            fields.append((key[len("data."):], value))
        elif key.startswith("field."):
            # Literal Wazuh field name, used for decoders (e.g. auditd) whose
            # decoded fields keep a dotted prefix like 'audit.exe', 'audit.type'.
            fields.append((key[len("field."):], value))
        else:
            raise ValueError(f"Unsupported field '{key}'. Only 'decoder.name', 'parent_id', 'data.<field>' and 'field.<literal_name>' are supported.")
    return decoded_as, parent_id, fields


def _build_correlation_rule(doc, correlation, id_map):
    sigma_id = doc.get("id") or doc["title"]
    rule_id = assign_rule_id(sigma_id, id_map)
    level = LEVEL_MAP.get(doc.get("level", "medium"), 7)
    description = doc.get("description") or doc["title"]
    mitre_ids = extract_mitre_ids(doc.get("tags"))
    groups = ["sentryforge"] + [
        t.split(".", 1)[1] for t in (doc.get("tags") or [])
        if t.lower().startswith("attack.") and not t.lower().startswith("attack.t")
    ]

    freq = correlation['frequency']
    tframe = correlation['timeframe']
    matched_sid = correlation['if_matched_sid']
    lines = [f'  <rule id="{rule_id}" level="{level}" frequency="{freq}" timeframe="{tframe}">']
    lines.append(f"    <if_matched_sid>{escape(str(matched_sid))}</if_matched_sid>")
    if correlation.get("same_source_ip"):
        lines.append("    <same_source_ip />")
    lines.append(f"    <description>{escape(description)}</description>")
    if mitre_ids:
        lines.append("    <mitre>")
        lines += [f"      <id>{escape(m)}</id>" for m in mitre_ids]
        lines.append("    </mitre>")
    if groups:
        lines.append(f'    <group>{escape(",".join(groups))},</group>')
    lines.append("  </rule>")
    return "\n".join(lines)


def convert_rule(path, id_map):
    doc = yaml.safe_load(Path(path).read_text())
    detection = doc.get("detection", {})
    condition = detection.get("condition", "").strip()

    correlation = doc.get("correlation")
    if correlation is not None:
        # Frequency/timeframe correlation rule: chains off an already-matched
        # sibling rule ID and counts repeats within a time window. Still no
        # OR logic — this is event-counting, not branching conditions.
        required = {"if_matched_sid", "frequency", "timeframe"}
        missing = required - correlation.keys()
        if missing:
            raise ValueError(f"'correlation' block missing required keys: {missing}")
        return _build_correlation_rule(doc, correlation, id_map)

    if condition != "selection":
        raise ValueError(f"Unsupported condition '{condition}'. Only 'condition: selection' is supported.")
    selection = detection.get("selection")
    if not isinstance(selection, dict):
        raise ValueError("Missing or malformed 'detection.selection' block.")

    decoded_as, parent_id, fields = convert_selection(selection)
    if decoded_as is None and parent_id is None:
        raise ValueError("This converter requires either 'decoder.name' or 'parent_id' in the selection.")

    sigma_id = doc.get("id") or doc["title"]
    rule_id = assign_rule_id(sigma_id, id_map)
    level = LEVEL_MAP.get(doc.get("level", "medium"), 7)
    description = doc.get("description") or doc["title"]
    mitre_ids = extract_mitre_ids(doc.get("tags"))
    groups = ["sentryforge"] + [
        t.split(".", 1)[1] for t in (doc.get("tags") or [])
        if t.lower().startswith("attack.") and not t.lower().startswith("attack.t")
    ]

    lines = [f'  <rule id="{rule_id}" level="{level}">']
    if parent_id is not None:
        lines.append(f"    <if_sid>{escape(str(parent_id))}</if_sid>")
    if decoded_as is not None:
        lines.append(f"    <decoded_as>{escape(decoded_as)}</decoded_as>")
    for name, value in fields:
        lines.append(f'    <field name="{escape(name)}">^{escape(str(value))}$</field>')
    lines.append(f"    <description>{escape(description)}</description>")
    if mitre_ids:
        lines.append("    <mitre>")
        lines += [f"      <id>{escape(m)}</id>" for m in mitre_ids]
        lines.append("    </mitre>")
    if groups:
        lines.append(f'    <group>{escape(",".join(groups))},</group>')
    lines.append("  </rule>")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: sigma_to_wazuh.py <sigma-rules-dir> [output-file]")
        sys.exit(1)
    sigma_dir = Path(sys.argv[1])
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("output/sentryforge_rules.xml")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    id_map = load_id_map()
    blocks = []
    for f in sorted(sigma_dir.glob("*.yml")):
        try:
            blocks.append(convert_rule(f, id_map))
            print(f"OK   {f.name}")
        except ValueError as e:
            print(f"FAIL {f.name}: {e}")
            sys.exit(1)
    save_id_map(id_map)

    xml = '<group name="sentryforge,">\n' + "\n".join(blocks) + "\n</group>\n"
    out_path.write_text(xml)
    print(f"\nWrote {len(blocks)} rule(s) to {out_path}")


if __name__ == "__main__":
    main()
