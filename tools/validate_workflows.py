"""Validate repository-owned n8n workflow document structure, not n8n runtime."""
import json
from pathlib import Path

paths = sorted(Path("workflows").glob("*.json"))
if len(paths) < 2:
    raise SystemExit("Expected two or more workflows")
for path in paths:
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(doc.get("name"), str) and doc["name"]
    assert doc.get("active") is False, f"{path} must be inactive"
    nodes = doc.get("nodes")
    assert isinstance(nodes, list) and len(nodes) > 1
    names = [n["name"] for n in nodes]
    assert len(names) == len(set(names))
    assert any(n["type"] == "n8n-nodes-base.manualTrigger" for n in nodes)
    assert all(n["type"] in {"n8n-nodes-base.manualTrigger", "n8n-nodes-base.code"} for n in nodes)
    assert isinstance(doc.get("connections"), dict)
    for node in nodes:
        assert isinstance(node["id"], str) and isinstance(node["parameters"], dict)
    assert "credentials" not in json.dumps(doc).lower()
    print(f"STRUCTURE OK: {path}")
print("NOTE: runtime import compatibility requires validation against the target n8n version.")
