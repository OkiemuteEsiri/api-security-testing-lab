from __future__ import annotations

import json
from pathlib import Path

from models import Endpoint


def load_inventory(path: str | Path) -> list[Endpoint]:
    with open(path, encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, list):
        raise ValueError("Inventory must be a JSON list")
    endpoints = [Endpoint.from_dict(item) for item in raw]
    seen: set[tuple[str, str]] = set()
    for endpoint in endpoints:
        key = (endpoint.method, endpoint.path)
        if key in seen:
            raise ValueError(f"Duplicate endpoint definition: {endpoint.method} {endpoint.path}")
        seen.add(key)
    return endpoints
