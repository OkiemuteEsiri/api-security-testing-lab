"""Backward-compatible entry point for the original lab interface."""
from __future__ import annotations
import json,sys
from pathlib import Path
from controls import audit_inventory as _audit_inventory, evaluate_endpoint
from io_utils import load_inventory as _load_inventory
from models import Endpoint

def load_inventory(path:str|Path)->list[dict]: return [e.__dict__ for e in _load_inventory(path)]
def audit_endpoint(endpoint:dict)->list[dict]: return [f.as_dict() for f in evaluate_endpoint(Endpoint.from_dict(endpoint))]
def audit_inventory(inventory:list[dict])->list[dict]: return [f.as_dict() for f in _audit_inventory([Endpoint.from_dict(i) for i in inventory])]
def main()->None:
    if len(sys.argv)!=2: raise SystemExit("Usage: python src/api_security_audit.py <inventory.json>")
    print(json.dumps(audit_inventory(load_inventory(sys.argv[1])),indent=2))
if __name__=="__main__": main()
