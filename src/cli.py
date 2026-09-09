from __future__ import annotations
import argparse,json
from pathlib import Path
from controls import audit_inventory
from io_utils import load_inventory
from reporting import render_markdown

def main()->None:
    parser=argparse.ArgumentParser(description="Defensive API security metadata assessor")
    parser.add_argument("inventory")
    parser.add_argument("--format",choices=("json","markdown"),default="markdown")
    parser.add_argument("--output")
    args=parser.parse_args()
    endpoints=load_inventory(args.inventory); findings=audit_inventory(endpoints)
    content=json.dumps([f.as_dict() for f in findings],indent=2) if args.format=="json" else render_markdown(endpoints,findings)
    if args.output: Path(args.output).write_text(content+"\n",encoding="utf-8")
    else: print(content)

if __name__=="__main__": main()
