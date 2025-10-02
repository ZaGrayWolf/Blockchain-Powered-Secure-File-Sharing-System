# blockchain_simulator.py
import os
import json
import hashlib
from datetime import datetime
from typing import Dict, Any

LEDGER_FILE_DEFAULT = "data/blockchain_ledger.json"

def _now_ts():
    return datetime.utcnow().timestamp()

def _now_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def _hash_block(block: Dict[str, Any]) -> str:
    h_input = json.dumps({
        "block_number": block["block_number"],
        "timestamp": block["timestamp"],
        "previous_hash": block["previous_hash"],
        "transaction": block["transaction"]
    }, sort_keys=True).encode('utf-8')
    return hashlib.sha256(h_input).hexdigest()

def _ensure_data_folder():
    os.makedirs(os.path.dirname(LEDGER_FILE_DEFAULT), exist_ok=True)

def load_ledger(path: str = LEDGER_FILE_DEFAULT) -> Dict[str, Any]:
    _ensure_data_folder()
    if not os.path.exists(path):
        genesis = {
            "chain": [],
            "block_count": 0
        }
        with open(path, "w") as f:
            json.dump(genesis, f, indent=2)
        return genesis
    with open(path, "r") as f:
        return json.load(f)

def save_ledger(ledger: Dict[str, Any], path: str = LEDGER_FILE_DEFAULT):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(ledger, f, indent=2)

def add_block(transaction: Dict[str, Any], user: str = "demo_user", path: str = LEDGER_FILE_DEFAULT) -> Dict[str, Any]:
    ledger = load_ledger(path)
    prev_hash = ledger["chain"][-1]["block_hash"] if ledger["chain"] else "0"*64
    block_number = ledger["block_count"] + 1
    block = {
        "block_number": block_number,
        "timestamp": _now_ts(),
        "datetime": _now_str(),
        "previous_hash": prev_hash,
        "transaction": transaction
    }
    block_hash = _hash_block(block)
    block["block_hash"] = block_hash

    ledger["chain"].append(block)
    ledger["block_count"] = block_number
    save_ledger(ledger, path)
    return block

def get_chain(path: str = LEDGER_FILE_DEFAULT):
    ledger = load_ledger(path)
    return ledger.get("chain", [])

def verify_chain(path: str = LEDGER_FILE_DEFAULT) -> Dict[str, Any]:
    ledger = load_ledger(path)
    chain = ledger.get("chain", [])
    problems = []
    for i, block in enumerate(chain):
        expected_hash = _hash_block({
            "block_number": block["block_number"],
            "timestamp": block["timestamp"],
            "previous_hash": block["previous_hash"],
            "transaction": block["transaction"]
        })
        if expected_hash != block.get("block_hash"):
            problems.append({"index": i, "reason": "block_hash_mismatch"})
        if i > 0 and block["previous_hash"] != chain[i-1]["block_hash"]:
            problems.append({"index": i, "reason": "previous_hash_mismatch"})
    return {"valid": len(problems) == 0, "problems": problems}
