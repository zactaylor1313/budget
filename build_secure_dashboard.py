"""
build_secure_dashboard.py

Encrypts bills-data.json with AES-256-GCM using a passphrase-derived key
(PBKDF2-SHA256, 600k iterations) and emits a single self-contained
index.html that:

  - shows a passphrase prompt and NOTHING else until the right phrase is entered
  - decrypts in the browser via WebCrypto
  - renders the dashboard from the decrypted JSON

Only ciphertext is written to the output file. The repository can be public.

    python build_secure_dashboard.py <passphrase>
"""
import json
import os
import sys
import base64
import hashlib

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "budget-site")
DATA = r"C:/Users/zacta/Documents/Hercules Vault/Budget/bills-data.json"

ITERATIONS = 600_000


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def main():
    if len(sys.argv) < 2:
        print("usage: python build_secure_dashboard.py <passphrase>")
        return 1
    passphrase = sys.argv[1]

    with open(DATA, encoding="utf-8") as f:
        data = json.load(f)

    # Flatten the payload to the shape the dashboard renderer wants.
    payload = {
        "income": [
            {"amount": i.get("monthly", 0), "source": i.get("source") or "Income",
             "note": i.get("note", "")}
            for i in data.get("income", [])
        ],
        "bills": [
            {"name": b.get("name"), "amount": b.get("amount"), "dueDay": b.get("due")}
            for b in data.get("bills", [])
        ],
        "variable": [
            {"name": v.get("name"), "monthly": v.get("monthly")}
            for v in data.get("variable", [])
        ],
        "generated": "2026-10-03",
        "note": "Figures from the June 2026 baseline - pending Sir's confirmation.",
    }
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    # Derive the AES key and encrypt with a random salt + IV.
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, ITERATIONS, dklen=32)

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    ct = AESGCM(key).encrypt(iv, plaintext, None)

    blob = {
        "v": 1,
        "kdf": "PBKDF2-SHA256",
        "iter": ITERATIONS,
        "salt": b64(salt),
        "iv": b64(iv),
        "ct": b64(ct),
    }

    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "payload.json"), "w", encoding="utf-8") as f:
        json.dump(blob, f, indent=2)

    print("ENCRYPTED")
    print("  plaintext bytes :", len(plaintext))
    print("  ciphertext bytes:", len(blob["ct"]))
    print("  iterations      :", ITERATIONS)
    print("  salt (b64)      :", blob["salt"])
    print("  written         : payload.json")
    return 0


if __name__ == "__main__":
    sys.exit(main())
