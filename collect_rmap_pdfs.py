#!/usr/bin/env python3
"""
RMAP PDF Collector for Group 10
--------------------------------
Fetches PDFs from other groups' Tatou servers using RMAP and saves them
as Group_<number>_<secret>.pdf in collected_pdfs/.
"""

from rmap.rmap_client import rmap_client_run
from pathlib import Path
from pgpy import PGPKey
import shutil

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GROUP_ID = "Group_10"
KEYS_DIR = Path("keys")
CLIENT_PRIV_PATH = KEYS_DIR / "server_priv.asc"
OUTPUT_DIR = Path("collected_pdfs")
OUTPUT_DIR.mkdir(exist_ok=True)

# Local subnet targets
targets = {
    "10.11.202.3":  "Group_11",
    "10.11.202.6":  "Group_15",
    "10.11.202.7":  "Group_13",
    "10.11.202.9":  "Group_06",
    "10.11.202.10": "Group_21",
    "10.11.202.11": "Group_23",
    "10.11.202.13": "Group_17",
    "10.11.202.14": "Group_18",
    "10.11.202.15": "Group_05",
    "10.11.202.16": "Group_16",
    "10.11.202.18": "Nicolas",
}

# ---------------------------------------------------------------------------
# Load private key
# ---------------------------------------------------------------------------

if not CLIENT_PRIV_PATH.exists():
    raise FileNotFoundError(f"❌ Missing private key: {CLIENT_PRIV_PATH}")

print(f"🔐 Loading private key from {CLIENT_PRIV_PATH}")
client_priv, _ = PGPKey.from_blob(CLIENT_PRIV_PATH.read_text())
client_priv.unlock("CLL")

# ---------------------------------------------------------------------------
# Iterate targets
# ---------------------------------------------------------------------------

for ip, group in targets.items():
    pub_path = KEYS_DIR / "pki" / f"{group}.asc"
    if not pub_path.exists():
        print(f"⚠️  Missing public key for {group} ({ip}), skipping.")
        continue

    server_pub, _ = PGPKey.from_blob(pub_path.read_text())
    print(f"\n🌐 Contacting {ip} ({group})")

    try:
        result = rmap_client_run(
            client_priv=client_priv,
            server_pub=server_pub,
            server_addr=ip,
            identity=GROUP_ID,
            outdir=OUTPUT_DIR,
        )

        # rmap_client_run() typically returns a dict like {"pdf": Path(...), "result": secret}
        if isinstance(result, dict) and "pdf" in result:
            downloaded = Path(result["pdf"])
        else:
            # fallback: get newest PDF in OUTPUT_DIR
            downloaded = max(OUTPUT_DIR.glob("*.pdf"), key=lambda p: p.stat().st_mtime)

        # Build new name: GroupName_<secret>.pdf
        secret = downloaded.stem  # filename without .pdf
        new_name = OUTPUT_DIR / f"{group}_{secret}.pdf"

        shutil.move(downloaded, new_name)
        print(f"✅ Saved as {new_name.name}")

    except Exception as e:
        print(f"⚠️  Failed for {group} ({ip}): {e}")

print("\n🏁 Collection finished. Check the 'collected_pdfs/' folder.")
