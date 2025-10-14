# collect_rmap_pdfs.py
from rmap.rmap_client import rmap_client_run
from pathlib import Path
from pgpy import PGPKey

# --- Setup ---
KEYS_DIR = Path("keys")
CLIENT_PRIV_PATH = KEYS_DIR / "server_priv.asc"
SERVER_PUB_PATH = KEYS_DIR / "server_pub.asc"
OUTPUT_DIR = Path("collected_pdfs")
OUTPUT_DIR.mkdir(exist_ok=True)

# --- Load PGP keys manually ---
with open(CLIENT_PRIV_PATH, "r") as f:
    client_priv, _ = PGPKey.from_blob(f.read())

with open(SERVER_PUB_PATH, "r") as f:
    server_pub, _ = PGPKey.from_blob(f.read())

# unlock private key (must match your server passphrase)
client_priv.unlock("CLL")

ips = [
    "10.11.202.3", "10.11.202.6", "10.11.202.7", "10.11.202.9",
    "10.11.202.10", "10.11.202.11", "10.11.202.13", "10.11.202.14",
    "10.11.202.15", "10.11.202.16", "10.11.12.17", "10.11.12.7",
    "10.11.12.8", "10.11.12.9", "10.11.12.10", "10.11.12.18",
    "10.11.12.19", "10.11.12.12"
]

# --- Collect PDFs ---
for ip in ips:
    print(f"\n🌐 Contacting {ip}")
    try:
        rmap_client_run(
            client_priv=client_priv,
            server_pub=server_pub,
            server_addr=f"{ip}",
            identity="Group_10",
            outdir=str(OUTPUT_DIR),
        )
        print(f"✅ Success: PDF collected from {ip}")
    except Exception as e:
        print(f"⚠️  Failed for {ip}: {e}")
