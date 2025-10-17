#!/usr/bin/env python3
"""
Tatou Flag Access Watchdog (Hybrid Version)
-------------------------------------------
- Uses inotify if available to detect file reads/writes in real time.
- Falls back to polling (mtime/hash) if no inotify events are received.
- Exposes Prometheus metrics to detect possible flag access attempts.
"""


import os
import time
import hashlib
import threading
from prometheus_client import start_http_server, Counter, Gauge


# Try to import inotify_simple if available
try:
    from inotify_simple import INotify, flags
    HAS_INOTIFY = True
except ImportError:
    HAS_INOTIFY = False


# ---------------- Configuration ---------------- #
FLAG_PATHS = [
    "/app/flag",
    "/app/server/flag",
    "/app/tatou/flag",
]
SCRAPE_PORT = 9101
POLL_INTERVAL = 5          # seconds (for hash polling)
INOTIFY_DEBOUNCE = 2.0     # seconds
INOTIFY_TIMEOUT = 10.0     # seconds to fall back if no events
# ------------------------------------------------ #


flag_access_attempts = Counter(
    "tatou_flag_access_attempts_total",
    "Number of detected flag file access or modification attempts",
    ["path", "pid", "process", "user"]
)


flag_integrity = Gauge(
    "tatou_flag_integrity",
    "1 if flag file hash intact, 0 if tampered",
    ["path"]
)


# Initialize metrics for Grafana (flat line at 0)
for path in FLAG_PATHS:
    flag_access_attempts.labels(path=path, pid="init", process="init", user="init").inc(0)
    flag_integrity.labels(path=path).set(1 if os.path.exists(path) else 0)




def hash_file(path):
    """Return sha256 hash of file contents."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None




def polling_loop():
    """Fallback: poll mtime/hash for changes every few seconds."""
    print("[Tatou Watchdog] Using polling mode (overlayfs or no inotify events)")
    last_hash = {p: hash_file(p) for p in FLAG_PATHS}
    while True:
        for p in FLAG_PATHS:
            if not os.path.exists(p):
                continue
            h = hash_file(p)
            if h and last_hash.get(p) and h != last_hash[p]:
                print(f"[ALERT] Flag file content changed: {p}")
                flag_access_attempts.labels(path=p, pid="polling", process="poll", user="unknown").inc()
                last_hash[p] = h
        time.sleep(POLL_INTERVAL)




def inotify_loop():
    """Primary: watch for filesystem events."""
    print("[Tatou Watchdog] Using inotify mode")
    inotify = INotify()
    watch_flags = flags.ACCESS | flags.CLOSE_WRITE | flags.MODIFY | flags.OPEN
    wd_to_paths = {}


    # Map each flag’s directory to a watch descriptor
    for p in FLAG_PATHS:
        if not os.path.exists(p):
            print(f"[Tatou Watchdog] Skipping missing flag path: {p}")
            continue
        dir_path = os.path.dirname(p)
        wd = inotify.add_watch(dir_path, watch_flags)
        wd_to_paths.setdefault(wd, set()).add(p)
        print(f"[Tatou Watchdog] Watching directory {dir_path} for {os.path.basename(p)}")


    last_trigger = {}
    last_event_time = time.time()


    while True:
        events = inotify.read(timeout=int(POLL_INTERVAL * 1000))  # ms
        now = time.time()
        if not events:
            # Check if we've gone too long with no events (possible silent overlayfs)
            if now - last_event_time > INOTIFY_TIMEOUT:
                print("[Tatou Watchdog] ⚠️ No inotify events detected; switching to polling mode")
                polling_loop()
                return
            continue


        last_event_time = now


        for event in events:
            wd = event.wd
            fname = event.name
            if wd not in wd_to_paths:
                continue
            for p in wd_to_paths[wd]:
                if os.path.basename(p) != fname:
                    continue
                key = (p, "inotify")
                if now - last_trigger.get(key, 0) > INOTIFY_DEBOUNCE:
                    print(f"[ALERT] Flag file accessed or modified: {p}")
                    flag_access_attempts.labels(
                        path=p, pid="inotify", process="access", user="unknown"
                    ).inc()
                    last_trigger[key] = now




def main():
    print("[Tatou Watchdog] Starting hybrid flag access monitor...")
    start_http_server(SCRAPE_PORT)
    print(f"[Tatou Watchdog] Prometheus exporter running on :{SCRAPE_PORT}")


    # Decide which mode to use
    if HAS_INOTIFY:
        # Run inotify loop in main thread
        try:
            inotify_loop()
        except Exception as e:
            print(f"[Tatou Watchdog] ⚠️ inotify failed ({e}); falling back to polling.")
            polling_loop()
    else:
        polling_loop()




if __name__ == "__main__":
    main()
