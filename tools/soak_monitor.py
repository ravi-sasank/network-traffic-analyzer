"""Soak-test monitor. Samples the running capture process's memory and the
DB file size at intervals, so you can prove the backend stays stable over a
long run. Start capture first, then run this in another terminal.

Usage: python tools/soak_monitor.py [minutes]
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import subprocess
import time
from backend.config import DB_PATH


def find_capture_pid():
    out = subprocess.run(["pgrep", "-f", "backend.capture_service"],
                         capture_output=True, text=True).stdout.strip()
    return out.split("\n")[0] if out else None


def rss_mb(pid):
    try:
        out = subprocess.run(["ps", "-o", "rss=", "-p", pid],
                             capture_output=True, text=True).stdout.strip()
        return int(out) / 1024 if out else None
    except (ValueError, subprocess.SubprocessError):
        return None


def db_mb():
    total = 0
    for suffix in ["", "-wal", "-shm"]:
        p = Path(str(DB_PATH) + suffix)
        if p.exists():
            total += p.stat().st_size
    return total / (1024 * 1024)


def main():
    minutes = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    pid = find_capture_pid()
    if not pid:
        print("No capture process found. Start it first.")
        return

    print("monitoring pid " + pid + " for " + str(minutes) + " min")
    print(f"{'elapsed':>8} {'mem_MB':>8} {'db_MB':>8}")
    start = time.time()
    samples = []
    while time.time() - start < minutes * 60:
        mem = rss_mb(pid)
        db = db_mb()
        if mem is None:
            print("capture process ended")
            break
        elapsed = int(time.time() - start)
        samples.append((elapsed, mem, db))
        print(f"{elapsed:>7}s {mem:>8.1f} {db:>8.2f}", flush=True)
        time.sleep(30)

    if len(samples) >= 2:
        mem_start, mem_end = samples[0][1], samples[-1][1]
        db_start, db_end = samples[0][2], samples[-1][2]
        print("\n=== soak summary ===")
        print("duration:      " + str(samples[-1][0]) + "s")
        print("memory:        " + str(round(mem_start, 1)) + " -> "
              + str(round(mem_end, 1)) + " MB  (drift "
              + str(round(mem_end - mem_start, 1)) + " MB)")
        print("database:      " + str(round(db_start, 2)) + " -> "
              + str(round(db_end, 2)) + " MB")
        drift = mem_end - mem_start
        verdict = "STABLE" if abs(drift) < 30 else "INVESTIGATE - memory drifted"
        print("verdict:       " + verdict)


if __name__ == "__main__":
    main()
