#!/usr/bin/env python3
"""Reboot the system, optionally after a delay.

Used by the VPS Dashboard reboot button and the post-update auto-reboot.
Runs detached (start_new_session) so it survives the dashboard service.

Usage:
  reboot_system.py [--delay SECONDS] [--reason TEXT] [--dry-run]
"""
import argparse
import subprocess
import sys
import time


def main():
    ap = argparse.ArgumentParser(description="Reboot the system (after optional delay).")
    ap.add_argument("--delay", type=int, default=5,
                    help="seconds to wait before rebooting (default 5)")
    ap.add_argument("--reason", default="",
                    help="optional reason shown to logged-in users via wall")
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would run without rebooting")
    args = ap.parse_args()

    if args.reason:
        try:
            subprocess.run(["wall", f"VPS Dashboard: rebooting — {args.reason}"],
                           check=False, timeout=5)
        except Exception:
            pass
    if args.dry_run:
        print(f"[dry-run] would run: systemctl reboot (after {args.delay}s delay)"
              + (f" | reason: {args.reason}" if args.reason else ""))
        return 0

    print(f"Rebooting in {args.delay}s...", flush=True)
    time.sleep(max(0, args.delay))
    try:
        r = subprocess.run(["systemctl", "reboot"], check=False, timeout=30)
        return r.returncode
    except FileNotFoundError:
        # fallback for non-systemd hosts
        try:
            return subprocess.run(["reboot"], check=False, timeout=30).returncode
        except Exception as e:
            print(f"reboot failed: {e}", file=sys.stderr)
            return 1
    except Exception as e:
        print(f"reboot failed: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
