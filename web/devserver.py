"""Launch the dashboard server fully detached (survives shell exit).

Usage:  python3 web/devserver.py [--port 8000]
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    log = open("/tmp/secops_web.log", "w")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "web.main:app",
         "--host", args.host, "--port", str(args.port)],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,   # POSIX setsid — detaches from this shell
    )
    print(f"server pid={proc.pid}  http://{args.host}:{args.port}  log=/tmp/secops_web.log")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
