#!/usr/bin/env python3
"""Build and run the timing tests of the constant-time code
(test/timing/ct_timing.goose), natively at -O2 as the code ships.

    python3 scripts/ct_timing.py [--goose PATH] [scale]

`scale` multiplies the number of runs of each test (default 1). The
compiler is --goose, else $GOOSE, else `goose` on PATH, else
../goose.git/build/goose beside this repository. Exit status 1 if a test
found a leak, or the control (BigInt's modpow) was not caught.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))


def find_goose(arg):
    for cand in [arg, os.environ.get("GOOSE"), shutil.which("goose"),
                 os.path.join(ROOT, "..", "goose.git", "build", "goose")]:
        if cand and os.path.isfile(cand):
            return cand
    sys.exit("no goose compiler found: pass --goose or set GOOSE")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose")
    ap.add_argument("scale", nargs="?", type=int, default=1)
    args = ap.parse_args()
    if args.scale < 1:
        ap.error("scale must be 1 or more")
    goose = find_goose(args.goose)
    src = os.path.join(ROOT, "test", "timing", "ct_timing.goose")
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "ct_timing")
        p = subprocess.run([goose, "build", "-O2", "-o", exe, src], capture_output=True, text=True)
        if p.returncode != 0:
            sys.stderr.write(p.stdout + p.stderr)
            sys.exit(1)
        sys.exit(subprocess.run([exe, str(args.scale)]).returncode)


if __name__ == "__main__":
    main()
