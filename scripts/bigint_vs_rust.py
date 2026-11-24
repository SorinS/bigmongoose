"""The BigInt layer's speed against Rust's num-bigint and crypto-bigint.

Builds examples/bigint_speed.goose natively and tools/rustbigbench with
cargo, runs both on the same inputs, and prints a Markdown table: the
Goose rate, Rust's (num-bigint for the general integers, crypto-bigint for
the constant-time Montgomery exponentiation, mont-modexp), and Goose /
Rust (above 1 is faster).

    python3 scripts/bigint_vs_rust.py [--goose PATH] [--seconds S] [prefix]
"""

import argparse
import os
import subprocess
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CRATE = os.path.join(ROOT, "tools", "rustbigbench")


def figures(out):
    got = []
    for line in out.splitlines():
        name, value, unit = line.split()
        got.append((name, float(value), unit))
    return got


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose", default=os.path.join(ROOT, "..", "goose.git", "build", "goose"))
    ap.add_argument("--seconds", type=float, default=0.5)
    ap.add_argument("prefix", nargs="?", default="")
    args = ap.parse_args()
    subprocess.run(["cargo", "build", "--release", "--quiet"], cwd=CRATE, check=True)
    rust_exe = os.path.join(CRATE, "target", "release", "rustbigbench")
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "bigint_speed")
        subprocess.run([args.goose, "build", "-o", exe, os.path.join(ROOT, "examples", "bigint_speed.goose")],
                       check=True, capture_output=True)
        goose = figures(subprocess.run([exe, args.prefix], check=True, capture_output=True, text=True).stdout)
    out = subprocess.run([rust_exe, "--seconds", str(args.seconds), args.prefix],
                         check=True, capture_output=True, text=True).stdout
    rust = {name: value for name, value, _ in figures(out)}
    print("| Operation | Goose | Rust (num-bigint / crypto-bigint) | Goose / Rust |")
    print("|---|---:|---:|---:|")
    for name, value, unit in goose:
        fmt = lambda v: f"{v:,.0f} {unit}" if v >= 100 else f"{v:,.1f} {unit}"
        r = rust.get(name)
        print(f"| {name} | {fmt(value)} | {fmt(r) if r else '-'} | {f'{value / r:.2f}' if r else '-'} |")


if __name__ == "__main__":
    main()
