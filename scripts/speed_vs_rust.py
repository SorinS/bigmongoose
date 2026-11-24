"""Every primitive's speed against Rust's RustCrypto crates on this machine.

Builds examples/speed.goose natively and tools/rustbench twice with cargo,
runs the three, and prints a Markdown table: the Goose figure, Rust's
without the CPU's crypto instructions (AES, PMULL/CLMUL, SHA, SIMD; the
Goose code uses none), Rust's with them, and Goose / Rust for each (above
1 is faster). Both measure the same operations on the same inputs.

    python3 scripts/speed_vs_rust.py [--goose PATH] [--seconds S] [prefix]
"""

import argparse
import os
import platform
import subprocess
import tempfile

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
CRATE = os.path.join(ROOT, "tools", "rustbench")

SOFT = ['--cfg aes_force_soft', '--cfg polyval_force_soft', '--cfg chacha20_force_soft',
        '--cfg curve25519_dalek_backend="serial"']
# x86 crates find AES-NI, CLMUL, SHA-NI and AVX2 at run time; aarch64 ones
# use AES, PMULL and NEON only when told to.
HW = ['--cfg aes_armv8', '--cfg polyval_armv8', '--cfg chacha20_force_neon'] \
    if platform.machine() in ("arm64", "aarch64") else []


def figures(out):
    got = []
    for line in out.splitlines():
        name, value, unit = line.split()
        got.append((name, float(value), unit))
    return got


def rust(variant, flags, secs, prefix):
    target = os.path.join(CRATE, "target", variant)
    env = dict(os.environ, RUSTFLAGS=" ".join(flags))
    subprocess.run(["cargo", "build", "--release", "--quiet", "--features", variant, "--target-dir", target],
                   cwd=CRATE, env=env, check=True)
    exe = os.path.join(target, "release", "rustbench")
    out = subprocess.run([exe, "--seconds", str(secs), prefix], check=True, capture_output=True, text=True).stdout
    return {name: value for name, value, _ in figures(out)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--goose", default=os.path.join(ROOT, "..", "goose.git", "build", "goose"))
    ap.add_argument("--seconds", type=float, default=1)
    ap.add_argument("prefix", nargs="?", default="")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        exe = os.path.join(tmp, "speed")
        subprocess.run([args.goose, "build", "-o", exe, os.path.join(ROOT, "examples", "speed.goose")],
                       check=True, capture_output=True)
        goose = figures(subprocess.run([exe, args.prefix], check=True, capture_output=True, text=True).stdout)
    soft = rust("soft", SOFT, args.seconds, args.prefix)
    hw = rust("hw", HW, args.seconds, args.prefix)
    rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout.split()[1]
    print(f"| Operation | Goose | Rust {rustc}, software | Rust, CPU instructions | Goose / software | Goose / CPU |")
    print("|---|---:|---:|---:|---:|---:|")
    for name, value, unit in goose:
        fmt = (lambda v: f"{v:,.0f} {unit}") if unit == "op/s" and value >= 100 else (lambda v: f"{v:,.1f} {unit}")
        s, h = soft.get(name), hw.get(name)
        cell = lambda v: fmt(v) if v else "-"
        ratio = lambda v: f"{value / v:.2f}" if v else "-"
        print(f"| {name} | {fmt(value)} | {cell(s)} | {cell(h)} | {ratio(s)} | {ratio(h)} |")


if __name__ == "__main__":
    main()
