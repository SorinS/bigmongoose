"""The comb points of every curve in ec.goose: 2^d G, 2^2d G and 2^3d G with
d = 8 * limbs (a quarter of the scalar's width), as the hex string that
ec_curve takes after gy: x and y of each point, each as wide as p's hex.

    python3 scripts/ec_comb_points.py

reads the curves' constants from ec.goose and prints one line per curve.
"""

import os
import re

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def affine_add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P == Q:
        l = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        l = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (l * l - x1 - x2) % p
    return x3, (l * (x1 - x3) - y1) % p


def main():
    src = open(os.path.join(ROOT, "ec.goose")).read()
    for m in re.finditer(r"fn (\w+)\(\) -> Curve \{\s*ec_curve\((\d+), \d+, \d+,((?:\s*\"[0-9a-f]*\",?)+)", src):
        name, nl = m.group(1), int(m.group(2))
        p_hex, a_hex, n_hex, b_hex, gx_hex, gy_hex = re.findall(r"\"([0-9a-f]*)\"", m.group(3))[:6]
        p = int(p_hex, 16)
        a = (p - 3) if a_hex == "" else int(a_hex, 16)
        P = (int(gx_hex, 16), int(gy_hex, 16))
        d = 8 * nl
        out = []
        for _ in range(3):
            for _ in range(d):
                P = affine_add(P, P, a, p)
            out.append(f"{P[0]:0{len(p_hex)}x}{P[1]:0{len(p_hex)}x}")
        print(name, "".join(out))


if __name__ == "__main__":
    main()
