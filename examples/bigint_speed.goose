// Operation rates of the BigInt layer and of the constant-time Montgomery
// exponentiation, one line each: "name value op/s", the name carrying the
// operands' size in bits. scripts/bigint_vs_rust.py builds this natively
// and sets each line against Rust's num-bigint and crypto-bigint on the
// same inputs (tools/rustbigbench). A name given as an argument runs only
// the lines it prefixes.
//
//   goose build -o bigint_speed examples/bigint_speed.goose && ./bigint_speed [prefix]
import std;
import os;
import bignum from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum.mont;

let SECS: f64 = 0.5;

var only: u8[>..] = [];

fn wanted(name: const u8[:]) -> bool {
    only.len == 0 || (name.len >= only.len && name[..only.len] == only)
}

struct Timer { t0: f64, n: i64 }

fn timer() -> Timer { Timer { t0: clock(), n: 0 } }

fn more(t: Timer&) -> bool {
    if t.n > 0 && clock() - t.t0 >= SECS { return false; }
    t.n++;
    return true;
}

fn ops(name: const u8[:], t: const Timer&) {
    let s = clock() - t.t0;
    print(name, " ", (t.n / s), " op/s");
}

fn name(op: const u8[:], bits: i64) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(op);
    out.append("-");
    format_int(out, bits, 10, 0, 32);
    return out;
}

fn bytes_of(n: i64, seed: i64) -> u8[>..] {
    var out: u8[>..] = [];
    for i in n { out.push(((i * 131 + seed * 17 + 7) % 251) as! u8); }
    return out;
}

// A number of exactly `bits` bits (top bit set), odd when asked; the same
// bytes as tools/rustbigbench's.
fn number(bits: i64, seed: i64, odd: bool) -> bignum::BigInt {
    var b = bytes_of(bits / 8, seed);
    b[0] = b[0] | 128;
    if odd { b[b.len - 1] = b[b.len - 1] | 1; }
    return bignum::from_bytes_be(b);
}

// One bit shorter than number(bits, ...), so below any modulus of `bits`.
fn below(bits: i64, seed: i64) -> bignum::BigInt {
    var b = bytes_of(bits / 8, seed);
    b[0] = (b[0] & 127) | 64;
    return bignum::from_bytes_be(b);
}

fn arith() {
    let sizes: i64[5] = [256, 1024, 4096, 16384, 65536];
    for bits in sizes {
        let a = number(bits, 1, false);
        let b = below(bits, 2);
        let na = name("add", bits);
        if wanted(na) { var t = timer(); while more(t) { let s = bignum::add(a, b); } ops(na, t); }
        let ns = name("sub", bits);
        if wanted(ns) { var t = timer(); while more(t) { let s = bignum::sub(a, b); } ops(ns, t); }
        let nm = name("mul", bits);
        if wanted(nm) { var t = timer(); while more(t) { let s = bignum::mul(a, b); } ops(nm, t); }
        let nq = name("sqr", bits);
        if wanted(nq) { var t = timer(); while more(t) { let s = bignum::sqr(a); } ops(nq, t); }
        let nl = name("shl", bits);
        if wanted(nl) { var t = timer(); while more(t) { let s = bignum::shl(a, 13); } ops(nl, t); }
        let nr = name("shr", bits);
        if wanted(nr) { var t = timer(); while more(t) { let s = bignum::shr(a, 13); } ops(nr, t); }
        // 2 bits by bits.
        let nd = name("divmod", bits);
        if bits <= 16384 && wanted(nd) {
            let x = bignum::mul(number(bits, 3, false), number(bits, 4, false));
            var t = timer(); while more(t) { let q, r = bignum::divmod(x, a); } ops(nd, t);
        }
    }
}

fn number_theory() {
    let sizes: i64[3] = [1024, 2048, 4096];
    for bits in sizes {
        let m = number(bits, 5, true);
        let x = below(bits, 6);
        let e = number(bits, 7, false);
        let np = name("modpow", bits);
        if wanted(np) { var t = timer(); while more(t) { let r = bignum::modpow(x, e, m); } ops(np, t); }
        let nc = name("mont-modexp", bits);
        if bits >= 2048 && wanted(nc) {
            let n = m.mag.len;
            var r: u32[>..] = [];
            r.resize(n, 0);
            var r2: u32[>..] = [];
            r2.resize(n, 0);
            bignum::mont_r2(r2, m.mag);
            var xl: u32[>..] = [];
            xl.resize(n, 0);
            for i in x.mag.len { xl[i] = x.mag[i]; }
            let m0i = bignum::mont_m0i(m.mag[0]);
            var t = timer(); while more(t) { bignum::mont_modexp(r, xl, e.mag, m.mag, m0i, r2); } ops(nc, t);
        }
        let b = number(bits, 8, false);
        let ng = name("gcd", bits);
        if bits != 2048 && wanted(ng) { var t = timer(); while more(t) { let g = bignum::gcd(e, b); } ops(ng, t); }
        let ni = name("modinv", bits);
        if bits != 2048 && wanted(ni) {
            var t = timer(); while more(t) { let v, ok = bignum::modinv(x, m); assert(ok); } ops(ni, t);
        }
    }
}

fn text() {
    let sizes: i64[2] = [4096, 65536];
    for bits in sizes {
        let a = number(bits, 9, false);
        let s = bignum::to_str(a);
        let nt = name("to_str", bits);
        if wanted(nt) { var t = timer(); while more(t) { let d = bignum::to_str(a); } ops(nt, t); }
        let np = name("parse", bits);
        if wanted(np) { var t = timer(); while more(t) { let v, ok = bignum::parse(s); assert(ok); } ops(np, t); }
    }
}

fn main() {
    let a = args();
    if a.len > 1 { only.append(a[1]); }
    arith();
    number_theory();
    text();
}
