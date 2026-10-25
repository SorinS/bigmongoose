// Differential test: every case in vectors/bigint.txt (made by
// scripts/gen_vectors.py from Python's integers) against bigman.
import std;
import bigman from "..";

var failures = 0;
var cases = 0;

fn hx(s: const u8[:]) -> bigman::BigInt {
    let v, ok = bigman::parse(s, 16);
    assert(ok);
    return v;
}

fn check(line: const u8[:], got, want: const u8[:]) {
    cases++;
    let g = bigman::to_hex(got);
    if g != want {
        failures++;
        if failures <= 10 { print("FAIL: ", line[..::min(line.len, 120)], "\n  got  ", g, "\n  want ", want); }
    }
}

fn check_bool(line: const u8[:], got: bool, want: const u8[:]) {
    cases++;
    if (if got { "1" } else { "0" }) != want {
        failures++;
        if failures <= 10 { print("FAIL: ", line[..::min(line.len, 120)], " got ", got); }
    }
}

fn small(s: const u8[:]) -> i64 {
    let v, ok = bigman::to_i64(hx(s));
    assert(ok);
    return v;
}

fn main() {
    let text = embed_file("vectors/bigint.txt");
    for line in split(text, '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let op = w[0];
        if op == "add" { check(line, bigman::add(hx(w[1]), hx(w[2])), w[3]); }
        else if op == "sub" { check(line, bigman::sub(hx(w[1]), hx(w[2])), w[3]); }
        else if op == "cmp" { check(line, bigman::big(bigman::cmp(hx(w[1]), hx(w[2]))), w[3]); }
        else if op == "mul" { check(line, bigman::mul(hx(w[1]), hx(w[2])), w[3]); }
        else if op == "divmod" {
            let q, r = bigman::divmod(hx(w[1]), hx(w[2]));
            check(line, q, w[3]);
            check(line, r, w[4]);
        } else if op == "divmod_floor" {
            let q, r = bigman::divmod_floor(hx(w[1]), hx(w[2]));
            check(line, q, w[3]);
            check(line, r, w[4]);
            check(line, bigman::div_floor(hx(w[1]), hx(w[2])), w[3]);
            check(line, bigman::mod_floor(hx(w[1]), hx(w[2])), w[4]);
        } else if op == "gcd" { check(line, bigman::gcd(hx(w[1]), hx(w[2])), w[3]); }
        else if op == "modinv" {
            let r, ok = bigman::modinv(hx(w[1]), hx(w[2]));
            check_bool(line, ok, w[4]);
            if ok { check(line, r, w[3]); }
        } else if op == "modpow" { check(line, bigman::modpow(hx(w[1]), hx(w[2]), hx(w[3])), w[4]); }
        else if op == "shl" { check(line, bigman::shl(hx(w[1]), small(w[2])), w[3]); }
        else if op == "shr" { check(line, bigman::shr(hx(w[1]), small(w[2])), w[3]); }
        else if op == "and" { check(line, bigman::bit_and(hx(w[1]), hx(w[2])), w[3]); }
        else if op == "or" { check(line, bigman::bit_or(hx(w[1]), hx(w[2])), w[3]); }
        else if op == "xor" { check(line, bigman::bit_xor(hx(w[1]), hx(w[2])), w[3]); }
        else if op == "not" { check(line, bigman::bit_not(hx(w[1])), w[2]); }
        else if op == "bit" { check_bool(line, bigman::test_bit(hx(w[1]), small(w[2])), w[3]); }
        else if op == "isqrt" { check(line, bigman::isqrt(hx(w[1])), w[2]); }
        else if op == "pow" { check(line, bigman::pow(hx(w[1]), small(w[2]) as u64), w[3]); }
        else if op == "dec" {
            cases++;
            let s = bigman::to_str(hx(w[1]));
            if s != w[2] { failures++; print("FAIL: ", line[..::min(line.len, 120)], " got ", s); }
            let v, ok = bigman::parse(w[2]);
            check(line, v, w[1]);
        } else { print("unknown op ", op); failures++; }
    }
    print("bigint vectors: ", cases, " checks, ", failures, " failed");
    assert(failures == 0);
}
